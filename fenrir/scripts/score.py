#!/usr/bin/env python3
"""Fenrir scoring utility: score agent results, vulnerabilities, and findings.

Usage:
    python3 scripts/score.py --finding '{"type": "xss", "severity": "medium", ...}'
    python3 scripts/score.py --vulns-file <findings.json>
    python3 scripts/score.py --scan-results <scan_output.json>
"""

import json
import sys
import hashlib

# Severity weights
SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 70,
    "medium": 40,
    "low": 10,
    "info": 2,
    "unknown": 5,
}

# Vulnerability type impact multipliers
VULN_MULTIPILIERS = {
    "sql_injection": 1.5,
    "sqli": 1.5,
    "command_injection": 1.5,
    "rce": 2.0,
    "ssrf": 1.3,
    "file_upload_unrestricted": 1.4,
    "unrestricted_upload": 1.4,
    "xss": 1.0,
    "reflected_xss": 1.0,
    "stored_xss": 1.2,
    "idor": 1.1,
    "auth_bypass": 1.5,
    "authentication_bypass": 1.5,
    "privilege_escalation": 1.4,
    "lfi": 1.2,
    "rfi": 1.3,
    "open_redirect": 0.6,
    "information_disclosure": 0.4,
    "misconfig": 0.3,
    "rate_limiting": 0.2,
}

# Chain bonus
CHAIN_BONUS = {
    2: 1.3,   # 2-step chain
    3: 1.5,   # 3-step chain
    4: 1.8,   # 4-step chain
    5: 2.0,   # 5+ step chain
}


def score_finding(finding: dict) -> dict:
    """Score a single vulnerability finding."""
    vuln_type = (finding.get("type") or finding.get("vuln_type") or "unknown").lower()
    severity = (finding.get("severity") or "unknown").lower()
    confirmed = bool(finding.get("confirmed", False))

    # Base score from severity
    base = SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS["unknown"])

    # Type multiplier
    multiplier = VULN_MULTIPILIERS.get(vuln_type, 1.0)
    score = base * multiplier

    # Confirmation bonus
    if confirmed:
        score *= 1.2

    # Evidence presence bonus
    if finding.get("evidence"):
        score *= 1.1
    if finding.get("poc"):
        score *= 1.15

    # Calculate CVSS-like estimate
    cvss_estimate = min(10.0, score / 10.0)

    return {
        "raw_score": round(score, 1),
        "cvss_estimate": cvss_estimate,
        "severity": severity,
        "vuln_type": vuln_type,
        "confirmed": confirmed,
    }


def score_scan_results(results: list[dict]) -> dict:
    """Score multiple agent results and compute overall risk."""
    total_score = 0.0
    vuln_count = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    scored_findings = []

    for result in results:
        for finding in result.get("findings", []):
            f_type = (finding.get("type") or finding.get("vuln_type") or "").lower()
            if f_type in VULN_MULTIPILIERS or any(k in f_type for k in VULN_MULTIPILIERS):
                scored = score_finding(finding)
                scored_findings.append(scored)
                total_score += scored["raw_score"]
                vuln_count += 1

                severity_counts[finding.get("severity", "info").lower()] += 1

    # Overall risk level
    if total_score >= 100:
        risk_level = "CRITICAL"
    elif total_score >= 50:
        risk_level = "HIGH"
    elif total_score >= 20:
        risk_level = "MEDIUM"
    elif total_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "CLEAR"

    return {
        "total_risk_score": round(total_score, 1),
        "risk_level": risk_level,
        "vulnerability_count": vuln_count,
        "severity_breakdown": severity_counts,
        "agents_run": len(results),
        "findings_per_agent": [
            {
                "agent": r.get("agent_name", "unknown"),
                "findings": len(r.get("findings", [])),
                "vulns_found": sum(
                    1 for f in r.get("findings", [])
                    if (f.get("type") or f.get("vuln_type", ""))
                ),
            }
            for r in results
        ],
        "scored_details": scored_findings,
    }


def generate_fingerprint(finding: dict) -> str:
    """Generate SHA256 fingerprint for a finding (dedup)."""
    key_data = {
        "url": finding.get("url", ""),
        "param": finding.get("parameter", ""),
        "type": finding.get("type", finding.get("vuln_type", "")),
    }
    raw = json.dumps(key_data, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def main():
    if len(sys.argv) < 2 or any(arg in sys.argv for arg in ("--help", "-h")):
        print(__doc__)
        return

    action = sys.argv[1]

    if action == "--finding":
        finding_json = sys.argv[2] if len(sys.argv) > 2 else ""
        finding = json.loads(finding_json)
        result = score_finding(finding)
        result["fingerprint"] = generate_fingerprint(finding)
        print(json.dumps(result, indent=2))

    elif action == "--scan-results":
        results_file = sys.argv[2] if len(sys.argv) > 2 else ""
        with open(results_file) as f:
            data = json.load(f)
        results = data if isinstance(data, list) else data.get("results", [])
        scored = score_scan_results(results)
        print(json.dumps(scored, indent=2))

    elif action == "--vulns-file":
        vulns_file = sys.argv[2] if len(sys.argv) > 2 else ""
        with open(vulns_file) as f:
            vulns = json.load(f)
        if isinstance(vulns, dict):
            vulns = vulns.get("vulns", [])
        for v in vulns:
            scored = score_finding(v)
            scored["fingerprint"] = generate_fingerprint(v)
            print(json.dumps(scored))

    else:
        print(f"Unknown action: {action}")


if __name__ == "__main__":
    main()
