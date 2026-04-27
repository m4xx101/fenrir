#!/usr/bin/env python3
"""Fenrir Pro-Max — Vulnerability Chain Builder

Usage:
    python3 fenrir/scripts/chain_builder.py <target>

Reads vulns.md, discovers chain patterns, saves to chains.md.
This script provides the DIFFERENTIATOR: compound vulnerability analysis.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

BRAIN_DIR = Path.home() / ".fenrir" / "brain"

CHAIN_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "XSS-CSRF-AccountTakeover",
        "required": ["xss"],
        "optional": ["csrf", "session"],
        "severity": "critical",
        "steps": [
            {"step": 1, "vuln": "xss", "description": "Exploit reflected or stored XSS to execute malicious JS on the domain"},
            {"step": 2, "vuln": "csrf_token_theft", "description": "Use injected JS to read CSRF tokens from the page"},
            {"step": 3, "vuln": "account_takeover", "description": "Forge authenticated requests to change email/password"},
        ],
        "impact": "Full account takeover of any user who visits the affected page",
    },
    {
        "name": "SQLi-FileRead-RCE",
        "required": ["sql_injection"],
        "optional": ["file_inclusion", "local_file_inclusion", "file_upload"],
        "severity": "critical",
        "steps": [
            {"step": 1, "vuln": "sql_injection", "description": "Use SQLi to read files, enumerate database, extract credentials"},
            {"step": 2, "vuln": "file_read", "description": "Read config files, source code, credentials from the filesystem"},
            {"step": 3, "vuln": "rce", "description": "Use SQLi INTO OUTFILE to write web shell or use credentials for SSH"},
        ],
        "impact": "Full server compromise and arbitrary code execution",
    },
    {
        "name": "SSRF-InternalService-DataExfil",
        "required": ["ssrf"],
        "optional": ["internal_service", "authentication_bypass"],
        "severity": "critical",
        "steps": [
            {"step": 1, "vuln": "ssrf", "description": "Reach internal services via SSRF (Redis, MongoDB, admin panels)"},
            {"step": 2, "vuln": "internal_service_exploit", "description": "Exploit discovered internal services for data access"},
            {"step": 3, "vuln": "data_exfiltration", "description": "Extract data from internal services"},
        ],
        "impact": "Access to internal infrastructure and sensitive data",
    },
    {
        "name": "IDOR-InfoDisc-AuthBypass",
        "required": ["idor", "broken_access_control"],
        "optional": ["information_disclosure", "authentication_bypass"],
        "severity": "high",
        "steps": [
            {"step": 1, "vuln": "idor", "description": "Enumerate user data by changing resource IDs"},
            {"step": 2, "vuln": "information_disclosure", "description": "Extract credentials, tokens, or sensitive data"},
            {"step": 3, "vuln": "authentication_bypass", "description": "Harvested credentials used for authentication"},
        ],
        "impact": "Account compromise for multiple users without brute force",
    },
    {
        "name": "FileUpload-PathTraversal-WebShell",
        "required": ["file_upload"],
        "optional": ["path_traversal", "local_file_inclusion"],
        "severity": "critical",
        "steps": [
            {"step": 1, "vuln": "file_upload", "description": "Upload a malicious web shell file"},
            {"step": 2, "vuln": "path_traversal", "description": "Use path traversal to place in executable directory"},
            {"step": 3, "vuln": "rce", "description": "Execute commands via uploaded web shell"},
        ],
        "impact": "Remote code execution on the web server",
    },
    {
        "name": "OpenRedirect-OAuthHijack",
        "required": ["open_redirect"],
        "optional": ["oauth", "authentication_bypass"],
        "severity": "high",
        "steps": [
            {"step": 1, "vuln": "open_redirect", "description": "Exploit open redirect to control OAuth flow redirect"},
            {"step": 2, "vuln": "oauth_flow_manipulation", "description": "Intercept OAuth authorization code"},
            {"step": 3, "vuln": "account_takeover", "description": "Exchange code for valid access token"},
        ],
        "impact": "Account takeover via OAuth flow hijacking",
    },
    {
        "name": "AuthBypass-PrivEsc-AdminAccess",
        "required": ["authentication_bypass", "privilege_escalation"],
        "optional": ["idor", "broken_access_control"],
        "severity": "critical",
        "steps": [
            {"step": 1, "vuln": "authentication_bypass", "description": "Bypass authentication to gain initial access"},
            {"step": 2, "vuln": "privilege_escalation", "description": "Escalate privileges from user to admin"},
            {"step": 3, "vuln": "full_access", "description": "Achieve full administrative access"},
        ],
        "impact": "Full administrative access via auth bypass and privilege escalation",
    },
    {
        "name": "Misconfig-ExposedService-DataBreach",
        "required": ["misconfiguration", "broken_access_control", "insecure_direct_object_references"],
        "optional": ["information_disclosure", "sensitive_file_exposure"],
        "severity": "high",
        "steps": [
            {"step": 1, "vuln": "misconfiguration", "description": "Exploit security misconfiguration (verbose errors, missing headers, defaults)"},
            {"step": 2, "vuln": "information_disclosure", "description": "Gather detailed system information from error messages and exposed pages"},
            {"step": 3, "vuln": "data_breach", "description": "Use gathered information for targeted attacks on remaining protections"},
        ],
        "impact": "Progressive information disclosure leading to targeted exploitation",
    },
]


def get_target_dir(target: str) -> Path:
    safe = target.replace("://", "_").replace("/", "_").replace(".", "_")
    d = BRAIN_DIR / "targets" / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_vuln_types(td: Path) -> set[str]:
    """Read vulns.md and extract vulnerability types."""
    vulns_file = td / "vulns.md"
    if not vulns_file.exists():
        return set()

    content = vulns_file.read_text()
    vuln_types = set()

    for line in content.split("\n"):
        line_lower = line.lower()
        if "sql_injection" in line_lower or "sqli" in line_lower:
            vuln_types.add("sql_injection")
        if "xss" in line_lower:
            vuln_types.add("xss")
        if "ssrf" in line_lower:
            vuln_types.add("ssrf")
        if "idor" in line_lower:
            vuln_types.add("idor")
        if "path_traversal" in line_lower or "lfi" in line_lower or "local_file_inclusion" in line_lower:
            vuln_types.add("local_file_inclusion")
        if "file_upload" in line_lower:
            vuln_types.add("file_upload")
        if "authentication_bypass" in line_lower or "auth_bypass" in line_lower:
            vuln_types.add("authentication_bypass")
        if "privilege_escalation" in line_lower or "priv_esc" in line_lower:
            vuln_types.add("privilege_escalation")
        if "open_redirect" in line_lower:
            vuln_types.add("open_redirect")
        if "misconfiguration" in line_lower or "cors" in line_lower or "csp" in line_lower:
            vuln_types.add("misconfiguration")
        if "broken_access_control" in line_lower:
            vuln_types.add("broken_access_control")
        if "session" in line_lower or "jwt" in line_lower:
            vuln_types.add("session")
        if "information_disclosure" in line_lower or "info_disc" in line_lower:
            vuln_types.add("information_disclosure")
        if "sensitive_file" in line_lower:
            vuln_types.add("sensitive_file_exposure")

    return vuln_types


def match_chains(vuln_types: set[str]) -> list[dict]:
    """Match discovered vuln types against chain patterns."""
    matched = []
    vuln_lower = {v.lower() for v in vuln_types}

    for pattern in CHAIN_PATTERNS:
        required = {r.lower() for r in pattern["required"]}
        optional = {o.lower() for o in pattern.get("optional", [])}

        met_required = vuln_lower & required
        met_optional = vuln_lower & (optional | required)

        if met_required:
            steps = []
            for step in pattern["steps"]:
                step_vuln = step["vuln"].lower()
                matched_flag = step_vuln in vuln_lower
                steps.append({
                    **step,
                    "matched": matched_flag,
                    "status": "confirmed" if matched_flag else "hypothesized",
                })

            severity = pattern["severity"]
            coverage = len(met_required) / max(len(required), 1)
            if coverage < 1.0:
                if severity == "critical":
                    severity = "high"
                elif severity == "high":
                    severity = "medium"

            matched.append({
                "name": pattern["name"],
                "steps": steps,
                "overall_severity": severity,
                "impact": pattern["impact"],
                "matched_required": list(met_required),
                "matched_optional": list(met_optional),
                "missing": list(required - met_required),
            })

    return matched


def save_chains(td: Path, chains: list[dict]):
    """Save chain analysis to chains.md."""
    chains_file = td / "chains.md"
    if not chains_file.exists():
        chains_file.write_text(f"# Vulnerability Chains\nLast updated: {datetime.utcnow().isoformat()}\n---\n")

    ts = datetime.utcnow().isoformat()
    for chain in chains:
        entry = f"\n## [{chain['overall_severity'].upper()}] {chain['name']} - {ts}\n"
        entry += f"**Impact**: {chain['impact']}\n"
        entry += f"**Status**: {len([s for s in chain['steps'] if s['status'] == 'confirmed'])}/{len(chain['steps'])} confirmed\n"
        if chain['missing']:
            entry += f"**Missing prerequisites**: {', '.join(chain['missing'])}\n"
        entry += "\n### Steps\n"
        for step in chain["steps"]:
            marker = "[CONFIRMED]" if step["status"] == "confirmed" else "[HYPOTHESIZED]"
            entry += f"  {marker} Step {step['step']}: **{step['vuln']}** - {step['description']}\n"
        entry += "\n### Chain-Breaking Recommendation\n"
        entry += f"  Fix the missing prerequisites: {', '.join(chain['missing']) if chain['missing'] else 'All steps confirmed - immediate remediation required'}\n"

    with open(chains_file, "a") as f:
        f.write(entry + "\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 fenrir/scripts/chain_builder.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    td = get_target_dir(target)

    print(f"=" * 50)
    print(f"FENRIR PRO-MAX — Chain Builder for {target}")
    print(f"=" * 50)
    print(f"\nAnalyzing {td}...")

    vuln_types = get_vuln_types(td)
    print(f"  Discovered vuln types: {vuln_types}")
    print(f"  Total types: {len(vuln_types)}")

    chains = match_chains(vuln_types)
    print(f"\n  Matched chains: {len(chains)}")

    for c in chains:
        confirmed = sum(1 for s in c['steps'] if s['status'] == 'confirmed')
        total = len(c['steps'])
        print(f"\n  [{c['overall_severity'].upper()}] {c['name']}")
        print(f"    Confirmed: {confirmed}/{total}")
        print(f"    Impact: {c['impact']}")
        print(f"    Missing: {c['missing']}")

    if chains:
        save_chains(td, chains)
        print(f"\n[RESULT] {len(chains)} chains saved to {td / 'chains.md'}")
    else:
        print(f"\n[RESULT] No chains matched. More vulnerabilities needed for chaining.")

    # Print JSON for Hermes to consume
    print(f"\n---JSON_START---")
    print(json.dumps(chains, indent=2))
    print(f"---JSON_END---")


if __name__ == "__main__":
    main()
