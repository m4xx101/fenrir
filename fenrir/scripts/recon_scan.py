#!/usr/bin/env python3
"""Fenrir Pro-Max — Reconnaissance Automation Script

Usage:
    python3 fenrir/scripts/recon_scan.py subdomains <target>
    python3 fenrir/scripts/recon_scan.py ports <target>
    python3 fenrir/scripts/recon_scan.py ports-full <target>
    python3 fenrir/scripts/recon_scan.py fingerprint <target_url>
    python3 fenrir/scripts/recon_scan.py passive <target>
    python3 fenrir/scripts/recon_scan.py all <target>
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl


BRAIN_DIR = Path.home() / ".fenrir" / "brain"
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def get_target_dir(target: str) -> Path:
    safe = target.replace("://", "_").replace("/", "_").replace(".", "_")
    d = BRAIN_DIR / "targets" / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def append_recon(target: str, category: str, data: dict):
    """Save a recon finding to the brain."""
    td = get_target_dir(target)
    recon_file = td / "recon.md"
    if not recon_file.exists():
        recon_file.write_text(f"# Reconnaissance: {target}\nLast updated: {datetime.utcnow().isoformat()}\n---\n")
    ts = datetime.utcnow().isoformat()
    entry = f"\n## [{category}] - {ts}\n"
    for k, v in data.items():
        entry += f"- **{k}**: {str(v)[:500]}\n"
    with open(recon_file, "a") as f:
        f.write(entry + "\n")


def update_state(target: str, phase: str, agent: str, success: bool, findings_count: int = 0):
    """Update the scan state file."""
    td = get_target_dir(target)
    state_file = td / "state.json"
    state = {}
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text())
        except:
            state = {}
    state.setdefault("target", target)
    state.setdefault("phase", phase)
    state.setdefault("completed_agents", [])
    state.setdefault("failed_agents", [])
    state.setdefault("findings_count", 0)
    state["findings_count"] += findings_count
    if success:
        if agent not in state["completed_agents"]:
            state["completed_agents"].append(agent)
    else:
        if agent not in state["failed_agents"]:
            state["failed_agents"].append(agent)
    state["phase"] = phase
    state["last_updated"] = datetime.utcnow().isoformat()
    state_file.write_text(json.dumps(state, indent=2))


def http_get(url: str, timeout: int = 15) -> tuple[int, str, dict]:
    """Simple HTTP GET. Returns (status, body, headers)."""
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; Fenrir/1.0)"})
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        body = resp.read().decode("utf-8", errors="ignore")
        return resp.status, body, dict(resp.headers)
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
        return e.code, body, dict(e.headers)
    except Exception as e:
        return 0, str(e), {}


def cmd_run(cmd: list[str], timeout: int = 120) -> str:
    """Run a command and return stdout."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except FileNotFoundError:
        return f"[COMMAND NOT FOUND: {' '.join(cmd)}]"
    except Exception as e:
        return f"[ERROR: {e}]"


# ─── Recon Functions ─────────────────────────────────────────────────────

def scan_subdomains(target: str) -> list[str]:
    """Enumerate subdomains via CRT.sh, DNS, and common prefixes."""
    domain = target.split("/")[0].split(":")[0]
    results = []

    # Method 1: Common subdomains via DNS
    common = [
        "www", "api", "admin", "mail", "ftp", "dev", "staging", "test",
        "app", "web", "portal", "dashboard", "login", "auth", "oauth",
        "cdn", "static", "assets", "docs", "blog", "shop", "support",
        "status", "vpn", "db", "database", "backup", "ci", "git",
        "jenkins", "grafana", "monitoring", "internal",
    ]
    for sub in common:
        fqdn = f"{sub}.{domain}"
        out = cmd_run(["dig", "+short", fqdn], timeout=5)
        if out.strip():
            ips = [l.strip() for l in out.strip().split("\n") if l.strip()]
            if ips:
                results.append({"subdomain": fqdn, "status": "resolved", "ips": ips})
            else:
                results.append({"subdomain": fqdn, "status": "not_resolved", "ips": []})
        append_recon(target, "subdomain_enum", {"subdomain": fqdn, "found": bool(out.strip()), "ips": ips if out.strip() else []})

    # Method 2: CRT.sh (Certificate Transparency)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    data = http_get(url, timeout=30)
    if data[0] == 200:
        try:
            entries = json.loads(data[1])
            for entry in entries[:100]:
                name = entry.get("name_value", "").replace("\\n", ",").split(",")
                for n in name:
                    n = n.strip().lstrip("*.")
                    if n and domain.lower() in n.lower() and n != domain:
                        results.append({"subdomain": n, "source": "crt.sh", "status": "found_in_ct"})
                        append_recon(target, "subdomain_ct", {"subdomain": n, "source": "crt.sh"})
        except:
            pass

    # Method 3: NS and MX records
    for rtype in ["NS", "MX"]:
        out = cmd_run(["dig", "+short", rtype, domain], timeout=10)
        if out.strip():
            records = [l.strip() for l in out.strip().split("\n") if l.strip()]
            append_recon(target, f"dns_{rtype.lower()}", {"records": records})

    print(f"\n[RECON] Subdomain scan complete: {len(results)} subdomains enumerated for {domain}")
    return results


def scan_ports(target: str, full: bool = False) -> list[dict]:
    """Scan ports with nmap/rustscan."""
    host = target.split("/")[0].split(":")[0]
    results = []

    # Try rustscan first (faster), fall back to nmap
    nmap_bin = os.environ.get("NMAP_BINARY", "nmap")
    rustscan_bin = os.environ.get("RUSTSCAN_BINARY", "rustscan")

    if full:
        ports = cmd_run([nmap_bin, "-p-", "-sV", "-T4", "--open", host], timeout=600)
    else:
        ports = cmd_run([nmap_bin, "-F", "-sV", "-T4", "--open", host], timeout=120)

    # Parse open ports
    for line in ports.split("\n"):
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                port_num = parts[0].split("/")[0]
                service = parts[2] if len(parts) > 2 else ""
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                results.append({"port": int(port_num), "service": service, "version": version})
                append_recon(target, "port", {"port": port_num, "service": service, "version": version})

    if not results:
        # Quick scan with rustscan if nmap had nothing
        rust_out = cmd_run([rustscan_bin, "-a", host, "--", "nmap", "-sV", "-T4", "--open"], timeout=120)
        for line in rust_out.split("\n"):
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_num = parts[0].split("/")[0]
                    service = parts[2] if len(parts) > 2 else ""
                    results.append({"port": int(port_num), "service": service})

    scan_type = "full" if full else "quick"
    print(f"\n[RECON] {scan_type.capitalize()} port scan complete: {len(results)} open ports found on {host}")
    return results


def fingerprint(target: str) -> dict:
    """Web technology fingerprinting."""
    if not target.startswith(("http://", "https://")):
        host = target.split("/")[0]
        urls = [f"http://{host}", f"https://{host}"]
    else:
        urls = [target]

    results = {}
    for url in urls:
        status, body, headers = http_get(url)
        if status == 0:
            continue

        tech = []
        server = headers.get("Server", "")
        x_powered = headers.get("X-Powered-By", "")
        cookies = headers.get("Set-Cookie", "").lower()

        if "PHPSESSID" in cookies: tech.append("PHP")
        if "JSESSIONID" in cookies: tech.append("Java")
        if "csrftoken" in cookies and "sessionid" in cookies: tech.append("Django")
        if "rails" in cookies: tech.append("Ruby on Rails")
        if "ASP.NET" in cookies or "ASPXAUTH" in cookies: tech.append("ASP.NET")
        if "connect.sid" in cookies: tech.append("Node.js/Express")
        if "laravel" in str(body).lower(): tech.append("Laravel")
        if "wordpress" in str(body).lower() or "wp-content" in str(body).lower(): tech.append("WordPress")
        if "drupal" in str(body).lower(): tech.append("Drupal")
        if "react" in str(body).lower(): tech.append("React")
        if "vue.js" in str(body).lower() or "vuejs" in str(body).lower(): tech.append("Vue.js")
        if "angular" in str(body).lower(): tech.append("Angular")

        missing_headers = []
        for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection"]:
            if h not in headers:
                missing_headers.append(h)

        forms_count = len(re.findall(r'<form[^>]*>', body))
        links = re.findall(r'href=["\'](.*?)["\']', body)[:30]

        result = {
            "url": url, "status": status, "server": server, "x_powered_by": x_powered,
            "technologies": tech, "missing_security_headers": missing_headers,
            "forms_count": forms_count, "links_sample": links,
        }
        results[url] = result
        append_recon(target, "web_fingerprint", result)

    print(f"\n[RECON] Fingerprint complete: {len(results)} URLs analyzed")
    print(f"  Technologies: {list(set(t for r in results.values() for t in r.get('technologies', [])))}")
    return results


def passive_recon(target: str) -> dict:
    """Passive reconnaissance — CT logs, Wayback, DNS."""
    domain = target.split("/")[0].split(":")[0]
    results = {}

    # Wayback Machine
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&matchType=domain&output=json&limit=50&filter=statuscode:200"
    data = http_get(url, timeout=30)
    endpoints = []
    if data[0] == 200:
        try:
            rows = json.loads(data[1])
            for row in rows[1:30]:
                if len(row) >= 2:
                    endpoints.append(row[1])
                    append_recon(target, "wayback_endpoint", {"url": row[1], "status": row[2] if len(row) > 2 else "unknown"})
        except:
            pass
    results["wayback_endpoints"] = endpoints

    # Shodan (if API key available)
    shodan_key = os.environ.get("SHODAN_API_KEY")
    if shodan_key:
        # Resolve domain
        dns_out = cmd_run(["dig", "+short", "A", domain], timeout=10)
        ips = [l.strip() for l in dns_out.split("\n") if l.strip() and re.match(r"\d+\.\d+\.\d+\.\d+", l.strip())]
        for ip in ips[:3]:
            shodan_url = f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}"
            sdata = http_get(shodan_url, timeout=15)
            if sdata[0] == 200:
                try:
                    info = json.loads(sdata[1])
                    ports = info.get("ports", [])
                    results[f"shodan_{ip}"] = {"ports": ports, "org": info.get("org", "unknown"), "hostnames": info.get("hostnames", [])}
                except:
                    pass

    print(f"\n[RECON] Passive recon complete: {len(endpoints)} historical endpoints found")
    return results


# ─── Main ──────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 fenrir/scripts/recon_scan.py <mode> <target>")
        print("Modes: subdomains, ports, ports-full, fingerprint, passive, all")
        sys.exit(1)

    mode = sys.argv[1]
    target = sys.argv[2]

    # Ensure brain dirs exist
    BRAIN_DIR.mkdir(parents=True, exist_ok=True)
    (BRAIN_DIR / "targets").mkdir(exist_ok=True)

    print(f"=" * 50)
    print(f"FENRIR PRO-MAX — Recon: {mode} ({target})")
    print(f"=" * 50)

    if mode == "subdomains":
        update_state(target, "recon", "subdomain_enum", False)
        scan_subdomains(target)
        update_state(target, "recon", "subdomain_enum", True)

    elif mode == "ports":
        update_state(target, "recon", "port_scan", False)
        scan_ports(target)
        update_state(target, "recon", "port_scan", True)

    elif mode == "ports-full":
        update_state(target, "recon", "port_scan_full", False)
        scan_ports(target, full=True)
        update_state(target, "recon", "port_scan_full", True)

    elif mode == "fingerprint":
        update_state(target, "recon", "web_fingerprint", False)
        fingerprint(target)
        update_state(target, "recon", "web_fingerprint", True)

    elif mode == "passive":
        scan_subdomains(target)
        passive_recon(target)
        update_state(target, "recon", "passive_recon", True)

    elif mode == "all":
        print("\n[Phase 1/4] Subdomain enumeration...")
        scan_subdomains(target)
        print("\n[Phase 2/4] Port scanning...")
        scan_ports(target)
        print("\n[Phase 3/4] Web fingerprinting...")
        fingerprint(target)
        print("\n[Phase 4/4] Passive recon...")
        passive_recon(target)
        print(f"\n[RECON] All recon complete for {target}")

    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)


if __name__ == "__main__":
    main()
