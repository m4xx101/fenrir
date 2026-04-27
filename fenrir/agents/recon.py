"""Reconnaissance agents: subdomain discovery, port scanning, web fingerprinting, browser recon."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from loguru import logger

from fenrir.agents.base import AgentResult, BaseAgent
from fenrir.config import LLMTier


class NmapScanner:
    """Simple Nmap wrapper without dependencies."""

    def __init__(self, binary: str = "nmap"):
        self.binary = binary

    def run(self, target: str, args: str = "-sV -T4", timeout: int = 300) -> str:
        """Run Nmap scan and return output."""
        import subprocess
        try:
            cmd = f"{self.binary} {args} {target}"
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=timeout
            )
            return result.stdout
        except Exception as e:
            return f"Error: {e}"

    def run_full(self, target: str) -> str:
        return self.run(target, "-p- -sV -O -T4", timeout=600)

    def run_quick(self, target: str) -> str:
        return self.run(target, "-F -sV -T4", timeout=60)


class WhoisLookup:
    """Whois lookup wrapper."""

    @staticmethod
    def lookup(domain: str) -> str:
        import subprocess
        try:
            result = subprocess.run(
                ["whois", domain], capture_output=True, text=True, timeout=30
            )
            return result.stdout
        except FileNotFoundError:
            return "whois command not available"
        except Exception as e:
            return f"Error: {e}"


class DNSRecon:
    """DNS enumeration helper."""

    @staticmethod
    def resolve(domain: str, record_type: str = "A") -> list[str]:
        import subprocess
        try:
            result = subprocess.run(
                ["dig", "+short", record_type, domain],
                capture_output=True, text=True, timeout=10
            )
            return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        except Exception:
            return []

    @staticmethod
    def get_nameservers(domain: str) -> list[str]:
        return DNSRecon.resolve(domain, "NS")

    @staticmethod
    def get_mx(domain: str) -> list[str]:
        return DNSRecon.resolve(domain, "MX")


class HTTPScanner:
    """HTTP-based recon without heavy dependencies."""

    @staticmethod
    def get_headers(url: str, timeout: int = 10) -> dict[str, str]:
        import urllib.request
        import ssl
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "Mozilla/5.0")
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            return dict(resp.headers)
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def get_body(url: str, timeout: int = 10) -> tuple[int, str]:
        import urllib.request
        import ssl
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0")
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            return resp.status, resp.read().decode("utf-8", errors="ignore")[:50000]
        except Exception as e:
            return 0, str(e)


class SubdomainAgent(BaseAgent):
    """Subdomain enumeration agent."""

    name = "subdomain_enum"
    role = "subdomain_enum"
    system_prompt = """You are Fenrir Pro-Max's Subdomain Enumeration Agent.

Your job is to discover all subdomains of a target domain. You have several approaches:

1. DNS brute forcing with common subdomain wordlists
2. Certificate Transparency log enumeration via crt.sh
3. Search engine dorking for discovered subdomains
4. Analyzing web content for subdomain references
5. DNS zone transfer attempts (AXFR)

For each discovered subdomain, determine if it resolves and what it's likely used for
based on the name pattern (api, admin, dev, staging, mail, etc.).

Output a structured list of:
- Subdomain
- Resolution status (resolves / doesn't resolve)
- IP address (if resolved)
- Likely purpose
- Priority for further investigation"""
    tier = LLMTier.TIER_0

    async def _run(self, task: str, context: str) -> AgentResult:
        # Extract domain from task if not explicitly set
        target = self.target or task.strip().split()[-1]

        findings = []
        subdomains = []

        # Method 1: DNS resolution attempts
        common_subs = [
            "www", "api", "admin", "mail", "ftp", "dev", "staging",
            "test", "app", "web", "portal", "dashboard", "login",
            "auth", "oauth", "cdn", "static", "assets", "images",
            "docs", "blog", "shop", "store", "support", "help",
            "status", "monitoring", "grafana", "jenkins", "git",
            "github", "gitlab", "bitbucket", "jira", "confluence",
            "wiki", "internal", "vpn", "ssh", "db", "database",
            "backup", "ci", "cd", "artifacts", "registry", "docker",
        ]

        dns_recon = DNSRecon()
        base_domain = target

        for sub in common_subs:
            fqdn = f"{sub}.{base_domain}"
            try:
                resolved = dns_recon.resolve(fqdn)
                if resolved:
                    findings.append({
                        "subdomain": fqdn,
                        "status": "resolved",
                        "ips": resolved,
                        "purpose": sub,
                    })
                    subdomains.append(fqdn)
                else:
                    findings.append({
                        "subdomain": fqdn,
                        "status": "not_resolved",
                        "ips": [],
                        "purpose": sub,
                    })
            except Exception:
                pass

        # Method 2: Get nameservers and MX records
        try:
            ns = DNSRecon.get_nameservers(base_domain)
            mx = DNSRecon.get_mx(base_domain)
            findings.append({
                "category": "dns_records",
                "nameservers": ns,
                "mx_records": mx,
            })
        except Exception:
            pass

        # Method 3: Whois lookup
        try:
            whois_data = WhoisLookup.lookup(base_domain)
            findings.append({
                "category": "whois",
                "data_preview": whois_data[:2000],
            })
        except Exception:
            pass

        return AgentResult(
            agent_name=self.name,
            success=True,
            summary=f"Found {len(subdomains)} subdomains for {base_domain}",
            findings=findings,
        )


class PortScanAgent(BaseAgent):
    """Port scanning and service fingerprinting agent."""

    name = "port_scan"
    role = "port_scan"
    system_prompt = """You are Fenrir Pro-Max's Port Scan Agent.

Your job is to perform comprehensive port scanning and service fingerprinting
of targets identified during reconnaissance.

Scan methodology:
1. Quick scan of top 1000 ports (-F) to identify common services
2. Full port range scan (-p-) for comprehensive coverage
3. Service version detection (-sV) on discovered ports
4. OS fingerprinting (-O) when possible
5. Default/script scans (-sC) on interesting services
6. UDP scan for common UDP services (DNS, SNMP, NTP, etc.)

For each open port, catalog:
- Port number and protocol
- Service name and version
- Any banner information
- Potential vulnerabilities associated with the service
- Priority for exploitation"""
    tier = LLMTier.TIER_0

    async def _run(self, task: str, context: str) -> AgentResult:
        import ipaddress

        # Extract target
        target = self.target or task.strip().split()[-1]

        findings = []
        nmap = NmapScanner()

        # Quick scan
        try:
            logger.info(f"Running quick Nmap scan against {target}")
            quick_result = nmap.run_quick(target)
            open_ports = []

            for line in quick_result.split("\n"):
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_info = parts[0].split("/")[0]
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else ""
                        if state == "open":
                            open_ports.append({
                                "port": int(port_info),
                                "service": service,
                                "protocol": "tcp",
                            })

            findings.append({
                "category": "quick_scan",
                "ports_found": len(open_ports),
                "open_ports": open_ports,
                "raw_output": quick_result[:3000],
            })
        except Exception as e:
            findings.append({"category": "quick_scan_error", "error": str(e)})

        # Full scan if quick scan found ports or on explicit request
        if any(f.get("ports_found", 0) > 0 for f in findings if f.get("category") == "quick_scan"):
            try:
                logger.info(f"Running full Nmap scan against {target}")
                full_result = nmap.run_full(target)

                # Parse for open ports
                for line in full_result.split("\n"):
                    if "/tcp" in line and "open" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port_info = parts[0].split("/")[0]
                            service = parts[2] if len(parts) > 2 else ""
                            version = " ".join(parts[3:]) if len(parts) > 3 else ""

                            # Check if this is a new port
                            existing_ports = []
                            if findings and findings[-1].get("category") == "quick_scan":
                                existing_ports = [p["port"] for p in findings[-1].get("open_ports", [])]

                            port_num = int(port_info)
                            if port_num not in existing_ports:
                                findings.append({
                                    "category": "full_scan",
                                    "port": port_num,
                                    "service": service,
                                    "version": version,
                                    "found_in": "full_scan",
                                })
            except Exception as e:
                findings.append({"category": "full_scan_error", "error": str(e)})

        # Save recon findings to brain
        for f in findings:
            if f.get("category") in ("quick_scan", "full_scan"):
                self.save_finding(f, "recon")

        return AgentResult(
            agent_name=self.name,
            success=True,
            summary=f"Port scan of {target} complete",
            findings=findings,
        )


class WebFingerprintAgent(BaseAgent):
    """Web technology fingerprinting agent."""

    name = "web_fingerprint"
    role = "web_fingerprint"
    system_prompt = """You are Fenrir Pro-Max's Web Fingerprint Agent.

Your job is to thoroughly fingerprint the web technologies of targets.

Analyze:
1. HTTP headers (Server, X-Powered-By, Via, Set-Cookie patterns)
2. HTTP response bodies for technology signatures
3. Default pages (404, 500, admin, login panels)
4. Framework-specific artifacts (Django CSRF tokens, Spring Boot actuator, etc.)
5. JavaScript libraries and frameworks
6. CMS identification (WordPress, Drupal, Joomla, etc.)
7. WAF detection (Cloudflare, Akamai, ModSecurity, etc.)
8. Security header analysis (CSP, HSTS, X-Frame-Options, etc.)

For each finding, determine:
- Technology name and version
- Confidence level
- Associated attack surface
- Known CVEs for that version"""
    tier = LLMTier.TIER_1

    async def _run(self, task: str, context: str) -> AgentResult:
        target = self.target or task.strip().split()[-1]
        findings = []

        # Ensure target has scheme
        if not target.startswith(("http://", "https://")):
            urls = [f"http://{target}", f"https://{target}"]
        else:
            urls = [target]

        for url in urls:
            try:
                status, body = HTTPScanner.get_body(url)
                headers = HTTPScanner.get_headers(url)

                if status == 0:
                    continue

                # Analyze headers for tech stacks
                server = headers.get("Server", "")
                x_powered_by = headers.get("X-Powered-By", "")
                cookies = headers.get("Set-Cookie", "")

                tech_indicators = []

                # Framework detection from cookies
                if "PHPSESSID" in cookies:
                    tech_indicators.append("PHP")
                if "JSESSIONID" in cookies:
                    tech_indicators.append("Java")
                if "csrftoken" in cookies and "sessionid" in cookies:
                    tech_indicators.append("Django")
                if "rails" in cookies.lower():
                    tech_indicators.append("Ruby on Rails")
                if "ASP.NET" in cookies or "ASPXAUTH" in cookies:
                    tech_indicators.append("ASP.NET")
                if "connect.sid" in cookies:
                    tech_indicators.append("Node.js/Express")

                # Body-based fingerprinting
                body_lower = body.lower()
                if "wordpress" in body_lower or "wp-content" in body_lower:
                    tech_indicators.append("WordPress")
                if "drupal" in body_lower:
                    tech_indicators.append("Drupal")
                if "laravel" in body_lower:
                    tech_indicators.append("Laravel")
                if "spring" in body_lower:
                    tech_indicators.append("Spring Framework")
                if "react" in body_lower:
                    tech_indicators.append("React")
                if "angular" in body_lower:
                    tech_indicators.append("Angular")
                if "vue" in body_lower:
                    tech_indicators.append("Vue.js")

                # WAF detection
                waf_headers = {
                    "cf-ray": "Cloudflare",
                    "x-amz-cf-id": "AWS CloudFront",
                    "x-cdn": "Multiple WAFs",
                    "x-sucuri-id": "Sucuri",
                    "x-akamai-request-id": "Akamai",
                }
                waf_detected = []
                for header, waf in waf_headers.items():
                    if header in {k.lower() for k in headers}:
                        waf_detected.append(waf)

                # Security headers analysis
                missing_headers = []
                required_security = [
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "X-XSS-Protection",
                    "Permissions-Policy",
                ]
                for header in required_security:
                    if header not in headers:
                        missing_headers.append(header)

                # Find forms
                import re
                forms = re.findall(r'<form[^>]*>', body)

                # Find interesting URLs
                hrefs = re.findall(r'href=["\'](.*?)["\']', body)
                scripts = re.findall(r'src=["\'](.*?)["\']', body)

                findings.append({
                    "category": "web_fingerprint",
                    "url": url,
                    "status_code": status,
                    "server": server,
                    "x_powered_by": x_powered_by,
                    "technologies": tech_indicators,
                    "waf_detected": waf_detected,
                    "missing_security_headers": missing_headers,
                    "forms_count": len(forms),
                    "links_count": len(hrefs),
                    "scripts_count": len(scripts),
                    "sample_links": hrefs[:20],
                    "all_headers": headers,
                })

            except Exception as e:
                findings.append({
                    "category": "web_fingerprint_error",
                    "url": url,
                    "error": str(e),
                })

        # Save to brain
        for f in findings:
            if f.get("category") == "web_fingerprint":
                self.save_finding(f, "recon")

        return AgentResult(
            agent_name=self.name,
            success=True,
            summary=f"Web fingerprint of {target} complete: {len(findings)} targets analyzed",
            findings=findings,
        )


class BrowserReconAgent(BaseAgent):
    """Browser-based reconnaissance for dynamic content."""

    name = "browser_recon"
    role = "browser_recon"
    system_prompt = """You are Fenrir Pro-Max's Browser Recon Agent.

Your job is to explore targets using a real browser to discover:
1. JavaScript-rendered content and endpoints
2. Hidden forms and navigation
3. API endpoints called by JavaScript
4. Authentication flows
5. Admin panels and restricted areas
6. Dynamic content loaded via XHR/Fetch
7. Local storage and session data
8. WebSocket connections

Focus on mapping the application's attack surface through interactive exploration."""
    tier = LLMTier.TIER_1

    async def _run(self, task: str, context: str) -> AgentResult:
        target = self.target or task.strip().split()[-1]
        findings = []

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        try:
            from fenrir.tools.browser import BrowserTool
            browser = BrowserTool(self.config)

            try:
                # Navigate
                nav_result = browser.navigate(target)
                findings.append({"category": "navigation", "result": nav_result})

                # Get content
                content = browser.get_content()
                findings.append({"category": "content", "info": {
                    "url": content.get("url"),
                    "title": content.get("title"),
                    "html_length": content.get("html_length"),
                    "preview": content.get("preview", "")[:1000],
                }})

                # Get links
                links = browser.get_links()
                if links:
                    findings.append({
                        "category": "endpoint_discovery",
                        "endpoints": links[:100],
                        "total": len(links),
                    })

                # Get forms
                forms = browser.get_forms()
                if forms:
                    findings.append({
                        "category": "form_discovery",
                        "forms": forms,
                    })

                # Get cookies
                cookies = browser.get_cookies()
                if cookies:
                    findings.append({
                        "category": "cookie_analysis",
                        "cookies": cookies,
                    })

                # Get local storage
                storage = browser.get_local_storage()
                if storage and "error" not in storage:
                    findings.append({
                        "category": "local_storage",
                        "data": storage,
                    })

            finally:
                browser.close()

        except Exception as e:
            findings.append({"category": "browser_error", "error": str(e)})
            logger.warning(f"Browser recon failed (browser not available?): {e}")

        return AgentResult(
            agent_name=self.name,
            success=True,
            summary=f"Browser recon of {target} complete: {len(findings)} categories analyzed",
            findings=findings,
        )
