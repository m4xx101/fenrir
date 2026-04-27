"""HTTP tool wrapper with requests, retry logic, and security analysis."""

from __future__ import annotations

import json
import ssl
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
from loguru import logger
from pydantic import BaseModel

# Accept self-signed SSL for security testing
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


class HTTPResult(BaseModel):
    """Structured HTTP response."""
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    cookies: dict[str, str]
    redirect_history: list[dict[str, Any]] = []
    elapsed_ms: float = 0
    content_type: str = ""
    server: str = ""
    error: str = ""

    def get_links(self) -> list[str]:
        """Extract links from response body."""
        if not self.body:
            return []
        soup = BeautifulSoup(self.body, "html.parser")
        links = []
        for tag in soup.find_all(["a", "link", "script", "img", "form"]):
            href = tag.get("href", "") or tag.get("src", "") or tag.get("action", "")
            if href:
                links.append(href)
        return links

    def get_forms(self) -> list[dict[str, Any]]:
        """Extract forms from response body."""
        if not self.body:
            return []
        soup = BeautifulSoup(self.body, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            forms.append({
                "action": form.get("action", ""),
                "method": form.get("method", "get").lower(),
                "inputs": [
                    {
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    }
                    for inp in form.find_all(["input", "textarea", "select"])
                ],
            })
        return forms

    def get_security_headers_analysis(self) -> dict[str, Any]:
        """Analyze security headers."""
        lower_headers = {k.lower(): v for k, v in self.headers.items()}
        analysis = {}

        security_headers = {
            "content-security-policy": "CSP header missing",
            "x-frame-options": "Clickjacking protection missing",
            "x-content-type-options": "MIME sniffing protection missing",
            "strict-transport-security": "HSTS not enabled",
            "x-xss-protection": "XSS Protection header missing",
            "referrer-policy": "Referrer Policy not set",
            "permissions-policy": "Permissions Policy not set",
            "cross-origin-opener-policy": "COOP missing",
            "cross-origin-resource-policy": "CORP missing",
            "cross-origin-embedder-policy": "COEP missing",
        }

        for header, issue in security_headers.items():
            if header in lower_headers:
                analysis[header] = {"status": "present", "value": lower_headers[header]}
            else:
                analysis[header] = {"status": "missing", "issue": issue}

        return analysis


class HTTPTool:
    """HTTP tool with retry logic, session management, and security analysis."""

    def __init__(self, config: Any = None):
        self.config = config
        self._session = httpx.Client(
            verify=False,
            follow_redirects=False,  # Manual redirect handling
            timeout=httpx.Timeout(15.0, connect=5.0),
            limits=httpx.Limits(max_connections=50),
        )
        self._async_session = httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=httpx.Timeout(15.0, connect=5.0),
            limits=httpx.Limits(max_connections=50),
        )

    def _normalize_url(self, url: str) -> str:
        """Normalize URL, adding scheme if missing."""
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url

    def _add_default_headers(self, headers: dict[str, str] | None) -> dict[str, str]:
        """Add default browser-like headers."""
        default = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }
        if headers:
            default.update(headers)
        return default

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        follow_redirects: bool = True,
        timeout: float = 15.0,
        max_retries: int = 2,
    ) -> dict[str, Any]:
        """Make an HTTP GET request."""
        url = self._normalize_url(url)
        all_headers = self._add_default_headers(headers)

        for attempt in range(max_retries + 1):
            try:
                self._session.timeout = httpx.Timeout(timeout, connect=5.0)
                resp = self._session.get(
                    url,
                    headers=all_headers,
                    params=params,
                    follow_redirects=follow_redirects,
                )

                redirect_history = []
                if resp.history:
                    for r in resp.history:
                        redirect_history.append({
                            "url": str(r.url),
                            "status": r.status_code,
                        })

                result = HTTPResult(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.text,
                    cookies=dict(resp.cookies),
                    redirect_history=redirect_history,
                    elapsed_ms=resp.elapsed.total_seconds() * 1000,
                    content_type=resp.headers.get("content-type", ""),
                    server=resp.headers.get("server", resp.headers.get("x-powered-by", "")),
                )
                logger.info(f"GET {url} -> {resp.status_code} ({resp.elapsed.total_seconds()*1000:.0f}ms)")
                return result.model_dump()

            except httpx.TimeoutException:
                if attempt == max_retries:
                    return {"error": f"Request timed out after {timeout}s", "url": url}
                logger.warning(f"Timeout on attempt {attempt+1} for {url}")
                time.sleep(1 * (attempt + 1))
            except Exception as e:
                return {"error": str(e), "url": url}

        return {"error": f"Failed after {max_retries+1} retries", "url": url}

    def post(
        self,
        url: str,
        data: dict[str, str] | str | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        files: dict[str, Any] | None = None,
        follow_redirects: bool = True,
        timeout: float = 15.0,
        max_retries: int = 2,
    ) -> dict[str, Any]:
        """Make an HTTP POST request."""
        url = self._normalize_url(url)
        all_headers = self._add_default_headers(headers)

        # Determine content type
        if json_data and "Content-Type" not in all_headers:
            all_headers["Content-Type"] = "application/json"

        for attempt in range(max_retries + 1):
            try:
                self._session.timeout = httpx.Timeout(timeout, connect=5.0)
                resp = self._session.post(
                    url,
                    headers=all_headers,
                    params=params,
                    data=data,
                    json=json_data,
                    files=files,
                    follow_redirects=follow_redirects,
                )

                redirect_history = []
                if resp.history:
                    for r in resp.history:
                        redirect_history.append({
                            "url": str(r.url),
                            "status": r.status_code,
                        })

                result = HTTPResult(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.text,
                    cookies=dict(resp.cookies),
                    redirect_history=redirect_history,
                    elapsed_ms=resp.elapsed.total_seconds() * 1000,
                    content_type=resp.headers.get("content-type", ""),
                    server=resp.headers.get("server", ""),
                )
                logger.info(f"POST {url} -> {resp.status_code}")
                return result.model_dump()

            except httpx.TimeoutException:
                if attempt == max_retries:
                    return {"error": f"Request timed out after {timeout}s", "url": url}
                time.sleep(1 * (attempt + 1))
            except Exception as e:
                return {"error": str(e), "url": url}

        return {"error": f"Failed after {max_retries+1} retries", "url": url}

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        data: dict[str, str] | str | None = None,
        json_data: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
        body: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make a custom HTTP request with any method."""
        url = self._normalize_url(url)
        all_headers = self._add_default_headers(headers)
        timeout = kwargs.get("timeout", 15.0)

        try:
            self._session.timeout = httpx.Timeout(timeout, connect=5.0)

            # Handle raw body
            if body and not data and not json_data:
                resp = self._session.send(
                    self._session.build_request(
                        method=method.upper(),
                        url=url,
                        headers=all_headers,
                        params=params,
                        content=body.encode(),
                    ),
                )
            else:
                resp = self._session.request(
                    method=method.upper(),
                    url=url,
                    headers=all_headers,
                    params=params,
                    data=data,
                    json=json_data,
                )

            result = HTTPResult(
                url=str(resp.url),
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                cookies=dict(resp.cookies),
                elapsed_ms=resp.elapsed.total_seconds() * 1000,
                content_type=resp.headers.get("content-type", ""),
                server=resp.headers.get("server", ""),
            )
            logger.info(f"{method} {url} -> {resp.status_code}")
            return result.model_dump()

        except Exception as e:
            return {"error": str(e), "url": url, "method": method}

    def crawl_page(
        self,
        url: str,
        max_depth: int = 2,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        """Simple crawler: find links and forms on a page."""
        url = self._normalize_url(url)
        result = self.get(url, timeout=timeout)

        if "error" in result:
            return result

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        links = []
        if "body" in result:
            soup = BeautifulSoup(result["body"], "html.parser")
            for tag in soup.find_all(["a", "form"]):
                href = tag.get("href", "") or tag.get("action", "")
                if href:
                    if href.startswith("http"):
                        links.append(href)
                    elif href.startswith("/"):
                        links.append(f"{base_url}{href}")
                    else:
                        links.append(f"{base_url}/{href}")

        forms = []
        if "body" in result:
            soup = BeautifulSoup(result["body"], "html.parser")
            for form in soup.find_all("form"):
                forms.append({
                    "action": form.get("action", ""),
                    "method": form.get("method", "get"),
                    "inputs": [
                        {
                            "name": inp.get("name", ""),
                            "type": inp.get("type", "text"),
                        }
                        for inp in form.find_all("input")
                    ],
                })

        return {
            "url": url,
            "status_code": result.get("status_code"),
            "links": links[:50],
            "forms": forms,
            "total_links": len(links),
            "total_forms": len(forms),
        }

    def get_cookies(self) -> dict[str, str]:
        """Get current session cookies."""
        return dict(self._session.cookies)

    def set_cookie(self, name: str, value: str, domain: str = "") -> None:
        """Set a cookie in the session."""
        self._session.cookies.set(name, value, domain=domain)

    def clear_session(self) -> None:
        """Clear session cookies."""
        self._session.cookies.clear()
