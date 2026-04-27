"""Passive reconnaissance engine for continuous target monitoring."""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl

from loguru import logger
from pydantic import BaseModel, Field

from fenrir.config import AppConfig
from fenrir.brain.storage import BrainStore, ReconEntry


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class PassiveFinding(BaseModel):
    """A single passive reconnaissance finding."""
    source: str                          # ct_log, github, shodan, dns, wayback
    category: str                        # subdomain, credential, service, endpoint
    data: dict[str, Any]                 # the finding payload
    timestamp: str = Field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    target: str = ""
    risk_level: str = "info"            # info, low, medium, high, critical
    is_new: bool = True                 # Whether this is a newly discovered item


class ReconMonitor:
    """Passive reconnaissance monitor that runs continuously or on-demand.

    Continuously monitors targets without active probing:
    - Certificate Transparency logs (crt.sh) for new subdomains
    - GitHub/GitLab for leaked credentials and API keys
    - Shodan/Censys for new service appearances
    - DNS record changes
    - Wayback Machine for endpoint discovery
    """

    def __init__(self, config: AppConfig, target: str, brain: BrainStore | None = None):
        self.config = config
        self.target = target
        self.brain = brain or BrainStore(config, target)
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE
        self._known_items: dict[str, str] = self._load_known_items()

    def _load_known_items(self) -> dict[str, str]:
        """Load previously discovered items to detect new ones only."""
        known = {}
        try:
            state_file = self._get_state_file()
            if state_file.exists():
                data = json.loads(state_file.read_text())
                known = data.get("known_items", {})
        except Exception as e:
            logger.debug(f"No previous passive recon state: {e}")
        return known

    def _save_known_items(self) -> None:
        """Save current known items for future delta detection."""
        state_file = self._get_state_file()
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps({
            "target": self.target,
            "last_run": datetime.datetime.utcnow().isoformat(),
            "known_items": self._known_items,
        }, indent=2))

    def _get_state_file(self) -> Path:
        """Get path to the monitor state file."""
        safe_name = self.target.replace("://", "_").replace("/", "_").replace(".", "_")
        return (
            self.config.brain.base_dir
            / "targets"
            / safe_name
            / "passive_monitor.json"
        )

    def _is_new(self, item_key: str, item_value: str) -> bool:
        """Check if an item is newly discovered."""
        key = f"{self.target}:{item_key}"
        if key in self._known_items:
            return self._known_items[key] != item_value
        self._known_items[key] = item_value
        return True

    def _http_get(self, url: str, timeout: int = 30) -> str | None:
        """Simple HTTP GET using stdlib."""
        try:
            req = Request(url, headers={"User-Agent": "Fenrir-Pro-Max/1.0"})
            resp = urlopen(req, timeout=timeout, context=self.ssl_ctx)
            return resp.read().decode("utf-8", errors="ignore")
        except (URLError, HTTPError, Exception) as e:
            logger.warning(f"HTTP GET {url} failed: {e}")
            return None

    def _save_to_brain(self, finding: PassiveFinding) -> None:
        """Save a passive finding to the brain."""
        try:
            if self.brain and finding.target:
                entry = ReconEntry(
                    target=finding.target,
                    category=finding.category,
                    data=finding.data,
                    source=f"passive_{finding.source}",
                )
                self.brain.add_recon(entry)
        except Exception as e:
            logger.warning(f"Failed to save passive finding: {e}")

    # ---------------------------------------------------------------------------
    # CT Log Monitor
    # ---------------------------------------------------------------------------

    def monitor_ct_logs(self) -> list[PassiveFinding]:
        """Check Certificate Transparency logs for new subdomains."""
        findings = []
        domain = self._extract_domain(self.target)
        if not domain:
            return findings

        logger.info(f"Checking CT logs for {domain}")

        # crt.sh API (no auth required)
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        data = self._http_get(url, timeout=60)
        if not data:
            return findings

        try:
            # crt.sh sometimes returns multiple JSON objects
            entries = json.loads(data)
            if not isinstance(entries, list):
                entries = [entries]
        except json.JSONDecodeError:
            # Parse manually if JSON is malformed (common with crt.sh)
            entries = self._parse_crt_manually(data)

        for entry in entries[:200]:  # Limit to most recent
            if not isinstance(entry, dict):
                continue

            name = entry.get("name_value", entry.get("common_name", ""))
            if not name or domain.lower() not in name.lower():
                continue

            # Normalize wildcard entries
            if "*" in name:
                name = name.lstrip("*.")

            cert_serial = entry.get("serial_number", "unknown")
            not_before = entry.get("not_before", "")
            issuer = entry.get("issuer_name", "")

            item_key = f"ct:{name}:{cert_serial}"
            if not self._is_new(item_key, str(not_before)):
                continue

            finding = PassiveFinding(
                source="ct_log",
                category="subdomain",
                target=self.target,
                data={
                    "subdomain": name,
                    "issuer": issuer[:100],
                    "not_before": not_before,
                    "source": "Certificate Transparency log",
                    "discovered_at": datetime.datetime.utcnow().isoformat(),
                },
                risk_level="info",
                is_new=True,
            )
            findings.append(finding)
            self._save_to_brain(finding)

        # Save state
        self._save_known_items()
        logger.info(f"CT log monitor: {len(findings)} new subdomains for {domain}")
        return findings

    def _parse_crt_manually(self, data: str) -> list[dict]:
        """Parse crt.sh output when JSON is invalid."""
        entries = []
        for m in re.finditer(r'"name_value"\s*:\s*"([^"]+)"', data):
            entries.append({"name_value": m.group(1).replace("\\n", "").replace("\n", "")})
        return entries

    # ---------------------------------------------------------------------------
    # GitHub Monitor
    # ---------------------------------------------------------------------------

    def monitor_github(self, github_token: str | None = None) -> list[PassiveFinding]:
        """Search GitHub for leaked credentials and sensitive files."""
        findings = []
        domain = self._extract_domain(self.target)
        if not domain:
            return findings

        logger.info(f"Searching GitHub for {domain} leaks")

        headers = {"User-Agent": "Fenrir-Pro-Max/1.0"}
        if github_token:
            headers["Authorization"] = f"token {github_token}"

        # Search patterns for leaks
        search_queries = [
            f"{domain} password",
            f"{domain} api_key",
            f"{domain} secret",
            f"{domain} token",
            f"{domain} apikey",
            f"{domain} credential",
            f"@{domain} password",
        ]

        for query in search_queries:
            encoded = query.replace(" ", "+")
            url = f"https://api.github.com/search/code?q={encoded}&per_page=10"
            body = self._http_get_with_headers(url, headers, timeout=30)
            if not body:
                continue

            try:
                results = json.loads(body)
                items = results.get("items", [])
                for item in items[:5]:
                    repo = item.get("full_name", "")
                    path = item.get("path", "")
                    html_url = item.get("html_url", "")
                    content_preview = item.get("text_matches", [{}])
                    if len(content_preview) > 0:
                        snippet = content_preview[0].get("matches", [{}])
                        if len(snippet) > 0:
                            snippet_text = snippet[0].get("fragment", "")[:200]

                    item_key = f"github:{repo}:{path}"
                    if not self._is_new(item_key, str(item.get("sha", ""))):
                        continue

                    finding = PassiveFinding(
                        source="github",
                        category="credential_leak",
                        target=self.target,
                        data={
                            "repository": repo,
                            "file_path": path,
                            "query_used": query,
                            "url": html_url,
                            "snippet_preview": snippet_text if 'snippet_text' in dir() else "",
                            "discovered_at": datetime.datetime.utcnow().isoformat(),
                        },
                        risk_level="high",
                        is_new=True,
                    )
                    findings.append(finding)
                    self._save_to_brain(finding)
            except (json.JSONDecodeError, KeyError):
                continue

        self._save_known_items()
        logger.info(f"GitHub monitor: {len(findings)} potential leaks for {domain}")
        return findings

    def _http_get_with_headers(self, url: str, headers: dict, timeout: int = 30) -> str | None:
        """HTTP GET with custom headers."""
        try:
            req = Request(url, headers=headers)
            resp = urlopen(req, timeout=timeout, context=self.ssl_ctx)
            return resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            logger.warning(f"HTTP GET {url} failed: {e}")
            return None

    # ---------------------------------------------------------------------------
    # DNS Monitor
    # ---------------------------------------------------------------------------

    def monitor_dns_changes(self) -> list[PassiveFinding]:
        """Monitor for new DNS records."""
        findings = []
        domain = self._extract_domain(self.target)
        if not domain:
            return findings

        logger.info(f"Checking DNS records for {domain}")

        # Query via public DNS (Google DNS over HTTPS)
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

        for rtype in record_types:
            url = f"https://dns.google/resolve?name={domain}&type={rtype}"
            data = self._http_get(url, timeout=15)
            if not data:
                continue

            try:
                result = json.loads(data)
                for answer in result.get("Answer", []):
                    name = answer.get("name", "")
                    value = answer.get("data", "")

                    item_key = f"dns:{rtype}:{name}:{value}"
                    if not self._is_new(item_key, str(answer)):
                        continue

                    finding = PassiveFinding(
                        source="dns",
                        category="dns_record",
                        target=self.target,
                        data={
                            "record_type": rtype,
                            "name": name,
                            "value": value,
                            "ttl": answer.get("TTL", 0),
                            "discovered_at": datetime.datetime.utcnow().isoformat(),
                        },
                        risk_level="info",
                        is_new=True,
                    )
                    findings.append(finding)
                    self._save_to_brain(finding)
            except (json.JSONDecodeError, Exception):
                continue

        self._save_known_items()
        logger.info(f"DNS monitor: {len(findings)} new records for {domain}")
        return findings

    # ---------------------------------------------------------------------------
    # Wayback Machine Monitor
    # ---------------------------------------------------------------------------

    def monitor_wayback(self) -> list[PassiveFinding]:
        """Check Wayback Machine for historical endpoints."""
        findings = []
        domain = self._extract_domain(self.target)
        if not domain:
            return findings

        logger.info(f"Checking Wayback Machine for {domain}")

        # CDX API
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*"
            f"&matchType=domain"
            f"&output=json"
            f"&fl=timestamp,original,statuscode,mimetype"
            f"&limit=100"
            f"&filter=statuscode:200"
        )

        data = self._http_get(url, timeout=60)
        if not data:
            return findings

        try:
            results = json.loads(data)
            if len(results) <= 1:  # Just header row
                return findings

            # Skip header row
            for row in results[1:50]:
                if len(row) < 4:
                    continue

                timestamp, original, status, mimetype = row
                
                # Filter for interesting content types
                if any(ext in mimetype.lower() for ext in ["image", "css", "js", "font", "ico"]):
                    continue

                item_key = f"wayback:{original}"
                if not self._is_new(item_key, timestamp):
                    continue

                finding = PassiveFinding(
                    source="wayback",
                    category="historical_endpoint",
                    target=self.target,
                    data={
                        "url": original,
                        "timestamp": timestamp,
                        "status_code": status,
                        "content_type": mimetype,
                        "discovered_at": datetime.datetime.utcnow().isoformat(),
                    },
                    risk_level="info",
                    is_new=True,
                )
                findings.append(finding)
                self._save_to_brain(finding)
        except (json.JSONDecodeError, Exception) as e:
            logger.warning(f"Wayback parsing failed: {e}")

        self._save_known_items()
        logger.info(f"Wayback monitor: {len(findings)} endpoints for {domain}")
        return findings

    # ---------------------------------------------------------------------------
    # Shodan-style Monitor (simplified, no API key)
    # ---------------------------------------------------------------------------

    def monitor_shodan(self, shodan_key: str | None = None) -> list[PassiveFinding]:
        """Check Shodan for services on the target (requires API key)."""
        findings = []
        domain = self._extract_domain(self.target)
        if not domain or not shodan_key:
            return findings

        logger.info(f"Checking Shodan for {domain}")

        # Resolve domain first
        dns_url = f"https://dns.google/resolve?name={domain}&type=A"
        data = self._http_get(dns_url)
        if not data:
            return findings

        try:
            result = json.loads(data)
            answers = result.get("Answer", [])
            ips = [a["data"] for a in answers if a.get("type") == 1]
        except Exception:
            return findings

        for ip in ips[:3]:
            shodan_url = f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}"
            shodan_data = self._http_get(shodan_url, timeout=30)
            if not shodan_data:
                continue

            try:
                host_info = json.loads(shodan_data)
                for service in host_info.get("data", [])[:10]:
                    port = service.get("port", 0)
                    product = service.get("product", "unknown")
                    version = service.get("version", "")
                    banner = service.get("data", "")[:500]

                    item_key = f"shodan:{ip}:{port}:{product}"
                    if not self._is_new(item_key, str(host_info.get("last_update", ""))):
                        continue

                    finding = PassiveFinding(
                        source="shodan",
                        category="service_discovery",
                        target=self.target,
                        data={
                            "ip": ip,
                            "port": port,
                            "product": product,
                            "version": version,
                            "banner_preview": banner,
                            "discovered_at": datetime.datetime.utcnow().isoformat(),
                        },
                        risk_level="medium" if port in [22, 3306, 5432, 6379, 27017] else "low",
                        is_new=True,
                    )
                    findings.append(finding)
                    self._save_to_brain(finding)
            except (json.JSONDecodeError, Exception):
                continue

        self._save_known_items()
        logger.info(f"Shodan monitor: {len(findings)} services for {domain}")
        return findings

    # ---------------------------------------------------------------------------
    # Main Monitor Loop
    # ---------------------------------------------------------------------------

    def run_once(self, github_token: str | None = None, shodan_key: str | None = None) -> dict[str, list[PassiveFinding]]:
        """Run all passive monitors once."""
        results = {
            "ct_logs": self.monitor_ct_logs(),
            "github": self.monitor_github(github_token),
            "dns": self.monitor_dns_changes(),
            "wayback": self.monitor_wayback(),
            "shodan": self.monitor_shodan(shodan_key),
        }

        total = sum(len(v) for v in results.values())
        logger.info(f"Passive recon complete: {total} total findings")
        return results

    def _extract_domain(self, target: str) -> str:
        """Extract the base domain from a target URL."""
        # Remove scheme
        t = target
        for prefix in ("http://", "https://", "ftp://"):
            t = t.removeprefix(prefix)

        # Take first path component
        domain = t.split("/")[0]

        # Remove port
        domain = domain.split(":")[0]

        return domain


class PassiveReconAgent:
    """Agent wrapper that integrates passive recon with the main brain."""

    def __init__(self, config: AppConfig, target: str, brain: BrainStore | None = None):
        self.config = config
        self.target = target
        self.monitor = ReconMonitor(config, target, brain)

    def run_passive_recon(self, github_token: str | None = None, shodan_key: str | None = None) -> dict:
        """Execute all passive reconnaissance checks."""
        results = self.monitor.run_once(github_token, shodan_key)
        
        summary = {}
        for source, findings in results.items():
            new_findings = [f for f in findings if f.is_new]
            summary[source] = {
                "total": len(findings),
                "new": len(new_findings),
                "categories": list(set(f.category for f in findings)),
                "finding_ids": len(findings),
            }
        
        return summary
