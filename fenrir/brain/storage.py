"""Python-side brain access: Markdown file management + SQLite indexing."""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field

from fenrir.config import AppConfig


class ReconEntry(BaseModel):
    """A reconnaissance finding."""
    target: str
    category: str  # subdomain, port, service, tech, header, etc.
    data: dict[str, Any]
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    source: str = ""


class VulnEntry(BaseModel):
    """A vulnerability finding."""
    target: str
    vuln_type: str  # sqli, xss, ssrf, idor, etc.
    severity: str = "unknown"  # critical, high, medium, low, info
    url: str = ""
    parameter: str = ""
    description: str = ""
    evidence: str = ""
    poc: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    confirmed: bool = False


class ChainEntry(BaseModel):
    """A vulnerability chain."""
    target: str
    chain_steps: list[dict[str, str]] = Field(default_factory=list)  # [{step, vuln, description}]
    overall_severity: str = "high"
    impact: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class BrainStore:
    """Manages the second brain: Markdown files + SQLite index."""

    def __init__(self, config: AppConfig, target: str = ""):
        self.config = config
        self.target = target
        self.base_dir = config.brain.base_dir
        self.sqlite_db = config.brain.sqlite_db

        self._ensure_dirs()
        self._init_sqlite()

    def _ensure_dirs(self) -> None:
        """Create brain directory structure."""
        dirs = [
            self.base_dir,
            self.base_dir / "targets",
            self.base_dir / "techniques",
            self.base_dir / "chains",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

        if self.target:
            target_dir = self.base_dir / "targets" / self._safe_name(self.target)
            (target_dir / "sessions").mkdir(parents=True, exist_ok=True)

    def _init_sqlite(self) -> None:
        """Create SQLite database and tables."""
        self.sqlite_db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self.sqlite_db)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS recon (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    category TEXT NOT NULL,
                    data TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source TEXT
                );

                CREATE TABLE IF NOT EXISTS vulns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'unknown',
                    url TEXT,
                    parameter TEXT,
                    description TEXT,
                    evidence TEXT,
                    poc TEXT,
                    timestamp TEXT NOT NULL,
                    confirmed INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS chains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    chain_steps TEXT NOT NULL,
                    overall_severity TEXT NOT NULL DEFAULT 'high',
                    impact TEXT,
                    timestamp TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_recon_target ON recon(target);
                CREATE INDEX IF NOT EXISTS idx_vulns_target ON vulns(target);
                CREATE INDEX IF NOT EXISTS idx_chains_target ON chains(target);
                CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulns(vuln_type);
            """)

    @property
    def target_dir(self) -> Path:
        if not self.target:
            raise ValueError("No target set")
        return self.base_dir / "targets" / self._safe_name(self.target)

    def _safe_name(self, name: str) -> str:
        return name.replace("://", "_").replace("/", "_").replace(".", "_")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self) -> None:
        """Database connection cleanup (if using context manager)."""
        pass

    # ─── Recon operations ───

    def add_recon(self, entry: ReconEntry) -> int:
        """Add recon finding to brain."""
        # Update Markdown
        self._append_recon_markdown(entry)

        # Insert into SQLite
        with sqlite3.connect(str(self.sqlite_db)) as conn:
            cursor = conn.execute(
                "INSERT INTO recon (target, category, data, timestamp, source) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    entry.target,
                    entry.category,
                    json.dumps(entry.data),
                    entry.timestamp,
                    entry.source,
                ),
            )
            logger.info(f"Recon entry added: {entry.category} for {entry.target}")
            return cursor.lastrowid

    def _append_recon_markdown(self, entry: ReconEntry) -> None:
        """Append recon entry to target's recon.md."""
        if not self.target:
            return
        recon_file = self.target_dir / "recon.md"

        if not recon_file.exists():
            header = [
                f"# Reconnaissance: {self.target}",
                f"---",
                f"last_updated: {datetime.utcnow().isoformat()}",
                f"---\n",
            ]
            recon_file.write_text("\n".join(header))

        section = f"## {entry.category}\n"
        if isinstance(entry.data, dict):
            for key, val in entry.data.items():
                section += f"- **{key}**: {val}\n"
        else:
            section += f"- {entry.data}\n"

        with open(recon_file, "a") as f:
            f.write(f"\n{section}\n")

    def query_recon(self, target: str | None = None, category: str | None = None) -> list[dict]:
        """Query recon entries."""
        query = "SELECT * FROM recon WHERE 1=1"
        params: list = []

        if target:
            query += " AND target = ?"
            params.append(target)
        if category:
            query += " AND category = ?"
            params.append(category)

        query += " ORDER BY timestamp DESC"

        with sqlite3.connect(str(self.sqlite_db)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    # ─── Vulnerability operations ───

    def add_vuln(self, entry: VulnEntry) -> int:
        """Add vulnerability finding to brain."""
        self._append_vuln_markdown(entry)

        with sqlite3.connect(str(self.sqlite_db)) as conn:
            cursor = conn.execute(
                "INSERT INTO vulns "
                "(target, vuln_type, severity, url, parameter, description, evidence, poc, timestamp, confirmed) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.target,
                    entry.vuln_type,
                    entry.severity,
                    entry.url,
                    entry.parameter,
                    entry.description,
                    entry.evidence,
                    entry.poc,
                    entry.timestamp,
                    int(entry.confirmed),
                ),
            )
            logger.info(
                f"Vuln added: {entry.vuln_type} ({entry.severity}) "
                f"on {entry.target}{' [CONFIRMED]' if entry.confirmed else ''}"
            )
            return cursor.lastrowid

    def _append_vuln_markdown(self, entry: VulnEntry) -> None:
        """Append vuln entry to target's vulns.md."""
        if not self.target:
            return
        vulns_file = self.target_dir / "vulns.md"

        if not vulns_file.exists():
            header = [
                f"# Vulnerability Report: {self.target}",
                f"---",
                f"last_updated: {datetime.utcnow().isoformat()}",
                f"---\n",
            ]
            vulns_file.write_text("\n".join(header))

        section = (
            f"## [{entry.severity.upper()}] {entry.vuln_type}\n"
            f"**URL**: `{entry.url}`\n"
            f"**Parameter**: `{entry.parameter}`\n"
            f"**Confirmed**: {entry.confirmed}\n"
            f"**Description**: {entry.description}\n"
            f"**Evidence**:\n```\n{entry.evidence}\n```\n"
            f"**PoC**:\n```\n{entry.poc}\n```\n"
        )

        with open(vulns_file, "a") as f:
            f.write(f"\n{section}\n")

    def query_vulns(
        self,
        target: str | None = None,
        vuln_type: str | None = None,
        severity: str | None = None,
        confirmed_only: bool = False,
    ) -> list[dict]:
        """Query vulnerability entries."""
        query = "SELECT * FROM vulns WHERE 1=1"
        params: list = []

        if target:
            query += " AND target = ?"
            params.append(target)
        if vuln_type:
            query += " AND vuln_type = ?"
            params.append(vuln_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if confirmed_only:
            query += " AND confirmed = 1"

        query += " ORDER BY severity DESC, timestamp DESC"

        with sqlite3.connect(str(self.sqlite_db)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    # ─── Chain operations ───

    def add_chain(self, entry: ChainEntry) -> int:
        """Add vulnerability chain to brain."""
        self._append_chain_markdown(entry)

        with sqlite3.connect(str(self.sqlite_db)) as conn:
            cursor = conn.execute(
                "INSERT INTO chains (target, chain_steps, overall_severity, impact, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    entry.target,
                    json.dumps(entry.chain_steps),
                    entry.overall_severity,
                    entry.impact,
                    entry.timestamp,
                ),
            )
            logger.info(f"Chain added: {len(entry.chain_steps)} steps, {entry.overall_severity}")
            return cursor.lastrowid

    def _append_chain_markdown(self, entry: ChainEntry) -> None:
        """Append chain to target's chains.md."""
        if not self.target:
            return
        chains_file = self.target_dir / "chains.md"

        if not chains_file.exists():
            header = [
                f"# Vulnerability Chains: {self.target}",
                f"---",
                f"last_updated: {datetime.utcnow().isoformat()}",
                f"---\n",
            ]
            chains_file.write_text("\n".join(header))

        section = f"## Chain (Severity: {entry.overall_severity.capitalize()})\n"
        for step in entry.chain_steps:
            section += f"  {step.get('step', '?')}: {step.get('vuln', '?')} - {step.get('description', '')}\n"
        section += f"\n**Impact**: {entry.impact}\n"

        with open(chains_file, "a") as f:
            f.write(f"\n{section}\n")

    def query_chains(self, target: str | None = None) -> list[dict]:
        """Query chain entries."""
        query = "SELECT * FROM chains WHERE 1=1"
        params: list = []

        if target:
            query += " AND target = ?"
            params.append(target)

        query += " ORDER BY timestamp DESC"

        with sqlite3.connect(str(self.sqlite_db)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["chain_steps"] = json.loads(d["chain_steps"]) if d.get("chain_steps") else []
                results.append(d)
            return results

    # ─── Query helpers ───

    def query_by_target(self, target: str) -> dict[str, list[dict]]:
        """Get all findings for a target."""
        return {
            "recon": self.query_recon(target=target),
            "vulns": self.query_vulns(target=target),
            "chains": self.query_chains(target=target),
        }

    def get_recon_context(self, target: str) -> str:
        """Get formatted recon context for agent prompts."""
        data = self.query_by_target(target)
        lines = [f"# Recon Context for {target}"]

        if data["recon"]:
            lines.append("\n## Recon Findings")
            for r in data["recon"]:
                try:
                    rdata = json.loads(r["data"]) if isinstance(r["data"], str) else r["data"]
                except json.JSONDecodeError:
                    rdata = {"raw": r["data"]}
                lines.append(f"\n### {r['category']}")
                for k, v in rdata.items():
                    lines.append(f"- {k}: {v}")

        if data["vulns"]:
            lines.append("\n## Vulnerabilities Found")
            for v in data["vulns"]:
                lines.append(
                    f"- [{v['severity'].upper()}] {v['vuln_type']} @ {v['url']} "
                    f"({'confirmed' if v['confirmed'] else 'unconfirmed'})"
                )

        if data["chains"]:
            lines.append("\n## Exploit Chains")
            for c in data["chains"]:
                lines.append(f"- Chain with {len(c['chain_steps'])} steps, impact: {c['impact']}")

        return "\n".join(lines)

    def save_session(self, session_id: str, content: str) -> Path:
        """Save a session log."""
        if not self.target:
            raise ValueError("No target set")
        session_file = self.target_dir / "sessions" / f"{session_id}.md"
        session_file.write_text(content)
        return session_file

    def load_session(self, session_id: str) -> str:
        """Load a session log."""
        if not self.target:
            raise ValueError("No target set")
        session_file = self.target_dir / "sessions" / f"{session_id}.md"
        return session_file.read_text() if session_file.exists() else ""
