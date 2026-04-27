#!/usr/bin/env python3
"""Fenrir brain utility: inspect, query, and manage brain data from CLI.

Usage (from agent's perspective):
    python3 scripts/brain.py status [target]
    python3 scripts/brain.py findings [target]
    python3 scripts/brain_vulns [target] [--severity critical]
    python3 scripts/brain.py chains [target]
    python3 scripts/brain.py search [target] [query]
    python3 scripts/brain.py export [target] [--format json|markdown]
"""

import json
import sqlite3
import sys
from pathlib import Path

BRAIN_DIR = Path.home() / ".fenrir" / "brain"
FINDINGS_DB = BRAIN_DIR / "findings.db"


def db_connect():
    """Connect to SQLite findings database."""
    FINDINGS_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(FINDINGS_DB))
    conn.row_factory = sqlite3.Row
    return conn


def status(target=None):
    """Print brain status."""
    print(f"Brain directory: {BRAIN_DIR}")
    conn = db_connect()

    for table in ["recon", "vulns", "chains"]:
        try:
            if target:
                rows = conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE target=?",
                    (target,),
                ).fetchone()[0]
            else:
                rows = conn.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
            print(f"  {table}: {rows} entries")
        except sqlite3.OperationalError:
            print(f"  {table}: 0 entries (table not created)")

    conn.close()


def findings(target=None):
    """Print all findings for a target."""
    conn = db_connect()

    print("=== RECON FINDINGS ===")
    if target:
        rows = conn.execute(
            "SELECT * FROM recon WHERE target=? ORDER BY timestamp DESC",
            (target,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM recon ORDER BY timestamp DESC LIMIT 20"
        ).fetchall()
    for r in rows:
        d = dict(r)
        try:
            d["data"] = json.loads(d["data"]) if isinstance(d["data"], str) else d["data"]
        except json.JSONDecodeError:
            pass
        print(f"  [{r['timestamp']}] {r['category']}: {json.dumps(d.get('data', {}), indent=4)[:200]}")

    print("\n=== VULNERABILITY FINDINGS ===")
    if target:
        rows = conn.execute(
            "SELECT * FROM vulns WHERE target=? ORDER BY severity DESC",
            (target,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM vulns ORDER BY severity DESC, timestamp DESC LIMIT 20"
        ).fetchall()
    for r in rows:
        d = dict(r)
        print(f"  [{r['severity'].upper()}] {r['vuln_type']} @ {r['url']} (confirmed: {bool(r['confirmed'])})")

    print("\n=== CHAINS ===")
    if target:
        rows = conn.execute(
            "SELECT * FROM chains WHERE target=?",
            (target,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM chains ORDER BY timestamp DESC LIMIT 10"
        ).fetchall()
    for r in rows:
        d = dict(r)
        d["chain_steps"] = json.loads(d["chain_steps"]) if isinstance(d["chain_steps"], str) else d["chain_steps"]
        print(f"  [{r['overall_severity'].upper()}] {len(d.get('chain_steps', []))} steps — {r.get('impact', '')[:100]}")

    conn.close()


def vulns(target=None, severity=None):
    """Filter vulnerability findings."""
    conn = db_connect()
    query = "SELECT * FROM vulns WHERE 1=1"
    params = []

    if target:
        query += " AND target=?"
        params.append(target)
    if severity:
        query += " AND severity=?"
        params.append(severity)

    query += " ORDER BY severity DESC, timestamp DESC"
    rows = conn.execute(query, params).fetchall()

    for r in rows:
        d = dict(r)
        print(f"[{r['severity'].upper()}] {r['vuln_type']}")
        print(f"  URL: {r['url']}")
        print(f"  Parameter: {r['parameter']}")
        if r['description']:
            print(f"  Description: {r['description'][:200]}")
        if r['evidence']:
            print(f"  Evidence: {r['evidence'][:200]}")
        if r['poc']:
            print(f"  PoC: {r['poc'][:200]}")
        print(f"  Confirmed: {bool(r['confirmed'])}")
        print()

    conn.close()


def chains(target=None):
    """Print vulnerability chains."""
    conn = db_connect()

    if target:
        rows = conn.execute(
            "SELECT * FROM chains WHERE target=?",
            (target,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM chains ORDER BY timestamp DESC"
        ).fetchall()

    for r in rows:
        d = dict(r)
        d["chain_steps"] = json.loads(d["chain_steps"]) if isinstance(d["chain_steps"], str) else d["chain_steps"]
        print(f"Chain (Severity: {r['overall_severity'].upper()}) on {r['target']}")
        print(f"Impact: {d.get('impact', '')}")
        print("Steps:")
        for step in d.get("chain_steps", []):
            if isinstance(step, dict):
                print(f"  {step.get('step', '?')}. {step.get('vuln', '?')} - {step.get('action', step.get('description', ''))}")
        print()

    conn.close()


def search(target=None, query_text=None):
    """Simple text search in findings."""
    conn = db_connect()

    if target:
        results = conn.execute(
            "SELECT * FROM vulns WHERE target LIKE ? OR url LIKE ? OR description LIKE ? OR evidence LIKE ?",
            (f"%{query_text}%",) * 4
        ).fetchall()
        for r in results:
            print(f"[{r['severity'].upper()}] {r['vuln_type']} @ {r['url']}")
            if r['description']:
                print(f"  Description: {r['description'][:200]}")
    else:
        results = conn.execute(
            "SELECT * FROM vulns WHERE description LIKE ? OR evidence LIKE ?",
            (f"%{query_text}%", f"%{query_text}%")
        ).fetchall()
        for r in results:
            print(f"[{r['severity'].upper()}] {r['vuln_type']} @ {r['url']} ({r['target']})")

    conn.close()


def export_target(target=None, fmt="json"):
    """Export all findings for a target."""
    conn = db_connect()
    data = {}

    for table in ["recon", "vulns", "chains"]:
        if target:
            rows = conn.execute(
                f"SELECT * FROM {table} WHERE target=?",
                (target,),
            ).fetchall()
        else:
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()

        result_list = []
        for r in rows:
            d = dict(r)
            # Parse JSON fields
            for field in ("data", "chain_steps"):
                if field in d and isinstance(d[field], str):
                    try:
                        d[field] = json.loads(d[field])
                    except json.JSONDecodeError:
                        pass
            result_list.append(d)
        data[table] = result_list

    conn.close()

    if fmt == "json":
        print(json.dumps(data, indent=2, default=str))
    else:
        for table, rows in data.items():
            print(f"\n# {table.upper()}")
            for r in rows:
                print(f"- {json.dumps(r, default=str)[:200]}")


def main():
    if len(sys.argv) < 2:
        print("Usage: brain.py {status|findings|vulns|chains|search|export} [target] [--severity X]")
        return

    action = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else None

    if action == "status":
        status(target)
    elif action == "findings":
        findings(target)
    elif action == "vulns":
        severity = None
        for arg in sys.argv[3:]:
            if arg.startswith("--severity"):
                severity = arg.split("=")[-1] if "=" in arg else sys.argv[sys.argv.index(arg) + 1]
        vulns(target, severity)
    elif action == "chains":
        chains(target)
    elif action == "search":
        query_text = sys.argv[2] if len(sys.argv) > 2 else ""
        target = None
        if len(sys.argv) > 3:
            target = sys.argv[2]
            query_text = sys.argv[3]
        search(target, query_text)
    elif action == "export":
        fmt = "json"
        for arg in sys.argv[3:]:
            if arg.startswith("--format"):
                fmt = arg.split("=")[-1]
        export_target(target, fmt)
    else:
        print(f"Unknown action: {action}")


if __name__ == "__main__":
    main()
