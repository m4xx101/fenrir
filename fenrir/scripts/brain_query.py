#!/usr/bin/env python3
"""Fenrir Pro-Max — Brain Query Helper

Usage:
    python3 fenrir/scripts/brain_query.py recon <target>
    python3 fenrir/scripts/brain_query.py vulns <target>
    python3 fenrir/scripts/brain_query.py chains <target>
    python3 fenrir/scripts/brain_query.py state <target>
    python3 fenrir/scripts/brain_query.py all <target>
    python3 fenrir/scripts/brain_query.py context <target>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BRAIN_DIR = Path.home() / ".fenrir" / "brain"


def get_target_dir(target: str) -> Path:
    safe = target.replace("://", "_").replace("/", "_").replace(".", "_")
    d = BRAIN_DIR / "targets" / safe
    return d


def read_file_safe(p: Path) -> str:
    return p.read_text() if p.exists() else ""


def read_state(td: Path) -> dict:
    state_file = td / "state.json"
    if state_file.exists():
        try:
            return json.loads(state_file.read_text())
        except:
            return {}
    return {}


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 fenrir/scripts/brain_query.py <mode> <target>")
        sys.exit(1)

    mode = sys.argv[1]
    target = sys.argv[2]
    td = get_target_dir(target)

    files = {
        "recon": td / "recon.md",
        "vulns": td / "vulns.md",
        "chains": td / "chains.md",
        "state": td / "state.json",
    }

    if mode == "state":
        state = read_state(td)
        print(json.dumps(state, indent=2))
    elif mode == "all":
        for name, path in files.items():
            print(f"\n{'='*50}\n# {name.upper()}\n{'='*50}")
            if path.suffix == ".json":
                print(json.dumps(read_state(td), indent=2) if path.exists() else "[No state found]")
            else:
                print(read_file_safe(path) or f"[No {name} findings yet]")
    elif mode == "context":
        # Build context for LLM consumption
        lines = [f"# Fenrir Context: {target}"]
        state = read_state(td)
        if state:
            lines.append(f"Phase: {state.get('phase', 'unknown')}")
            lines.append(f"Completed: {', '.join(state.get('completed_agents', []))}")
            lines.append(f"Findings: {state.get('findings_count', 0)}")
        for name, path in files.items():
            if name == "state":
                continue
            content = read_file_safe(path)
            if content:
                lines.append(f"\n## {name.upper()}\n{content[:3000]}")
        print("\n".join(lines))
    elif mode in files:
        path = files[mode]
        if path.suffix == ".json":
            print(json.dumps(read_state(td), indent=2) if path.exists() else "{}")
        else:
            print(read_file_safe(path) or f"[No {mode} data for {target}]")
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)


if __name__ == "__main__":
    main()
