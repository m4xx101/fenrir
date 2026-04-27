
"""No context rot. Smart context management for Fenrir agents."""

from __future__ import annotations

import json
import re
from typing import Any

from loguru import logger


class ContextWindowManager:
    """Manages agent context to prevent context rot and token waste.

    Features:
    - Token budget tracking with hard caps
    - Relevance scoring for brain entries
    - Progressive summarization of old findings
    - Sliding window for agent conversation history
    - Cost-aware: expensive tokens only for critical data
    """

    def __init__(
        self,
        max_tokens: int = 8000,  # Conservative default, agents can override
        max_findings: int = 50,
        reserve_for_response: int = 2000,
    ):
        self.max_tokens = max_tokens
        self.max_findings = max_findings
        self.reserve_for_response = reserve_for_response
        self.usable = max_tokens - reserve_for_response
        self.context_chunks: list[_ContextChunk] = []

    def build_context(
        self,
        target: str,
        recon_entries: list[dict],
        vuln_entries: list[dict],
        chain_entries: list[dict],
        current_phase: str = "",
        system_overhead: int = 500,
    ) -> str:
        """Build optimized context from all brain data."""
        usable = self.usable - system_overhead
        lines = [f"# Fenrir Pro-Max Context for {target}"]
        if current_phase:
            lines.append(f"Current phase: {current_phase}")
            usable -= 50

        # Score and sort recon entries by relevance
        scored_recon = []
        for entry in recon_entries:
            score = _score_recon_entry(entry, target)
            scored_recon.append((score, entry))
        scored_recon.sort(key=lambda x: -x[0])

        # Score vulns by severity
        scored_vulns = []
        for v in vuln_entries:
            score = _score_vuln_entry(v)
            scored_vulns.append((score, v))
        scored_vulns.sort(key=lambda x: -x[0])

        # Build context in priority order: vulns > high-value recon > chains > rest
        budget = usable
        tokens_used = 0

        # 1. Always include all vulnerabilities (highest value)
        for score, vuln in scored_vulns:
            entry_str = _format_vuln(vuln)
            entry_tokens = _estimate_tokens(entry_str)
            if tokens_used + entry_tokens <= budget:
                lines.append(entry_str)
                tokens_used += entry_tokens

        # 2. Include chains (compound risk is critical)
        for chain in chain_entries:
            entry_str = _format_chain(chain)
            entry_tokens = _estimate_tokens(entry_str)
            if tokens_used + entry_tokens <= budget:
                lines.append(entry_str)
                tokens_used += entry_tokens

        # 3. Include high-relevance recon entries (summarize low-relevance)
        included_recon = 0
        summarized_recon = []
        for score, entry in scored_recon:
            entry_str = _format_recon(entry)
            entry_tokens = _estimate_tokens(entry_str)

            if tokens_used + entry_tokens <= budget:
                lines.append(entry_str)
                tokens_used += entry_tokens
                included_recon += 1
            else:
                summarized_recon.append(entry)

        # 4. Summarize any remaining recon entries
        if summarized_recon:
            summary = _summarize_entries(summarized_recon, max_items=10)
            lines.append("\n## Additional Recon (summary only)\n")
            lines.append(summary)

        # Final check: if budget exceeded, truncate
        full_context = "\n".join(lines)
        if _estimate_tokens(full_context) > usable:
            full_context = _truncate_to_budget(full_context, usable)

        logger.debug(
            f"Context built: {len(lines)} lines, "
            f"{_estimate_tokens(full_context)} tokens "
            f"(budget: {usable}), "
            f"{included_recon}/{len(scored_recon)} recon entries included"
        )
        return full_context

    def trim_conversation_history(
        self,
        messages: list[dict[str, str]],
        token_limit: int | None = None,
    ) -> list[dict[str, str]]:
        """Trim conversation history to fit token budget.

        Always keeps system message. Trims oldest user/assistant pairs first.
        """
        limit = token_limit or self.reserve_for_response

        if not messages:
            return []

        # Always keep the system message
        system_msgs = [m for m in messages if m.get("role") == "system"]
        non_system = [m for m in messages if m.get("role") != "system"]

        # Remove from oldest first
        while _estimate_tokens(
            json.dumps(system_msgs) + json.dumps(non_system)
        ) > limit and len(non_system) > 2:
            non_system.pop(0)

        return system_msgs + non_system

    def inject_findings_into_prompt(
        self,
        system_prompt: str,
        recent_findings: list[dict],
        max_tokens_for_findings: int = 2000,
    ) -> str:
        """Inject recent findings into an agent's system prompt."""
        if not recent_findings:
            return system_prompt

        lines = [system_prompt, "\n## Recent Findings\n"]
        budget = max_tokens_for_findings
        used = 0

        for f in recent_findings:
            entry = f.get("summary", json.dumps(f, default=str)[:300])
            if used + _estimate_tokens(entry) < budget:
                lines.append(f"- {entry}")
                used += _estimate_tokens(entry)

        return "\n".join(lines)


# ─── Internal Helpers ────────────────────────────────────────────────────────

class _ContextChunk:
    def __init__(self, content: str, priority: int, token_count: int):
        self.content = content
        self.priority = priority
        self.token_count = token_count


def _estimate_tokens(text: str) -> int:
    """Rough token count (1 token ~4 chars for English)."""
    return len(text) // 4


def _score_recon_entry(entry: dict, target: str) -> float:
    """Score recon entry by relevance."""
    score = 1.0
    category = entry.get("category", "").lower()

    # High-value categories
    if any(kw in category for kw in ["auth", "login", "admin", "api", "endpoint"]):
        score += 3.0
    elif "port" in category or "service" in category:
        score += 2.0
    elif "header" in category or "tech" in category:
        score += 1.5
    elif "subdomain" in category:
        score += 1.0

    # Fresh entries get higher priority
    timestamp = entry.get("timestamp", "")
    if timestamp:
        score += 0.5

    return score


def _score_vuln_entry(vuln: dict) -> float:
    """Score vulnerability by severity and confirmation status."""
    scores = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0, "info": 0.5}
    score = scores.get(vuln.get("severity", "info").lower(), 0.5)

    if vuln.get("confirmed"):
        score *= 2.0

    if vuln.get("evidence"):
        score += 1.0

    return score


def _format_vuln(vuln: dict) -> str:
    """Format a vulnerability entry for context."""
    lines = [f"\n### VULN [{vuln.get('severity', 'unknown').upper()}] {vuln.get('vuln_type', 'unknown')}"]
    if vuln.get("url"):
        lines.append(f"URL: {vuln['url']}")
    if vuln.get("parameter"):
        lines.append(f"Parameter: {vuln['parameter']}")
    if vuln.get("confirmed"):
        lines.append(f"Status: CONFIRMED")
    if vuln.get("description"):
        lines.append(f"Desc: {vuln['description'][:200]}")
    if vuln.get("evidence"):
        lines.append(f"Evidence: {vuln['evidence'][:100]}")
    return "\n".join(lines)


def _format_recon(entry: dict) -> str:
    """Format a recon entry for context."""
    lines = [f"\n### RECON [{entry.get('category', 'general')}]"]
    try:
        data = entry.get("data", {})
        if isinstance(data, str):
            data = json.loads(data)
        if isinstance(data, dict):
            for k, v in list(data.items())[:5]:
                lines.append(f"  {k}: {str(v)[:150]}")
    except Exception:
        lines.append(f"  Data: {str(entry.get('data', ''))[:200]}")
    return "\n".join(lines)


def _format_chain(chain: dict) -> str:
    """Format a chain entry for context."""
    lines = [
        f"\n### CHAIN [{chain.get('overall_severity', 'high').upper()}] {chain.get('chain_name', 'unknown')}"
    ]
    steps = chain.get("chain_steps", [])
    if isinstance(steps, str):
        try:
            steps = json.loads(steps)
        except Exception:
            steps = []
    for step in steps:
        if isinstance(step, dict):
            lines.append(
                f"  Step {step.get('step', '?')}: {step.get('vuln', '?')} - {step.get('description', '')[:100]}"
            )
    if chain.get("impact"):
        lines.append(f"  Impact: {chain['impact'][:150]}")
    return "\n".join(lines)


def _summarize_entries(entries: list[dict], max_items: int = 10) -> str:
    """Summarize multiple recon entries into a compact form."""
    categories: dict[str, int] = {}
    for entry in entries[:max_items]:
        cat = entry.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1

    lines = ["Summary of omitted entries:"]
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        lines.append(f"  {cat}: {count} entries (full data omitted to save tokens)")
    return "\n".join(lines)


def _truncate_to_budget(text: str, budget_chars: int) -> str:
    """Truncate text to stay within budget, keeping complete lines."""
    budget_chars = budget_chars * 4  # Estimate: 1 token = 4 chars
    lines = text.split("\n")
    truncated = []
    total = 0

    for line in lines:
        if total + len(line) > budget_chars and total > 0:
            truncated.append(f"\n[Context truncated: {total} chars of {len(text)} total]")
            break
        truncated.append(line)
        total += len(line)

    return "\n".join(truncated)
