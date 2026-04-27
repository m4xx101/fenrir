
"""Real-time token and cost tracking for Fenrir Pro-Max."""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger


# Approximate per-1M-token costs (OpenRouter pricing as of 2026-04)
COST_TABLE: dict[str, dict[str, float]] = {
    "nousresearch/hermes3:8b": {"input": 0, "output": 0},  # local = free
    "deepseek/deepseek-chat": {"input": 0.27, "output": 1.10},
    "anthropic/claude-sonnet-4": {"input": 3.00, "output": 15.00},
    "anthropic/claude-3.7-sonnet": {"input": 3.00, "output": 15.00},
    "openai/gpt-4o": {"input": 2.50, "output": 10.00},
    "openai/gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "nousresearch/hermes-3-llama-3.1-70b": {"input": 0.56, "output": 0.79},
    "default": {"input": 1.00, "output": 3.00},  # fallback estimate
}


class CostTracker:
    """Tracks token usage and estimated costs across all Fenrir operations.

    Features:
    - Real-time per-agent cost tracking
    - Budget enforcement (hard cap to prevent runaway spending)
    - Cost breakdown by phase, model, and agent
    - Exportable reports
    - Predictive cost estimation for remaining work
    """

    def __init__(
        self,
        budget_usd: float = 10.0,
        log_dir: Path | None = None,
    ):
        self.budget_usd = budget_usd
        self.log_dir = log_dir or Path.home() / ".fenrir" / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Accumulated totals
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_requests = 0
        self.total_cost_usd = 0.0

        # Per-agent tracking
        self.agent_costs: dict[str, dict[str, Any]] = {}
        # Per-tier tracking
        self.tier_costs: dict[str, dict[str, Any]] = {}
        # Per-model tracking
        self.model_costs: dict[str, dict[str, Any]] = {}
        # Per-request log
        self.request_log: list[dict[str, Any]] = []

        # Start time
        self.start_time = datetime.utcnow()

    def record(
        self,
        agent_name: str,
        model: str,
        tier: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_s: float = 0.0,
    ) -> dict[str, Any]:
        """Record a single LLM API call.

        Returns the cost info for this call.
        """
        cost = self._estimate_cost(model, prompt_tokens, completion_tokens)
        timestamp = datetime.utcnow()

        entry = {
            "timestamp": timestamp.isoformat(),
            "agent": agent_name,
            "model": model,
            "tier": tier,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "cost_usd": cost,
            "latency_s": latency_s,
        }

        # Update totals
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_requests += 1
        self.total_cost_usd += cost

        # Update per-agent
        if agent_name not in self.agent_costs:
            self.agent_costs[agent_name] = {
                "requests": 0, "prompt_tokens": 0, "completion_tokens": 0,
                "total_tokens": 0, "cost_usd": 0.0, "models_used": set(),
            }
        ac = self.agent_costs[agent_name]
        ac["requests"] += 1
        ac["prompt_tokens"] += prompt_tokens
        ac["completion_tokens"] += completion_tokens
        ac["total_tokens"] += prompt_tokens + completion_tokens
        ac["cost_usd"] += cost
        if isinstance(ac.get("models_used"), set):
            ac["models_used"].add(model)

        # Update per-tier
        if tier not in self.tier_costs:
            self.tier_costs[tier] = {
                "requests": 0, "total_tokens": 0, "cost_usd": 0.0,
            }
        self.tier_costs[tier]["requests"] += 1
        self.tier_costs[tier]["total_tokens"] += prompt_tokens + completion_tokens
        self.tier_costs[tier]["cost_usd"] += cost

        # Update per-model
        if model not in self.model_costs:
            self.model_costs[model] = {
                "requests": 0, "total_tokens": 0, "cost_usd": 0.0,
            }
        self.model_costs[model]["requests"] += 1
        self.model_costs[model]["total_tokens"] += prompt_tokens + completion_tokens
        self.model_costs[model]["cost_usd"] += cost

        # Log request
        self.request_log.append(entry)

        # Budget check
        if self.total_cost_usd > self.budget_usd:
            logger.warning(
                f"Budget EXCEEDED: ${self.total_cost_usd:.4f} / ${self.budget_usd:.2f}"
            )

        # Periodic persistence
        if self.total_requests % 10 == 0:
            self.save()

        return entry

    def _estimate_cost(
        self, model: str, prompt_tokens: int, completion_tokens: int
    ) -> float:
        """Estimate cost based on model and token counts."""
        # Check exact match
        if model in COST_TABLE:
            rates = COST_TABLE[model]
        else:
            # Try partial match
            rates = COST_TABLE.get("default", {"input": 1.00, "output": 3.00})
            for known_model, known_rates in COST_TABLE.items():
                if known_model in model:
                    rates = known_rates
                    break

        input_cost = (prompt_tokens / 1_000_000) * rates["input"]
        output_cost = (completion_tokens / 1_000_000) * rates["output"]
        return round(input_cost + output_cost, 6)

    def remaining_budget(self) -> float:
        """Return remaining budget in USD."""
        return max(0, self.budget_usd - self.total_cost_usd)

    def budget_percent_used(self) -> float:
        """Return percentage of budget used."""
        if self.budget_usd <= 0:
            return 100.0
        return round((self.total_cost_usd / self.budget_usd) * 100, 2)

    def is_over_budget(self) -> bool:
        """Check if we've exceeded the budget."""
        return self.total_cost_usd > self.budget_usd

    def get_agent_breakdown(self) -> list[dict[str, Any]]:
        """Get cost breakdown by agent."""
        result = []
        for agent_name, data in sorted(
            self.agent_costs.items(), key=lambda x: -x[1]["cost_usd"]
        ):
            models = data.get("models_used", set())
            if isinstance(models, set):
                models = list(models)
            result.append({
                "agent": agent_name,
                "requests": data["requests"],
                "total_tokens": data["total_tokens"],
                "cost_usd": round(data["cost_usd"], 4),
                "models_used": models,
            })
        return result

    def get_tier_breakdown(self) -> list[dict[str, Any]]:
        """Get cost breakdown by LLM tier."""
        tier_order = ["tier_0", "tier_1", "tier_2", "tier_3", "tier_4"]
        result = []
        for tier in tier_order:
            data = self.tier_costs.get(tier, {})
            if data:
                result.append({
                    "tier": tier,
                    "requests": data["requests"],
                    "total_tokens": data["total_tokens"],
                    "cost_usd": round(data["cost_usd"], 4),
                })
        return result

    def estimate_remaining_cost(
        self, remaining_phases: list[str], average_cost_per_phase: float
    ) -> float:
        """Estimate cost for remaining phases based on current averages."""
        return len(remaining_phases) * average_cost_per_phase

    def format_summary(self) -> str:
        """Format a human-readable cost summary."""
        elapsed = (datetime.utcnow() - self.start_time).total_seconds()
        avg_cost_per_req = (
            round(self.total_cost_usd / self.total_requests, 4)
            if self.total_requests > 0
            else 0
        )

        lines = [
            "=" * 55,
            "FENRIR PRO-MAX - Cost & Token Usage Report",
            "=" * 55,
            f"  Duration: {elapsed:.0f}s ({elapsed/60:.1f}m)",
            f"  Total requests: {self.total_requests}",
            f"  Total tokens: {self.total_prompt_tokens + self.total_completion_tokens:,}",
            f"    Prompt:     {self.total_prompt_tokens:,}",
            f"    Completion: {self.total_completion_tokens:,}",
            f"  Total cost:   ${self.total_cost_usd:.4f} / ${self.budget_usd:.2f} budget",
            f"  Budget used:  {self.budget_percent_used():.1f}%",
            f"  Avg per req:  ${avg_cost_per_req:.4f}",
        ]

        # Per-agent breakdown
        agent_data = self.get_agent_breakdown()
        if agent_data:
            lines.append("")
            lines.append("  Cost by Agent:")
            for a in agent_data:
                bar = "#" * min(int(a["cost_usd"] / max(self.total_cost_usd, 0.001) * 30), 30)
                lines.append(
                    f"    {a['agent']:<25s} ${a['cost_usd']:.4f} [{bar}]"
                )

        # Per-tier breakdown
        tier_data = self.get_tier_breakdown()
        if tier_data:
            lines.append("")
            lines.append("  Cost by Tier:")
            for t in tier_data:
                lines.append(
                    f"    {t['tier']:<15s} ${t['cost_usd']:.4f} ({t['total_tokens']:,} tokens)"
                )

        lines.append("")
        if self.is_over_budget():
            lines.append(f"  WARNING: Budget exceeded by ${self.total_cost_usd - self.budget_usd:.4f}")
        elif self.budget_percent_used() > 80:
            lines.append(f"  NOTICE: Approaching budget limit ({self.budget_percent_used():.1f}% used)")
        else:
            lines.append("  Budget status: OK")

        lines.append("=" * 55)
        return "\n".join(lines)

    def save(self, path: Path | None = None) -> None:
        """Persist cost data to disk."""
        save_path = path or (self.log_dir / "cost_report.json")
        save_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "start_time": self.start_time.isoformat(),
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_requests": self.total_requests,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "agent_costs": {
                k: {
                    "requests": v["requests"],
                    "total_tokens": v["total_tokens"],
                    "cost_usd": round(v["cost_usd"], 6),
                }
                for k, v in self.agent_costs.items()
            },
            "tier_costs": self.tier_costs,
            "budget_usd": self.budget_usd,
            "request_count": len(self.request_log),
        }

        save_path.write_text(json.dumps(data, indent=2))
        logger.debug(f"Cost report saved: {save_path}")

    def load(self, path: Path | None = None) -> None:
        """Load previous cost data from disk."""
        save_path = path or (self.log_dir / "cost_report.json")
        if not save_path.exists():
            return

        try:
            data = json.loads(save_path.read_text())
            self.total_prompt_tokens = data.get("total_prompt_tokens", 0)
            self.total_completion_tokens = data.get("total_completion_tokens", 0)
            self.total_requests = data.get("total_requests", 0)
            self.total_cost_usd = data.get("total_cost_usd", 0.0)
            logger.info(f"Loaded cost data: {self.total_requests} requests, ${self.total_cost_usd:.4f}")
        except Exception as e:
            logger.warning(f"Failed to load cost data: {e}")

    def reset(self) -> None:
        """Reset all cost tracking."""
        self.__init__(budget_usd=self.budget_usd, log_dir=self.log_dir)
