"""LLM router: automatic tier selection based on task complexity."""

from __future__ import annotations

import asyncio
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field

from fenrir.config import AppConfig, LLMConfig, LLMTier
from fenrir.llm_client import LLMClient, LLMResponse, LLMUsage


class RouterMetrics(BaseModel):
    """Aggregated metrics across all tier calls."""
    calls_by_tier: dict[str, int] = Field(default_factory=dict)
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    total_latency_s: float = 0.0


class LLMRouter:
    """Routes LLM requests to appropriate tier based on task complexity."""

    def __init__(self, config: AppConfig):
        self.config = config
        self._clients: dict[LLMTier, LLMClient | None] = {
            LLMTier.TIER_0: None,
            LLMTier.TIER_1: None,
            LLMTier.TIER_2: None,
            LLMTier.TIER_3: None,
            LLMTier.TIER_4: None,
        }
        self._embedding_client: LLMClient | None = None
        self.metrics = RouterMetrics()

    def _get_client(self, tier: LLMTier) -> LLMClient:
        """Lazy-initialize client for a tier."""
        if self._clients[tier] is None:
            tier_map = {
                LLMTier.TIER_0: self.config.llm_providers.tier_0,
                LLMTier.TIER_1: self.config.llm_providers.tier_1,
                LLMTier.TIER_2: self.config.llm_providers.tier_2,
                LLMTier.TIER_3: self.config.llm_providers.tier_3,
                LLMTier.TIER_4: self.config.llm_providers.tier_4,
            }
            llm_config = tier_map[tier]
            if not llm_config.api_key:
                logger.warning(f"No API key configured for {tier.value}, skipping")
                raise ValueError(f"No API key configured for {tier.value}")
            self._clients[tier] = LLMClient(config=llm_config, tier=tier)
        return self._clients[tier]

    def _estimate_complexity(
        self,
        messages: list[dict[str, Any]],
        tier_hint: LLMTier | None = None,
    ) -> LLMTier:
        """Estimate which tier to use based on message content."""
        if tier_hint:
            return tier_hint

        full_text = " ".join(m.get("content", "") for m in messages)
        text_len = len(full_text)

        # Simple heuristic based on task type indicators
        complex_indicators = [
            "chain", "exploit", "escalate", "report", "analysis",
            "multi-step", "creative", "strategy", "plan",
        ]

        score = 0
        for indicator in complex_indicators:
            if indicator.lower() in full_text.lower():
                score += 1

        if score >= 2 or text_len > 4000:
            return LLMTier.TIER_2
        elif score >= 1 or text_len > 2000:
            return LLMTier.TIER_1
        else:
            return LLMTier.TIER_0

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tier: LLMTier | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        fallback_chain: list[LLMTier] | None = None,
    ) -> LLMResponse:
        """Route chat request to appropriate tier with fallback."""
        chosen_tier = self._estimate_complexity(messages, tier)
        chain = [chosen_tier] + (fallback_chain or [LLMTier.TIER_3, LLMTier.TIER_4])

        last_error = None
        for t in chain:
            try:
                client = self._get_client(t)
                response = await client.chat(
                    messages,
                    tools=tools,
                    tool_choice=tool_choice,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                self.metrics.calls_by_tier[t.value] = (
                    self.metrics.calls_by_tier.get(t.value, 0) + 1
                )
                self.metrics.total_tokens += response.usage.total_tokens
                self.metrics.total_cost_usd += response.usage.cost_usd
                self.metrics.total_latency_s += response.latency_s
                return response
            except Exception as e:
                last_error = e
                logger.warning(f"Tier {t.value} failed, trying next: {e}")

        raise last_error or RuntimeError("All LLM tiers failed")

    def get_embedding_client(self) -> LLMClient:
        """Get client configured for embeddings."""
        if self._embedding_client is None:
            config = LLMConfig(
                model=self.config.llm_providers.embedding_model,
                base_url=self.config.llm_providers.embedding_base_url,
                api_key=self.config.llm_providers.embedding_api_key,
                max_tokens=8192,
                temperature=0.0,
            )
            self._embedding_client = LLMClient(
                config=config, tier=LLMTier.TIER_1
            )
        return self._embedding_client

    def get_status(self) -> dict:
        """Return router status summary."""
        status = {}
        for tier in LLMTier:
            cfg_map = {
                LLMTier.TIER_0: self.config.llm_providers.tier_0,
                LLMTier.TIER_1: self.config.llm_providers.tier_1,
                LLMTier.TIER_2: self.config.llm_providers.tier_2,
                LLMTier.TIER_3: self.config.llm_providers.tier_3,
                LLMTier.TIER_4: self.config.llm_providers.tier_4,
            }
            cfg = cfg_map[tier]
            status[tier.value] = {
                "model": cfg.model,
                "configured": bool(cfg.api_key),
                "calls": self.metrics.calls_by_tier.get(tier.value, 0),
            }
        return status

    async def chat_sync(
        self,
        messages: list[dict[str, Any]],
        tier: LLMTier | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        fallback_chain: list[LLMTier] | None = None,
    ) -> LLMResponse:
        """Synchronous wrapper for chat (for non-async contexts)."""
        return asyncio.get_event_loop().run_until_complete(
            self.chat(messages, tier, tools, tool_choice, temperature, max_tokens, fallback_chain)
        )
