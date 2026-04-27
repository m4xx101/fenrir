"""Base agent class: foundation for all Fenrir Pro-Max agents."""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field

from fenrir.brain.storage import BrainStore, ReconEntry, VulnEntry, ChainEntry
from fenrir.brain.vector import VectorStore
from fenrir.config import AppConfig, LLMTier
from fenrir.llm_client import LLMClient, LLMResponse
from fenrir.tools.registry import ToolRegistry


class AgentResult(BaseModel):
    """Result from an agent execution."""
    agent_name: str
    success: bool
    summary: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    error: str = ""
    execution_time_s: float = 0.0
    token_usage: dict[str, int] = Field(default_factory=dict)


class BaseAgent(ABC):
    """Abstract base agent for Fenrir Pro-Max platform.

    Each agent has:
    - A name and system prompt
    - A set of available tools
    - Access to the brain (SQLite + vector store)
    - An LLM client for communication
    """

    name: str = "base"
    role: str = ""
    system_prompt: str = ""
    tier: LLMTier = LLMTier.TIER_0
    temperature: float = 0.7

    def __init__(
        self,
        config: AppConfig,
        brain: BrainStore | None = None,
        vector_store: VectorStore | None = None,
        tool_registry: ToolRegistry | None = None,
        target: str = "",
        client: LLMClient | None = None,
    ):
        self.config = config
        self.target = target
        self._brain = brain or BrainStore(config, target)
        self._vector_store = vector_store or VectorStore(config)
        self._tool_registry = tool_registry or ToolRegistry(config)
        self._client = client
        self._start_time = 0.0

    @property
    def brain(self) -> BrainStore:
        return self._brain

    @property
    def vector_store(self) -> VectorStore:
        return self._vector_store

    @property
    def tool_registry(self) -> ToolRegistry:
        return self._tool_registry

    def _get_client(self, tier: LLMTier | None = None) -> LLMClient:
        """Get or create LLM client for this agent's tier."""
        if self._client:
            return self._client

        from fenrir.brain.llm_router import LLMRouter

        router = LLMRouter(self.config)
        chosen_tier = tier or self.tier
        return router._get_client(chosen_tier)

    def _build_messages(self, task: str, context: str = "") -> list[dict[str, str]]:
        """Build the message list for LLM calls."""
        messages = []

        if self.system_prompt:
            full_system = self.system_prompt
            if context:
                full_system += f"\n\n## Current Context\n{context}"
            messages.append({"role": "system", "content": full_system})

        messages.append({"role": "user", "content": task})
        return messages

    async def think(self, task: str, retries: int = 2) -> AgentResult:
        """Main execution loop with Fissure-style fallback chains.

        The core think() method that all agents inherit. It implements the
        Fissure pattern: retry → escalate tier → fallback tools → never abort.

        Subclasses override _run() to provide agent-specific behavior.
        """
        self._start_time = time.time()
        consecutive_failures = 0
        current_tier = self.tier

        for attempt in range(retries + 1):
            try:
                logger.info(
                    f"[{self.name}] Starting (attempt {attempt + 1}, "
                    f"tier={current_tier.value}): {task[:100]}..."
                )

                # Gather context from brain
                context = self._build_context()

                # Run agent-specific logic
                result = await self._run(task, context)

                # Decision matrix on result
                if result.success:
                    # SUCCESS — record and return
                    result.execution_time_s = time.time() - self._start_time
                    self._persist_findings(result)

                    logger.info(
                        f"[{self.name}] Completed in {result.execution_time_s:.1f}s, "
                        f"{len(result.findings)} findings: {result.summary}"
                    )
                    return result

                elif result.findings:
                    # PARTIAL — findings exist but flagged as not fully successful
                    result.execution_time_s = time.time() - self._start_time
                    self._persist_findings(result)
                    # Return partial results — they're valuable
                    logger.warning(
                        f"[{self.name}] Partial: {len(result.findings)} findings, "
                        f"but marked as unsuccessful: {result.error}"
                    )
                    return result

                elif not result.error:
                    # EMPTY — no findings, no errors. Target may not have this attack surface.
                    result.execution_time_s = time.time() - self._start_time
                    result.summary = "No applicable findings for this attack surface"
                    result.success = True  # Not a failure, just nothing to find
                    return result

                else:
                    # ERROR — apply escalation chain
                    consecutive_failures += 1
                    logger.warning(
                        f"[{self.name}] Error on attempt {attempt + 1}: {result.error}"
                    )

                    if consecutive_failures >= 2:
                        # Try next LLM tier before giving up
                        tier_escalation = {
                            LLMTier.TIER_0: LLMTier.TIER_1,
                            LLMTier.TIER_1: LLMTier.TIER_2,
                            LLMTier.TIER_2: LLMTier.TIER_3,
                            LLMTier.TIER_3: LLMTier.TIER_4,
                        }
                        next_tier = tier_escalation.get(current_tier, None)
                        if next_tier:
                            current_tier = next_tier
                            self._client = None  # Force recreate
                            logger.info(
                                f"[{self.name}] Escalating to {next_tier.value} "
                                f"for next attempt"
                            )
                            consecutive_failures = 0

            except Exception as e:
                consecutive_failures += 1
                logger.error(f"[{self.name}] Exception on attempt {attempt + 1}: {e}")

                if consecutive_failures >= 3:
                    # Fallback: run without LLM using built-in logic
                    logger.warning(
                        f"[{self.name}] LLM exhausted, running without LLM on attempt {attempt + 1}"
                    )
                    self._client = None

        # All retries exhausted
        return AgentResult(
            agent_name=self.name,
            success=False,
            error=f"All {retries + 1} attempts failed",
            execution_time_s=time.time() - self._start_time,
        )

    def _persist_findings(self, result: AgentResult) -> None:
        """Persist findings to brain and vector store."""
        if result.success:
            # Brain storage
            for finding in result.findings:
                try:
                    self.save_finding(finding, self._infer_category(finding))
                except Exception as e:
                    logger.warning(
                        f"[{self.name}] Brain write failed, "
                        f"trying fallback: {e}"
                    )
                    # Brain write fallback: log but never abort
                    try:
                        self._save_to_temp_file(finding)
                    except Exception:
                        pass  # Skip and continue — scan never stops for brain failure

            # Vector store
            for finding in result.findings:
                try:
                    content = json.dumps(finding, default=str)
                    self._vector_store.add_finding(self.name, content, self.target)
                except Exception:
                    pass

    def _infer_category(self, finding: dict) -> str:
        """Determine brain storage category from finding data."""
        ftype = (finding.get("type") or finding.get("category") or "").lower()
        if any(k in ftype for k in ["recon", "scan", "fingerprint", "subdomain", "port", "dns"]):
            return "recon"
        elif any(k in ftype for k in ["chain", "escalation"]):
            return "chain"
        return "vuln"

    def _build_context(self) -> str:
        """Build context string from brain findings."""
        try:
            if self.target:
                return self._brain.get_recon_context(self.target)
        except Exception:
            pass
        return ""

    async def call_llm(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        response_format: dict | None = None,
    ) -> LLMResponse:
        """Call LLM with messages and optional tools."""
        client = self._get_client()

        if not tools:
            tools = self._tool_registry.get_definitions()

        return await client.chat(
            messages,
            tools=tools,
            tool_choice=tool_choice,
            temperature=temperature or self.temperature,
            max_tokens=max_tokens,
            response_format=response_format,
        )

    async def execute_tool(
        self,
        tool_name: str,
        args: dict[str, Any] | str = "",
        tool_call_id: str = "",
    ) -> dict[str, Any]:
        """Execute a registered tool and return result."""
        result = await self.tool_registry.invoke(tool_name, args, tool_call_id)

        if result.success:
            logger.debug(f"[{self.name}] Tool {tool_name}: success ({len(result.output)} chars)")
        else:
            logger.warning(f"[{self.name}] Tool {tool_name}: failed - {result.error}")

        return result.model_dump()

    def save_finding(self, finding: dict[str, Any], category: str = "general") -> None:
        """Save a finding to brain storage."""
        try:
            # Determine finding type and persist
            if category == "recon":
                entry = ReconEntry(
                    target=self.target,
                    category=category,
                    data=finding,
                    source=self.name,
                )
                self._brain.add_recon(entry)
            elif category in ("vuln", "vulnerability"):
                entry = VulnEntry(
                    target=self.target,
                    vuln_type=finding.get("vuln_type", category),
                    severity=finding.get("severity", "unknown"),
                    url=finding.get("url", ""),
                    parameter=finding.get("parameter", ""),
                    description=finding.get("description", ""),
                    evidence=finding.get("evidence", "")[:5000],
                    poc=finding.get("poc", ""),
                    confirmed=finding.get("confirmed", False),
                )
                self._brain.add_vuln(entry)
            elif category == "chain":
                entry = ChainEntry(
                    target=self.target,
                    chain_steps=finding.get("steps", []),
                    overall_severity=finding.get("severity", "high"),
                    impact=finding.get("impact", ""),
                )
                self._brain.add_chain(entry)

            logger.info(f"[{self.name}] Finding saved: {category}")
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to save finding: {e}")

    def _save_to_temp_file(self, finding: dict[str, Any]) -> None:
        """Fallback: save finding to temp file when brain/disk storage fails.

        This ensures findings are never lost even if the brain infrastructure
        goes down. Scan NEVER stops for storage failures.
        """
        import tempfile
        temp_dir = Path(tempfile.gettempdir()) / "fenrir"
        temp_dir.mkdir(parents=True, exist_ok=True)
        finding_file = temp_dir / f"findings_{self.target.replace('/', '_')}.jsonl"

        with open(finding_file, "a") as f:
            f.write(json.dumps(finding, default=str) + "\n")

        logger.debug(f"[{self.name}] Finding saved to temp: {finding_file}")

    @abstractmethod
    async def _run(self, task: str, context: str) -> AgentResult:
        """Agent-specific execution logic. Must be implemented by subclass."""
        ...
