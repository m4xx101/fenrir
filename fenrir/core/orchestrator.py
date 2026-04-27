
"""Autonomous harness orchestrator - the brain of Fenrir."""

from __future__ import annotations

import asyncio
import json
import signal
import sys
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from loguru import logger

from fenrir.config import AppConfig
from fenrir.brain.storage import BrainStore
from fenrir.brain.vector import VectorStore
from fenrir.tools.registry import ToolRegistry
from fenrir.agents.base import AgentResult


class ScanPhase(str, Enum):
    """Pipeline phases in order."""
    INIT = "init"
    RECON = "recon"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    CHAINING = "chaining"
    RESEARCH = "research"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    DONE = "done"


class ScanState:
    """Checkpoint-safe scan state."""

    def __init__(self, target: str, config: AppConfig):
        self.target = target
        self.config = config
        self.phase = ScanPhase.INIT
        self.completed_agents: list[str] = []
        self.failed_agents: list[str] = []
        self.total_findings = 0
        self.start_time = datetime.utcnow()
        self.elapsed = 0.0
        self.cost_summary = {}
        self.interrupted = False
        self.pause_requested = False
        self.pause_event = asyncio.Event()
        self.pause_event.set()  # Start unpaused
        self.checkpoint_path = config.brain.base_dir / "targets" / _safe_name(target) / "scan_state.json"

    def save_checkpoint(self) -> None:
        """Save current state to disk for resume."""
        try:
            self.elapsed = time.time()
            data = {
                "target": self.target,
                "phase": self.phase.value,
                "completed_agents": self.completed_agents,
                "failed_agents": self.failed_agents,
                "total_findings": self.total_findings,
                "start_time": self.start_time.isoformat(),
                "elapsed": self.elapsed,
                "cost_summary": self.cost_summary,
            }
            self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            self.checkpoint_path.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.warning(f"Checkpoint save failed: {e}")

    @classmethod
    def load_checkpoint(cls, target: str, config: AppConfig) -> ScanState | None:
        """Load last checkpoint if exists."""
        path = config.brain.base_dir / "targets" / _safe_name(target) / "scan_state.json"
        if not path.exists():
            return None

        try:
            data = json.loads(path.read_text())
            state = cls(target, config)
            state.phase = ScanPhase(data.get("phase", "init"))
            state.completed_agents = data.get("completed_agents", [])
            state.failed_agents = data.get("failed_agents", [])
            state.total_findings = data.get("total_findings", 0)
            state.start_time = datetime.fromisoformat(data.get("start_time", datetime.utcnow().isoformat()))
            state.cost_summary = data.get("cost_summary", {})
            logger.info(f"Loaded checkpoint: phase={state.phase.value}, {len(state.completed_agents)} agents done")
            return state
        except Exception as e:
            logger.warning(f"Failed to load checkpoint: {e}")
            return None

    def skip_agent(self, agent_name: str) -> bool:
        """Check if agent should be skipped (already completed)."""
        return agent_name in self.completed_agents


def _safe_name(name: str) -> str:
    return name.replace("://", "_").replace("/", "_").replace(".", "_")


class AgentDescriptor:
    """Describes an agent for the orchestrator."""

    def __init__(self, name: str, phase: ScanPhase, import_path: str, tier: str = "tier_1"):
        self.name = name
        self.phase = phase
        self.import_path = import_path
        self.tier = tier


# All agents in the Fenrir pipeline
ALL_AGENTS = [
    # RECON (4 agents)
    AgentDescriptor("subdomain_enum", ScanPhase.RECON, "fenrir.agents.recon.SubdomainAgent", "tier_0"),
    AgentDescriptor("port_scan", ScanPhase.RECON, "fenrir.agents.recon.PortScanAgent", "tier_0"),
    AgentDescriptor("web_fingerprint", ScanPhase.RECON, "fenrir.agents.recon.WebFingerprintAgent", "tier_1"),
    AgentDescriptor("browser_recon", ScanPhase.RECON, "fenrir.agents.recon.BrowserReconAgent", "tier_1"),

    # ANALYSIS (7 agents)
    AgentDescriptor("injection", ScanPhase.ANALYSIS, "fenrir.agents.analysis.InjectionAgent", "tier_1"),
    AgentDescriptor("xss", ScanPhase.ANALYSIS, "fenrir.agents.analysis.XSSAgent", "tier_1"),
    AgentDescriptor("auth", ScanPhase.ANALYSIS, "fenrir.agents.analysis.AuthAgent", "tier_1"),
    AgentDescriptor("authz", ScanPhase.ANALYSIS, "fenrir.agents.analysis.AuthzAgent", "tier_2"),
    AgentDescriptor("ssrf", ScanPhase.ANALYSIS, "fenrir.agents.analysis.SSRFAgent", "tier_1"),
    AgentDescriptor("misconfig", ScanPhase.ANALYSIS, "fenrir.agents.analysis.MisconfigAgent", "tier_1"),
    AgentDescriptor("file_attack", ScanPhase.ANALYSIS, "fenrir.agents.analysis.FileAttackAgent", "tier_1"),

    # EXPLOITATION (4 agents)
    AgentDescriptor("poc_generation", ScanPhase.EXPLOITATION, "fenrir.agents.exploitation.PoCAgent", "tier_1"),
    AgentDescriptor("privilege_escalation", ScanPhase.EXPLOITATION, "fenrir.agents.exploitation.EscalationAgent", "tier_2"),
    AgentDescriptor("persistence_testing", ScanPhase.EXPLOITATION, "fenrir.agents.exploitation.PersistenceAgent", "tier_2"),
    AgentDescriptor("lateral_movement", ScanPhase.EXPLOITATION, "fenrir.agents.exploitation.LateralMovementAgent", "tier_2"),

    # CHAINING (1 agent)
    AgentDescriptor("chain_building", ScanPhase.CHAINING, "fenrir.agents.exploitation.ChainAgent", "tier_2"),

    # RESEARCH (1 agent)
    AgentDescriptor("crescendo_research", ScanPhase.RESEARCH, "fenrir.agents.research.ResearchAgent", "tier_2"),

    # POST EXPLOITATION (1 agent)
    AgentDescriptor("exfiltration", ScanPhase.POST_EXPLOITATION, "fenrir.agents.exploitation.ExfiltrationAgent", "tier_2"),

    # REPORTING (1 agent)
    AgentDescriptor("reporting", ScanPhase.REPORTING, "fenrir.agents.reporting.ReportingAgent", "tier_1"),
]


class FenrirHarness:
    """The autonomous core that runs the full Fenrir scan lifecycle.

    Features:
    - Phase-based state machine with checkpoint/resume
    - Concurrent agent execution within phases
    - Graceful pause/resume/abort on signals
    - User guidance on interruptions
    - Cost tracking across all phases
    - Context-aware pipeline (each phase reads brain from previous)
    """

    def __init__(self, config: AppConfig, target: str, resume: bool = False):
        self.config = config
        self.target = target
        self.state = ScanState.load_checkpoint(target, config) if resume else ScanState(target, config)
        if not self.state:
            self.state = ScanState(target, config)

        self.brain = BrainStore(config, target)
        self.vector_store = VectorStore(config)
        self.tool_registry = ToolRegistry(config)
        self._aborted = False
        self._paused = False
        self._running = False

        # Setup signal handlers for graceful interruption
        self._loop_task: asyncio.Task | None = None
        try:
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self._handle_signal(s)))
        except Exception:
            pass  # Not in running loop yet

    async def run(
        self,
        phases: list[ScanPhase] | None = None,
        agent_filter: list[str] | None = None,
        max_concurrent: int = 3,
    ) -> list[AgentResult]:
        """Execute the full Fenrir pipeline.

        Args:
            phases: Run only these phases. None = all phases in order.
            agent_filter: Run only these agent names. None = all agents.
            max_concurrent: Max concurrent agents per phase.
        """
        self._running = True
        self.state.start_time = datetime.utcnow()
        all_results: list[AgentResult] = []

        phase_order = phases or list(ScanPhase)

        for phase in phase_order:
            if self._aborted:
                logger.info("Abort requested. Stopping pipeline.")
                break

            if phase.value not in [p.value for p in [ScanPhase.INIT, ScanPhase.DONE]]:
                self.state.pause_requested = False
                await self._wait_if_paused()
                await self._run_phase(phase, agent_filter, max_concurrent, all_results)

        self.state.phase = ScanPhase.DONE
        self.state.save_checkpoint()
        self._running = False

        return all_results

    async def _run_phase(
        self,
        phase: ScanPhase,
        agent_filter: list[str] | None,
        max_concurrent: int,
        results: list[AgentResult],
    ) -> None:
        """Run all agents for a single phase."""
        self.state.phase = phase
        self.state.save_checkpoint()

        phase_agents = [a for a in ALL_AGENTS if a.phase == phase]
        if agent_filter:
            phase_agents = [a for a in phase_agents if a.name in agent_filter]

        if not phase_agents:
            return

        logger.info(f"Phase {phase.value.upper()}: {len(phase_agents)} agent(s)")

        # Run agents concurrently within the phase
        tasks = []
        for agent_desc in phase_agents:
            if self.state.skip_agent(agent_desc.name):
                logger.info(f"  Skipping {agent_desc.name} (already completed)")
                continue

            task = asyncio.create_task(self._run_single_agent(agent_desc))
            tasks.append((agent_desc.name, task))

        # Process tasks as they complete with concurrency limit
        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_run(name: str, coro):
            async with semaphore:
                await self._wait_if_paused()
                return await coro

        coros = [limited_run(name, task) for name, task in tasks]
        phase_results = await asyncio.gather(*coros, return_exceptions=True)

        # Collect results
        for i, (name, task) in enumerate(tasks):
            result = phase_results[i]
            if isinstance(result, Exception):
                logger.error(f"  {name}: crashed - {result}")
                self.state.failed_agents.append(name)
                results.append(AgentResult(
                    agent_name=name,
                    success=False,
                    error=str(result),
                ))
            else:
                results.append(result)
                if result.success:
                    self.state.completed_agents.append(name)
                    self.state.total_findings += len(result.findings)
                else:
                    self.state.failed_agents.append(name)
                self.state.save_checkpoint()

    async def _run_single_agent(self, desc: AgentDescriptor) -> AgentResult:
        """Instantiate and run a single agent."""
        try:
            module_path, class_name = desc.import_path.rsplit(".", 1)
            import importlib
            mod = importlib.import_module(module_path)
            agent_cls = getattr(mod, class_name)
        except ImportError as e:
            return AgentResult(
                agent_name=desc.name,
                success=False,
                error=f"Module not available: {e}",
            )
        except AttributeError as e:
            return AgentResult(
                agent_name=desc.name,
                success=False,
                error=f"Agent class not found: {e}",
            )

        agent = agent_cls(
            config=self.config,
            brain=self.brain,
            vector_store=self.vector_store,
            tool_registry=self.tool_registry,
            target=self.target,
        )

        logger.info(f"  Starting {desc.name}...")
        result = await agent.think(f"Target: {self.target}")
        return result

    async def pause(self) -> None:
        """Pause the current scan."""
        self.state.pause_requested = True
        self._paused = True
        self.state.pause_event.clear()
        self.state.save_checkpoint()
        logger.info("Scan PAUSED. Resume to continue.")

    async def resume(self) -> None:
        """Resume a paused scan."""
        self._paused = False
        self.state.pause_requested = False
        self.state.pause_event.set()
        logger.info("Scan RESUMED.")

    async def abort(self) -> None:
        """Abort the current scan."""
        self._aborted = True
        self.state.interrupted = True
        self.state.pause_event.set()  # Unblock waiting tasks
        self.state.save_checkpoint()
        logger.info("Scan ABORTED.")

    async def _wait_if_paused(self) -> None:
        """Block if scan is paused."""
        if self._paused:
            logger.info("Scan is paused. Waiting for resume...")
            await self.state.pause_event.wait()

    async def _handle_signal(self, sig):
        """Handle SIGINT/SIGTERM gracefully."""
        if sig == signal.SIGINT:
            if self._paused:
                # Second Ctrl-C while paused = abort
                await self.abort()
            elif not self.state.pause_requested:
                # First Ctrl-C = pause, offer guidance
                await self.pause()
                logger.info(
                    "\n⏸ Scan PAUSED.\n"
                    "  Options:\n"
                    "  - Press Ctrl-C again to ABORT\n"
                    f"  - Resume later: fenrir scan {self.target} --resume\n"
                    "  - Status: fenrir status\n"
                )
        elif sig == signal.SIGTERM:
            await self.abort()

    def print_summary(self, results: list[AgentResult]) -> str:
        """Print a scan summary."""
        elapsed = time.time() if not self.state.paused else self.state.elapsed
        successful = sum(1 for r in results if r.success)
        failed = sum(1 for r in results if not r.success)
        total_findings = sum(len(r.findings) for r in results)

        brain_path = str(self.config.brain.sqlite_db)[:41]

        summary = [
            "=" * 58,
            f"  FENRIR SCAN COMPLETE: {self.target[:35]}",
            "-" * 58,
            f"  Status:       {self.state.phase.value.upper()}",
            f"  Agents:       {successful} passed, {failed} failed",
            f"  Findings:     {total_findings}",
            f"  Brain storage: {brain_path}",
            "=" * 58,
        ]
        text = "\n".join(summary)
        print(text)
        return text


async def run_single_phase(
    config: AppConfig,
    target: str,
    phase: ScanPhase,
    max_concurrent: int = 3,
) -> list[AgentResult]:
    """Convenience: run a single phase without full harness."""
    harness = FenrirHarness(config, target)
    results = []
    await harness._run_phase(phase, None, max_concurrent, results)
    return results
