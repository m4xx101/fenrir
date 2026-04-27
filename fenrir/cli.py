"""CLI entry point for Fenrir Pro-Max with Click commands."""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from loguru import logger

from fenrir.config import AppConfig, LLMTier, load_config
from fenrir.core.orchestrator import FenrirHarness, ScanPhase, ALL_AGENTS
from fenrir.core.cost_tracker import CostTracker
from fenrir.core.update import FenrirUpdater
from fenrir.agents.base import AgentResult


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------

class CLIContext:
    """Shared context for CLI commands."""

    def __init__(self, config: AppConfig):
        self.config = config


pass_ctx = click.make_pass_decorator(CLIContext)


@click.group()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    default=None,
    help="Path to Fenrir config YAML file.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose/debug logging.",
)
@click.pass_context
def cli(ctx, config: Optional[str], verbose: bool):
    """Fenrir Pro-Max -- Autonomous Offensive Security Platform.

    An independent, AI-powered autonomous penetration testing platform.
    Run full assessments, recon, research, or check system status.
    """
    cfg = load_config(config)

    if verbose:
        logger.remove()
        logger.add(sys.stderr, level="DEBUG", colorize=True)
    else:
        logger.remove()
        logger.add(sys.stderr, level=cfg.logging.level, colorize=True)

    # Ensure data directories exist
    updater = FenrirUpdater(cfg)
    updater.ensure_data_dirs()

    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg


# ---------------------------------------------------------------------------
# Scan Command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("target")
@click.option(
    "--agents", "-a", "agent_filter",
    multiple=True,
    default=None,
    help="Run specific agents only. Repeatable. Default: all.",
)
@click.option(
    "--phases", "-p", "phase_filter",
    multiple=True,
    default=None,
    type=click.Choice([p.value for p in ScanPhase if p.value not in ("init", "done")]),
    help="Run only specific phases.",
)
@click.option(
    "--resume", "-r",
    is_flag=True,
    default=False,
    help="Resume from last checkpoint.",
)
@click.option(
    "--concurrency",
    type=int,
    default=3,
    help="Max concurrent agents per phase.",
)
@click.option(
    "--budget",
    type=float,
    default=None,
    help="Cost budget in USD (overrides config).",
)
@click.pass_context
def scan(ctx, target: str, agent_filter: Optional[tuple[str, ...]],
         phase_filter: Optional[tuple[str, ...]], resume: bool,
         concurrency: int, budget: Optional[float]):
    """Run full autonomous scan pipeline against a target.

    Executes the complete Fenrir assessment pipeline:
    1. Reconnaissance (subdomain, port scan, web fingerprinting, browser)
    2. Vulnerability analysis (injection, XSS, auth, SSRF, etc.)
    3. Exploitation (PoC, privilege escalation, persistence, lateral movement)
    4. Chain building (vulnerability chaining)
    5. Research (Crescendo methodology)
    6. Post-exploitation (exfiltration analysis)
    7. Reporting

    Examples:
        fenrir scan https://juice-shop.example.com
        fenrir scan example.com --phases recon analysis
        fenrir scan example.com --agents xss sqli --resume
    """
    config: AppConfig = ctx.obj["config"]

    if budget is not None:
        from fenrir.config import BrainConfig, ToolConfig, LoggingConfig
        # We can't modify config.budget directly, pass through harness

    phases = None
    if phase_filter:
        phases = [ScanPhase(p) for p in phase_filter]

    agent_list = list(agent_filter) if agent_filter else None

    logger.info(f"Starting Fenrir scan against: {target}")
    if resume:
        logger.info("Resuming from checkpoint...")
    if agent_list:
        logger.info(f"Agent filter: {agent_list}")
    if phases:
        logger.info(f"Phase filter: {[p.value for p in phases]}")

    start_time = time.monotonic()

    results = asyncio.run(run_scan_with_costs(
        config, target, agent_list, phases, concurrency, resume, budget
    ))

    elapsed = time.time() - start_time

    # Print summary
    print("")
    print("=" * 60)
    print(f"FENRIR SCAN COMPLETE: {target}")
    print(f"Duration: {elapsed:.1f}s")
    print("=" * 60)

    successful = sum(1 for r in results if r.success)
    failed = sum(1 for r in results if not r.success)
    total_findings = sum(len(r.findings) for r in results)

    for r in results:
        status = " OK " if r.success else "FAIL"
        print(
            f"  [{status}] {r.agent_name:<28s} "
            f"{r.summary[:50]:<50s} "
            f"({r.execution_time_s:.1f}s, {len(r.findings)} findings)"
        )

    if failed:
        print(f"\n  FAILED AGENTS ({failed}):")
        for r in results:
            if not r.success:
                print(f"    - {r.agent_name}: {r.error[:100]}")

    print(f"\n  Total: {total_findings} findings from {successful}/{successful + failed} agents")
    print(f"  Brain: {config.brain.sqlite_db}")
    print(f"  Results saved to: {config.brain.base_dir}")


async def run_scan_with_costs(
    config: AppConfig,
    target: str,
    agent_filter: list[str] | None,
    phases: list[ScanPhase] | None,
    concurrency: int,
    resume: bool,
    budget: float | None = None,
) -> list[AgentResult]:
    """Run scan with cost tracking."""
    cost_log = Path.home() / ".fenrir" / "logs" / "cost_report.json"
    tracker = CostTracker(
        budget_usd=budget or 10.0,
        log_dir=Path.home() / ".fenrir" / "logs",
    )
    tracker.load()

    harness = FenrirHarness(config, target, resume=resume)
    results = await harness.run(
        phases=phases,
        agent_filter=agent_filter,
        max_concurrent=concurrency,
    )

    print("")
    print(tracker.format_summary())

    harness.print_summary(results)

    # Save checkpoint
    harness.state.save_checkpoint()

    return results


# ---------------------------------------------------------------------------
# Recon Command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("target")
@click.option(
    "--full/--quick",
    default=True,
    help="Run full or quick reconnaissance.",
)
@click.pass_context
def recon(ctx, target: str, full: bool):
    """Run reconnaissance only against a target.

    Performs subdomain enumeration, port scanning,
    web fingerprinting, and browser-based reconnaissance.
    """
    config: AppConfig = ctx.obj["config"]

    logger.info(f"Starting reconnaissance against: {target} (full={full})")
    start_time = time.monotonic()

    recon_phases = [ScanPhase.RECON]
    results = asyncio.run(run_scan_with_costs(
        config=config,
        target=target,
        agent_filter=None,
        phases=recon_phases,
        concurrency=3,
        resume=False,
        budget=None,
    ))

    elapsed = time.monotonic() - start_time

    print("\n" + "=" * 60)
    print(f"RECON COMPLETE: {target}")
    print(f"Duration: {elapsed:.1f}s")
    print("=" * 60)

    total_findings = sum(len(r.findings) for r in results)
    for r in results:
        status = "OK" if r.success else "FAILED"
        print(f"  [{status}] {r.agent_name}: {r.summary} ({len(r.findings)} findings)")

    print(f"\nTotal: {total_findings} recon findings")
    print(f"Results saved to: {config.brain.base_dir}")


# ---------------------------------------------------------------------------
# Status Command
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    default=None,
    help="Path to Fenrir config YAML file.",
)
def status(config: Optional[str]):
    """Show configuration and LLM tier status."""
    cfg = load_config(config)
    updater = FenrirUpdater(cfg)

    print("=" * 60)
    print("FENRIR PRO-MAX -- Configuration Status")
    print("=" * 60)

    # Version info
    version_info = updater.get_current_version()
    update_info = updater.check_for_updates()
    print(f"\n  Version: {version_info.get('version', 'unknown')}")
    if update_info.get("has_update"):
        print(f"  Update available: {update_info['current_version']} -> {update_info['latest_version']}")
    else:
        print(f"  Status: UP TO DATE")

    # Brain storage
    print(f"\n[Brain Storage]")
    print(f"  Base directory:   {cfg.brain.base_dir}")
    print(f"  SQLite database:  {cfg.brain.sqlite_db}")
    print(f"  Chroma embeddings: {cfg.brain.chroma_db_dir}")

    # LLM Tiers
    print(f"\n[LLM Tier Configuration]")

    tiers = [
        ("TIER_0 (Local Ollama)", cfg.llm_providers.tier_0),
        ("TIER_1 (Cloud Cheap)", cfg.llm_providers.tier_1),
        ("TIER_2 (Cloud Strong)", cfg.llm_providers.tier_2),
        ("TIER_3 (Uncensored)", cfg.llm_providers.tier_3),
        ("TIER_4 (Abliterated)", cfg.llm_providers.tier_4),
    ]

    for name, tier_cfg in tiers:
        has_key = bool(tier_cfg.api_key)
        status_icon = "OK " if has_key else "---"
        key_status = "KEYED" if has_key else "NO KEY"
        print(f"  [{status_icon}] {name}: {tier_cfg.model} ({key_status})")
        if tier_cfg.base_url:
            print(f"        URL: {tier_cfg.base_url}")

    print(f"\n  Fallback model: {cfg.llm_providers.fallback_model}")
    print(f"  Embedding model: {cfg.llm_providers.embedding_model}")

    # Tool configuration
    print(f"\n[Tool Configuration]")
    print(f"  Sandbox: {cfg.tools.sandbox_enabled}")
    print(f"  Default timeout: {cfg.tools.default_timeout}s")
    print(f"  Max output: {cfg.tools.max_shell_output_bytes} bytes")
    print(f"  Nmap: {cfg.tools.nmap_binary}")
    print(f"  Rustscan: {cfg.tools.rustscan_binary}")

    # Scan configuration
    print(f"\n[Scan Configuration]")
    print(f"  Scan timeout: {cfg.scan_timeout}s")
    print(f"  Max concurrent agents: {cfg.max_concurrent_agents}")

    # Logging
    print(f"\n[Logging]")
    print(f"  Level: {cfg.logging.level}")
    print(f"  Log directory: {cfg.logging.log_dir}")

    # Data directories
    print(f"\n[Data Directories]")
    from fenrir.core.update import FENRIR_DATA
    print(f"  Fenrir data: {FENRIR_DATA} ({'exists' if FENRIR_DATA.exists() else 'MISSING'})")
    print(f"  Brain targets: {FENRIR_DATA / 'brain' / 'targets'}")

    print("\n" + "=" * 60)


# ---------------------------------------------------------------------------
# Update Command
# ---------------------------------------------------------------------------

@cli.command(name="update")
@click.option(
    "--check",
    is_flag=True,
    help="Only check for updates, do not install.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Force reinstall even if up to date.",
)
@click.option(
    "--pip/--git",
    default=True,
    help="Update via pip (default) or git pull.",
)
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
def update_cmd(check: bool, force: bool, pip: bool, config: Optional[str]):
    """Update Fenrir Pro-Max to the latest version."""
    cfg = load_config(config)
    updater = FenrirUpdater(cfg)

    if check:
        info = updater.check_for_updates()
        print(f"Current version: {info['current_version']}")
        print(f"Latest version:  {info['latest_version']}")
        if info['has_update']:
            print("\n  Update available! Run: fenrir update")
        else:
            print("\n  You are up to date.")
        return

    print(f"Current version: {updater.get_current_version().get('version', 'unknown')}")

    if updater.update(use_pip=pip, force=force):
        print("Fenrir updated successfully.")
        version_info = updater.get_current_version()
        print(f"New version: {version_info.get('version', 'unknown')}")
    else:
        print("Update failed. Check logs for details.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Doctor Command
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--fix", is_flag=True, help="Attempt to fix detected issues.")
@click.pass_context
def doctor(ctx, fix: bool):
    """Check Fenrir installation and dependencies."""
    config: AppConfig = ctx.obj["config"]
    updater = FenrirUpdater(config)

    print("=" * 50)
    print("FENRIR PRO-MAX - Installation Check")
    print("=" * 50)

    checks = updater.verify_installation()

    all_ok = True
    for check_name, status in sorted(checks.items()):
        icon = "OK " if status else "   "
        print(f"  [{icon}] {check_name}")
        if not status:
            all_ok = False

    print("")
    if all_ok:
        print("  All checks passed. Fenrir is ready.")
    else:
        print("  Some checks failed.")
        if fix:
            print("\n  Attempting automatic fixes...")
            if not checks.get("data_dirs"):
                updater.ensure_data_dirs()
                print("  [OK] Created data directories")
            if not checks.get("config_exists"):
                updater.install_default_config()
                print("  [OK] Created default config")
            failed_deps = [k.replace("dep_", "") for k, v in checks.items() if k.startswith("dep_") and not v]
            if failed_deps:
                print(f"  Missing dependencies: {', '.join(failed_deps)}")
                print("  Run: fenrir update --force")

    print("=" * 50)



# ---------------------------------------------------------------------------
# Passive Recon Command
# ---------------------------------------------------------------------------

@cli.command(name="passive-recon")
@click.argument("target")
@click.option("--github-token", default=None, help="GitHub token for leak search.")
@click.option("--shodan-key", default=None, help="Shodan API key.")
@click.pass_context
def passive_recon(ctx, target: str, github_token: str | None, shodan_key: str | None):
    """Run passive reconnaissance against a target.

    Monitors Certificate Transparency logs, GitHub leaks,
    DNS records, Wayback Machine, and Shodan -- all without touching the target.
    """
    config = ctx.obj["config"]
    logger.info(f"Starting passive recon against: {target}")

    from fenrir.brain.storage import BrainStore
    from fenrir.core.passive_recon import PassiveReconAgent

    brain = BrainStore(config, target)
    agent = PassiveReconAgent(config, target, brain)
    results = agent.run_passive_recon(github_token, shodan_key)

    print("\n" + "=" * 60)
    print(f"PASSIVE RECON COMPLETE: {target}")
    print("=" * 60)

    total = 0
    for source, data in results.items():
        total += data["new"]
        print(f"  {source:<15s}: {data['new']} new / {data['total']} total")

    print(f"\n  Total new findings: {total}")
    print(f"  Saved to brain: {config.brain.sqlite_db}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# List Agents
# ---------------------------------------------------------------------------

@cli.command("list-agents")
def list_agents_cmd():
    """List all available Fenrir agents and their phases."""
    print("=" * 60)
    print("FENRIR PRO-MAX -- Available Agents")
    print("=" * 60)

    current_phase = None
    for agent in ALL_AGENTS:
        if agent.phase != current_phase:
            current_phase = agent.phase
            print(f"\n  [{current_phase.value.upper()}]")

        print(f"    {agent.name:<28s} (tier: {agent.tier})")

    print(f"\n  Total: {len(ALL_AGENTS)} agents across {len(set(a.phase for a in ALL_AGENTS))} phases")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main():
    """CLI entry point."""
    cli()


if __name__ == "__main__":
    main()
