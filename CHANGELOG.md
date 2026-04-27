# Changelog

## [0.1.0] - 2026-04-26

### Added

#### Autonomous Harness (10 modules)
- **Orchestrator**: Phase-based state machine with checkpoint/resume, concurrent agent execution, pause/abort signals, ScanState persistence
- **Context Manager**: Token budget tracking, relevance scoring, progressive summarization, no context rot
- **Chain of Thought (CoT)**: ReAct multi-step reasoning loop, self-correction with contradiction detection, backtracking, confidence threshold early exit
- **Interrupt Handler**: Graceful Ctrl-C pause/resume, double Ctrl-C abort, Rich terminal formatting, CAPTCHA detection (45+ patterns + browser screenshots), SessionGuard context manager
- **Tool Loader**: AST-based script analysis, git repo cloning with venv isolation, auto-generate typed MCP wrappers, validate and register with ToolRegistry
- **Cost Tracker**: Per-agent/tier/model cost tracking, budget enforcement with hard cap, OpenRouter pricing table, cost report CSV/JSON export
- **Update Manager**: pip index version check, git remote comparison, `fenrir update`, `fenrir doctor --fix` auto-fixes, version tracking
- **MCP Client**: JSON-RPC 2.0 stdio/SSE transports, Kali/Burp/Metasploit pre-config, auto-registration with ToolRegistry
- **Passive Recon**: Certificate Transparency logs (crt.sh), GitHub leak detection, DNS record monitoring, Wayback Machine endpoint discovery, Shodan service discovery
- **Docker Sandbox**: Container isolation, read-only filesystem, no-network default, CPU/memory cgroups, non-root user, audit logging, ScriptSecurityScanner

#### Agents (19 total)
- **Recon (4)**: SubdomainAgent, PortScanAgent, WebFingerprintAgent, BrowserReconAgent
- **Analysis (7)**: InjectionAgent, XSSAgent, AuthAgent, AuthzAgent, SSRFAgent, MisconfigAgent, FileAttackAgent
- **Exploitation (4)**: PoCAgent, EscalationAgent, PersistenceAgent, LateralMovementAgent
- **Chaining (1)**: ChainAgent — 8 predefined chain templates + LLM novel chains + vector store matching
- **Research (1)**: ResearchAgent — 5-round Crescendo methodology, roleplay framing, uncensored fallback
- **Post-Exploitation (1)**: ExfiltrationAgent — data exfil paths, blast radius estimation
- **Reporting (1)**: ReportingAgent — executive summary, technical report, chain impact analysis

#### CLI Commands (7)
- `fenrir scan` — Full autonomous pipeline
- `fenrir recon` — Recon only
- `fenrir passive-recon` — Zero-touch monitoring
- `fenrir status` — Config and tier status
- `fenrir update` — Update/version management
- `fenrir doctor` — Health check with auto-fix
- `fenrir list-agents` — Show all agents

### Architecture
- 36 Python files, 14,000+ LOC
- 5-tier LLM routing (TIER_0 through TIER_4)
- SQLite + ChromaDB second brain with per-target organization
- Checkpoint-based state machine (pause/resume without data loss)
