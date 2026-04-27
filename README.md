# Fenrir Pro-Max — Autonomous Offensive Security Platform

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-0.1.0-orange)

**Fenrir Pro-Max** is a fully autonomous, AI-powered offensive security assessment platform that performs end-to-end penetration testing without human intervention. It uses a tiered multi-model LLM routing system, a self-improving second brain with semantic search, and 19 specialized security agents working in parallel phases.

## Why Fenrir?

The Norse wolf destined to break chains — because security tools shouldn't be constrained by what they're told to look for. Fenrir discovers attack surfaces autonomously, chains vulnerabilities for maximum impact, and continuously learns from every assessment.

## Features

### Autonomy
- **19 specialized agents** across 8 assessment phases (Recon → Analysis → Exploitation → Chaining → Research → Post-Exploitation → Reporting)
- **Vulnerability chaining** — automatically discovers compound attack paths (XSS → CSRF → Account Takeover, SQLi → File Read → RCE)
- **Chain-of-thought reasoning** — agents think, act, observe, and self-correct through multi-step reasoning loops
- **Graceful interruption handling** — pause, resume, and abort scans without losing state. User guidance on ambiguity.

### LLM Architecture
- **5-tier hybrid routing** — from free local Ollama (Tier 0) to ablated uncensored models (Tier 4)
- **45-93% token savings** via intelligent model selection (cheap models for formatting, expensive for reasoning)
- **Auto-fallback on refusal** — when a model blocks, escalate to less-restricted tiers automatically
- **Cost tracking** — real-time per-agent/tier cost monitoring with budget enforcement

### Second Brain
- **SQLite + ChromaDB** — structured findings with vector embeddings for semantic search
- **Self-improving** — every assessment makes the system smarter about techniques that work
- **Per-target knowledge** — recon, vulnerabilities, and chains organized by target
- **No context rot** — intelligent token budgeting prioritizes high-value findings

### Tool Integration
- **MCP protocol support** — connect to Kali MCP, Burp MCP, MetasploitMCP, or any custom MCP server
- **Dynamic tool onboarding** — analyze any Python script or git repo, auto-generate typed wrappers, and register as tools
- **Docker sandboxing** — all tools run in isolated containers with resource limits, read-only filesystems, and audit logging

### Reconnaissance
- **Active recon** — subdomain enumeration, port scanning, web fingerprinting, browser-based endpoint discovery
- **Passive recon** — continuous monitoring via Certificate Transparency logs, GitHub leak detection, DNS changes, Wayback Machine, and Shodan
- **Zero-touch** — gather intelligence without sending a single packet to the target

### Reporting
- **Executive summary** — severity distribution, key findings, risk matrix
- **Technical report** — per-vulnerability reproduction steps, PoC details, remediation
- **Chain impact analysis** — shows how individual vulnerabilities compound into critical attack paths

## Architecture

```
fenrir/
├── core/                    # Autonomous Harness
│   ├── orchestrator.py      # Phase-based state machine, concurrent execution, checkpoint/resume
│   ├── context.py           # Token budget management, no context rot
│   ├── cot.py               # Chain-of-thought reasoning with ReAct self-correction
│   ├── interrupt.py         # Graceful pause/resume/abort, user guidance, CAPTCHA handling
│   ├── tool_loader.py       # Dynamic tool onboarding from scripts/git repos
│   ├── cost_tracker.py      # Per-agent/tier token cost tracking with budget caps
│   ├── update.py            # Install/update/doctor/version management
│   ├── mcp_client.py        # MCP protocol client for Kali/Burp/Metasploit
│   ├── passive_recon.py     # CT logs, GitHub, DNS, Wayback, Shodan monitoring
│   └── sandbox.py           # Docker isolation with security constraints
├── agents/                  # 19 Specialized Security Agents
│   ├── recon.py             # SubdomainAgent, PortScanAgent, WebFingerprintAgent, BrowserReconAgent
│   ├── analysis.py          # InjectionAgent, XSSAgent, AuthAgent, AuthzAgent, SSRFAgent, MisconfigAgent, FileAttackAgent
│   ├── exploitation.py      # PoCAgent, EscalationAgent, PersistenceAgent, LateralMovementAgent, ExfiltrationAgent, ChainAgent
│   ├── research.py          # ResearchAgent (Crescendo methodology)
│   └── reporting.py         # ReportingAgent (3 markdown reports)
├── brain/                   # Second Brain (SQLite + ChromaDB RAG)
├── tools/                   # Nmap, HTTP, Browser, Shell, Registry
└── cli.py                   # CLI: scan, recon, passive-recon, status, update, doctor
```

## Quick Start

```bash
# Install
git clone https://github.com/NousResearch/fenrir.git
cd fenrir
pip install -e .

# Check installation
fenrir doctor

# Quick scan
fenrir scan https://target.example.com

# Resume interrupted scan
fenrir scan https://target.example.com --resume

# Recon only
fenrir recon target.example.com

# Passive recon (zero-touch)
fenrir passive-recon target.example.com

# Check status and LLM tiers
fenrir status
```

## Assessment Pipeline

```
PHASE 1: RECONNAISSANCE
  SubdomainAgent ─────→ Discover subdomains via DNS brute-force, CT logs
  PortScanAgent  ─────→ Nmap service discovery, version detection
  WebFingerprintAgent ─→ Tech stack, WAF, headers, framework analysis
  BrowserReconAgent ───→ Playwright-driven endpoint & form discovery

PHASE 2: VULNERABILITY ANALYSIS (7 agents in parallel)
  InjectionAgent  ────→ SQLi, NoSQLi, Command Injection, SSTI
  XSSAgent ───────────→ Reflected, Stored, DOM, mXSS
  AuthAgent ──────────→ Auth bypass, JWT, OAuth, 2FA
  AuthzAgent ─────────→ IDOR, privilege escalation, role manipulation
  SSRFAgent ──────────→ Internal probing, cloud metadata, blind SSRF
  MisconfigAgent ─────→ Headers, CORS, CSP, verbose errors
  FileAttackAgent ────→ Path traversal, LFI/RFI, upload bypass

PHASE 3: EXPLOITATION
  PoCAgent ───────────→ Generate working proof-of-concept code
  EscalationAgent ────→ Privilege escalation testing
  PersistenceAgent ───→ Webshells, SSH keys, cron jobs, backdoors
  LateralMovementAgent ─ Internal pivoting, credential reuse

PHASE 4: VULNERABILITY CHAINING (The Differentiator)
  ChainAgent ─────────→ Discover compound attack paths across vulns
                        XSS→CSRF→AccountTakeover, SQLi→FileRead→RCE, etc.

PHASE 5: RESEARCH
  ResearchAgent ──────→ Crescendo-style creative technique discovery

PHASE 6: POST-EXPLOITATION
  ExfiltrationAgent ───→ Data exfil paths, blast radius estimation

PHASE 7: REPORTING
  ReportingAgent ─────→ Executive summary, technical report, chain analysis
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `fenrir scan <target>` | Full autonomous assessment pipeline |
| `fenrir scan <target> --resume` | Resume from checkpoint |
| `fenrir scan <target> --phases recon analysis` | Run specific phases only |
| `fenrir scan <target> --agents xss sqli` | Run specific agents only |
| `fenrir recon <target>` | Reconnaissance only |
| `fenrir passive-recon <target>` | Passive monitoring (CT, GitHub, DNS) |
| `fenrir status` | Configuration and LLM tier status |
| `fenrir update` | Update to latest version |
| `fenrir update --check` | Check for updates |
| `fenrir doctor` | Installation health check |
| `fenrir doctor --fix` | Auto-fix detected issues |
| `fenrir list-agents` | List all 19 agents and phases |

## Configuration

```yaml
# ~/.fenrir/config.yaml
llm_providers:
  tier_0:  # Local Ollama (FREE)
    model: "nousresearch/hermes3:8b"
    base_url: "http://localhost:11434/v1"
  tier_1:  # Cloud Cheap (~$0.27/M tokens)
    model: "deepseek/deepseek-chat"
    base_url: "https://openrouter.ai/api/v1"
    api_key: "${OPENROUTER_API_KEY}"
  tier_2:  # Cloud Strong (reasoning, chaining)
    model: "anthropic/claude-sonnet-4"
    base_url: "https://openrouter.ai/api/v1"
    api_key: "${OPENROUTER_API_KEY}"
  tier_3:  # Uncensored (auto-fallback)
    model: "nousresearch/hermes-3-llama-3.1-70b"
    base_url: "https://openrouter.ai/api/v1"
    api_key: "${OPENROUTER_API_KEY}"
  tier_4:  # Abliterated (last resort)

brain:
  base_dir: "~/.fenrir/brain"
```

## Agent Model Routing

| Agent | Tier | Why |
|-------|------|-----|
| SubdomainEnum | TIER_0 | Simple DNS lookups, no reasoning needed |
| PortScan | TIER_0 | Tool execution + output parsing |
| WebFingerprint | TIER_1 | Pattern matching, moderate reasoning |
| Injection | TIER_1 | Payload generation, error analysis |
| XSS | TIER_1 | Context-aware payload crafting |
| Auth | TIER_1 | Flow analysis, token manipulation |
| Authz | TIER_2 | Role matrix inference, parameter tampering |
| SSRF | TIER_1 | Internal probing logic |
| ChainBuilder | TIER_2 | **Complex multi-step reasoning** |
| Research | TIER_2 | **Creative technique discovery** |
| Escalation | TIER_2 | **Adversarial reasoning** |
| LateralMovement | TIER_2 | **Network topology reasoning** |
| Exfiltration | TIER_2 | **Impact quantification** |
| Reporting | TIER_1 | Structured output generation |

## Data Storage

```
~/.fenrir/
├── config.yaml              # Main configuration
├── brain/                   # Second brain
│   ├── findings.db           # SQLite index
│   ├── embeddings/           # ChromaDB vectors
│   └── targets/
│       └── example_com/
│           ├── recon.md      # Reconnaissance findings
│           ├── vulns.md      # Vulnerabilities
│           ├── chains.md     # Attack chains
│           ├── passive_monitor.json  # Passive recon state
│           └── sessions/     # Per-session logs
├── logs/
│   ├── tool-execution.log   # Audit trail
│   └── cost_report.json     # Cost tracking
├── version.json             # Version tracking
└── cache/                   # Temporary files
```

## License

MIT — See [LICENSE](LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Credits

Built by [Nous Research](https://nousresearch.com). Part of the Hermes Agent ecosystem.

## Disclaimer

Fenrir Pro-Max is designed for authorized security assessments only. Use responsibly and ethically. The authors are not responsible for misuse of this tool. Always obtain proper authorization before testing any system you do not own.
