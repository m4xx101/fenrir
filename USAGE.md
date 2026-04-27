# Fenrir Pro-Max — Usage Guide

## Setup

### Prerequisites

- Python 3.10+
- Docker (optional, for sandboxed tool execution)
- Ollama (optional, for free local LLM inference)

### Install

```bash
# Clone
git clone https://github.com/NousResearch/fenrir.git
cd fenrir

# Install with pip
pip install -e .

# Install with dev dependencies
pip install -e ".[dev]"

# Verify
fenrir doctor
fenrir status
```

### Quick Config

```bash
# Set your API key
export OPENROUTER_API_KEY="your-key-here"

# Or for local-only (free, no API keys needed)
ollama pull nousresearch/hermes3:8b
```

## Running Scans

### Full Assessment

```bash
fenrir scan https://target.example.com
```

This runs the complete 8-phase pipeline:
1. **Recon** (4 agents): Subdomains, ports, fingerprints, browser discovery
2. **Analysis** (7 agents in parallel): SQLi, XSS, Auth, Authz, SSRF, Misconfig, File attacks
3. **Exploitation** (4 agents): PoC, escalation, persistence, lateral movement
4. **Chaining** (1 agent): Compound vulnerability chains
5. **Research** (1 agent): Crescent-style creative discovery
6. **Post-Exploitation** (1 agent): Exfiltration paths
7. **Reporting** (1 agent): Executive summary, technical report, chain analysis

### Recon Only

```bash
fenrir recon https://target.example.com
```

### Passive Recon (Zero-Touch)

```bash
# Monitor CT logs, DNS records, Wayback Machine
fenrir passive-recon target.example.com

# With GitHub leak search
fenrir passive-recon target.example.com --github-token ghp_xxx

# With Shodan service discovery
fenrir passive-recon target.example.com --shodan-key xxx
```

### Select Specific Phases

```bash
fenrir scan target.example.com --phases recon analysis

# Multiple phases
fenrir scan target.example.com --phases exploit chaining research
```

### Select Specific Agents

```bash
# Run only certain agents
fenrir scan target.example.com --agents xss sqli

# Run multiple specific agents
fenrir scan target.example.com --agents authz ssrf chain_building
```

### Resume Interrupted Scans

```bash
# If a scan was interrupted (Ctrl-C, network issue, etc.)
fenrir scan https://target.example.com --resume
```

Scan state is automatically checkpointed after each agent. If interrupted:
- First Ctrl-C: **Pause** (shows options)
- Second Ctrl-C: **Abort** (saves state, you can resume)

### Concurrency Control

```bash
# Default: 3 concurrent agents per phase
fenrir scan target.example.com --concurrency 5

# Use fewer for slower LLM APIs
fenrir scan target.example.com --concurrency 1
```

### Budget Control

```bash
# Set maximum cost budget
fenrir scan target.example.com --budget 5.0
```

## Agent Details

### Reconnaissance Agents

| Agent | What it does | Model Tier |
|------|--------------|------------|
| `subdomain_enum` | DNS brute-force on common subdomains | TIER_0 (free) |
| `port_scan` | Nmap scan + service detection | TIER_0 (free) |
| `web_fingerprint` | HTTP headers/tokens/framework detection | TIER_1 |
| `browser_recon` | Playwright-driven exploration | TIER_1 |

### Analysis Agents

| Agent | What it tests | Model Tier |
|------|---------------|------------|
| `injection` | SQLi, Cmd Injection, SSTI, LDAP, NoSQLi | TIER_1 |
| `xss` | Reflected, Stored, DOM, mXSS | TIER_1 |
| `auth` | Brute force, JWT, OAuth, 2FA bypass | TIER_1 |
| `authz` | IDOR, privilege escalation, role matrix | TIER_2 |
| `ssrf` | Internal probing, cloud metadata | TIER_1 |
| `misconfig` | Headers, CORS, CSP, verbose errors | TIER_1 |
| `file_attack` | Path traversal, LFI/RFI, upload bypass | TIER_1 |

### Exploitation Agents

| Agent | What it does | Model Tier |
|------|-------------|------------|
| `poc_generation` | Generates working PoC code | TIER_1 |
| `privilege_escalation` | JWT tampering, role injection, mass assignment | TIER_2 |
| `persistence_testing` | Webshells, SSH keys, cron, backdoors | TIER_2 |
| `lateral_movement` | Internal pivoting, credential reuse | TIER_2 |

### Chain & Research

| Agent | What it does | Model Tier |
|------|-------------|------------|
| `chain_building` | **Key differentiator** — compound attack paths | TIER_2 |
| `crescendo_research` | Creative technique discovery via multi-round LLM | TIER_2 |
| `exfiltration` | Data exfil paths and blast radius | TIER_2 |
| `reporting` | Executive + technical + chain analysis reports | TIER_1 |

### All Agents

```bash
fenrir list-agents
```

## LLM Configuration

### Tier System

Fenrir uses 5 tiers for cost-effective model selection:

```
TIER_0 — Local (Ollama/LM Studio)  FREE
  → SubdomainEnum, PortScan
  Model: nousresearch/hermes3:8b (default)

TIER_1 — Cloud Cheap (~$0.27/M)     CHEAP
  → Injection, XSS, Auth, SSRF, Misconfig, BrowserRecon
  Model: deepseek/deepseek-chat (default)

TIER_2 — Cloud Strong (~$3.00/M)    REASONING
  → Authz, ChainBuilder, Research, Exploitation, Post-Exploitation
  Model: anthropic/claude-sonnet-4 (default)

TIER_3 — Uncensored (~$0.56/M)      FALLBACK
  → When TIER_1 or TIER_2 refuses security content
  Model: nousresearch/hermes-3-llama-3.1-70b (default)

TIER_4 — Abliterated                LAST RESORT
  → When everything else refuses
  Model: User-configured abliterated model
```

### Customizing Model Providers

Create `~/.fenrir/config.yaml` with your providers:

```yaml
llm_providers:
  tier_0:
    model: "llama3.2:8b"
    base_url: "http://localhost:11434/v1"
    api_key: "ollama"
  tier_1:
    model: "anthropic/claude-sonnet-4"
    base_url: "https://openrouter.ai/api/v1"
    api_key: "${OPENROUTER_API_KEY}"
  tier_2:
    model: "openai/gpt-4o"
    base_url: "https://openrouter.ai/api/v1"
    api_key: "${OPENROUTER_API_KEY}"
```

### Local-Only Mode (Zero Cost)

If you only have Ollama:

```bash
# Pull a capable model
ollama pull nousresearch/hermes3:8b

# Run with free local inference
fenrir scan https://target.example.com
```

All agents will use TIER_0 (local model). Results may be less detailed but fully functional.

## The Second Brain

Fenrir maintains intelligent memory across sessions:

```
~/.fenrir/brain/
├── findings.db          # SQLite index
├── embeddings/          # ChromaDB vectors
└── targets/
    └── example_com/
        ├── recon.md     # Recon findings
        ├── vulns.md     # Vulnerabilities
        ├── chains.md    # Attack chains
        └── sessions/    # Per-session logs
```

### How It Works

1. Every agent saves findings to the brain automatically
2. The vector store enables semantic search: "What worked on Flask+MongoDB behind Cloudflare?"
3. Previous sessions inform current ones — Fenrir gets smarter over time
4. No context rot — findings are relevance-scored and prioritized by token budget

### Viewing Findings

```bash
# Check the SQLite database directly
sqlite3 ~/.fenrir/brain/findings.db
  .tables     # recon, vulns, chains
  SELECT * FROM vulns WHERE confirmed = 1;

# Or view the markdown reports
cat ~/.fenrir/brain/targets/target_name/vulns.md
cat ~/.fenrir/brain/targets/target_name/chains.md
```

## Dynamic Tool Onboarding

Fenrir can use any Python script or git repo as a security tool:

```python
# In your scan logic (or via MCP client)
from fenrir.core.tool_loader import ToolLoader

loader = ToolLoader()

# Analyze a user script
meta = loader.analyze_script("/path/to/custom_fuzzer.py")

# Or clone and analyze a repo
info = loader.analyze_repo("https://github.com/user/custom-tool", "/tmp/tool-dir")

# Generate wrapper and register
wrapper_path = loader.generate_mcp_wrapper(info)
loader.register_with_registry(wrapper_path)
```

The `ReActAgent` class can then dynamically use these tools:

```python
from fenrir.core.cot import ReActAgent

agent = ReActAgent(config=config, brain=brain, target="target.com")
result = agent.think("Use the custom fuzzer to test the login endpoint")
```

## Output Format

### Scan Summary

```
============================================================
  FENRIR SCAN COMPLETE: https://target.example.com
------------------------------------------------------------
  Status:       REPORTING
  Agents:       16 passed, 3 failed
  Findings:     47
  Brain storage: /root/.fenrir/brain/findings.db
============================================================
```

### Reports

After completion, three markdown files are generated:

```
~/.fenrir/brain/targets/target_name/
├── executive_summary_20260426_210000.md
├── technical_report_20260426_210000.md
└── chain_impact_analysis_20260426_210000.md
```

## Interruption Handling

### Ctrl-C (Pause)
First Ctrl-C pauses the scan with guidance:
```
⏸ Scan PAUSED.
  Options:
  - Press Ctrl-C again to ABORT
  - Resume later: fenrir scan <target> --resume
  - Status: fenrir status
```

### Ctrl-C Ctrl-C (Abort)
Second Ctrl-C saves state and aborts. Resume with `--resume`.

### CAPTCHA Detection
If a CAPTCHA is detected:
1. Browser screenshot taken
2. User prompted with screenshot
3. Scan pauses until user resolves
4. Auto-resume timeout configurable

## Cost Estimation

### Token Usage

```
FENRIR PRO-MAX - Cost & Token Usage Report
=======================================================
  Duration: 1450s (24.2 minutes)
  Total requests: 127
  Total tokens: 847,230
    Prompt:     523,100
    Completion: 324,130
  Total cost:   $0.8470 / $10.00 budget
-------------------------------------------------------
  Cost by Agent:
    ChainAgent                 $0.2100 [##########]
    ResearchAgent              $0.1800 [########]
    AuthzAgent                 $0.1200 [#####]
    InjectionAgent             $0.0850 [####]
    XSSAgent                   $0.0620 [###]
  Cost by Tier:
    TIER_0         $0.0000 (45,200 tokens)  ← FREE
    TIER_1         $0.1200 (380,000 tokens) ← CHEAP
    TIER_2         $0.7270 (422,030 tokens) ← REASONING
```

### Budget Management

```bash
# Set a hard budget cap
fenrir scan target.com --budget 2.0

# Check current costs
cat ~/.fenrir/logs/cost_report.json
```

## Troubleshooting

```bash
# Check installation
fenrir doctor

# Auto-fix issues
fenrir doctor --fix

# Update
fenrir update

# Force reinstall
fenrir update --force

# Debug mode
fenrir scan target.com --verbose

# Clear brain data (start fresh)
rm -rf ~/.fenrir/brain
```

### Common Issues

**"Docker not found"** — Tools will run without sandboxing. Install Docker for security isolation.

**"llm_client failed"** — Check API keys: `fenrir status` shows which tiers have keys.

**"Browser not available"** — Playwright not installed. Run `playwright install chromium`.

**Slow scans** — Local Ollama is slower. Add a TIER_1 or TIER_2 cloud model for faster execution.

**Context errors** — Increase max_tokens in config.yaml for TIER_2 responses.

## Full Command Reference

```bash
fenrir scan <target>                          # Full scan
fenrir scan <target> --resume                 # Resume
fenrir scan <target> --phases recon           # Specific phases
fenrir scan <target> --agents xss             # Specific agents
fenrir scan <target> --concurrency 5          # Concurrency
fenrir scan <target> --budget 5.0             # Cost budget
fenrir recon <target>                         # Recon only
fenrir recon <target> --full/--quick          # Full or quick
fenrir passive-recon <target>                 # Passive monitoring
fenrir passive-recon <target> --github-token  # With GitHub
fenrir passive-recon <target> --shodan-key    # With Shodan
fenrir status                                 # Show config
fenrir update                                 # Update
fenrir update --check                         # Check only
fenrir update --force                         # Force reinstall
fenrir doctor                                 # Health check
fenrir doctor --fix                           # Auto-fix
fenrir list-agents                            # Show all agents
fenrir --verbose                              # Debug mode
```
