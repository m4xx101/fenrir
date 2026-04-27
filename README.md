# FENRIR — Autonomous Offensive Security Platform (Hermess Skill)

Fenrir transforms [Hermess Agent](https://hermes-agent.nousresearch.com/) into an intelligent, reasoning-first penetration testing engine that discovers vulnerabilities, bypasses defenses, and chains findings into critical impact — evolving with every assessment.

## What Makes Fenrir Different

**Not a scanner. Not a payload sprayer.** Fenrir is a dynamic security researcher that:

- **Learns tools on-the-fly** — User mentions any tool/repo/Fenrir clones it, reads its README.md, understands --help, and uses it correctly. No hardcoded commands.
- **Understands before acting** — Determines context, defenses, and framework BEFORE testing. Every failure narrows the search space.
- **Bypasses intelligently** — Analyzes WAF blocking patterns, reverse-engineers filter rules, and crafts targeted bypasses. No spraying.
- **Evolves across sessions** — Uses llm-wiki as persistent memory. Every finding, bypass technique, and WAF signature compounds knowledge.
- **Finds zero-days** — Thinks like a developer, not a scanner. Looks for edge cases, state machine flaws, and business logic abuse that automated tools miss.
- **Chains findings** — Connects individual vulnerabilities into compound attack paths (XSS→CSRF→AccountTakeover, SQLi→FileRead→RCE, etc.)

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/m4xx101/fenrir/refs/heads/main/scripts/install-fenrir.sh | bash
```

Or manual:
```bash
git clone https://github.com/m4xx101/fenrir.git
cp -r fenrir/SKILL.md ~/.hermes/skills/fenrir/
```

## Quick Start

1. **Start Heres Agent** → `/skill fenrir` (or just say "scan target.com")
2. **Give a target** → `scan example.com`
3. **Watch it work** → Passive recon, active scanning, vulnerability testing, chain building, reporting — all autonomous

## Commands

```
fenrir scan <target>          # Full autonomous security assessment
fenrir scan <target> --resume # Resume from last checkpoint (read wiki)
scan <target>                 # Shorthand for fenrir scan
```

## How It Works

### Phase 0: Intelligence Gathering (Passive)
Discover everything WITHOUT touching target: CT logs, GitHub leaks, Shodan, Censys, Job postings, DNS history, Wayback Machine, public exploits, tech stack research.

### Phase 1: Active Reconnaissance  
Network mapping, application discovery, JavaScript reverse-engineering, authentication flow mapping, endpoint enumeration, technology fingerprinting.

### Phase 2: Vulnerability Discovery (Reason-First)  
For EVERY input point: Determine context → Send unique marker → Analyze response → Choose ONE targeted test → Analyze result → Adapt → Save to wiki.

### Phase 3: WAF Bypass Intelligence
Analyze block patterns → Identify triggering rules → Craft single targeted bypass → Test → Learn → Save pattern to wiki. Never spray.

### Phase 4: Creative Attack Research
Brainstorming skill generates attacks scanners miss: race conditions, business logic abuse, protocol-level attacks, encoding edge cases, state machine flaws, GraphQL exploitation, WebSocket attacks, third-party integration abuse.

### Phase 5: Vulnerability Chaining
Connect individual findings: XSS+CSRF=ATO, SQLi+FileRead=RCE, SSRF+Internal=DBExfil, IDOR+Enum=CredentialStuffing. Document and validate each chain.

### Phase 6: Zero-Day Hunting
Read source code if available, analyze dependencies, look for unusual data flows, test edge cases vendors overlooked, chain small findings into critical impact, study framework security model assumptions.

### Phase 7: Dynamic Tool Discovery
User mentions ANY tool → Clone/install → Read README/docs → Understand capabilities → Map to target → Test → Learn → Store in wiki for future reuse.

### Phase 8: Reporting
Executive summary, technical report with evidence/PoC/remediation, chain impact analysis with chain-breaking recommendations.

## Uses Your Existing Heres Agent Capabilities

Fenrir leverages what Heres already has:

| Heres Feature | How Fenrir Uses It |
|---------------|-------------------|
| **llm-wiki** | Persistent second brain — findings compound across every session |
| **Browser tools** | Full recon: navigate, snapshot, scroll, extract forms, monitor network, screenshots |
| **Web search** | OSINT, CVEs, leaked credentials, public exploits, tech stack research |
| **Terminal** | Run security tools, install dependencies, clone repos, build scripts |
| **Code execution** | Write/run Python/bash for automation, analysis, custom attack vectors |
| **Vision** | Analyze CAPTCHAs, read error screenshots, interpret complex UIs |
| **Brainstorming** | Creative attack research, zero-day hypothesis generation |
| **Planning** | Structured execution, multi-phase assessment coordination |

## The LLM-WIKI Is Your Evolving Intelligence

```
~/wiki/
├── SCHEMA.md          # Security assessment conventions
├── index.md           # All targets, techniques, findings
├── log.md             # Chronological action log
├── raw/               # Immutable source material
├── targets/           # Per-target knowledge pages
├── entities/          # Frameworks, services, WAFs, cloud providers
├── concepts/          # Techniques, bypass methods, attack patterns
├── comparisons/       # WAF analysis, framework analysis
└── queries/           # Valuable research results
```

Every finding, bypass, failure, tool discovery, and WAF signature is saved here. Every session makes the next smarter.

## Requirements

- **Hermess Agent** with llm-wiki, browser tools, web search, terminal, code execution enabled
- **nmap** (install: `apt install nmap` or `brew install nmap`)
- **dig** (usually pre-installed on Linux/macOS)
- **Playwright/browser** (for JS-rendered app mapping)

## License

MIT

## Disclaimer

Fenrir is for authorized security assessments only. Use responsibly. The authors are not responsible for misuse. Always obtain proper authorization before testing any system you do not own.
