#!/usr/bin/env python3
"""Fissure-style fallback chains reference.

This module provides the FallbackChain registry for Fenrir agents.
Every critical operation has defined fallback paths.

Usage:
    from fenrir.scripts.fallback import FALLBACK_CHAINS
    FALLBACK_CHAINS["nmap_scan"].follow(context)
"""

FALLBACK_CHAINS = {
    # === RECON ===
    "subdomain_enum": {
        "description": "Subdomain enumeration fallback chain",
        "steps": [
            {
                "name": "DNS_resolution",
                "tool": "python3 -c \"import socket; print(socket.gethostbyname(sub))\"",
                "description": "Try DNS resolution for common subdomains",
            },
            {
                "name": "crt_sh_search",
                "tool": "browser_navigate('https://crt.sh/?q=domain')",
                "description": "Query Certificate Transparency logs",
            },
            {
                "name": "search_engine_dork",
                "tool": "HTTP GET to search engine with site:domain",
                "description": "Use search engines to find indexed subdomains",
            },
            {
                "name": "passive_dns_history",
                "tool": "HTTP GET to DNS history APIs",
                "description": "Check DNS history services",
            },
        ],
        "fallback_order": [0, 1, 2, 3],
    },

    "port_scan": {
        "description": "Port scanning fallback chain",
        "steps": [
            {
                "name": "nmap_quick",
                "tool": "nmap -F -sV -T4 target",
                "description": "Quick scan top 100 ports with version detection",
            },
            {
                "name": "nmap_full",
                "tool": "nmap -p- -sV -T4 target",
                "description": "Full port range scan",
            },
            {
                "name": "netcat_probe",
                "tool": "for port in $(seq 1 1000); do nc -z -w1 target $port && echo $port; done",
                "description": "Direct TCP probe using netcat (no Nmap needed)",
            },
            {
                "name": "curl_probe",
                "tool": "curl -s http://target:PORT/",
                "description": "HTTP probe on common web ports",
            },
        ],
        "fallback_order": [0, 1, 2, 3],
    },

    "http_request": {
        "description": "HTTP request fallback chain",
        "steps": [
            {
                "name": "python_urllib",
                "tool": "urllib.request.urlopen()",
                "description": "Use Python's built-in urllib",
            },
            {
                "name": "curl_command",
                "tool": "curl -s -L URL",
                "description": "Use shell curl command",
            },
            {
                "name": "wget",
                "tool": "wget -q -O- URL",
                "description": "Use wget as alternative",
            },
            {
                "name": "browser_fetch",
                "tool": "browser_navigate() → get_content()",
                "description": "Use real browser for JS-rendered content",
            },
        ],
        "fallback_order": [0, 1, 2, 3],
    },

    "browser_interaction": {
        "description": "Browser interaction fallback chain",
        "steps": [
            {
                "name": "playwright_direct",
                "tool": "playwright Page.click/fill/type",
                "description": "Direct Playwright interaction",
            },
            {
                "name": "javascript_injection",
                "tool": "browser_console to inject JS",
                "description": "Execute JS to interact with page",
            },
            {
                "name": "keyboard_tab_navigation",
                "tool": "browser_press('Tab') -> Enter",
                "description": "Tab through elements to reach target",
            },
            {
                "name": "http_fallback",
                "tool": "HTTP POST with form data directly",
                "description": "Skip browser, send HTTP directly",
            },
        ],
        "fallback_order": [0, 1, 2, 3],
    },

    # === ANALYSIS ===
    "vulnerability_test": {
        "description": "Vulnerability testing fallback chain",
        "steps": [
            {
                "name": "http_based_test",
                "tool": "HTTP GET/POST with payloads",
                "description": "Send vulnerability payloads via HTTP requests",
            },
            {
                "name": "browser_based_test",
                "tool": "Browser automate the interaction",
                "description": "Use real browser for JavaScript-heavy payloads",
            },
            {
                "name": "timing_based_test",
                "tool": "Measure response times for blind injection",
                "description": "Timing-based detection when output not visible",
            },
            {
                "name": "error_based_test",
                "tool": "Analyze error responses",
                "description": "Extract information from verbose error messages",
            },
        ],
        "fallback_order": [0, 1, 2, 3],
    },

    # === EXPLOITATION ===
    "exploit_execution": {
        "description": "Exploit execution fallback chain",
        "steps": [
            {
                "name": "direct_http_exploit",
                "tool": "HTTP GET/POST with exploitation payload",
                "description": "Direct HTTP exploitation",
            },
            {
                "name": "browser_exploit",
                "tool": "Browser-based payload delivery",
                "description": "Use browser for exploitation (XSS, CSRF)",
            },
            {
                "name": "script_execution",
                "tool": "python3 exploit_script.py",
                "description": "Run a custom exploit script",
            },
            {
                "name": "manual_verification",
                "tool": "Agent manually analyzes the target",
                "description": "Agent uses reasoning to find manual exploitation path",
            },
        ],
        "fallback_order": [0, 1, 2, 3],
    },

    # === BRAIN / STORAGE ===
    "brain_write": {
        "description": "Brain write fallback chain",
        "steps": [
            {
                "name": "sqlite_write",
                "tool": "SQLite INSERT",
                "description": "Write to SQLite database",
            },
            {
                "name": "markdown_append",
                "tool": "Append to markdown file",
                "description": "Write to markdown files",
            },
            {
                "name": "temp_file",
                "tool": "Write to /tmp/fenrir/findings.json",
                "description": "Write to temporary JSON file",
            },
            {
                "name": "skip_and_log",
                "tool": "Log failure, continue scan",
                "description": "Record the failure but don't abort",
            },
        ],
        "fallback_order": [0, 1, 2, 3],
    },

    "llm_request": {
        "description": "LLM request fallback chain",
        "steps": [
            {
                "name": "tier_0_ollama",
                "tool": "Ollama local model",
                "description": "Local Ollama model (fast, free)",
            },
            {
                "name": "tier_1_deeps ek",
                "tool": "DeepSeek V3 via OpenRouter",
                "description": "Cloud cheap model",
            },
            {
                "name": "tier_2_claude",
                "tool": "Claude Sonnet via OpenRouter",
                "description": "Cloud strong model",
            },
            {
                "name": "tier_3_un censored",
                "tool": "Hermes 4 / Dolphin",
                "description": "Uncensored model",
            },
            {
                "name": "no_llm_fallback",
                "tool": "Use built-in agent logic",
                "description": "Run without LLM using hardcoded logic",
            },
        ],
        "fallback_order": [0, 1, 2, 3, 4],
    },

    # === SESSION MANAGEMENT ===
    "checkpoint_save": {
        "description": "Session checkpoint fallback",
        "steps": [
            {
                "name": "brain_checkpoint",
                "tool": "Save to ~/.fenrir/brain/checkpoints/",
                "description": "Save checkpoint to brain directory",
            },
            {
                "name": "state_file",
                "tool": "Save to ~/.fenrir/state.json",
                "description": "Save to main state file",
            },
            {
                "name": "emergency_save",
                "tool": "Save to /tmp/fenrir_emergency/",
                "description": "Emergency save to temp directory",
            },
            {
                "name": "skip",
                "tool": "Log and continue without checkpoint",
                "description": "Skip, continue scanning",
            },
        ],
        "fallback_order": [0, 1, 2, 3],
    },

    "tool_execution_failed": {
        "description": "Tool execution failure recovery",
        "steps": [
            {
                "name": "retry",
                "tool": "Retry the same tool call",
                "description": "Simple retry with same parameters",
            },
            {
                "name": "retry_with_timeout",
                "tool": "Retry with increased timeout",
                "description": "Retry with doubled timeout",
            },
            {
                "name": "alternative_tool",
                "tool": "Find alternative tool for same purpose",
                "description": "Use a different tool to achieve same goal",
            },
            {
                "name": "manual_approach",
                "tool": "Agent performs task manually",
                "description": "Agent uses its own reasoning and available tools",
            },
        ],
        "fallback_order": [0, 1, 2, 3],
    },
}


def get_fallback(chain_name: str) -> dict:
    """Get fallback chain by name."""
    return FALLBACK_CHAINS.get(chain_name, FALLBACK_CHAINS["tool_execution_failed"])


def get_next_fallback(chain_name: str, failed_step: int) -> dict | None:
    """Get the next fallback step after a failure."""
    chain = FALLBACK_CHAINS.get(chain_name)
    if not chain:
        return None

    order = chain["fallback_order"]
    current_idx = 0
    for i, step in enumerate(order):
        if step == failed_step:
            current_idx = i
            break

    if current_idx + 1 < len(order):
        next_step = order[current_idx + 1]
        return chain["steps"][next_step]

    return None


def main():
    print("Available fallback chains:")
    for name, chain in FALLBACK_CHAINS.items():
        print(f"  {name}: {chain['description']}")
        for i, step_idx in enumerate(chain["fallback_order"]):
            step = chain["steps"][step_idx]
            print(f"    [{i}] {step['name']}: {step['description']}")


if __name__ == "__main__":
    main()
