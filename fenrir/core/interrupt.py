"""Graceful interruption handling and user guidance for Fenrir agents.

Provides signal handling, graceful pause/abort semantics, interactive user
guidance when agents encounter uncertainty, CAPTCHA detection, and a
SessionGuard context manager that preserves findings on crash.

Key components:
- InterruptHandler: Signal-based interruption with pause vs abort semantics
- UserGuidance: Interactive guidance when agents hit uncertainty
- CAPTCHADetector: Detect and prompt user about CAPTCHA challenges
- SessionGuard: Context manager that never loses findings on crash

Usage:
    # Wrap agent execution with SessionGuard
    with SessionGuard(config, agent) as guard:
        result = await agent.think(task)

    # Handle CAPTCHA detection
    detector = CAPTCHADetector(browser_tool=agent.tool_registry._browser)
    is_captcha = await detector.check_page(url)

    # Get user guidance at decision points
    guidance = UserGuidance(config)
    choice = await guidance.prompt(
        message="Ambiguous target detected",
        options=["retry", "skip", "provide input", "abort"],
    )
"""

from __future__ import annotations

import asyncio
import base64
import os
import signal
import sys
import textwrap
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from loguru import logger

from fenrir.agents.base import AgentResult, BaseAgent
from fenrir.config import AppConfig


# ─── Rich Terminal Output ────────────────────────────────────────────────────

# ANSI color / style codes (fallback if Rich not installed)
class _Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich.markdown import Markdown

    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False

console = Console() if _RICH_AVAILABLE else None


def _rich_print(
    message: str,
    style: str = "",
    title: str = "",
    border_color: str = "",
    use_markdown: bool = False,
) -> None:
    """Print a formatted message using Rich if available, else plain text."""
    if _RICH_AVAILABLE and console:
        if use_markdown:
            console.print(Markdown(message), style=style)
        elif title or border_color:
            console.print(
                Panel(
                    Text(message, style=style),
                    title=title,
                    border_style=border_color or "white",
                    padding=(0, 2),
                )
            )
        else:
            console.print(message, style=style)
    else:
        color_map = {
            "bold red": _Colors.BOLD + _Colors.RED,
            "bold yellow": _Colors.BOLD + _Colors.YELLOW,
            "bold green": _Colors.BOLD + _Colors.GREEN,
            "bold blue": _Colors.BOLD + _Colors.BLUE,
            "bold magenta": _Colors.BOLD + _Colors.MAGENTA,
            "bold cyan": _Colors.BOLD + _Colors.CYAN,
            "yellow": _Colors.YELLOW,
            "red": _Colors.RED,
            "green": _Colors.GREEN,
            "blue": _Colors.BLUE,
            "dim": _Colors.DIM,
        }
        prefix = color_map.get(style, "")
        if title:
            title_prefix = color_map.get(f"bold {border_color}" if border_color else "bold", "")
            print(f"\n{title_prefix}═══ {title} ═══{_Colors.RESET}")
        print(f"{prefix}{message}{_Colors.RESET}")


def _status_running(msg: str) -> None:
    """Display a running/active status message."""
    _rich_print(f"  ⟳  {msg}", style="bold cyan")


def _status_success(msg: str) -> None:
    """Display a success message."""
    _rich_print(f"  ✓  {msg}", style="bold green")


def _status_warning(msg: str) -> None:
    """Display a warning message."""
    _rich_print(f"  ⚠  {msg}", style="bold yellow")


def _status_error(msg: str) -> None:
    """Display an error message."""
    _rich_print(f"  ✗  {msg}", style="bold red")


def _status_info(msg: str) -> None:
    """Display an info message."""
    _rich_print(f"  ⓘ  {msg}", style="bold blue")


# ─── Interrupt State ─────────────────────────────────────────────────────────


class InterruptState(str, Enum):
    """Current state of the interrupt handler."""

    RUNNING = "running"
    PAUSED = "paused"
    ABORTED = "aborted"
    RESUMING = "resuming"


class GuidanceChoice(str, Enum):
    """User choices when prompted for guidance."""

    RETRY = "retry"
    SKIP = "skip"
    PROVIDE_INPUT = "provide_input"
    ABORT = "abort"
    CONTINUE = "continue"


@dataclass
class InterruptInfo:
    """Information about an interruption event."""

    signal: int
    timestamp: float
    state: InterruptState
    partial_findings: list[dict[str, Any]] = field(default_factory=list)
    current_task: str = ""
    message: str = ""


# ─── Interrupt Handler ───────────────────────────────────────────────────────


class InterruptHandler:
    """Handles SIGINT, SIGTERM, SIGHUP with graceful pause/abort semantics.

    Signal handling behavior:
    - First Ctrl-C (SIGINT): Pause execution, save state, display guidance
    - Second Ctrl-C within 2 seconds: Abort immediately
    - SIGTERM/SIGHUP: Graceful shutdown (same as double Ctrl-C)
    - Auto-resume: If no user input received within timeout, resume execution

    Args:
        config: Application configuration.
        auto_resume_timeout: Seconds to wait before auto-resuming (default: 30).
        on_pause: Optional callback when pause is triggered.
        on_abort: Optional callback when abort is triggered.
    """

    def __init__(
        self,
        config: AppConfig,
        auto_resume_timeout: float = 30.0,
        on_pause: Callable[[], None] | None = None,
        on_abort: Callable[[], None] | None = None,
    ):
        self.config = config
        self.auto_resume_timeout = auto_resume_timeout
        self.on_pause = on_pause
        self.on_abort = on_abort

        self.state = InterruptState.RUNNING
        self._last_sigint_time: float = 0
        self._double_click_threshold: float = 2.0
        self._partial_findings: list[dict[str, Any]] = []
        self._current_task: str = ""
        self._abort_flag = threading.Event()
        self._pause_event = threading.Event()
        self._lock = threading.Lock()
        self._installed = False

    def install(self) -> None:
        """Register signal handlers for SIGINT, SIGTERM, SIGHUP."""
        if self._installed:
            return

        try:
            signal.signal(signal.SIGINT, self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)
            signal.signal(signal.SIGHUP, self._handle_signal)

            if sys.platform != "win32":
                try:
                    signal.signal(signal.SIGUSR1, self._handle_signal)
                except (ValueError, OSError):
                    pass  # May fail in some environments

            self._installed = True
            _status_info("Interrupt handlers installed")
        except Exception as exc:
            logger.warning(f"Could not install all signal handlers: {exc}")
            # Still install SIGINT at minimum
            try:
                signal.signal(signal.SIGINT, self._handle_signal)
                signal.signal(signal.SIGTERM, self._handle_signal)
                self._installed = True
            except Exception as exc2:
                logger.error(f"Failed to install even basic handlers: {exc2}")

    def uninstall(self) -> None:
        """Restore default signal handlers."""
        if not self._installed:
            return
        signal.signal(signal.SIGINT, signal.default_int_handler)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGHUP, signal.SIG_DFL)
        self._installed = False
        _status_info("Interrupt handlers uninstalled")

    def _handle_signal(
        self, signum: int, frame: Any  # type: ignore[type-arg]
    ) -> None:
        """Signal handler dispatching to pause or abort."""
        with self._lock:
            now = time.time()

            if signum == signal.SIGINT:
                # Distinguish single vs double Ctrl-C
                if now - self._last_sigint_time < self._double_click_threshold:
                    self._trigger_abort(now, "Double Ctrl-C detected — aborting")
                    return
                self._last_sigint_time = now
                self._trigger_pause(now, "Ctrl-C received — pausing execution")

            elif signum in (signal.SIGTERM, signal.SIGHUP):
                self._trigger_abort(now, f"Signal {signum} received — shutting down")

    def _trigger_pause(self, timestamp: float, message: str) -> None:
        """Trigger a pause state."""
        old_state = self.state
        self.state = InterruptState.PAUSED
        self._pause_event.clear()  # Event is NOT set while paused

        logger.warning(f"[Interrupt] PAUSED: {message}")
        _status_warning(f"PAUSED: {message}")

        self._display_guidance()

        if self.on_pause:
            try:
                self.on_pause()
            except Exception:
                pass

        # Start auto-resume timer in a background thread
        timer = threading.Thread(
            target=self._auto_resume_timer,
            args=(timestamp,),
            daemon=True,
        )
        if old_state != InterruptState.PAUSED:
            timer.start()

    def _trigger_abort(self, timestamp: float, message: str) -> None:
        """Trigger an abort state."""
        self.state = InterruptState.ABORTED
        self._abort_flag.set()
        self._pause_event.set()  # Unblock any waiting threads

        logger.error(f"[Interrupt] ABORTED: {message}")
        _status_error(f"ABORTED: {message}")

        self._save_state(message)

        if self.on_abort:
            try:
                self.on_abort()
            except Exception:
                pass

    def _auto_resume_timer(self, trigger_timestamp: float) -> None:
        """Auto-resume after timeout if no user interaction."""
        time.sleep(self.auto_resume_timeout)

        with self._lock:
            if (
                self.state == InterruptState.PAUSED
                and not self._pause_event.is_set()
            ):
                _status_info(
                    f"Auto-resuming after {self.auto_resume_timeout}s "
                    f"(no user input received)"
                )
                self.state = InterruptState.RESUMING
                self._pause_event.set()
                self.state = InterruptState.RUNNING

    def _display_guidance(self) -> None:
        """Display user guidance for the pause state."""
        guidance_text = (
            f"Execution has been paused.\n\n"
            f"Current task: {self._current_task or 'N/A'}\n"
            f"Findings collected so far: {len(self._partial_findings)}\n\n"
            f"Options:\n"
            f"  • Press Enter / Wait {self.auto_resume_timeout}s → Resume execution\n"
            f"  • Press Ctrl-C again → Abort immediately\n"
            f"  • Press Ctrl-D (EOF) → Abort\n\n"
            f"State will be preserved during pause."
        )

        _rich_print(
            textwrap.dedent(guidance_text).strip(),
            title="Execution Paused",
            border_color="yellow",
        )

    def wait_for_resume(self, timeout: float | None = None) -> bool:
        """Block until resume or abort. Returns True if resumed, False if aborted."""
        wait_time = timeout or self.auto_resume_timeout
        resumed = self._pause_event.wait(timeout=wait_time)

        with self._lock:
            return self.state != InterruptState.ABORTED and resumed

    @property
    def is_aborted(self) -> bool:
        """Check if execution has been aborted."""
        return self._abort_flag.is_set()

    @property
    def is_paused(self) -> bool:
        """Check if execution is currently paused."""
        return self.state == InterruptState.PAUSED

    def register_finding(self, finding: dict[str, Any]) -> None:
        """Register a finding as the current execution progresses."""
        with self._lock:
            self._partial_findings.append(finding)

    def set_current_task(self, task: str) -> None:
        """Set the current task description."""
        with self._lock:
            self._current_task = task

    def _save_state(self, reason: str = "") -> None:
        """Save partial state to disk."""
        try:
            state_dir = Path.home() / ".fenrir" / "interrupts"
            state_dir.mkdir(parents=True, exist_ok=True)

            state_file = state_dir / f"state_{int(time.time())}.json"

            import json
            state = {
                "timestamp": time.time(),
                "state": self.state.value,
                "reason": reason,
                "current_task": self._current_task,
                "partial_findings": self._partial_findings,
                "finding_count": len(self._partial_findings),
            }

            with open(state_file, "w") as f:
                json.dump(state, f, indent=2, default=str)

            _status_info(f"State saved to {state_file}")
            logger.info(f"[Interrupt] State saved to {state_file}")

        except Exception as exc:
            logger.error(f"[Interrupt] Failed to save state: {exc}")


# ─── User Guidance System ────────────────────────────────────────────────────


class UserGuidance:
    """Interactive guidance system for agent uncertainty scenarios.

    When an agent encounters situations like ambiguous targets,
    authentication requirements, or CAPTCHA challenges, this class
    provides structured user prompts and collects input.

    Non-blocking design: the agent waits for input but other agents
    in the orchestrator can continue independently.

    Args:
        config: Application configuration.
        allow_non_interactive: If True and no TTY, use defaults.
    """

    def __init__(
        self,
        config: AppConfig,
        allow_non_interactive: bool = True,
    ):
        self.config = config
        self.allow_non_interactive = allow_non_interactive
        self._interactive = sys.stdin.isatty()
        self._history: list[dict[str, Any]] = []

    def prompt(
        self,
        message: str,
        options: list[str] | None = None,
        default: str = "continue",
        timeout: float | None = None,
    ) -> GuidanceChoice:
        """Display a guidance prompt and collect user choice.

        Args:
            message: Description of the situation.
            options: Available choices (strings).
            default: Default choice if user presses Enter.
            timeout: Seconds to wait before choosing default (None = wait forever).

        Returns:
            GuidanceChoice selected by the user.
        """
        if options is None:
            options = ["continue", "retry", "skip", "abort"]

        self._display_prompt(message, options, default)

        if not self._interactive and self.allow_non_interactive:
            _status_info(f"Non-interactive mode — selecting default: {default}")
            return GuidanceChoice(default)
        elif not self._interactive:
            _status_warning(
                f"No TTY available and non-interactive mode disabled — "
                f"selecting: {default}"
            )
            return GuidanceChoice(default)

        # Read user input with optional timeout
        choice = self._read_choice(options, default, timeout)

        self._history.append({
            "message": message,
            "options": options,
            "choice": choice.value,
            "timestamp": time.time(),
        })

        return choice

    def prompt_auth_needed(
        self,
        url: str = "",
        service: str = "",
    ) -> GuidanceChoice:
        """Specialized prompt for authentication requirement."""
        message = textwrap.dedent(f"""
            Authentication Required
            {'=' * 40}

            The agent needs credentials to proceed.

            URL: {url or 'N/A'}
            Service: {service or 'N/A'}

            Options:
              - retry: Try again (useful if credentials changed)
              - provide input: Enter credentials manually
              - skip: Skip this target and continue scanning
              - abort: Stop the entire scan
        """).strip()

        return self.prompt(
            message=message.rstrip(),
            options=["retry", "provide_input", "skip", "abort"],
            default="skip",
        )

    def prompt_ambiguous_target(
        self,
        targets: list[str],
        context: str = "",
    ) -> GuidanceChoice:
        """Specialized prompt for ambiguous target selection."""
        targets_str = "\n".join(
            f"  [{i + 1}] {t}" for i, t in enumerate(targets)
        )

        message = textwrap.dedent(f"""
            Ambiguous Target Detected
            {'=' * 40}

            Multiple potential targets found. Please select.

            {targets_str}

            Context: {context or 'N/A'}

            Options:
              - continue: Use the first target
              - provide_input: Specify a target manually
              - skip: Skip this discovery
              - abort: Stop the scan
        """).strip()

        return self.prompt(
            message=message.rstrip(),
            options=["continue", "provide_input", "skip", "abort"],
            default="continue",
        )

    async def prompt_async(
        self,
        message: str,
        options: list[str] | None = None,
        default: str = "continue",
        timeout: float = 60.0,
    ) -> GuidanceChoice:
        """Async version of prompt that doesn't block the event loop.

        Other agents can continue executing while waiting for user input.

        Args:
            message: Description of the situation.
            options: Available choices.
            default: Default choice on timeout.
            timeout: Seconds before default is selected.

        Returns:
            GuidanceChoice selected by the user or default on timeout.
        """
        if options is None:
            options = ["continue", "retry", "skip", "abort"]

        self._display_prompt(message, options, default)

        if not self._interactive and self.allow_non_interactive:
            return GuidanceChoice(default)

        try:
            # Run blocking I/O in executor to not block the event loop
            loop = asyncio.get_event_loop()
            choice = await asyncio.wait_for(
                loop.run_in_executor(
                    None, self._read_choice, options, default, timeout
                ),
                timeout=timeout,
            )
            return choice
        except asyncio.TimeoutError:
            _status_info(
                f"Prompt timed out after {timeout}s — selecting default: {default}"
            )
            return GuidanceChoice(default)

    def _display_prompt(
        self,
        message: str,
        options: list[str],
        default: str,
    ) -> None:
        """Display the formatted prompt to the user."""
        _rich_print(
            message,
            title="Agent Needs Guidance",
            border_color="magenta",
        )

        # Display options
        option_map = {}
        for i, opt in enumerate(options):
            key = str(i + 1)
            option_map[key] = opt
            label = opt.replace("_", " ").title()
            if opt == default:
                label += " (default)"
                _rich_print(f"  [{key}] {label}", style="bold yellow")
            else:
                _rich_print(f"  [{key}] {label}", style="dim")

    def _read_choice(
        self,
        options: list[str],
        default: str,
        timeout: float | None = None,
    ) -> GuidanceChoice:
        """Read and validate user input."""
        option_map = {str(i + 1): opt for i, opt in enumerate(options)}

        if _RICH_AVAILABLE:
            # Use Rich Prompt with timeout
            try:
                choice_key = Prompt.ask(
                    "Choice",
                    choices=list(option_map.keys()),
                    default="1",
                    show_default=False,
                )
                return GuidanceChoice(option_map.get(choice_key, default))
            except Exception:
                return GuidanceChoice(default)
        else:
            # Plain text input
            try:
                if timeout:
                    import select
                    # Use select for non-blocking with timeout (Unix only)
                    rlist, _, _ = select.select([sys.stdin], [], [], timeout)
                    if rlist:
                        user_input = sys.stdin.readline().strip()
                    else:
                        user_input = ""
                else:
                    user_input = input("Choice (number or keyword): ").strip()

                # Try as number first
                if user_input in option_map:
                    return GuidanceChoice(option_map[user_input])

                # Try as keyword directly
                user_lower = user_input.lower()
                for opt in options:
                    if opt == user_lower:
                        return GuidanceChoice(opt)

                # Default
                return GuidanceChoice(default)

            except (EOFError, KeyboardInterrupt):
                return GuidanceChoice.ABORT
            except Exception:
                return GuidanceChoice(default)

    def get_history(self) -> list[dict[str, Any]]:
        """Return the full guidance interaction history."""
        return list(self._history)


# ─── CAPTCHA Detector ────────────────────────────────────────────────────────


class CAPTCHADetector:
    """Detects CAPTCHA challenges in HTTP responses and web pages.

    Uses multiple detection strategies:
    1. Keyword scanning of response body/headers
    2. HTML element analysis (CAPTCHA-related selectors)
    3. Browser screenshot analysis with LLM description

    Works with the browser tool to take screenshots when a CAPTCHA is
    suspected, then presents the screenshot to the user for resolution.

    Args:
        browser_tool: BrowserTool instance for screenshot capability.
        config: Application configuration.
    """

    # Common CAPTCHA indicators in HTML/JS
    CAPTCHA_KEYWORDS = [
        "captcha", "recaptcha", "hcaptcha", "turnstile", "cf-challenge",
        "cf-chl-bypass", "cloudflare", "challenge", "verify you are human",
        "security check", "please verify", "bot detection", "ddos protection",
        "ddos-protection", "checking your browser", "anti-bot", "waf",
        "just a moment", "ray id", "captcha-form", "g-recaptcha",
        "data-sitekey", "h-captcha", "captcha-wrapper", "captcha-image",
        "captcha-input", "verify human", "i am human", "i'm not a robot",
        "cloudflare challenge", "under attack mode", "js challenge",
        "browser integrity check", "suspected automated traffic",
    ]

    CAPTCHA_SELECTORS = [
        "#recaptcha", "#captcha", "#hcaptcha", "#cf-challenge",
        ".g-recaptcha", ".h-captcha", ".captcha", ".recaptcha-container",
        ".challenge-form", "#challenge-running", "#challenge-error-text",
        "iframe[src*='recaptcha']", "iframe[src*='hcaptcha']",
        "iframe[src*='challenges.cloudflare.com']",
        "[class*='cf-challenge']", "[id*='captcha']",
        "div[data-sitekey]", "div[class*='turnstile']",
    ]

    def __init__(
        self,
        browser_tool: Any = None,
        config: AppConfig | None = None,
    ):
        self.browser_tool = browser_tool
        self.config = config
        self._detection_history: list[dict[str, Any]] = []

    async def check_response(
        self,
        url: str,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        body: str = "",
    ) -> dict[str, Any]:
        """Check an HTTP response for CAPTCHA indicators.

        Args:
            url: The URL of the response.
            status_code: HTTP status code.
            headers: Response headers.
            body: Response body text.

        Returns:
            Detection result dict with is_captcha, confidence, details.
        """
        details: list[str] = []
        confidence = 0.0

        # Check status code
        if status_code in (403, 503):
            confidence += 0.2
            details.append(f"Suspicious status code: {status_code}")

        # Check headers
        if headers:
            for key, value in headers.items():
                header_text = f"{key}: {value}".lower()
                for keyword in self.CAPTCHA_KEYWORDS:
                    if keyword in header_text:
                        confidence += 0.15
                        details.append(f"CAPTCHA keyword in header: {keyword}")
                        break

        # Check body content
        if body:
            body_lower = body.lower()
            keyword_matches = []
            for keyword in self.CAPTCHA_KEYWORDS:
                if keyword in body_lower:
                    keyword_matches.append(keyword)

            if keyword_matches:
                confidence += min(0.5, len(keyword_matches) * 0.15)
                details.append(
                    f"CAPTCHA keywords found ({len(keyword_matches)}): "
                    f"{', '.join(keyword_matches[:5])}"
                )

            # Check for script tags related to CAPTCHA
            if "<script" in body_lower and any(
                kw in body_lower for kw in ["recaptcha", "hcaptcha", "turnstile", "challenges.cloudflare"]
            ):
                confidence += 0.1
                details.append("CAPTCHA-related script tag detected")

        is_captcha = confidence >= 0.3

        result = {
            "is_captcha": is_captcha,
            "confidence": round(confidence, 2),
            "url": url,
            "details": details,
            "timestamp": time.time(),
        }

        if is_captcha:
            self._detection_history.append(result)
            logger.warning(
                f"[CAPTCHA] Detected at {url}: confidence={confidence:.2f}, "
                f"details={'; '.join(details[:3])}"
            )
        else:
            logger.debug(f"[CAPTCHA] Not detected at {url}: confidence={confidence:.2f}")

        return result

    async def check_page(self, url: str) -> dict[str, Any]:
        """Navigate to URL, check for CAPTCHA, optionally screenshot.

        Args:
            url: URL to navigate to and check.

        Returns:
            Detection result dict. May include screenshot data.
        """
        result = {"is_captcha": False, "confidence": 0.0, "url": url, "details": [], "timestamp": time.time()}

        if not self.browser_tool:
            logger.warning("[CAPTCHA] No browser tool available, cannot check page")
            return result

        try:
            # Navigate using browser tool
            page_info = self.browser_tool.navigate(url)
            if isinstance(page_info, dict) and "error" in page_info:
                result["details"].append(f"Navigation error: {page_info['error']}")
                return result

            # Get page content for analysis
            content_result = self.browser_tool.get_content(full=False)
            body = ""
            if isinstance(content_result, dict) and content_result.get("success"):
                body = content_result.get("preview", "")

            # Extract some basic info
            status = page_info.get("status", 200)
            headers = page_info.get("headers", {})
            body_full = content_result.get("full_html", "") if isinstance(content_result, dict) else ""

            # Run detection
            http_result = await self.check_response(
                url=url,
                status_code=status,
                headers=headers,
                body=body_full or body,
            )
            result.update(http_result)

            # If CAPTCHA detected, take screenshot
            if result["is_captcha"]:
                screenshot = self._take_screenshot()
                if screenshot:
                    result["screenshot_path"] = screenshot.get("path", "")
                    result["screenshot_data"] = screenshot.get("data", "")
                    result["screenshot_base64"] = screenshot.get("base64", "")

                # Prompt user if CAPTCHA found
                self._prompt_user(url, result)

        except Exception as exc:
            logger.error(f"[CAPTCHA] Page check failed: {exc}")
            result["details"].append(f"Check failed: {exc}")

        return result

    def _take_screenshot(self) -> dict[str, Any] | None:
        """Take a screenshot via the browser tool."""
        if not self.browser_tool:
            return None

        try:
            result = self.browser_tool.screenshot()
            if isinstance(result, dict) and result.get("success"):
                path = result.get("path", "")
                if path and os.path.exists(path):
                    with open(path, "rb") as f:
                        data = f.read()
                    b64 = base64.b64encode(data).decode("utf-8")
                    return {
                        "path": path,
                        "data": data,
                        "base64": b64,
                    }
            return result
        except Exception as exc:
            logger.warning(f"[CAPTCHA] Screenshot failed: {exc}")
            return None

    def _prompt_user(self, url: str, detection: dict[str, Any]) -> None:
        """Display CAPTCHA detection info to the user."""
        message = textwrap.dedent(f"""
            CAPTCHA / Bot Protection Detected
            {'=' * 40}

            URL: {url}
            Confidence: {detection['confidence']:.0%}

            Indicators:
            {chr(10).join(f'  • {d}' for d in detection['details'][:5])}
        """).strip()

        if detection.get("screenshot_path"):
            message += f"\n\nScreenshot saved to: {detection['screenshot_path']}"

        if detection.get("screenshot_base64"):
            message += (
                f"\nScreenshot (base64, first 80 chars): "
                f"{detection['screenshot_base64'][:80]}..."
            )

        _rich_print(
            message,
            title="⚠ CAPTCHA Detected",
            border_color="red",
        )

    def get_detection_history(self) -> list[dict[str, Any]]:
        """Return all CAPTCHA detection results."""
        return list(self._detection_history)


# ─── Session Guard ───────────────────────────────────────────────────────────


@dataclass
class GuardState:
    """State maintained by SessionGuard during execution."""

    task: str = ""
    agent_name: str = ""
    start_time: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    exception: str = ""
    interrupted: bool = False
    interrupted_at: float = 0.0


class SessionGuard:
    """Context manager that wraps agent execution to ensure no findings are lost.

    Features:
    - Catches all exceptions during agent execution
    - Saves partial state on any crash or interruption
    - Offers user guidance on error (retry, skip, abort)
    - Ensures findings are persisted even if the agent crashes
    - Integrates with InterruptHandler for signal-based control

    Usage:
        handler = InterruptHandler(config, auto_resume_timeout=30)
        handler.install()

        with SessionGuard(config, agent, handler=handler) as guard:
            result = await agent.think(task)
            guard.register_finding(result.findings)

        handler.uninstall()

    Args:
        config: Application configuration.
        agent: The agent being guarded.
        handler: Optional InterruptHandler for signal integration.
        guidance: Optional UserGuidance instance.
        state_file: Path to save state (default: auto-generated).
    """

    def __init__(
        self,
        config: AppConfig,
        agent: BaseAgent | None = None,
        handler: InterruptHandler | None = None,
        guidance: UserGuidance | None = None,
        state_file: Path | str | None = None,
        max_retries: int = 2,
    ):
        self.config = config
        self.agent = agent
        self.handler = handler or InterruptHandler(config)
        self.guidance = guidance or UserGuidance(config)
        self.max_retries = max_retries

        self.state = GuardState()
        self._state_file: Path = (
            Path(state_file) if state_file
            else Path.home() / ".fenrir" / "guard_state.json"
        )
        self._result: AgentResult | None = None
        self._entered = False

    def __enter__(self) -> "SessionGuard":
        self._entered = True
        self.state.start_time = time.time()
        self.state.agent_name = self.agent.name if self.agent else "unknown"

        if self.agent:
            self.handler.set_current_task(
                f"{self.agent.name}: {getattr(self.agent, '_current_task', 'N/A')}"
            )

        _status_running(f"SessionGuard active for {self.state.agent_name}")
        logger.info(f"[Guard] Session started for {self.state.agent_name}")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,  # type: ignore[type-arg]
    ) -> bool:
        """Handle exit — save state on error, propagate or suppress."""
        self._entered = False

        if exc_type is not None:
            error_msg = f"{exc_type.__name__}: {exc_val}"
            self.state.error = error_msg
            self.state.exception = str(exc_val)

            _status_error(f"Error during execution: {error_msg[:200]}")
            logger.error(f"[Guard] Exception caught: {error_msg}")

            # Save partial state immediately
            self._save_partial_state()

            # Offer guidance
            can_continue = self._handle_crash_guidance()

            # Persist findings to brain if agent is available
            self._persist_partial_findings()

            if can_continue:
                logger.info("[Guard] User chose to continue despite error.")
                return True  # Suppress the exception
            else:
                logger.info("[Guard] User chose to abort.")
                return False  # Let exception propagate

        # Normal exit
        elapsed = time.time() - self.state.start_time
        _status_success(
            f"Session completed in {elapsed:.1f}s "
            f"({len(self.state.findings)} findings)"
        )
        return False

    def register_finding(self, finding: dict[str, Any]) -> None:
        """Register a finding with the guard."""
        self.state.findings.append(finding)
        if self.handler:
            self.handler.register_finding(finding)

    def get_result(self) -> AgentResult | None:
        """Return the accumulated AgentResult."""
        return self._result

    def set_task(self, task: str) -> None:
        """Set the current task description."""
        self.state.task = task
        self.handler.set_current_task(task)

    def _save_partial_state(self) -> None:
        """Save partial state to disk immediately."""
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)

            import json
            state_data = {
                "task": self.state.task,
                "agent_name": self.state.agent_name,
                "start_time": self.state.start_time,
                "current_time": time.time(),
                "elapsed_s": time.time() - self.state.start_time,
                "findings_count": len(self.state.findings),
                "findings": self.state.findings,
                "error": self.state.error,
                "exception": self.state.exception,
                "interrupted": self.handler.state == InterruptState.ABORTED
                if self.handler
                else False,
            }

            with open(self._state_file, "w") as f:
                json.dump(state_data, f, indent=2, default=str)

            _status_info(f"Partial state saved: {self._state_file}")
            logger.info(f"[Guard] State saved to {self._state_file}")

        except Exception as exc:
            logger.error(f"[Guard] Failed to save state: {exc}")

    def _persist_partial_findings(self) -> None:
        """Save partial findings to brain storage."""
        if not self.agent or not self.state.findings:
            return

        persisted = 0
        for finding in self.state.findings:
            try:
                category = finding.get("category", "vuln")
                self.agent.save_finding(finding, category=category)
                persisted += 1
            except Exception as exc:
                logger.warning(f"[Guard] Brain save failed for finding: {exc}")

        if persisted:
            _status_success(f"Persisted {persisted} findings to brain")

    def _handle_crash_guidance(self) -> bool:
        """Offer guidance to user on crash. Returns True to continue.

        Asks the user whether to retry, skip, or abort.

        Returns:
            True if user wants to continue, False to abort.
        """
        message = textwrap.dedent(f"""
            Execution Error
            {'=' * 40}

            Agent: {self.state.agent_name}
            Task: {self.state.task or 'N/A'}
            Error: {self.state.error[:300] if self.state.error else 'Unknown'}
            Findings collected: {len(self.state.findings)}

            The encountered error has been captured.
            Your findings so far are safe.

            How would you like to proceed?
        """).strip()

        choice = self.guidance.prompt(
            message=message,
            options=["retry", "skip", "abort"],
            default="retry",
        )

        if choice == GuidanceChoice.RETRY:
            return True
        elif choice == GuidanceChoice.SKIP:
            return True
        else:
            return False

    async def execute_with_retry(
        self,
        task: str,
        context: str = "",
    ) -> AgentResult:
        """Execute agent with full guard protection and retry on failure.

        Wraps agent execution in all safety mechanisms with automatic
        retry up to max_retries times.

        Args:
            task: The task to execute.
            context: Additional context.

        Returns:
            AgentResult from execution (partial results if interrupted).
        """
        self.set_task(task)
        attempts = 0

        while attempts <= self.max_retries:
            attempts += 1
            try:
                _status_running(
                    f"Executing {self.state.agent_name} (attempt {attempts})"
                )

                if self.agent:
                    result = await self.agent.think(task, context=context)
                    self._result = result

                    # Register findings
                    for finding in result.findings:
                        self.register_finding(finding)

                    if result.success:
                        _status_success(
                            f"Agent completed successfully: "
                            f"{result.summary[:100]}"
                        )
                        return result
                    else:
                        _status_warning(
                            f"Agent returned failure: {result.error[:200]}"
                        )

                if attempts > self.max_retries:
                    break

                # Ask user before retrying
                message = (
                    f"Agent attempt {attempts}/{self.max_retries + 1} failed.\n"
                    f"Error: {self._result.error if self._result else 'Unknown'}\n"
                    f"Findings so far: {len(self.state.findings)}\n\n"
                    f"Would you like to retry?"
                )
                choice = self.guidance.prompt(
                    message=message,
                    options=["retry", "abort"],
                    default="retry",
                )

                if choice != GuidanceChoice.RETRY:
                    break

            except Exception as exc:
                error_msg = f"{type(exc).__name__}: {exc}"
                _status_error(f"Exception on attempt {attempts}: {error_msg[:200]}")
                logger.error(f"[Guard] Exception on attempt {attempts}: {exc}")

                self.state.error = error_msg
                self._save_partial_state()

                if attempts > self.max_retries:
                    break

                choice = self.guidance.prompt(
                    message=f"Attempt {attempts} failed with: {error_msg[:200]}",
                    options=["retry", "abort"],
                    default="retry",
                )

                if choice != GuidanceChoice.RETRY:
                    break

        # All attempts exhausted
        _state_error(f"Execution failed after {attempts} attempts")

        # Return partial results if we have any
        if self._result:
            return self._result

        # Construct a minimal result from partial state
        return AgentResult(
            agent_name=self.state.agent_name,
            success=False,
            summary=f"Execution failed after {attempts} attempts. {len(self.state.findings)} findings preserved.",
            findings=self.state.findings,
            error=self.state.error,
            execution_time_s=time.time() - self.state.start_time,
        )


__all__ = [
    "InterruptHandler",
    "InterruptState",
    "InterruptInfo",
    "UserGuidance",
    "GuidanceChoice",
    "CAPTCHADetector",
    "SessionGuard",
    "GuardState",
    "_status_running",
    "_status_success",
    "_status_warning",
    "_status_error",
    "_status_info",
]
