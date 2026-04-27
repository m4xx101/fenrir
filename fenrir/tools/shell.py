"""Shell command wrapper with sandboxing."""

from __future__ import annotations

import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field

from fenrir.config import AppConfig


class ShellResult(BaseModel):
    """Result from shell command execution."""
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timed_out: bool = False
    truncated: bool = False


class ShellTool:
    """Shell command execution with sandboxing and output limits."""

    ALLOWED_COMMANDS = {
        "whois", "dig", "nslookup", "host", "ping", "traceroute",
        "curl", "wget", "nc", "nmap", "whatweb", "wafw00f",
        "ffuf", "gobuster", "dirb", "nikto", "sqlmap",
        "cat", "ls", "find", "grep", "wc", "head", "tail", "awk", "sed",
        "python3", "python", "bash", "sh",
        "echo", "printf", "env", "id", "uname", "hostname",
    }

    BLOCKED_PATTERNS = [
        "rm -rf /", "mkfs", "dd if=", ":(){:|:&};:",  # Dangerous patterns
        "/dev/sd", "/dev/hd",  # Block devices
        "chmod 777",  # Dangerous permissions
        "nohup", "&>/dev/null",  # Background processes
    ]

    def __init__(self, config: AppConfig | None = None):
        self.config = config
        self.max_output_bytes = 65536
        self.default_timeout = 30
        self.sandbox_enabled = True

        if config and hasattr(config, "tools"):
            self.max_output_bytes = config.tools.max_shell_output_bytes
            self.default_timeout = config.tools.default_timeout
            self.sandbox_enabled = config.tools.sandbox_enabled

    def _is_safe_command(self, command: str) -> tuple[bool, str]:
        """Check if command is safe to execute."""
        # Check blocked patterns
        for pattern in self.BLOCKED_PATTERNS:
            if pattern.lower() in command.lower():
                return False, f"Blocked pattern: {pattern}"

        # Extract base command
        parts = command.split()
        if not parts:
            return False, "Empty command"

        base_cmd = parts[0]

        # Check if command is in allowed list (if sandbox is enabled)
        if self.sandbox_enabled and base_cmd not in self.ALLOWED_COMMANDS:
            # Check common aliases and paths
            base_basename = Path(base_cmd).name
            if base_basename not in self.ALLOWED_COMMANDS:
                return False, f"Command not in allowed list: {base_cmd}"

        return True, ""

    def _sanitize_output(self, output: str, max_bytes: int | None = None) -> tuple[str, bool]:
        """Truncate output if too long."""
        limit = max_bytes or self.max_output_bytes
        if len(output.encode()) > limit:
            truncated = output.encode()[:limit].decode(errors="ignore")
            return truncated, True
        return output, False

    def execute(
        self,
        command: str,
        timeout: int | None = None,
        shell: bool = True,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Execute shell command with sandboxing.

        Args:
            command: Command to execute
            timeout: Timeout in seconds (overrides default)
            shell: Execute in shell (allows pipes, etc.)
            cwd: Working directory
            env: Environment variables
        """
        timeout = timeout or self.default_timeout

        # Safety check
        safe, reason = self._is_safe_command(command)
        if not safe:
            return {
                "command": command,
                "stdout": "",
                "stderr": f"Command blocked: {reason}",
                "exit_code": -1,
            }

        logger.info(f"Executing: {command}")

        # Use a temp dir for execution
        exec_cwd = cwd or tempfile.mkdtemp(prefix="fenrir_exec_")

        try:
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=exec_cwd,
                env=env,
            )

            stdout, truncated_out = self._sanitize_output(result.stdout)
            stderr, truncated_err = self._sanitize_output(result.stderr)

            shell_result = ShellResult(
                command=command,
                stdout=stdout,
                stderr=stderr,
                exit_code=result.returncode,
                timed_out=False,
                truncated=truncated_out or truncated_err,
            )

            logger.info(f"Command completed: exit={result.returncode}")
            return shell_result.model_dump()

        except subprocess.TimeoutExpired:
            shell_result = ShellResult(
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                exit_code=-1,
                timed_out=True,
            )
            logger.warning(f"Command timed out: {command}")
            return shell_result.model_dump()

        except Exception as e:
            return {
                "command": command,
                "stdout": "",
                "stderr": f"Execution error: {type(e).__name__}: {str(e)}",
                "exit_code": -1,
            }

    def run_script(
        self,
        script: str,
        language: str = "python3",
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Execute a script inline."""
        timeout = timeout or self.default_timeout * 2

        with tempfile.NamedTemporaryFile(
            suffix=f".{language}", mode="w", delete=False
        ) as f:
            f.write(script)
            f.flush()
            return self.execute(
                f"{language} {shlex.quote(f.name)}", timeout=timeout, shell=False
            )
