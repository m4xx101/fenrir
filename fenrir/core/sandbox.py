"""Docker sandboxing for secure tool execution in Fenrir."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class SandboxResult(BaseModel):
    """Result from sandboxed command execution."""
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    execution_time_s: float
    command: str
    tool_name: str = ""


class SandboxConfig(BaseModel):
    """Configuration for a sandboxed execution."""
    image: str = "python:3.12-slim"
    timeout: int = 30
    max_output_bytes: int = 65536
    network_enabled: bool = False
    network_hosts: list[str] = Field(default_factory=list)
    max_memory_mb: int = 512
    max_cpu: float = 1.0
    read_only: bool = True
    writable_paths: list[str] = Field(default_factory=list)
    env_vars: dict[str, str] = Field(default_factory=dict)
    user: str = "nobody"


# ---------------------------------------------------------------------------
# Docker Sandbox
# ---------------------------------------------------------------------------

class DockerSandbox:
    """Runs commands in isolated Docker containers.

    Security constraints:
    - No default network access (explicit opt-in)
    - Read-only filesystem except /tmp and designated output dirs
    - CPU/memory limits via cgroups
    - 30-second default timeout
    - Full command audit logging
    - Non-root user execution
    """

    def __init__(self, config: SandboxConfig | None = None):
        self.config = config or SandboxConfig()
        self._docker_available: bool | None = None
        self._log_file = Path.home() / ".fenrir" / "logs" / "tool-execution.log"
        self._log_file.parent.mkdir(parents=True, exist_ok=True)

    def is_available(self) -> bool:
        """Check if Docker is available."""
        if self._docker_available is not None:
            return self._docker_available

        try:
            result = subprocess.run(
                ["docker", "info", "-f", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=10
            )
            self._docker_available = result.returncode == 0
            if self._docker_available:
                logger.info(f"Docker sandbox available: {result.stdout.strip()}")
            else:
                logger.warning(f"Docker sandbox not available: {result.stderr[:200]}")
            return self._docker_available
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("Docker not found in PATH")
            self._docker_available = False
            return False

    def execute(
        self,
        command: str | list[str],
        tool_name: str = "",
        config: SandboxConfig | None = None,
        work_dir: str | None = None,
        input_files: dict[str, str] | None = None,
    ) -> SandboxResult:
        """Execute a command inside a Docker sandbox.

        Args:
            command: Shell command or command list.
            tool_name: Name of the tool being executed (for logging).
            config: Sandbox constraints. Defaults to self.config.
            work_dir: Working directory inside the container.
            input_files: Dict of {container_path: content} to mount as files.
        """
        if not self.is_available():
            logger.warning("Docker sandbox not available, falling back to direct execution")
            return self._execute_direct(command, tool_name)

        cfg = config or self.config
        container_name = f"fenrir-sandbox-{uuid.uuid4().hex[:8]}"

        # Build docker run command
        docker_cmd = self._build_docker_run(
            container_name, cfg, work_dir, input_files
        )

        # Append the actual command
        if isinstance(command, list):
            docker_cmd.extend(command)
        else:
            docker_cmd.extend(["/bin/sh", "-c", command])

        # Audit log
        self._audit_log(tool_name, command, cfg)

        start_time = datetime.utcnow()

        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=cfg.timeout,
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds()
            stdout = result.stdout[:cfg.max_output_bytes] if result.stdout else ""
            stderr = result.stderr[:cfg.max_output_bytes] if result.stderr else ""

            logger.info(
                f"[sandbox:{tool_name}] exit={result.returncode}, "
                f"time={execution_time:.1f}s, "
                f"stdout={len(stdout)}B, stderr={len(stderr)}B"
            )

            # Cleanup container
            self._cleanup_container(container_name)

            return SandboxResult(
                success=result.returncode == 0,
                exit_code=result.returncode,
                stdout=stdout,
                stderr=stderr,
                execution_time_s=execution_time,
                command=str(command),
                tool_name=tool_name,
            )

        except subprocess.TimeoutExpired:
            logger.error(f"[sandbox:{tool_name}] Command timed out after {cfg.timeout}s")
            self._cleanup_container(container_name, force=True)

            return SandboxResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {cfg.timeout}s",
                execution_time_s=cfg.timeout,
                command=str(command),
                tool_name=tool_name,
            )

        except Exception as e:
            logger.error(f"[sandbox:{tool_name}] Sandbox error: {e}")
            self._cleanup_container(container_name, force=True)

            return SandboxResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time_s=0,
                command=str(command),
                tool_name=tool_name,
            )

    def _build_docker_run(
        self,
        container_name: str,
        config: SandboxConfig,
        work_dir: str | None,
        input_files: dict[str, str] | None,
    ) -> list[str]:
        """Build the docker run command with all security flags."""
        cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--user", config.user,
        ]

        # Resource limits
        cmd.extend(["--memory", f"{config.max_memory_mb}m"])
        cmd.extend(["--cpus", str(config.max_cpu)])

        # Security hardening
        cmd.extend(["--security-opt", "no-new-privileges=true"])
        cmd.extend(["--read-only"])
        if not config.network_enabled:
            cmd.extend(["--network", "none"])
        else:
            # Restrict to specific hosts if specified
            if config.network_hosts:
                for host in config.network_hosts:
                    # For host-level restrictions, we'd use --network=custom
                    # For simplicity, just allow all network access when enabled
                    pass

        # Writable tmpfs mounts for /tmp and /var/tmp
        cmd.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=50m"])
        cmd.extend(["--tmpfs", "/var/tmp:rw,noexec,nosuid,size=20m"])

        # Additional writable paths
        for wp in config.writable_paths:
            cmd.extend(["--mount", f"type=tmpfs,destination={wp}"])

        # Input files (via bind mount)
        if input_files:
            tmp_base = tempfile.mkdtemp(prefix="fenrir-sandbox-")
            for container_path, content in input_files.items():
                host_path = Path(tmp_base) / f"input_{uuid.uuid4().hex[:8]}"
                host_path.write_text(content)
                cmd.extend(["-v", f"{host_path}:{container_path}:ro"])

        # Working directory
        if work_dir:
            cmd.extend(["-w", work_dir])

        # Environment variables
        for key, value in config.env_vars.items():
            cmd.extend(["-e", f"{key}={value}"])

        # Image
        cmd.append(config.image)

        return cmd

    def _cleanup_container(self, container_name: str, force: bool = False) -> None:
        """Ensure the container is removed."""
        try:
            kill_flag = "--force" if force else ""
            subprocess.run(
                ["docker", "rm", kill_flag, container_name],
                capture_output=True, text=True, timeout=5
            )
        except Exception:
            pass  # Container may already be removed (--rm flag)

    def _execute_direct(
        self, command: str | list[str], tool_name: str = ""
    ) -> SandboxResult:
        """Fallback: execute directly without Docker (less secure)."""
        logger.warning(f"[sandbox:{tool_name}] Running without Docker sandbox")

        if isinstance(command, list):
            cmd_str = " ".join(command)
            proc_cmd = command
        else:
            cmd_str = command
            proc_cmd = ["/bin/sh", "-c", command]

        self._audit_log(tool_name, cmd_str, self.config)

        start_time = datetime.utcnow()
        try:
            result = subprocess.run(
                proc_cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )
            execution_time = (datetime.utcnow() - start_time).total_seconds()

            return SandboxResult(
                success=result.returncode == 0,
                exit_code=result.returncode,
                stdout=result.stdout[:self.config.max_output_bytes],
                stderr=result.stderr[:self.config.max_output_bytes],
                execution_time_s=execution_time,
                command=cmd_str,
                tool_name=tool_name,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {self.config.timeout}s",
                execution_time_s=self.config.timeout,
                command=cmd_str,
                tool_name=tool_name,
            )

    def _audit_log(self, tool_name: str, command: Any, config: SandboxConfig) -> None:
        """Log command execution for audit trail."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": tool_name,
            "command": str(command),
            "sandboxed": self.is_available(),
            "image": config.image,
            "network": config.network_enabled,
        }

        try:
            with open(self._log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass  # Don't fail execution for logging errors

    def pull_image(self, image: str) -> bool:
        """Pull a Docker image for sandbox use."""
        try:
            result = subprocess.run(
                ["docker", "pull", image],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                logger.info(f"Pulled Docker image: {image}")
                return True
            else:
                logger.error(f"Failed to pull {image}: {result.stderr[:200]}")
                return False
        except Exception as e:
            logger.error(f"Failed to pull image {image}: {e}")
            return False


# ---------------------------------------------------------------------------
# Security Scanner
# ---------------------------------------------------------------------------

class ScriptSecurityScanner:
    """Scan Python scripts for dangerous operations before execution."""

    DANGEROUS_PATTERNS = [
        ("eval(", "Python eval() - arbitrary code execution"),
        ("exec(", "Python exec() - arbitrary code execution"),
        ("__import__(", "Dynamic import - potential code injection"),
        ("os.system(", "OS command execution via os.system"),
        ("subprocess.call(", "Subprocess execution"),
        ("subprocess.Popen(", "Subprocess execution"),
        ("shutil.rmtree(", "Recursive directory deletion"),
        ("shutil.rmtree", "Recursive directory deletion"),
        ("os.remove(", "File deletion"),
        ("os.unlink(", "File deletion"),
        ("rm -rf", "Recursive forced deletion"),
        ("chmod", "File permission modification"),
        ("chmod ", "File permission modification"),
    ]

    @classmethod
    def scan_script(cls, script_path: str) -> dict[str, Any]:
        """Scan a script for dangerous operations."""
        results = {
            "path": script_path,
            "dangerous_operations": [],
            "risk_level": "low",
            "safe_to_run": True,
        }

        try:
            content = Path(script_path).read_text()
        except Exception as e:
            results["error"] = str(e)
            results["safe_to_run"] = False
            return results

        for pattern, description in cls.DANGEROUS_PATTERNS:
            if pattern in content:
                results["dangerous_operations"].append({
                    "pattern": pattern,
                    "description": description,
                    "line_numbers": [
                        i + 1 for i, line in enumerate(content.split("\n"))
                        if pattern in line
                    ],
                })

        # Calculate risk
        count = len(results["dangerous_operations"])
        if count == 0:
            results["risk_level"] = "low"
            results["safe_to_run"] = True
        elif count <= 2:
            results["risk_level"] = "medium"
            results["safe_to_run"] = True
        else:
            results["risk_level"] = "high"
            results["safe_to_run"] = False

        return results
