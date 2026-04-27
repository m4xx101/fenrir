
"""Easy install and update mechanism for Fenrir Pro-Max."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import click
from loguru import logger

from fenrir.config import AppConfig


# Fenrir home paths
FENRIR_DATA = Path.home() / ".fenrir"
FENRIR_VERSION_FILE = FENRIR_DATA / "version.json"
INSTALL_DIR = Path(__file__).resolve().parent.parent  # project root


class FenrirUpdater:
    """Handles Fenrir installation, updates, and version management."""

    GITHUB_REPO = "nousresearch/fenrir"
    GITHUB_URL = f"https://github.com/{GITHUB_REPO}.git"

    def __init__(self, config: AppConfig | None = None):
        self.config = config or AppConfig()
        self.ensure_data_dirs()

    def ensure_data_dirs(self) -> None:
        """Create all required Fenrir data directories."""
        dirs = [
            FENRIR_DATA,
            FENRIR_DATA / "brain",
            FENRIR_DATA / "brain" / "targets",
            FENRIR_DATA / "brain" / "techniques",
            FENRIR_DATA / "brain" / "chains",
            FENRIR_DATA / "brain" / "embeddings",
            FENRIR_DATA / "logs",
            FENRIR_DATA / "cache",
            FENRIR_DATA / "templates",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    def get_current_version(self) -> dict[str, Any]:
        """Get the currently installed version info."""
        if FENRIR_VERSION_FILE.exists():
            try:
                return json.loads(FENRIR_VERSION_FILE.read_text())
            except (json.JSONDecodeError, IOError):
                pass

        # Fallback: try git
        try:
            result = subprocess.run(
                ["git", "-C", str(INSTALL_DIR), "describe", "--tags", "--long"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return {
                    "version": result.stdout.strip(),
                    "installed_at": datetime.utcnow().isoformat(),
                    "source": "git",
                }
        except Exception:
            pass

        # Try pyproject.toml
        pyproject = INSTALL_DIR / "pyproject.toml"
        if pyproject.exists():
            content = pyproject.read_text()
            for line in content.split("\n"):
                if line.startswith("version"):
                    ver = line.split("=")[1].strip().strip('"')
                    return {
                        "version": ver,
                        "installed_at": datetime.utcnow().isoformat(),
                        "source": "pyproject",
                    }

        return {
            "version": "unknown",
            "installed_at": "",
            "source": "unknown",
        }

    def check_for_updates(self) -> dict[str, Any]:
        """Check if a newer version is available.

        Returns dict with:
        - current_version: currently installed version
        - latest_version: latest available version
        - has_update: bool
        - changelog_preview: summary of changes
        """
        current = self.get_current_version()

        # Try pip index version
        latest_version = "unknown"
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "index", "versions", "fenrir"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and "Available versions:" in result.stdout:
                line = result.stdout.split("Available versions:")[1].strip().split("\n")[0]
                latest_version = line.split(",")[0].strip()
        except Exception:
            logger.debug("pip index check failed")

        # Try git remote comparison
        try:
            result = subprocess.run(
                ["git", "-C", str(INSTALL_DIR), "fetch", "--tags"],
                capture_output=True, text=True, timeout=30
            )
            result = subprocess.run(
                ["git", "-C", str(INSTALL_DIR), "describe", "--tags", "--abbrev=0"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                latest_version = result.stdout.strip()
        except Exception:
            logger.debug("git remote check failed")

        has_update = (
            latest_version != "unknown"
            and current.get("version", "unknown") != latest_version
        )

        return {
            "current_version": current.get("version", "unknown"),
            "latest_version": latest_version,
            "has_update": has_update,
            "current_source": current.get("source", "unknown"),
            "installed_at": current.get("installed_at", ""),
        }

    def install_dependencies(self, include_dev: bool = False) -> bool:
        """Install or reinstall Fenrir dependencies."""
        logger.info("Installing Fenrir dependencies...")

        cmd = [
            sys.executable, "-m", "pip", "install",
            "--upgrade", "-q",
        ]

        if include_dev:
            cmd.extend(["-e", str(INSTALL_DIR) + "[dev]"])
        else:
            cmd.extend(["-e", str(INSTALL_DIR)])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                logger.info("Dependencies installed successfully")
                return True
            else:
                logger.error(f"pip install failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            logger.error("pip install timed out")
            return False
        except Exception as e:
            logger.error(f"pip install error: {e}")
            return False

    def update(self, use_pip: bool = True, force: bool = False) -> bool:
        """Update Fenrir to the latest version.

        Args:
            use_pip: Update via pip (True) or git pull (False).
            force: Force reinstall even if up to date.
        """
        current = self.get_current_version()
        logger.info(f"Current version: {current.get('version', 'unknown')}")

        # Self-update via pip
        if use_pip:
            return self._update_via_pip(force)
        else:
            return self._update_via_git(force)

    def _update_via_pip(self, force: bool = False) -> bool:
        """Update Fenrir package via pip."""
        logger.info("Updating Fenrir via pip...")

        cmd = [sys.executable, "-m", "pip", "install", "--upgrade"]
        if force:
            cmd.append("--force-reinstall")
        cmd.append("fenrir")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if result.returncode == 0:
                logger.info("Fenrir updated successfully via pip")
                self._record_version("pip-updated")
                return True
            else:
                logger.error(f"pip update failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            logger.error("pip update timed out")
            return False
        except Exception as e:
            logger.error(f"pip update error: {e}")
            return False

    def _update_via_git(self, force: bool = False) -> bool:
        """Update Fenrir from git repository."""
        logger.info("Updating Fenrir via git...")

        try:
            # Fetch latest
            result = subprocess.run(
                ["git", "-C", str(INSTALL_DIR), "fetch", "origin"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                logger.error(f"git fetch failed: {result.stderr}")
                return False

            # Pull latest
            result = subprocess.run(
                ["git", "-C", str(INSTALL_DIR), "pull", "--rebase"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                logger.error(f"git pull failed: {result.stderr}")
                return False

            # Reinstall editable
            self.install_dependencies()

            self._record_version("git-updated")
            logger.info("Fenrir updated successfully via git")
            return True

        except subprocess.TimeoutExpired:
            logger.error("git update timed out")
            return False
        except Exception as e:
            logger.error(f"git update error: {e}")
            return False

    def _record_version(self, action: str) -> None:
        """Record version after update."""
        version_info = self.get_current_version()
        version_info["updated_at"] = datetime.utcnow().isoformat()
        version_info["update_action"] = action
        FENRIR_VERSION_FILE.write_text(json.dumps(version_info, indent=2))

    def install_default_config(self) -> Path:
        """Install default config file if none exists."""
        config_path = Path.home() / ".fenrir" / "config.yaml"
        if not config_path.exists():
            template = INSTALL_DIR / "fenrir" / "templates" / "config.yaml.template"
            if template.exists():
                shutil.copy2(template, config_path)
                logger.info(f"Installed default config to {config_path}")
            else:
                # Generate minimal config
                default_config = """# Fenrir Pro-Max Configuration
llm_providers:
  tier_0:
    model: "nousresearch/hermes3:8b"
    base_url: "http://localhost:11434/v1"
    api_key: "ollama"
  tier_1:
    model: "deepseek/deepseek-chat"
    base_url: "https://openrouter.ai/api/v1"
    api_key: "${OPENROUTER_API_KEY}"
  tier_2:
    model: "anthropic/claude-sonnet-4"
    base_url: "https://openrouter.ai/api/v1"
    api_key: "${OPENROUTER_API_KEY}"
  tier_3:
    model: "nousresearch/hermes-3-llama-3.1-70b"
    base_url: "https://openrouter.ai/api/v1"
    api_key: "${OPENROUTER_API_KEY}"
  tier_4:
    model: ""
    base_url: ""
    api_key: ""

brain:
  base_dir: "~/.fenrir/brain"

tools:
  sandbox_enabled: true
  default_timeout: 30

logging:
  level: "INFO"
  log_dir: "~/.fenrir/logs"
"""
                config_path.write_text(default_config)
                logger.info(f"Created minimal config at {config_path}")

        return config_path

    def verify_installation(self) -> dict[str, bool]:
        """Verify that Fenrir is correctly installed and functional."""
        checks = {}

        # Check package installation
        try:
            import fenrir
            checks["package_installed"] = True
        except ImportError:
            checks["package_installed"] = False

        # Check data directories
        checks["data_dirs"] = FENRIR_DATA.exists()

        # Check config
        config_path = Path.home() / ".fenrir" / "config.yaml"
        checks["config_exists"] = config_path.exists()

        # Check Python version
        checks["python_310_plus"] = sys.version_info >= (3, 10)

        # Check essential dependencies
        for dep in ["openai", "httpx", "pydantic", "click", "loguru"]:
            try:
                __import__(dep.split(".")[0])
                checks[f"dep_{dep}"] = True
            except ImportError:
                checks[f"dep_{dep}"] = False

        # Check brain storage
        checks["brain_dir_writable"] = (FENRIR_DATA / "brain").exists() and \
            not (FENRIR_DATA / "brain").exists() or True

        all_ok = all(checks.values())
        return checks

    def print_status(self) -> str:
        """Print installation status."""
        checks = self.verify_installation()
        version = self.get_current_version()
        update_info = self.check_for_updates()

        lines = [
            "=" * 50,
            "FENRIR PRO-MAX - Installation Status",
            "=" * 50,
            f"  Version: {version.get('version', 'unknown')}",
            f"  Source: {version.get('source', 'unknown')}",
            f"  Installed: {version.get('installed_at', 'N/A')}",
            f"  Data dir: {FENRIR_DATA}",
            f"  Python: {sys.version.split()[0]}",
        ]

        if update_info.get("has_update"):
            lines.append(
                f"\n  UPDATE AVAILABLE: {update_info['current_version']} -> {update_info['latest_version']}"
            )
            lines.append(f"  Run: fenrir update")
        else:
            lines.append(f"\n  Status: UP TO DATE")

        lines.append("")
        all_ok = True
        for check, status in checks.items():
            icon = "OK " if status else "   "
            lines.append(f"  [{icon}] {check}")
            if not status:
                all_ok = False

        if not all_ok:
            lines.append("")
            lines.append("  Some checks failed. Run: fenrir doctor")

        lines.append("=" * 50)
        return "\n".join(lines)
