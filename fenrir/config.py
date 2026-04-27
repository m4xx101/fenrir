"""Configuration loading from YAML/env for Fenrir Pro-Max."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load .env from project root and user home
load_dotenv()
load_dotenv(Path.home() / ".fenrir" / ".env", override=True)


class LLMTier(str, Enum):
    """LLM tier for routing tasks by complexity."""
    TIER_0 = "tier_0"        # Local Ollama/LM Studio (free)
    TIER_1 = "tier_1"        # Cloud cheap (DeepSeek V3, Groq)
    TIER_2 = "tier_2"        # Cloud strong (Claude Sonnet, GPT-4o)
    TIER_3 = "tier_3"        # Uncensored (Hermes 4, Dolphin)
    TIER_4 = "tier_4"        # Abliterated (Heretic pipeline)


class LLMConfig(BaseModel):
    """Configuration for a single LLM provider."""
    model: str = Field(default="")
    api_key: str = Field(default="", alias="api_key")
    base_url: str = Field(default="")
    max_tokens: int = Field(default=8192)
    temperature: float = Field(default=0.7)
    top_p: float = Field(default=1.0)
    timeout: float = Field(default=120.0)

    class Config:
        populate_by_name = True


class ProviderConfig(BaseModel):
    """All LLM providers for tiered routing."""
    tier_0: LLMConfig = Field(
        default_factory=lambda: LLMConfig(
            model=os.getenv("OLLAMA_MODEL", "nousresearch/hermes3:8b"),
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
            api_key=os.getenv("OLLAMA_API_KEY", "ollama"),
        )
    )
    tier_1: LLMConfig = Field(
        default_factory=lambda: LLMConfig(
            model=os.getenv("TIER1_MODEL", "deepseek/deepseek-chat"),
            base_url=os.getenv("TIER1_BASE_URL", "https://openrouter.ai/api/v1"),
            api_key=os.getenv("OPENROUTER_API_KEY", ""),
        )
    )
    tier_2: LLMConfig = Field(
        default_factory=lambda: LLMConfig(
            model=os.getenv("TIER2_MODEL", "anthropic/claude-3.5-sonnet"),
            base_url=os.getenv("TIER2_BASE_URL", "https://openrouter.ai/api/v1"),
            api_key=os.getenv("OPENROUTER_API_KEY", ""),
        )
    )
    tier_3: LLMConfig = Field(
        default_factory=lambda: LLMConfig(
            model=os.getenv("TIER3_MODEL", "nousresearch/hermes-3-llama-3.1-70b"),
            base_url=os.getenv("TIER3_BASE_URL", "https://openrouter.ai/api/v1"),
            api_key=os.getenv("OPENROUTER_API_KEY", ""),
        )
    )
    tier_4: LLMConfig = Field(
        default_factory=lambda: LLMConfig(
            model=os.getenv("TIER4_MODEL", ""),
            base_url=os.getenv("TIER4_BASE_URL", ""),
            api_key=os.getenv("OPENROUTER_API_KEY", ""),
        )
    )
    fallback_model: str = Field(
        default=os.getenv("FALLBACK_MODEL", "nousresearch/hermes-3-llama-3.1-70b")
    )
    # Embedding model for vector store
    embedding_model: str = Field(
        default=os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")
    )
    embedding_base_url: str = Field(
        default=os.getenv("EMBEDDING_BASE_URL", "https://api.openai.com/v1")
    )
    embedding_api_key: str = Field(
        default=os.getenv("OPENAI_API_KEY", "")
    )


class BrainConfig(BaseModel):
    """Second brain configuration."""
    base_dir: Path = Field(
        default=Path(os.getenv("FENRIR_BRAIN_DIR", Path.home() / ".fenrir" / "brain"))
    )
    chroma_db_dir: Path = Field(
        default=Path(os.getenv("FENRIR_CHROMA_DIR", Path.home() / ".fenrir" / "brain" / "embeddings"))
    )
    sqlite_db: Path = Field(
        default=Path(os.getenv("FENRIR_SQLITE_DB", Path.home() / ".fenrir" / "brain" / "findings.db"))
    )


class ToolConfig(BaseModel):
    """Tool execution configuration."""
    sandbox_enabled: bool = Field(default=os.getenv("FENRIR_SANDBOX", "true").lower() == "true")
    default_timeout: int = Field(default=int(os.getenv("FENRIR_TOOL_TIMEOUT", "30")))
    max_shell_output_bytes: int = Field(default=int(os.getenv("FENRIR_MAX_OUTPUT", "65536")))
    nmap_binary: str = Field(default=os.getenv("NMAP_BINARY", "nmap"))
    rustscan_binary: str = Field(default=os.getenv("RUSTSCAN_BINARY", "rustscan"))
    masscan_binary: str = Field(default=os.getenv("MASSCAN_BINARY", "masscan"))


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = Field(default=os.getenv("FENRIR_LOG_LEVEL", "INFO"))
    log_dir: Path = Field(
        default=Path(os.getenv("FENRIR_LOG_DIR", Path.home() / ".fenrir" / "logs"))
    )
    file_enabled: bool = Field(default=True)
    console_enabled: bool = Field(default=True)


class AppConfig(BaseModel):
    """Top-level application configuration."""
    llm_providers: ProviderConfig = Field(default_factory=ProviderConfig)
    brain: BrainConfig = Field(default_factory=BrainConfig)
    tools: ToolConfig = Field(default_factory=ToolConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    scan_timeout: int = Field(default=int(os.getenv("FENRIR_SCAN_TIMEOUT", "3600")))
    max_concurrent_agents: int = Field(default=int(os.getenv("FENRIR_MAX_AGENTS", "4")))

    class Config:
        env_prefix = "FENRIR_"


def load_config(config_path: str | Path | None = None) -> AppConfig:
    """Load configuration from YAML file, falling back to env vars."""
    if config_path:
        config_path = Path(config_path)
        if config_path.exists():
            with open(config_path) as f:
                data = yaml.safe_load(f)
            if data:
                return AppConfig(**data)

    # Check default locations
    for default_path in [
        Path("fenrir.yaml"),
        Path.home() / ".fenrir" / "config.yaml",
        Path("/etc/fenrir/config.yaml"),
    ]:
        if default_path.exists():
            with open(default_path) as f:
                data = yaml.safe_load(f)
            if data:
                return AppConfig(**data)

    return AppConfig()
