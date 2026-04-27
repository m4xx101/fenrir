"""Tool package — re-exports all tool classes and registry types."""

from __future__ import annotations

from fenrir.tools.browser import BrowserTool
from fenrir.tools.http import HTTPTool
from fenrir.tools.nmap import NmapTool
from fenrir.tools.registry import (
    ToolDefinition,
    ToolParameter,
    ToolRegistry,
    ToolResult,
)
from fenrir.tools.shell import ShellTool

__all__ = [
    "BrowserTool",
    "HTTPTool",
    "NmapTool",
    "ShellTool",
    "ToolRegistry",
    "ToolResult",
    "ToolDefinition",
    "ToolParameter",
]
