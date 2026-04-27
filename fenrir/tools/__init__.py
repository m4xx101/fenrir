Fenrir Pro-Max tools package

from fenrir.tools.browser import BrowserTool
from fenrir.tools.http import HTTPTool
from fenrir.tools.nmap import NmapTool
from fenrir.tools.shell import ShellTool
from fenrir.tools.registry import ToolRegistry, ToolResult, ToolDefinition, ToolParameter

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
