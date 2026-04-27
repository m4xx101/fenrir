"""Tool registry with MCP-compatible output format."""

from __future__ import annotations

import asyncio
import inspect
import json
from typing import Any, Callable

from loguru import logger
from pydantic import BaseModel, Field

from fenrir.tools.nmap import NmapTool
from fenrir.tools.http import HTTPTool
from fenrir.tools.browser import BrowserTool
from fenrir.tools.shell import ShellTool


class ToolParameter(BaseModel):
    """Parameter definition for a registered tool."""
    name: str
    type: str = "string"
    description: str = ""
    required: bool = True
    default: Any = None


class ToolDefinition(BaseModel):
    """OpenAI-compatible tool definition."""
    type: str = "function"
    function: dict[str, Any]


class ToolResult(BaseModel):
    """Result from tool execution."""
    tool_name: str
    success: bool
    output: str = ""
    error: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_tool_message(self) -> dict[str, Any]:
        """Convert to OpenAI tool response format."""
        return {
            "role": "tool",
            "tool_call_id": self.metadata.get("tool_call_id", ""),
            "content": self.output if self.success else self.error,
        }


class ToolRegistry:
    """Registry of available tools with MCP-compatible format."""

    def __init__(self, config: Any = None):
        self._tools: dict[str, Callable] = {}
        self._definitions: dict[str, dict] = {}
        self._config = config
        # Register built-in tools
        self._register_builtin_tools()

    def _register_builtin_tools(self) -> None:
        """Register all built-in tools."""
        self._nmap = NmapTool(self._config) if self._config else NmapTool()
        self._http = HTTPTool(self._config) if self._config else HTTPTool()
        self._browser = BrowserTool(self._config) if self._config else BrowserTool()
        self._shell = ShellTool(self._config) if self._config else ShellTool()

        # HTTP tools
        self.register("http_get", self._http.get, "Make an HTTP GET request")
        self.register("http_post", self._http.post, "Make an HTTP POST request")
        self.register("http_request", self._http.request, "Make a custom HTTP request")

        # Nmap tools
        self.register("nmap_scan", self._nmap.scan, "Run Nmap port/service scan")
        self.register("nmap_parse_xml", self._nmap.parse_xml, "Parse Nmap XML output")

        # Browser tools
        self.register("browser_navigate", self._browser.navigate, "Navigate browser to URL")
        self.register("browser_click", self._browser.click, "Click element in browser")
        self.register("browser_fill", self._browser.fill, "Fill form field in browser")
        self.register("browser_screenshot", self._browser.screenshot, "Take browser screenshot")
        self.register("browser_evaluate", self._browser.evaluate, "Execute JavaScript in browser")
        self.register("browser_get_content", self._browser.get_content, "Get page HTML content")

        # Shell tools
        self.register("shell_exec", self._shell.execute, "Execute shell command with sandboxing")

    def register(
        self,
        name: str,
        func: Callable,
        description: str | None = None,
    ) -> None:
        """Register a tool with its function."""
        self._tools[name] = func

        # Generate OpenAI function schema
        sig = inspect.signature(func)
        parameters = {
            "type": "object",
            "properties": {},
            "required": [],
        }

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue
            param_type = "string"
            if param.annotation is int:
                param_type = "integer"
            elif param.annotation is bool:
                param_type = "boolean"
            elif param.annotation is float:
                param_type = "number"

            param_def = {
                "type": param_type,
                "description": f"Parameter: {param_name}",
            }

            if param.default is not inspect.Parameter.empty:
                param_def["default"] = param.default

            parameters["properties"][param_name] = param_def
            if param.default is inspect.Parameter.empty:
                parameters["required"].append(param_name)

        self._definitions[name] = {
            "type": "function",
            "function": {
                "name": name,
                "description": description or func.__doc__ or f"Execute tool: {name}",
                "parameters": parameters,
            },
        }
        logger.debug(f"Registered tool: {name}")

    def get_definitions(self) -> list[dict[str, Any]]:
        """Get all tool definitions in OpenAI format."""
        return list(self._definitions.values())

    def get_tool(self, name: str) -> Callable | None:
        """Get registered tool by name."""
        return self._tools.get(name)

    async def invoke(
        self,
        tool_name: str,
        arguments: dict[str, Any] | str = "",
        tool_call_id: str = "",
    ) -> ToolResult:
        """Invoke a tool with arguments and sandboxing."""
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments) if arguments else {}
            except json.JSONDecodeError:
                return ToolResult(
                    tool_name=tool_name,
                    success=False,
                    error=f"Invalid JSON arguments: {arguments}",
                    metadata={"tool_call_id": tool_call_id},
                )

        func = self._tools.get(tool_name)
        if not func:
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Unknown tool: {tool_name}. Available: {list(self._tools.keys())}",
                metadata={"tool_call_id": tool_call_id},
            )

        try:
            logger.info(f"Executing tool: {tool_name} with {arguments}")

            # Handle async functions
            result = func(**arguments)
            if asyncio.iscoroutine(result):
                result = await result

            # Normalize result to string
            if isinstance(result, dict):
                output = json.dumps(result, indent=2, default=str)
            elif isinstance(result, (list, tuple)):
                output = json.dumps(result, indent=2, default=str)
            else:
                output = str(result)

            return ToolResult(
                tool_name=tool_name,
                success=True,
                output=output,
                metadata={"tool_call_id": tool_call_id},
            )

        except Exception as e:
            logger.error(f"Tool {tool_name} failed: {e}")
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Error: {type(e).__name__}: {str(e)}",
                metadata={"tool_call_id": tool_call_id},
            )

    def execute_all_tool_calls(
        self, tool_calls: list[dict[str, Any]]
    ) -> list[ToolResult]:
        """Execute a batch of tool calls (for use in sync contexts)."""
        return asyncio.get_event_loop().run_until_complete(
            self._execute_all_async(tool_calls)
        )

    async def _execute_all_async(
        self, tool_calls: list[dict[str, Any]]
    ) -> list[ToolResult]:
        """Execute all tool calls concurrently where possible."""
        tasks = []
        for tc in tool_calls:
            func_info = tc.get("function", {})
            tool_name = func_info.get("name", "")
            arguments = func_info.get("arguments", "")
            tool_call_id = tc.get("id", "")
            tasks.append(
                self.invoke(tool_name, arguments, tool_call_id)
            )

        # Execute sequentially for safety with system tools
        results = []
        for task in tasks:
            result = await task
            results.append(result)

        return results
