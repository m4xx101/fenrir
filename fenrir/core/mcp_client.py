"""MCP (Model Context Protocol) client integration for Fenrir.

Connects to external MCP servers (Kali MCP, Burp MCP, Metasploit MCP)
so Fenrir agents can discover and invoke security tools transparently.

Protocol: JSON-RPC 2.0 over stdio (subprocess) or SSE (HTTP).
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from typing import Any

import httpx
from loguru import logger
from pydantic import BaseModel, Field

from fenrir.tools.registry import ToolRegistry


# ---------------------------------------------------------------------------
# Server configuration model
# ---------------------------------------------------------------------------


class MCPServerConfig(BaseModel):
    """Configuration for a single MCP server."""

    name: str = Field(description="Human-readable server name")
    command: list[str] = Field(
        default_factory=list,
        description="Command + args for stdio transport (e.g. ['npx', '-y', 'kali-mcp-server'])",
    )
    url: str = Field(
        default="",
        description="Full URL for SSE transport (e.g. http://localhost:3100/sse)",
    )
    transport_type: str = Field(
        default="stdio",
        description="Transport: 'stdio' or 'sse'",
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Extra HTTP headers (SSE transport only)",
    )
    env: dict[str, str] = Field(
        default_factory=dict,
        description="Environment variables for the subprocess (stdio only)",
    )
    enabled: bool = Field(
        default=True,
        description="Whether this server should be auto-connected",
    )
    health_check_endpoint: str = Field(
        default="ping",
        description="Method name used for health-checking the server",
    )

    def model_post_init__(self, __context: Any) -> None:
        if self.transport_type not in ("stdio", "sse"):
            raise ValueError(f"transport_type must be 'stdio' or 'sse', got '{self.transport_type}'")
        if self.transport_type == "stdio" and not self.command:
            raise ValueError("command is required for stdio transport")
        if self.transport_type == "sse" and not self.url:
            raise ValueError("url is required for sse transport")


# ---------------------------------------------------------------------------
# Transport layer
# ---------------------------------------------------------------------------


class StdioTransport:
    """JSON-RPC 2.0 transport over stdin/stdout of a subprocess."""

    def __init__(self, command: list[str], env: dict[str, str] | None = None) -> None:
        self.command = command
        self._env: dict[str, str] = {
            **(env or {}),
        }
        self._process: subprocess.Popen | None = None
        self._msg_id = 0
        self._lock = threading.Lock()
        self._connected = False
        # Buffer for partial readline across boundaries
        self._response_map: dict[int, dict[str, Any]] = {}
        self._reader_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # -- lifecycle ----------------------------------------------------------

    def connect(self) -> None:
        """Launch the subprocess and start the reader thread."""
        if self._connected:
            return
        logger.info("Starting MCP stdio transport: {}", self.command)
        self._process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**self._get_clean_env(), **self._env},
            text=True,
            bufsize=1,  # line-buffered
        )
        self._connected = True
        self._stop_event.clear()
        self._reader_thread = threading.Thread(
            target=self._read_loop, daemon=True, name=f"mcp-stdio-{self.command[0]}"
        )
        self._reader_thread.start()
        logger.info("MCP stdio transport connected (pid={})", self._process.pid)

    def disconnect(self) -> None:
        """Cleanly shut down the subprocess."""
        self._connected = False
        self._stop_event.set()
        if self._reader_thread:
            self._reader_thread.join(timeout=5)
        if self._process:
            try:
                if self._process.stdin:
                    self._process.stdin.close()
            except Exception:
                pass
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            logger.info("MCP stdio transport disconnected")

    # -- message I/O --------------------------------------------------------

    def _send(self, message: dict[str, Any]) -> int:
        """Send a JSON-RPC message and return its ID."""
        if not self._process or not self._process.stdin:
            raise RuntimeError("StdioTransport is not connected")
        msg_id = self._next_id()
        message["id"] = msg_id
        payload = json.dumps(message) + "\n"
        logger.debug("Stdio sending -> {} (id={})", message.get("method", "response"), msg_id)
        self._process.stdin.write(payload)
        self._process.stdin.flush()
        return msg_id

    def _read_loop(self) -> None:
        """Continuously read JSON lines from stdout."""
        assert self._process and self._process.stdout
        while not self._stop_event.is_set():
            try:
                line = self._process.stdout.readline()
                if not line:
                    logger.warning("StdioTransport: subprocess stdout closed")
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    resp = json.loads(line)
                    resp_id = resp.get("id")
                    if resp_id is not None:
                        self._response_map[resp_id] = resp
                except json.JSONDecodeError:
                    logger.warning("StdioTransport: non-JSON line received: {}", line)
            except Exception:
                logger.opt(exception=True).debug("StdioTransport read error")

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = 30.0) -> dict[str, Any]:
        """Send a JSON-RPC request and block until a response arrives."""
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        msg_id = self._send(msg)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if msg_id in self._response_map:
                response = self._response_map.pop(msg_id)
                if "error" in response:
                    err = response["error"]
                    raise MCPServerError(f"Server error: {err.get('message', err)}", response=err)
                return response.get("result", {})
            time.sleep(0.05)
        raise TimeoutError(f"MCP stdio request timed out after {timeout}s (method={method})")

    # -- helpers ------------------------------------------------------------

    def _next_id(self) -> int:
        with self._lock:
            self._msg_id += 1
            return self._msg_id

    def _get_clean_env(self) -> dict[str, str]:
        """Return the current environment as str→str suitable for subprocess."""
        import os
        return {k: v for k, v in os.environ.items() if v is not None}


class SSETransport:
    """JSON-RPC 2.0 transport over HTTP Server-Sent Events."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.url = url
        self._headers = headers or {}
        self._timeout = timeout
        self._client: httpx.Client | None = None
        self._connected = False
        self._msg_id = 0
        self._lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------------

    def connect(self) -> None:
        """Open an HTTP client (keepalive)."""
        if self._connected:
            return
        self._client = httpx.Client(
            base_url=self.url,
            headers=self._headers,
            timeout=self._timeout,
        )
        self._connected = True
        logger.info("MCP SSE transport connected: {}", self.url)

    def disconnect(self) -> None:
        """Close the HTTP client."""
        if self._client:
            self._client.close()
            self._client = None
        self._connected = False
        logger.info("MCP SSE transport disconnected")

    # -- message I/O --------------------------------------------------------

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float | None = None) -> dict[str, Any]:
        """Send a JSON-RPC request via HTTP POST and return the result."""
        if not self._client:
            raise RuntimeError("SSETransport is not connected")

        msg_id = self._next_id()
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": msg_id, "method": method}
        if params is not None:
            body["params"] = params

        logger.debug("SSE sending -> {} (id={})", method, msg_id)

        resp = self._client.post(
            "/",  # path is relative to base_url
            json=body,
            timeout=timeout or self._timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        if isinstance(data, list):
            # Some SSE servers return arrays; use first element
            data = data[0] if data else {}

        if "error" in data:
            err = data["error"]
            raise MCPServerError(f"Server error: {err.get('message', err)}", response=err)

        return data.get("result", {})

    # -- helpers ------------------------------------------------------------

    def _next_id(self) -> int:
        with self._lock:
            self._msg_id += 1
            return self._msg_id


# ---------------------------------------------------------------------------
# Exception types
# ---------------------------------------------------------------------------


class MCPServerError(Exception):
    """Raised when the MCP server reports an error."""

    def __init__(self, message: str, response: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.response = response


class MCPConnectionError(Exception):
    """Raised when a connection cannot be established."""


# ---------------------------------------------------------------------------
# MCPServer — wraps one server + one transport
# ---------------------------------------------------------------------------


class MCPServer:
    """Wraps a single MCP server and its transport."""

    def __init__(self, config: MCPServerConfig) -> None:
        self.config = config
        self.transport: StdioTransport | SSETransport | None = None
        self._connected = False
        self._tools_cache: list[dict[str, Any]] = []

    # -- lifecycle ----------------------------------------------------------

    def connect(self) -> None:
        """Establish a connection to the server."""
        if self._connected:
            return
        logger.info("Connecting to MCP server: {}", self.config.name)

        if self.config.transport_type == "stdio":
            self.transport = StdioTransport(
                command=self.config.command,
                env=self.config.env or None,
            )
        elif self.config.transport_type == "sse":
            self.transport = SSETransport(
                url=self.config.url,
                headers=self.config.headers or None,
            )
        else:
            raise ValueError(f"Unknown transport_type: {self.config.transport_type}")

        try:
            self.transport.connect()
            self._connected = True
            # Prepop tool cache
            try:
                self._tools_cache = self.list_tools()
            except Exception as exc:
                logger.warning("Could not list tools on connect: {}", exc)
        except Exception as exc:
            raise MCPConnectionError(
                f"Failed to connect to MCP server '{self.config.name}': {exc}"
            ) from exc

        logger.info("MCP server '{}' connected", self.config.name)

    def disconnect(self) -> None:
        """Cleanly shut down the transport."""
        if self.transport:
            self.transport.disconnect()
        self._connected = False
        self._tools_cache = []
        logger.info("MCP server '{}' disconnected", self.config.name)

    # -- tool discovery & invocation ----------------------------------------

    def list_tools(self) -> list[dict[str, Any]]:
        """
        Query the server for its available tools.

        Returns a list of tool descriptors (each has at minimum
        'name', 'description', and optionally 'inputSchema').
        """
        if not self.transport:
            raise MCPConnectionError("Server is not connected")
        raw = self.transport.request("tools/list")
        tools = raw.get("tools", [])
        self._tools_cache = tools
        return tools

    def call_tool(self, name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a named tool on the server with the given parameters."""
        if not self.transport:
            raise MCPConnectionError("Server is not connected")
        call_params: dict[str, Any] = {"name": name}
        if params:
            call_params["arguments"] = params
        return self.transport.request("tools/call", params=call_params)

    # -- health check -------------------------------------------------------

    def health_check(self) -> bool:
        """Return True if the server appears responsive."""
        if not self.transport or not self._connected:
            return False
        try:
            # Try the configured health method first, fall back to tools/list
            method = self.config.health_check_endpoint or "ping"
            self.transport.request(method, timeout=5.0)
            return True
        except (TimeoutError, MCPServerError, MCPConnectionError):
            try:
                self.transport.request("tools/list", timeout=5.0)
                return True
            except Exception:
                return False

    # -- property -----------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        return self._connected


# ---------------------------------------------------------------------------
# FenrirMCPClient — manages multiple MCP servers
# ---------------------------------------------------------------------------


class FenrirMCPClient:
    """High-level MCP client for Fenrir.

    Manages a collection of MCP servers, lazily connects to them,
    can auto-register discovered tools into Fenrir's ToolRegistry,
    and provides a unified ``call_tool`` entry point.
    """

    def __init__(self) -> None:
        self._servers: dict[str, MCPServer] = {}

    # -- default servers ----------------------------------------------------

    def load_default_servers(self) -> FenrirMCPClient:
        """Register the built-in security MCP servers."""
        defaults: list[MCPServerConfig] = [
            MCPServerConfig(
                name="kali-mcp",
                command=["npx", "-y", "kali-mcp-server"],
                transport_type="stdio",
                enabled=True,
            ),
            MCPServerConfig(
                name="burp-mcp",
                command=["npx", "-y", "@portswigger/burp-mcp-server"],
                transport_type="stdio",
                enabled=True,
            ),
            MCPServerConfig(
                name="metasploit-mcp",
                command=["npx", "-y", "metasploit-mcp"],
                transport_type="stdio",
                enabled=True,
            ),
        ]
        for cfg in defaults:
            self.add_server(cfg)
        logger.info("Loaded {} default MCP servers: {}", len(defaults), [c.name for c in defaults])
        return self

    # -- server management --------------------------------------------------

    def add_server(self, config: MCPServerConfig) -> MCPServer:
        """Add (or replace) a server configuration."""
        server = MCPServer(config)
        self._servers[config.name] = server
        logger.debug("Added MCP server: {}", config.name)
        return server

    def remove_server(self, name: str) -> bool:
        """Remove a server (disconnect if connected)."""
        server = self._servers.pop(name, None)
        if server:
            try:
                server.disconnect()
            except Exception:
                pass
            logger.info("Removed MCP server: {}", name)
            return True
        return False

    def list_servers(self) -> list[dict[str, Any]]:
        """Return a summary of all configured servers."""
        result: list[dict[str, Any]] = []
        for name, srv in self._servers.items():
            result.append({
                "name": name,
                "transport_type": srv.config.transport_type,
                "command": srv.config.command,
                "url": srv.config.url,
                "enabled": srv.config.enabled,
                "connected": srv.is_connected,
                "tools_cached": len(srv._tools_cache),
            })
        return result

    # -- connectivity -------------------------------------------------------

    def connect_all(self) -> FenrirMCPClient:
        """Connect to every enabled server that is not yet connected."""
        for name, srv in self._servers.items():
            if srv.config.enabled and not srv.is_connected:
                try:
                    srv.connect()
                except Exception as exc:
                    logger.warning("Failed to connect to '{}': {}", name, exc)
        return self

    def disconnect_all(self) -> None:
        """Disconnect all servers."""
        for srv in list(self._servers.values()):
            try:
                srv.disconnect()
            except Exception:
                pass

    # -- unified tool calling -----------------------------------------------

    def call_tool(self, name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a tool by name, searching across all connected servers.

        The first connected server that has the tool is used.
        If no connected server knows the tool, attempts to connect enabled
        servers and retry once.
        """
        # Phase 1: try already-connected servers
        for srv in self._servers.values():
            if not srv.is_connected:
                continue
            tools = srv._tools_cache or []
            if any(t.get("name") == name for t in tools):
                logger.debug("Calling '{}' on '{}'", name, srv.config.name)
                return srv.call_tool(name, params)

        # Phase 2: try to connect enabled servers and retry
        for srv in self._servers.values():
            if srv.config.enabled and not srv.is_connected:
                try:
                    srv.connect()
                except Exception:
                    continue
                tools = srv._tools_cache or []
                if any(t.get("name") == name for t in tools):
                    logger.debug(
                        "Connected to '{}' and calling '{}'", srv.config.name, name
                    )
                    return srv.call_tool(name, params)

        raise MCPConnectionError(
            f"Tool '{name}' not found on any connected MCP server"
        )

    # -- ToolRegistry integration -------------------------------------------

    def register_with_registry(self, registry: ToolRegistry) -> int:
        """Discover tools from all connected servers and register them.

        Each MCP tool becomes a ToolRegistry entry so Fenrir agents
        can discover and invoke them transparently.

        Returns the number of tools registered.
        """
        count = 0
        for name, srv in self._servers.items():
            if not srv.is_connected:
                logger.warning("Skipping unconnected server '{}' for tool registration", name)
                continue
            try:
                tools = srv.list_tools()
            except Exception as exc:
                logger.warning("Cannot list tools from '{}': {}", name, exc)
                continue

            for tool in tools:
                tool_name = tool.get("name", "")
                if not tool_name:
                    continue
                description = tool.get("description", "")

                def _make_handler(server_name: str, t_name: str):
                    """Capture server_name and t_name in a closure."""
                    def handler(*args: Any, **kwargs: Any) -> dict[str, Any]:
                        """Handler that returns raw content (wrapped by invoke)."""
                        raw = self._servers[server_name].call_tool(t_name, kwargs or (args[0] if args else {}))
                        return self._extract_content(raw)
                    return handler

                registry.register(
                    name=tool_name,
                    func=_make_handler(name, tool_name),
                    description=description,
                )
                count += 1
                logger.debug("Registered MCP tool '{}' (from '{}')", tool_name, name)

        logger.info("Registered {} MCP tools with ToolRegistry", count)
        return count

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _extract_content(raw: dict[str, Any]) -> str:
        """MCP tool-call response -> plain text string."""
        content_list = raw.get("content", [])
        parts: list[str] = []
        for item in content_list:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(item.get("text", ""))
                elif item.get("type") == "image":
                    parts.append(f"[image: {item.get('mimeType', 'unknown')}]")
                else:
                    parts.append(json.dumps(item))
            else:
                parts.append(str(item))
        if not parts:
            return json.dumps(raw)
        return "\n".join(parts)

    # -- context manager ----------------------------------------------------

    def __enter__(self) -> FenrirMCPClient:
        self.connect_all()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.disconnect_all()
