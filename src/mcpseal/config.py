"""Parse and normalise MCP client configuration files.

Every MCP client stores the same idea in a slightly different shape:

* Claude Desktop  -> ``claude_desktop_config.json`` with ``mcpServers``
* Claude Code     -> ``.mcp.json`` with ``mcpServers``
* Cursor          -> ``.cursor/mcp.json`` with ``mcpServers`` (stdio or url)
* VS Code         -> ``.vscode/mcp.json`` with ``servers`` and ``type``
* Windsurf        -> ``.windsurf/mcp.json``
* Kiro            -> ``.kiro/settings/mcp.json``

This module flattens all of them into one :class:`ServerSpec` so the rules only
have to reason about a single representation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SERVER_CONTAINER_KEYS = ("mcpServers", "servers", "mcp_servers")
ENV_REF_RE = re.compile(r"^\$(?:\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*)$|^%[A-Za-z_][A-Za-z0-9_]*%$")
TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")


class ConfigError(Exception):
    """Raised when a configuration file cannot be read or understood."""


@dataclass
class ServerSpec:
    """One MCP server registration, normalised across clients."""

    name: str
    source: str
    client: str
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    transport: str = "stdio"
    auto_approve: Any = None
    disabled: bool = False
    cwd: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def command_line(self) -> str:
        """The full launch string, for evidence output."""
        parts = [self.command or ""] + list(self.args)
        return " ".join(p for p in parts if p)

    @property
    def remote(self) -> bool:
        """True when this server is reached over the network instead of stdio."""
        if self.url:
            return True
        return str(self.transport).lower() in ("http", "sse", "streamable-http", "streamablehttp")


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, preserving strings.

    MCP configs are routinely hand-edited JSONC (VS Code, Cursor, Kiro all
    accept comments), so a strict ``json.loads`` would reject real files.
    """
    out: List[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return TRAILING_COMMA_RE.sub(r"\1", "".join(out))


def detect_client(path: str) -> str:
    """Best-effort label for which client owns this configuration file."""
    p = path.replace("\\", "/").lower()
    if "claude_desktop_config.json" in p:
        return "claude-desktop"
    if "/.cursor/" in p or p.endswith(".cursor/mcp.json"):
        return "cursor"
    if "/.vscode/" in p:
        return "vscode"
    if "/.windsurf/" in p:
        return "windsurf"
    if "/.kiro/" in p:
        return "kiro"
    if p.endswith(".mcp.json"):
        return "claude-code"
    return "generic"


def _string_map(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    out: Dict[str, str] = {}
    for key, item in value.items():
        if item is None:
            out[str(key)] = ""
        elif isinstance(item, bool):
            out[str(key)] = "true" if item else "false"
        elif isinstance(item, (int, float)):
            out[str(key)] = str(item)
        else:
            out[str(key)] = str(item)
    return out


def _string_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def normalise_server(name: str, entry: Dict[str, Any], source: str, client: str) -> ServerSpec:
    """Turn one raw server entry into a :class:`ServerSpec`."""
    if not isinstance(entry, dict):
        raise ConfigError("server %r is not an object" % name)

    command = entry.get("command")
    url = entry.get("url") or entry.get("serverUrl") or entry.get("endpoint")
    transport = entry.get("type") or entry.get("transport") or ("http" if url else "stdio")
    auto = entry.get("autoApprove", entry.get("auto_approve", entry.get("alwaysAllow")))
    disabled = bool(entry.get("disabled", entry.get("enabled") is False))
    cwd = entry.get("cwd") or entry.get("workingDirectory")

    return ServerSpec(
        name=str(name),
        source=source,
        client=client,
        command=str(command) if command is not None else None,
        args=_string_list(entry.get("args")),
        env=_string_map(entry.get("env") if entry.get("env") is not None else entry.get("environment")),
        url=str(url) if url else None,
        headers=_string_map(entry.get("headers") or entry.get("httpHeaders")),
        transport=str(transport),
        auto_approve=auto,
        disabled=disabled,
        cwd=str(cwd) if cwd else None,
        raw=entry if isinstance(entry, dict) else {},
    )


def parse_text(text: str, source: str = "<memory>", client: Optional[str] = None) -> List[ServerSpec]:
    """Parse configuration text into normalised server specs."""
    cleaned = strip_jsonc(text)
    try:
        data = json.loads(cleaned) if cleaned.strip() else {}
    except ValueError as exc:
        raise ConfigError("%s is not valid JSON: %s" % (source, exc))
    if not isinstance(data, dict):
        raise ConfigError("%s must contain a JSON object at the top level" % source)

    servers: Any = None
    for key in SERVER_CONTAINER_KEYS:
        if isinstance(data.get(key), dict):
            servers = data[key]
            break
    if servers is None:
        raise ConfigError(
            "%s has no MCP server block (expected one of: %s)"
            % (source, ", ".join(SERVER_CONTAINER_KEYS))
        )

    label = client or detect_client(source)
    return [normalise_server(name, entry, source, label) for name, entry in servers.items()]


def parse_file(path: str) -> List[ServerSpec]:
    """Read and parse a configuration file from disk."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise ConfigError("cannot read %s: %s" % (path, exc))
    return parse_text(text, source=path)
