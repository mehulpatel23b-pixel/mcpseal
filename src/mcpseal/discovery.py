"""Locate MCP configuration files on disk."""

from __future__ import annotations

import os
from typing import List

from .config import ConfigError

# Ordered by how likely each one is to be the config a user means.
KNOWN_CONFIG_PATHS = (
    ".mcp.json",                      # Claude Code (project scope)
    ".cursor/mcp.json",               # Cursor (project scope)
    ".vscode/mcp.json",               # VS Code
    ".windsurf/mcp.json",             # Windsurf
    ".kiro/settings/mcp.json",        # Kiro
    "claude_desktop_config.json",     # Claude Desktop (when copied into a repo)
    "mcp.json",                       # generic
    ".mcp/config.json",               # generic
)


def looks_like_config(path: str) -> bool:
    """True when the file name is one of the known MCP config names."""
    base = os.path.basename(path).lower()
    known = {os.path.basename(p).lower() for p in KNOWN_CONFIG_PATHS}
    return base in known or base.endswith("_config.json")


def discover(target: str) -> List[str]:
    """Return every MCP configuration file reachable from ``target``.

    ``target`` may be a config file or a directory (usually a project root). A
    single file is always returned as-is so ``mcpseal ~/.config/foo.json`` works
    for a hand-rolled config name.
    """
    if not os.path.exists(target):
        raise ConfigError("no such file or directory: %s" % target)

    if os.path.isfile(target):
        return [target]

    found: List[str] = []
    seen = set()
    for relative in KNOWN_CONFIG_PATHS:
        candidate = os.path.join(target, relative)
        if os.path.isfile(candidate):
            real = os.path.realpath(candidate)
            if real not in seen:
                seen.add(real)
                found.append(candidate)
    return found


def default_global_paths(home: str) -> List[str]:
    """Well-known per-user config locations, for the ``--global`` flag."""
    return [
        os.path.join(home, ".claude.json"),
        os.path.join(home, ".config", "claude", "claude_desktop_config.json"),
        os.path.join(home, ".cursor", "mcp.json"),
        os.path.join(home, ".codeium", "windsurf", "mcp_config.json"),
    ]
