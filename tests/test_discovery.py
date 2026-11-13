"""Discovery tests: find the config that is actually in a project."""

import os

import pytest

from mcpseal.config import ConfigError
from mcpseal.discovery import discover, looks_like_config


def _write(path, text="{ \"mcpServers\": {} }"):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def test_discover_finds_project_configs(tmp_path):
    _write(str(tmp_path / ".mcp.json"))
    _write(str(tmp_path / ".cursor" / "mcp.json"))
    found = discover(str(tmp_path))
    names = [os.path.basename(os.path.dirname(p)) + "/" + os.path.basename(p) for p in found]
    assert any("mcp.json" in name for name in names)
    assert len(found) == 2


def test_discover_returns_explicit_file(tmp_path):
    target = tmp_path / "my-servers.json"
    _write(str(target))
    assert discover(str(target)) == [str(target)]


def test_discover_empty_project_is_empty_list(tmp_path):
    assert discover(str(tmp_path)) == []


def test_discover_missing_target_raises(tmp_path):
    with pytest.raises(ConfigError):
        discover(str(tmp_path / "nope"))


def test_looks_like_config():
    assert looks_like_config("/repo/.mcp.json") is True
    assert looks_like_config("/repo/claude_desktop_config.json") is True
    assert looks_like_config("/repo/.vscode/mcp.json") is True
    assert looks_like_config("/repo/package.json") is False
