"""Parser tests: every client shape collapses into one ServerSpec."""

import pytest

from mcpseal.config import (
    ConfigError,
    ServerSpec,
    detect_client,
    normalise_server,
    parse_text,
    strip_jsonc,
)

CLAUDE_DESKTOP = """
{
  "mcpServers": {
    "files": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "./src"],
      "env": {"LOG_LEVEL": "info", "MAX_DEPTH": 4}
    }
  }
}
"""

CURSOR_REMOTE = """
{
  "mcpServers": {
    "vendor": {
      "url": "https://api.vendor.example.com/mcp",
      "headers": {"Authorization": "Bearer ${TOKEN}"}
    }
  }
}
"""

VSCODE_JSONC = """
{
  // VS Code ships JSONC, comments included
  "servers": {
    "git": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "mcp-server-git==0.6.2", /* pin it */
      ],
    },
  },
}
"""


def test_parse_claude_desktop_stdio():
    servers = parse_text(CLAUDE_DESKTOP, source="claude_desktop_config.json")
    assert len(servers) == 1
    server = servers[0]
    assert server.name == "files"
    assert server.command == "npx"
    assert server.args[0] == "-y"
    assert server.env["LOG_LEVEL"] == "info"
    assert server.client == "claude-desktop"
    assert server.remote is False


def test_parse_remote_url_and_headers():
    servers = parse_text(CURSOR_REMOTE, source="/p/.cursor/mcp.json")
    server = servers[0]
    assert server.url == "https://api.vendor.example.com/mcp"
    assert server.headers["Authorization"] == "Bearer ${TOKEN}"
    assert server.transport == "http"
    assert server.remote is True


def test_jsonc_comments_and_trailing_commas():
    servers = parse_text(VSCODE_JSONC, source="/p/.vscode/mcp.json")
    server = servers[0]
    assert server.name == "git"
    assert server.args == ["mcp-server-git==0.6.2"]
    assert server.client == "vscode"


def test_strip_jsonc_keeps_strings_intact():
    text = '{"a": "keep // this /* and this */", "b": 1}'
    cleaned = strip_jsonc(text)
    assert "keep // this /* and this */" in cleaned
    assert cleaned.count("{") == 1


def test_missing_server_block_is_an_error():
    with pytest.raises(ConfigError) as excinfo:
        parse_text('{"mcp": {}}', source="bad.json")
    assert "mcpServers" in str(excinfo.value)


def test_invalid_json_is_an_error():
    with pytest.raises(ConfigError):
        parse_text("{ not json", source="bad.json")


def test_env_values_are_coerced_to_strings():
    server = normalise_server(
        "x",
        {"command": "node", "env": {"PORT": 8080, "DEBUG": True, "NOTHING": None}},
        source="c.json",
        client="generic",
    )
    assert server.env == {"PORT": "8080", "DEBUG": "true", "NOTHING": ""}


def test_auto_approve_and_disabled_flags():
    server = normalise_server(
        "x",
        {"command": "node", "autoApprove": ["write_file"], "enabled": False},
        source="c.json",
        client="generic",
    )
    assert server.auto_approve == ["write_file"]
    assert server.disabled is True


def test_command_line_is_reconstructable():
    spec = ServerSpec(name="x", source="c.json", client="generic", command="uvx", args=["pkg==1"])
    assert spec.command_line == "uvx pkg==1"


def test_detect_client_labels():
    assert detect_client("/home/u/claude_desktop_config.json") == "claude-desktop"
    assert detect_client("/home/u/.cursor/mcp.json") == "cursor"
    assert detect_client("/home/u/.vscode/mcp.json") == "vscode"
    assert detect_client("/repo/.mcp.json") == "claude-code"
    assert detect_client("/repo/mcp.json") == "generic"
