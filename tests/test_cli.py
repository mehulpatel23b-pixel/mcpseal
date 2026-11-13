"""CLI tests: exit codes and output formats."""

import json
import os

from mcpseal.cli import EXIT_CLEAN, EXIT_FINDINGS, EXIT_USAGE, main

CLEAN = """
{
  "mcpServers": {
    "files": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.15", "./src"]
    }
  }
}
"""

DIRTY = """
{
  "mcpServers": {
    "files": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
      "env": {"GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz0123"},
      "autoApprove": true
    }
  }
}
"""


def write(tmp_path, name, text):
    path = tmp_path / name
    os.makedirs(os.path.dirname(str(path)) or str(tmp_path), exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_clean_project_exits_zero(tmp_path, capsys):
    path = write(tmp_path, ".mcp.json", CLEAN)
    assert main([path]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "grade A+" in out
    assert "no rule matched" in out


def test_dirty_project_fails_on_high(tmp_path, capsys):
    path = write(tmp_path, ".mcp.json", DIRTY)
    assert main([path, "--fail-on", "high"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "MCP001" in out
    assert "CRITICAL" in out


def test_without_fail_on_exit_is_zero(tmp_path, capsys):
    path = write(tmp_path, ".mcp.json", DIRTY)
    assert main([path]) == EXIT_CLEAN
    capsys.readouterr()


def test_fail_on_critical_ignores_high(tmp_path, capsys):
    path = write(tmp_path, ".mcp.json", CLEAN.replace("@2025.8.15", ""))
    assert main([path, "--fail-on", "critical"]) == EXIT_CLEAN
    capsys.readouterr()


def test_json_format_is_machine_readable(tmp_path, capsys):
    path = write(tmp_path, ".mcp.json", DIRTY)
    assert main([path, "--format", "json"]) == EXIT_CLEAN
    payload = json.loads(capsys.readouterr().out)
    assert payload["server_count"] == 1
    assert payload["score"] < 100
    assert payload["findings"]


def test_markdown_format(tmp_path, capsys):
    path = write(tmp_path, ".mcp.json", DIRTY)
    assert main([path, "--format", "markdown"]) == EXIT_CLEAN
    assert "# mcpseal report" in capsys.readouterr().out


def test_list_rules(capsys):
    assert main(["--list-rules"]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "MCP001" in out
    assert "MCP016" in out


def test_output_file(tmp_path, capsys):
    path = write(tmp_path, ".mcp.json", DIRTY)
    out_path = str(tmp_path / "report.json")
    assert main([path, "--format", "json", "--quiet", "--output", out_path]) == EXIT_CLEAN
    assert capsys.readouterr().out == ""
    with open(out_path, encoding="utf-8") as handle:
        assert json.load(handle)["server_count"] == 1


def test_missing_target_is_usage_error(tmp_path, capsys):
    assert main([str(tmp_path / "nope")]) == EXIT_USAGE
    assert "no such file" in capsys.readouterr().err


def test_empty_project_is_usage_error(tmp_path, capsys):
    (tmp_path / "src").mkdir()
    assert main([str(tmp_path)]) == EXIT_USAGE
    assert "no MCP configuration found" in capsys.readouterr().err


def test_invalid_config_is_usage_error(tmp_path, capsys):
    path = write(tmp_path, "mcp.json", "{ not json")
    assert main([path]) == EXIT_USAGE
    assert "not valid JSON" in capsys.readouterr().err
