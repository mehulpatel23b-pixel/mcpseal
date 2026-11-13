"""Report tests: score, grade, and the three renderers."""

import json

from mcpseal.config import ServerSpec
from mcpseal.report import (
    build_report,
    grade_for,
    health_score,
    render_json,
    render_markdown,
    render_text,
)
from mcpseal.rules import Finding, evaluate


def finding(rule_id="MCP001", severity="critical", server="srv"):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="t",
        server=server,
        source="/tmp/mcp.json",
        evidence=["e"],
        why="w",
        fix="f",
        ref="r",
    )


def test_score_is_100_minus_weighted_findings():
    assert health_score([]) == 100
    assert health_score([finding(severity="high")]) == 82
    assert health_score([finding(severity="critical"), finding(severity="medium")]) == 53


def test_score_never_goes_below_zero():
    assert health_score([finding() for _ in range(10)]) == 0


def test_grade_bands():
    assert grade_for(100) == "A+"
    assert grade_for(92) == "A"
    assert grade_for(84) == "B"
    assert grade_for(72) == "C"
    assert grade_for(61) == "D"
    assert grade_for(0) == "F"


def test_build_report_shape():
    server = ServerSpec(name="files", source="/tmp/mcp.json", client="generic",
                        command="npx", args=["pkg"] )
    findings = evaluate([server])
    report = build_report([server], findings, ["/tmp/mcp.json"], "/tmp")
    assert report["server_count"] == 1
    assert report["counts"]["high"] >= 1
    assert report["grade"] in ("A+", "A", "B", "C", "D", "F")
    assert report["findings"][0]["rule"] == "MCP002"


def test_render_text_contains_rule_and_fix():
    server = ServerSpec(name="files", source="/tmp/mcp.json", client="generic",
                        command="npx", args=["pkg"])
    report = build_report([server], evaluate([server]), ["/tmp/mcp.json"], "/tmp")
    body = render_text(report)
    assert "MCP002" in body
    assert "Fix" in body
    assert "grade" in body


def test_render_json_round_trips():
    report = build_report([], [], [], ".")
    assert json.loads(render_json(report))["score"] == 100


def test_render_markdown_table():
    server = ServerSpec(name="files", source="/tmp/mcp.json", client="generic",
                        command="npx", args=["pkg"])
    report = build_report([server], evaluate([server]), ["/tmp/mcp.json"], "/tmp")
    body = render_markdown(report)
    assert "| Rule | Severity | Server | Title |" in body
    assert "`MCP002`" in body


def test_report_lists_clean_servers():
    clean = ServerSpec(name="ok", source="/tmp/mcp.json", client="generic",
                       command="npx", args=["pkg@1.0.0"])
    report = build_report([clean], evaluate([clean]), ["/tmp/mcp.json"], "/tmp")
    assert report["clean_servers"] == ["ok"]
    assert report["findings"] == []
