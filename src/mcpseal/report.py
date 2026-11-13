"""Scoring and rendering.

The score is a *health* score: it starts at 100 and subtracts a fixed weight per
finding, so it is reproducible and explainable instead of a mystery number. The
weights are steep on purpose - one critical finding should be enough to fail a
build.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from . import __version__
from .config import ServerSpec
from .rules import Finding, count_by_severity

WEIGHTS = {"critical": 40, "high": 18, "medium": 7, "low": 3, "info": 0}

GRADE_BANDS = (
    (95, "A+"),
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
)

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def health_score(findings: List[Finding]) -> int:
    """100 minus the weighted cost of every finding, floored at zero."""
    penalty = sum(WEIGHTS.get(finding.severity, 0) for finding in findings)
    return max(0, 100 - penalty)


def grade_for(score: int) -> str:
    for threshold, grade in GRADE_BANDS:
        if score >= threshold:
            return grade
    return "F"


def build_report(
    servers: List[ServerSpec],
    findings: List[Finding],
    files: List[str],
    target: str,
) -> Dict[str, Any]:
    """Assemble everything the renderers need."""
    score = health_score(findings)
    counts = count_by_severity(findings)
    flagged = {finding.server for finding in findings}
    disabled = [server.name for server in servers if server.disabled]
    clean = [
        server.name
        for server in servers
        if not server.disabled and server.name not in flagged
    ]
    return {
        "tool": "mcpseal",
        "version": __version__,
        "target": target,
        "files": files,
        "servers": [
            {
                "name": server.name,
                "client": server.client,
                "transport": server.transport,
                "disabled": server.disabled,
                "command": server.command,
                "args": server.args,
                "url": server.url,
            }
            for server in servers
        ],
        "server_count": len(servers),
        "disabled_servers": disabled,
        "clean_servers": clean,
        "score": score,
        "grade": grade_for(score),
        "counts": counts,
        "findings": [
            {
                "rule": finding.rule_id,
                "severity": finding.severity,
                "title": finding.title,
                "server": finding.server,
                "source": finding.source,
                "evidence": finding.evidence,
                "why": finding.why,
                "fix": finding.fix,
                "ref": finding.ref,
            }
            for finding in findings
        ],
    }


def _wrap(text: str, width: int, label: str) -> str:
    """Wrap ``text`` after ``label`` and align every continuation with it."""
    indent = " " * len(label)
    words = text.split()
    line = ""
    lines: List[str] = []
    for word in words:
        candidate = (line + " " + word).strip()
        if len(candidate) > width and line:
            lines.append(line)
            line = word
        else:
            line = candidate
    if line:
        lines.append(line)
    if not lines:
        return label.rstrip()
    rendered = [label + lines[0]]
    rendered.extend(indent + extra for extra in lines[1:])
    return "\n".join(rendered)


def render_text(report: Dict[str, Any]) -> str:
    rule_line = "=" * 78
    thin = "-" * 78
    out: List[str] = []
    out.append(rule_line)
    out.append("mcpseal  offline MCP configuration security audit")
    out.append(rule_line)
    out.append("Target       : %s" % report["target"])
    out.append("Config files : %d" % len(report["files"]))
    for path in report["files"]:
        out.append("               %s" % path)
    out.append("Servers      : %d" % report["server_count"])
    if report["disabled_servers"]:
        out.append("Disabled     : %s" % ", ".join(report["disabled_servers"]))
    counts = report["counts"]
    out.append(
        "Score        : %d/100  grade %s" % (report["score"], report["grade"])
    )
    out.append(
        "Findings     : %d critical, %d high, %d medium, %d low, %d info"
        % (
            counts.get("critical", 0),
            counts.get("high", 0),
            counts.get("medium", 0),
            counts.get("low", 0),
            counts.get("info", 0),
        )
    )

    if not report["servers"]:
        out.append("")
        out.append("No MCP servers are registered in the files that were found.")
        out.append("")
        return "\n".join(out)

    for finding in report["findings"]:
        out.append("")
        out.append(thin)
        out.append(
            "[%s] %s  %s"
            % (SEVERITY_LABEL.get(finding["severity"], finding["severity"].upper()),
               finding["rule"], finding["title"])
        )
        out.append("  Server   : %s" % finding["server"])
        for index, evidence in enumerate(finding["evidence"]):
            prefix = "  Evidence : " if index == 0 else "             "
            out.append(prefix + evidence)
        out.append(_wrap(finding["why"], 62, "  Why      : "))
        out.append(_wrap(finding["fix"], 62, "  Fix      : "))
        if finding["ref"]:
            out.append("  Ref      : %s" % finding["ref"])

    out.append("")
    out.append(thin)
    clean = report["clean_servers"]
    if clean:
        out.append("No findings : %s" % ", ".join(clean))
    if report["findings"]:
        out.append(
            "Result      : %d finding(s) across %d of %d server(s)"
            % (
                len(report["findings"]),
                len({finding["server"] for finding in report["findings"]}),
                report["server_count"],
            )
        )
    else:
        out.append("Result      : clean - no rule matched any registered server")
    out.append("")
    return "\n".join(out)


def render_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# mcpseal report")
    lines.append("")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append("| Target | `%s` |" % report["target"])
    lines.append("| Config files | %d |" % len(report["files"]))
    lines.append("| Servers | %d |" % report["server_count"])
    lines.append("| Score | **%d/100** (grade %s) |" % (report["score"], report["grade"]))
    counts = report["counts"]
    lines.append(
        "| Findings | %d critical, %d high, %d medium, %d low, %d info |"
        % (
            counts.get("critical", 0),
            counts.get("high", 0),
            counts.get("medium", 0),
            counts.get("low", 0),
            counts.get("info", 0),
        )
    )
    lines.append("")
    if report["findings"]:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Rule | Severity | Server | Title |")
        lines.append("|---|---|---|---|")
        for finding in report["findings"]:
            lines.append(
                "| `%s` | %s | `%s` | %s |"
                % (finding["rule"], finding["severity"], finding["server"], finding["title"])
            )
        lines.append("")
        for finding in report["findings"]:
            lines.append(
                "### `%s` %s on `%s`" % (finding["rule"], finding["title"], finding["server"])
            )
            lines.append("")
            lines.append("- **Severity:** %s" % finding["severity"])
            for evidence in finding["evidence"]:
                lines.append("- **Evidence:** %s" % evidence)
            lines.append("- **Why:** %s" % finding["why"])
            lines.append("- **Fix:** %s" % finding["fix"])
            if finding["ref"]:
                lines.append("- **Reference:** %s" % finding["ref"])
            lines.append("")
    else:
        lines.append("No rule matched any registered server.")
        lines.append("")
    return "\n".join(lines)


def render_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=False)


def render(
    report: Dict[str, Any], fmt: str = "text", path: Optional[str] = None
) -> str:
    if fmt == "json":
        body = render_json(report)
    elif fmt == "markdown":
        body = render_markdown(report)
    else:
        body = render_text(report)
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body + ("\n" if not body.endswith("\n") else ""))
    return body
