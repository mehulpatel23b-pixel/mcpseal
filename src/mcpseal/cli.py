"""Command line interface for mcpseal."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .config import ConfigError, parse_file
from .discovery import default_global_paths, discover
from .report import build_report, render
from .rules import RULES, SEVERITY_ORDER, evaluate

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpseal",
        description=(
            "Offline security audit for MCP (Model Context Protocol) server configuration. "
            "Reads claude_desktop_config.json, .mcp.json, .cursor/mcp.json, .vscode/mcp.json and "
            "friends, then reports explainable findings with the exact fix. No network, no "
            "server launch, no dependencies."
        ),
        epilog=(
            "Examples:\n"
            "  mcpseal .                       # audit every known config in this project\n"
            "  mcpseal ~/.cursor/mcp.json      # audit one file\n"
            "  mcpseal . --fail-on high        # CI gate: exit 1 on high or worse\n"
            "  mcpseal . --format json > out.json\n"
            "  mcpseal --list-rules\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="config file or project directory to audit (default: .)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "markdown", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="PATH",
        help="also write the report to PATH",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none",) + tuple(SEVERITY_ORDER),
        default="none",
        help="exit with status 1 when a finding at or above this severity exists (default: none)",
    )
    parser.add_argument(
        "--global",
        dest="use_global",
        action="store_true",
        help="also audit well-known per-user config locations for this machine",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="print the rule set and exit",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the report; only the exit code matters",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="mcpseal %s" % __version__,
    )
    return parser


def list_rules_text() -> str:
    lines = ["mcpseal rule set (%d rules)" % len(RULES), ""]
    for rule in RULES:
        lines.append("%s  %-8s %s" % (rule.id, rule.severity.upper(), rule.title))
        lines.append("        fix: %s" % rule.fix)
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        print(list_rules_text())
        return EXIT_CLEAN

    try:
        files = discover(args.target)
    except ConfigError as exc:
        print("mcpseal: %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    if args.use_global:
        for path in default_global_paths(os.path.expanduser("~")):
            if os.path.isfile(path) and path not in files:
                files.append(path)

    if not files:
        print(
            "mcpseal: no MCP configuration found under %s\n"
            "Looked for: .mcp.json, .cursor/mcp.json, .vscode/mcp.json, "
            ".windsurf/mcp.json, .kiro/settings/mcp.json, claude_desktop_config.json, "
            "mcp.json" % args.target,
            file=sys.stderr,
        )
        return EXIT_USAGE

    servers = []
    for path in files:
        try:
            servers.extend(parse_file(path))
        except ConfigError as exc:
            print("mcpseal: %s" % exc, file=sys.stderr)
            return EXIT_USAGE

    findings = evaluate(servers, root=args.target if os.path.isdir(args.target) else None)
    report = build_report(servers, findings, files, args.target)

    if not args.quiet:
        body = render(report, fmt=args.format, path=args.output)
        print(body)
    elif args.output:
        render(report, fmt=args.format, path=args.output)

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in findings):
            return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
