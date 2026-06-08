"""Command-line interface for CORSAUDIT.

Subcommands:
  headers   Analyze a captured response-header block (file or stdin).
  config    Analyze a declarative CORS config (JSON file or stdin).

Global options:
  --version            Print tool name + version and exit.
  --format {table,json}

Exit codes:
  0  no findings
  1  one or more findings reported
  2  usage / input error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Finding,
    SEVERITY_ORDER,
    analyze_config,
    analyze_headers,
    parse_header_block,
)


def _read_input(path: Optional[str]) -> str:
    if path is None or path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _render_table(findings: List[Finding]) -> str:
    if not findings:
        return "No CORS misconfigurations detected."
    lines = []
    header = "{:<8} {:<9} {}".format("RULE", "SEVERITY", "TITLE")
    lines.append(header)
    lines.append("-" * len(header))
    for f in findings:
        lines.append("{:<8} {:<9} {}".format(f.rule, f.severity.upper(), f.title))
        if f.origin:
            lines.append("           origin: {}".format(f.origin))
        lines.append("           {}".format(f.detail))
        if f.remediation:
            lines.append("           fix: {}".format(f.remediation))
        lines.append("")
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(
        "{} {}".format(counts[s], s)
        for s in sorted(counts, key=lambda x: SEVERITY_ORDER.get(x, 0), reverse=True)
    )
    lines.append("Summary: {} finding(s) [{}]".format(len(findings), summary))
    return "\n".join(lines)


def _render_json(findings: List[Finding]) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "finding_count": len(findings),
        "max_severity": (
            max((f.severity for f in findings), key=lambda s: SEVERITY_ORDER.get(s, 0))
            if findings
            else None
        ),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def _output(findings: List[Finding], fmt: str) -> None:
    if fmt == "json":
        print(_render_json(findings))
    else:
        print(_render_table(findings))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Detect permissive/misconfigured CORS from captured response "
            "headers or a config. Defensive analysis only -- performs no "
            "network requests."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version="{} {}".format(TOOL_NAME, TOOL_VERSION),
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table).",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_headers = sub.add_parser(
        "headers",
        help="Analyze a captured 'Name: value' response-header block.",
    )
    p_headers.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Path to header file, or '-' for stdin (default).",
    )
    p_headers.add_argument(
        "--origin",
        help="The Origin header that was sent in the probe request (enables reflection checks).",
    )

    p_config = sub.add_parser(
        "config",
        help="Analyze a declarative CORS config from a JSON file.",
    )
    p_config.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Path to JSON config, or '-' for stdin (default).",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "headers":
            text = _read_input(args.input)
            headers = parse_header_block(text)
            if not headers:
                print("error: no parseable headers in input", file=sys.stderr)
                return 2
            findings = analyze_headers(headers, request_origin=args.origin)
        elif args.command == "config":
            text = _read_input(args.input)
            try:
                config = json.loads(text)
            except json.JSONDecodeError as exc:
                print("error: invalid JSON config: {}".format(exc), file=sys.stderr)
                return 2
            if not isinstance(config, dict):
                print("error: config must be a JSON object", file=sys.stderr)
                return 2
            findings = analyze_config(config)
        else:  # pragma: no cover - argparse enforces this
            parser.error("unknown command")
            return 2
    except FileNotFoundError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    _output(findings, args.format)
    return 1 if findings else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
