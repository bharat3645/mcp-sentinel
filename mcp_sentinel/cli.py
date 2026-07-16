"""Command-line entrypoint: `mcp-sentinel scan [path]`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scanner import ConfigError, ScanReport, discover_config_paths, scan_file

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_ICON = {
    "critical": "[CRIT]",
    "high": "[HIGH]",
    "medium": "[MED] ",
    "low": "[LOW] ",
    "info": "[INFO]",
}


def _print_report(report: ScanReport) -> None:
    print(f"\n{report.source}")
    print("=" * len(report.source))
    if not report.servers:
        print("No MCP server entries found.")
        return
    for server in sorted(report.servers, key=lambda s: s.score):
        print(f"\n{server.name}  ->  grade {server.grade} ({server.score}/100)")
        if not server.findings:
            print("   no issues found")
            continue
        ordered = sorted(
            server.findings, key=lambda f: SEVERITY_ORDER.index(f.severity)
        )
        for f in ordered:
            print(f"   {SEVERITY_ICON[f.severity]} {f.rule_id}: {f.message}")
    print(f"\nOverall: grade {report.overall_grade} ({report.overall_score}/100)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-sentinel",
        description=(
            "Offline risk scanner for MCP client configs. Reads local JSON "
            "config files only -- no network calls, ever."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan one or more MCP config files")
    scan_p.add_argument(
        "paths", nargs="*", help="Path(s) to MCP config JSON file(s)"
    )
    scan_p.add_argument(
        "--auto",
        action="store_true",
        help="Also scan common MCP client config locations if they exist",
    )
    scan_p.add_argument(
        "--fail-under",
        type=int,
        default=None,
        help="Exit non-zero if overall score of any file is below this value",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        targets = [Path(p) for p in args.paths]
        if args.auto:
            targets.extend(discover_config_paths())
        if not targets:
            print(
                "No config paths given and none found via --auto. "
                "Pass a path, e.g.: mcp-sentinel scan ./mcp.json",
                file=sys.stderr,
            )
            return 2

        worst_score = 100
        any_ok = False
        for path in targets:
            if not path.is_file():
                print(f"\n{path}: file not found, skipping", file=sys.stderr)
                continue
            try:
                report = scan_file(path)
            except ConfigError as exc:
                print(f"\n{path}: {exc}", file=sys.stderr)
                continue
            _print_report(report)
            worst_score = min(worst_score, report.overall_score)
            any_ok = True

        if not any_ok:
            return 2
        if args.fail_under is not None and worst_score < args.fail_under:
            return 1
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
