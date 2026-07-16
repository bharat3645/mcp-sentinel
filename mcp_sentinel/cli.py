"""Command-line entrypoint: `mcp-sentinel scan|lock|verify`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .lockfile import (
    DEFAULT_LOCKFILE_NAME,
    LockError,
    build_lock,
    read_lock,
    verify_lock,
    write_lock,
)
from .scanner import (
    ConfigError,
    ScanReport,
    discover_config_paths,
    find_server_entries,
    load_config,
    scan_file,
)

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


def _parse_tools_args(pairs: list[str]) -> dict:
    """Parse repeated --tools NAME=PATH options into {name: parsed JSON}."""
    docs = {}
    for pair in pairs:
        name, sep, raw_path = pair.partition("=")
        if not sep or not name or not raw_path:
            raise LockError(
                f"--tools expects NAME=PATH (a server name and a JSON file "
                f"of its tools/list response), got: {pair!r}"
            )
        path = Path(raw_path)
        try:
            docs[name] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LockError(f"Cannot read tools capture {path}: {exc}") from exc
    return docs


def _cmd_scan(args) -> int:
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


def _cmd_lock(args) -> int:
    config_path = Path(args.config)
    try:
        entries = find_server_entries(load_config(config_path))
        tools_docs = _parse_tools_args(args.tools)
        lock = build_lock(entries, tools_docs, version=__version__)
    except (ConfigError, LockError, OSError) as exc:
        print(f"mcp-sentinel lock: {exc}", file=sys.stderr)
        return 2

    out = Path(args.output) if args.output else config_path.parent / DEFAULT_LOCKFILE_NAME
    write_lock(lock, out)
    pinned = sum(1 for s in lock["servers"].values() if s["toolsHash"])
    print(
        f"Locked {len(lock['servers'])} server(s) -> {out} "
        f"({pinned} with tool-schema hashes)"
    )
    if pinned < len(lock["servers"]):
        print(
            "Tip: pass --tools NAME=tools.json (a captured tools/list "
            "response) to also pin tool schemas -- that's what catches "
            "rug-pull tool mutations."
        )
    return 0


def _cmd_verify(args) -> int:
    config_path = Path(args.config)
    lock_path = (
        Path(args.lock) if args.lock else config_path.parent / DEFAULT_LOCKFILE_NAME
    )
    try:
        entries = find_server_entries(load_config(config_path))
        lock = read_lock(lock_path)
        tools_docs = _parse_tools_args(args.tools)
        drifts = verify_lock(entries, lock, tools_docs)
    except (ConfigError, LockError, OSError) as exc:
        print(f"mcp-sentinel verify: {exc}", file=sys.stderr)
        return 2

    if not drifts:
        print(f"OK: {config_path} matches {lock_path} -- no drift.")
        return 0

    print(f"DRIFT: {config_path} no longer matches {lock_path}:\n")
    ordered = sorted(drifts, key=lambda d: SEVERITY_ORDER.index(d.severity))
    for d in ordered:
        print(f"   {SEVERITY_ICON[d.severity]} {d.kind}: {d.message}")
    print(
        "\nIf these changes are expected and reviewed, re-pin with: "
        f"mcp-sentinel lock {config_path}"
    )
    blocking = [d for d in drifts if d.severity != "info"]
    return 1 if blocking else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-sentinel",
        description=(
            "Offline risk scanner + lockfile for MCP client configs. Reads "
            "local JSON files only -- no network calls, ever."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
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

    lock_p = sub.add_parser(
        "lock",
        help="Pin every configured server (and optionally its tool schemas) "
        "to a lockfile",
    )
    lock_p.add_argument("config", help="Path to the MCP config JSON file")
    lock_p.add_argument(
        "-o",
        "--output",
        default=None,
        help=f"Lockfile path (default: {DEFAULT_LOCKFILE_NAME} next to the config)",
    )
    lock_p.add_argument(
        "--tools",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Captured tools/list JSON for server NAME; hash is pinned in "
        "the lockfile (repeatable)",
    )

    verify_p = sub.add_parser(
        "verify",
        help="Detect drift between a config (and optional tools captures) "
        "and the lockfile; exit 1 on drift",
    )
    verify_p.add_argument("config", help="Path to the MCP config JSON file")
    verify_p.add_argument(
        "--lock",
        default=None,
        help=f"Lockfile path (default: {DEFAULT_LOCKFILE_NAME} next to the config)",
    )
    verify_p.add_argument(
        "--tools",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Captured tools/list JSON for server NAME to check against the "
        "pinned hash (repeatable)",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "lock":
        return _cmd_lock(args)
    if args.command == "verify":
        return _cmd_verify(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
