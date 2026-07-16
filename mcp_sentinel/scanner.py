"""Load an MCP client config and grade its risk, server by server."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .rules import SEVERITY_WEIGHTS, Finding, evaluate_entry

# Common config locations across MCP clients, checked in --auto mode.
# Read-only, best-effort: a path that doesn't exist is silently skipped.
COMMON_CONFIG_PATHS = [
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.config/Claude/claude_desktop_config.json",
    "%APPDATA%/Claude/claude_desktop_config.json",
    ".cursor/mcp.json",
    "~/.cursor/mcp.json",
    ".vscode/mcp.json",
    ".mcp.json",
]


class ConfigError(ValueError):
    """Raised when a file doesn't look like a recognizable MCP config."""


@dataclass
class ServerReport:
    name: str
    findings: list[Finding]

    @property
    def score(self) -> int:
        deduction = sum(SEVERITY_WEIGHTS[f.severity] for f in self.findings)
        return max(0, 100 - deduction)

    @property
    def grade(self) -> str:
        return score_to_grade(self.score)


@dataclass
class ScanReport:
    source: str
    servers: list[ServerReport] = field(default_factory=list)

    @property
    def overall_score(self) -> int:
        if not self.servers:
            return 100
        return round(sum(s.score for s in self.servers) / len(self.servers))

    @property
    def overall_grade(self) -> str:
        return score_to_grade(self.overall_score)


def score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def find_server_entries(config: dict) -> dict:
    """Support the two shapes MCP clients commonly use."""
    if "mcpServers" in config and isinstance(config["mcpServers"], dict):
        return config["mcpServers"]
    if "servers" in config and isinstance(config["servers"], dict):
        return config["servers"]
    raise ConfigError(
        "No 'mcpServers' or 'servers' object found -- doesn't look like an "
        "MCP client config."
    )


def load_config(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Not valid JSON: {exc}") from exc


def scan_file(path: Path) -> ScanReport:
    config = load_config(path)
    entries = find_server_entries(config)
    report = ScanReport(source=str(path))
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        findings = evaluate_entry(name, entry)
        report.servers.append(ServerReport(name=name, findings=findings))
    return report


def discover_config_paths() -> list[Path]:
    found = []
    for raw in COMMON_CONFIG_PATHS:
        expanded = os.path.expandvars(os.path.expanduser(raw))
        p = Path(expanded)
        if p.is_file():
            found.append(p)
    return found
