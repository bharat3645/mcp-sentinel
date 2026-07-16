"""Heuristic risk rules for a single MCP server config entry.

Each rule is a plain function: (name: str, entry: dict) -> Finding | None.
All rules are purely local/string-based -- no network access, no execution
of the scanned commands. That is a deliberate design constraint so the tool
itself can never become a supply-chain risk.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}

# A small curated list of well-known, legitimate MCP server package names.
# Used only for typosquat *similarity* detection -- never treated as an
# allowlist/denylist of what's safe to run.
KNOWN_PACKAGES = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@playwright/mcp",
]

SECRET_LIKE = re.compile(
    r"^(sk-|ghp_|gho_|ghu_|github_pat_|xox[baprs]-|AKIA|AIza|glpat-)[A-Za-z0-9_\-]{10,}$"
)
SHELL_METACHARS = re.compile(r"[;&|`]|\$\(")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str  # critical | high | medium | low | info
    message: str


def _command_line(entry: dict) -> str:
    cmd = entry.get("command", "")
    args = entry.get("args", []) or []
    try:
        return " ".join([cmd, *[str(a) for a in args]]).strip()
    except TypeError:
        return str(cmd)


def rule_latest_tag(name: str, entry: dict) -> Finding | None:
    line = _command_line(entry)
    if re.search(r"@latest\b", line):
        return Finding(
            "LATEST_TAG",
            "high",
            f"'{name}' pins its package to @latest, so the exact code that "
            "runs can change silently on every launch with no review step.",
        )
    return None


def rule_unpinned_version(name: str, entry: dict) -> Finding | None:
    cmd = entry.get("command", "")
    args = [str(a) for a in (entry.get("args") or [])]
    if cmd not in ("npx", "uvx", "pipx"):
        return None
    # find the package-looking arg (skip flags like -y/--yes)
    pkg_args = [a for a in args if not a.startswith("-")]
    if not pkg_args:
        return None
    pkg = pkg_args[0]
    if "@latest" in pkg:
        return None  # already covered by rule_latest_tag
    has_version = bool(re.search(r"@\d", pkg)) or bool(re.search(r"==", pkg))
    if not has_version:
        return Finding(
            "UNPINNED_VERSION",
            "medium",
            f"'{name}' launches '{pkg}' via {cmd} with no version pin, "
            "so it resolves to whatever is newest at launch time.",
        )
    return None


def rule_inline_secret(name: str, entry: dict) -> Finding | None:
    env = entry.get("env", {}) or {}
    for key, value in env.items():
        if not isinstance(value, str):
            continue
        if value.startswith("${") or value.startswith("$"):
            continue  # references an external var/secret store, not inline
        if SECRET_LIKE.match(value.strip()):
            return Finding(
                "INLINE_SECRET",
                "critical",
                f"'{name}' has what looks like a live credential hardcoded "
                f"directly in env['{key}'] instead of referencing an "
                "environment variable or secret store.",
            )
    return None


def rule_shell_indirection(name: str, entry: dict) -> Finding | None:
    cmd = entry.get("command", "")
    if cmd in ("sh", "bash", "zsh", "cmd", "cmd.exe", "powershell"):
        return Finding(
            "SHELL_INDIRECTION",
            "high",
            f"'{name}' launches through a shell ({cmd}) instead of invoking "
            "the server binary directly, which hides the real command from "
            "anyone reviewing the config at a glance.",
        )
    return None


def rule_command_injection_chars(name: str, entry: dict) -> Finding | None:
    line = _command_line(entry)
    if SHELL_METACHARS.search(line):
        return Finding(
            "SHELL_METACHARACTERS",
            "high",
            f"'{name}' contains shell metacharacters (;, &, |, or `$(...)`) "
            "in its command/args, which usually means multiple commands are "
            "being chained where only one server launch is expected.",
        )
    return None


def rule_broad_filesystem_scope(name: str, entry: dict) -> Finding | None:
    args = [str(a) for a in (entry.get("args") or [])]
    risky_roots = {"/", "~", "C:\\", "/etc", "/Users", "/home"}
    for a in args:
        if a in risky_roots:
            return Finding(
                "BROAD_FS_SCOPE",
                "medium",
                f"'{name}' is granted '{a}' as a filesystem root, which is "
                "far broader than most MCP filesystem servers need -- scope "
                "it to a specific project directory instead.",
            )
    return None


def rule_typosquat_similarity(name: str, entry: dict) -> Finding | None:
    args = [str(a) for a in (entry.get("args") or [])]
    pkg_args = [a for a in args if not a.startswith("-")]
    if not pkg_args:
        return None
    pkg = re.sub(r"@(latest|\d[\w.\-]*)$", "", pkg_args[0])
    if pkg in KNOWN_PACKAGES:
        return None
    for known in KNOWN_PACKAGES:
        ratio = SequenceMatcher(None, pkg, known).ratio()
        if 0.80 <= ratio < 1.0:
            return Finding(
                "POSSIBLE_TYPOSQUAT",
                "high",
                f"'{name}' uses package '{pkg}', which is suspiciously "
                f"similar to the well-known '{known}' ({ratio:.0%} match) "
                "but not identical -- verify this isn't a typosquat.",
            )
    return None


def rule_missing_description(name: str, entry: dict) -> Finding | None:
    if not entry.get("description") and not entry.get("_comment"):
        return Finding(
            "NO_PROVENANCE_NOTE",
            "info",
            f"'{name}' has no description/comment noting where it came from "
            "or why it's trusted -- harmless, but makes future review harder.",
        )
    return None


ALL_RULES = [
    rule_latest_tag,
    rule_unpinned_version,
    rule_inline_secret,
    rule_shell_indirection,
    rule_command_injection_chars,
    rule_broad_filesystem_scope,
    rule_typosquat_similarity,
    rule_missing_description,
]


def evaluate_entry(name: str, entry: dict) -> list[Finding]:
    findings = []
    for rule in ALL_RULES:
        result = rule(name, entry)
        if result is not None:
            findings.append(result)
    return findings
