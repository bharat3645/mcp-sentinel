"""Lockfile + drift detection for MCP client configs ("npm audit" meets "package-lock").

`sentinel lock` records a fingerprint of every configured server: its launch
command, args, the *names* (never values) of its env vars, and optionally a
hash of the server's `tools/list` response captured by the user. `sentinel
verify` then detects drift against that lockfile.

Why this matters: the rug-pull attack shape (e.g. postmark-mcp) ships N clean
versions, then silently changes behavior -- a changed launch line, a new env
var grab, or a mutated tool description. A lockfile turns "silently changed"
into a failing CI check.

Design constraints, same as the scanner:
- Zero network calls. Tool schemas are hashed from a JSON file the *user*
  captured (e.g. the raw `tools/list` response); sentinel never talks to the
  server itself.
- Env var VALUES are never written to the lockfile and never hashed -- only
  key names are recorded. Hashing secret values would make the lockfile an
  offline dictionary-attack target.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

LOCKFILE_VERSION = 1
DEFAULT_LOCKFILE_NAME = "mcp-sentinel.lock"

# Drift kinds -> severity. command/args/tools changes are the rug-pull shape.
DRIFT_SEVERITY = {
    "command-changed": "critical",
    "args-changed": "critical",
    "tools-changed": "critical",
    "env-keys-changed": "high",
    "server-added": "high",
    "server-removed": "medium",
    "tools-not-in-lock": "info",
}


class LockError(ValueError):
    """Raised for unreadable/invalid lockfiles or tools captures."""


@dataclass(frozen=True)
class Drift:
    kind: str
    server: str
    message: str

    @property
    def severity(self) -> str:
        return DRIFT_SEVERITY[self.kind]


def _canonical(obj) -> str:
    """Deterministic JSON: sorted keys, no whitespace variance."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def entry_fingerprint(entry: dict) -> dict:
    """Reduce a server entry to the fields that matter for drift detection.

    Env values are deliberately dropped; only sorted key names remain.
    """
    return {
        "command": str(entry.get("command", "")),
        "args": [str(a) for a in (entry.get("args") or [])],
        "envKeys": sorted((entry.get("env") or {}).keys()),
    }


def entry_hash(entry: dict) -> str:
    return _sha256(_canonical(entry_fingerprint(entry)))


def normalize_tools(tools_doc) -> list:
    """Accept a raw `tools/list` response ({\"tools\": [...]}) or a bare list.

    Normalizes to the drift-relevant surface of each tool -- name,
    description, and inputSchema -- sorted by name, so key order and
    transport wrappers don't produce false drift.
    """
    if isinstance(tools_doc, dict):
        tools = tools_doc.get("tools")
        if tools is None and "result" in tools_doc:
            tools = (tools_doc.get("result") or {}).get("tools")
    else:
        tools = tools_doc
    if not isinstance(tools, list):
        raise LockError(
            "Tools capture must be a tools/list response object or a JSON "
            "array of tool definitions."
        )
    normalized = []
    for t in tools:
        if not isinstance(t, dict):
            raise LockError("Each tool definition must be a JSON object.")
        normalized.append(
            {
                "name": t.get("name", ""),
                "description": t.get("description", ""),
                "inputSchema": t.get("inputSchema", t.get("input_schema", {})),
            }
        )
    normalized.sort(key=lambda t: t["name"])
    return normalized


def tools_hash(tools_doc) -> str:
    return _sha256(_canonical(normalize_tools(tools_doc)))


def build_lock(entries: dict, tools_docs: dict | None = None, version: str = "") -> dict:
    """Build a lockfile dict from config server entries.

    tools_docs: optional {server_name: parsed tools/list JSON}.
    """
    tools_docs = tools_docs or {}
    unknown = set(tools_docs) - set(entries)
    if unknown:
        raise LockError(
            "Tools capture given for server(s) not present in the config: "
            + ", ".join(sorted(unknown))
        )
    servers = {}
    for name, entry in sorted(entries.items()):
        if not isinstance(entry, dict):
            continue
        fp = entry_fingerprint(entry)
        servers[name] = {
            "command": fp["command"],
            "args": fp["args"],
            "envKeys": fp["envKeys"],
            "entryHash": entry_hash(entry),
            "toolsHash": tools_hash(tools_docs[name]) if name in tools_docs else None,
        }
    return {
        "lockfileVersion": LOCKFILE_VERSION,
        "generatedBy": f"mcp-sentinel {version}".strip(),
        "servers": servers,
    }


def write_lock(lock: dict, path: Path) -> None:
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_lock(path: Path) -> dict:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LockError(f"Cannot read lockfile {path}: {exc}") from exc
    if not isinstance(lock, dict) or "servers" not in lock:
        raise LockError(f"{path} does not look like an mcp-sentinel lockfile.")
    if lock.get("lockfileVersion") != LOCKFILE_VERSION:
        raise LockError(
            f"Unsupported lockfileVersion {lock.get('lockfileVersion')!r} "
            f"(this build supports {LOCKFILE_VERSION})."
        )
    return lock


def verify_lock(entries: dict, lock: dict, tools_docs: dict | None = None) -> list[Drift]:
    """Compare current config entries (and optional tools captures) to a lockfile."""
    tools_docs = tools_docs or {}
    locked = lock["servers"]
    drifts: list[Drift] = []

    for name in sorted(set(locked) - set(entries)):
        drifts.append(
            Drift(
                "server-removed",
                name,
                f"'{name}' is in the lockfile but no longer in the config.",
            )
        )
    for name in sorted(set(entries) - set(locked)):
        drifts.append(
            Drift(
                "server-added",
                name,
                f"'{name}' is in the config but not in the lockfile -- new, "
                "unreviewed server.",
            )
        )

    for name in sorted(set(entries) & set(locked)):
        entry = entries[name]
        if not isinstance(entry, dict):
            continue
        rec = locked[name]
        fp = entry_fingerprint(entry)
        if entry_hash(entry) != rec.get("entryHash"):
            if fp["command"] != rec.get("command"):
                drifts.append(
                    Drift(
                        "command-changed",
                        name,
                        f"'{name}' launch command changed: "
                        f"{rec.get('command')!r} -> {fp['command']!r}.",
                    )
                )
            if fp["args"] != rec.get("args"):
                drifts.append(
                    Drift(
                        "args-changed",
                        name,
                        f"'{name}' launch args changed: "
                        f"{rec.get('args')!r} -> {fp['args']!r}.",
                    )
                )
            if fp["envKeys"] != rec.get("envKeys"):
                drifts.append(
                    Drift(
                        "env-keys-changed",
                        name,
                        f"'{name}' env var set changed: "
                        f"{rec.get('envKeys')!r} -> {fp['envKeys']!r} -- "
                        "check what the new variables expose.",
                    )
                )

        if name in tools_docs:
            current_hash = tools_hash(tools_docs[name])
            locked_hash = rec.get("toolsHash")
            if locked_hash is None:
                drifts.append(
                    Drift(
                        "tools-not-in-lock",
                        name,
                        f"'{name}' has a tools capture now but none was "
                        "recorded in the lockfile -- re-run `lock` to pin it.",
                    )
                )
            elif current_hash != locked_hash:
                drifts.append(
                    Drift(
                        "tools-changed",
                        name,
                        f"'{name}' tool schema drifted from the locked hash "
                        "-- tool names, descriptions, or input schemas "
                        "changed since you locked. This is the rug-pull "
                        "shape: re-review before trusting.",
                    )
                )
    return drifts
