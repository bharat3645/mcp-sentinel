# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [0.2.0] - 2026-07-16

### Added
- **`mcp-sentinel lock`** — pins every configured server to `mcp-sentinel.lock`:
  launch command, args, env var *names* (values are never stored or hashed —
  hashing secrets would make the lockfile a dictionary-attack target), a
  canonical entry hash, and optionally a **tool-schema hash** from a captured
  `tools/list` response (`--tools NAME=PATH`, repeatable).
- **`mcp-sentinel verify`** — drift detection against the lockfile; exit 1 on
  blocking drift, 2 on errors. Detects the rug-pull attack shape:
  - `command-changed` / `args-changed` / `tools-changed` → critical
  - `env-keys-changed` / `server-added` → high
  - `server-removed` → medium; unpinned tools capture → info
- Tool-schema hashing is order- and wrapper-insensitive (accepts a raw
  `tools/list` response, a JSON-RPC result, or a bare array; sorts by name).
- 18 new tests (suite 19 → 37, stdlib `unittest`).
- GitHub Actions CI (Python 3.9–3.13) — first CI for this repo.
- `--version` flag.

### Changed
- CLI restructured into `scan` / `lock` / `verify` subcommands (`scan`
  behavior unchanged).

## [0.1.0] - 2026-07-16

### Added
- Initial release: `scan` command with 8 heuristic rules (inline secrets,
  @latest pins, shell indirection, metacharacters, typosquat similarity,
  unpinned versions, broad FS scope, provenance notes), A–F grading,
  `--auto` config discovery, `--fail-under` CI gate, 19 stdlib tests.
