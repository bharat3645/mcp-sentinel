# mcp-sentinel

Offline risk scanner for [MCP](https://modelcontextprotocol.io) (Model Context
Protocol) client configs. Point it at a `claude_desktop_config.json`,
`.cursor/mcp.json`, `.vscode/mcp.json`, or any file using the same
`mcpServers` shape, and it grades every configured server A-F based on
concrete, explainable risk signals in how it's launched and configured.

**Zero network calls. Zero third-party dependencies.** It only reads the
JSON file(s) you point it at — it never contacts a registry, never executes
the servers it's scanning, and never phones home. That's a deliberate design
choice: a tool meant to catch supply-chain risk shouldn't introduce its own.

## Why

MCP adoption has exploded through 2026 as the standard interoperability
layer between AI agents and tools, which also means MCP server configs are
now a real attack surface: floating `@latest` package pins that can change
silently, servers launched through a shell with obscured commands,
credentials pasted directly into config files, and typosquatted package
names. Most of that is invisible at a glance in a JSON file. `mcp-sentinel`
makes it visible.

## Install

```bash
git clone https://github.com/bharat3645/mcp-sentinel.git
cd mcp-sentinel
pip install -e .
```

Requires Python 3.9+. No other dependencies.

## Usage

```bash
# Scan a specific config file
mcp-sentinel scan ./mcp.json

# Scan common client config locations automatically (read-only, best-effort)
mcp-sentinel scan --auto

# Scan multiple files, and fail (non-zero exit) if any overall score is below 70
# -- handy in a pre-commit hook or CI job
mcp-sentinel scan ./mcp.json ./.cursor/mcp.json --fail-under 70
```

Example output:

```
tests/fixtures/risky.json
==========================

shell-wrapper  ->  grade D (45/100)
   [CRIT] INLINE_SECRET: 'shell-wrapper' has what looks like a live credential hardcoded directly in env['GITHUB_TOKEN'] instead of referencing an environment variable or secret store.
   [HIGH] SHELL_INDIRECTION: 'shell-wrapper' launches through a shell (bash) instead of invoking the server binary directly, which hides the real command from anyone reviewing the config at a glance.
   [HIGH] SHELL_METACHARACTERS: 'shell-wrapper' contains shell metacharacters (;, &, |, or `$(...)`) in its command/args, which usually means multiple commands are being chained where only one server launch is expected.
   [INFO] NO_PROVENANCE_NOTE: 'shell-wrapper' has no description/comment noting where it came from or why it's trusted -- harmless, but makes future review harder.

sketchy-fs  ->  grade C (69/100)
   [HIGH] POSSIBLE_TYPOSQUAT: 'sketchy-fs' uses package '@modelcontextprotocol/server-filesytem', which is suspiciously similar to the well-known '@modelcontextprotocol/server-filesystem' (99% match) but not identical -- verify this isn't a typosquat.
   [MED]  UNPINNED_VERSION: 'sketchy-fs' launches '@modelcontextprotocol/server-filesytem' via npx with no version pin, so it resolves to whatever is newest at launch time.
   [MED]  BROAD_FS_SCOPE: 'sketchy-fs' is granted '/' as a filesystem root, which is far broader than most MCP filesystem servers need -- scope it to a specific project directory instead.
   [INFO] NO_PROVENANCE_NOTE: 'sketchy-fs' has no description/comment noting where it came from or why it's trusted -- harmless, but makes future review harder.

floating  ->  grade B (85/100)
   [HIGH] LATEST_TAG: 'floating' pins its package to @latest, so the exact code that runs can change silently on every launch with no review step.
   [INFO] NO_PROVENANCE_NOTE: 'floating' has no description/comment noting where it came from or why it's trusted -- harmless, but makes future review harder.

Overall: grade C (66/100)
```

## What it checks

| Rule | Severity | What it catches |
|---|---|---|
| `INLINE_SECRET` | critical | A live-looking credential (GitHub token, AWS key, Stripe key, Slack token, etc.) hardcoded directly in `env` instead of referenced via `${VAR}` |
| `LATEST_TAG` | high | Package pinned to `@latest`, so the code that runs can change without review |
| `SHELL_INDIRECTION` | high | Server launched via `bash -c` / `sh -c` / etc., which hides the real command |
| `SHELL_METACHARACTERS` | high | `;`, `&`, `\|`, or `` `$(...)` `` in the command/args, suggesting chained commands |
| `POSSIBLE_TYPOSQUAT` | high | Package name is a near-miss (80-99% similar) to a well-known MCP server package |
| `UNPINNED_VERSION` | medium | `npx`/`uvx`/`pipx` invocation with no version pin at all |
| `BROAD_FS_SCOPE` | medium | Filesystem server granted a root as broad as `/`, `~`, or `/etc` |
| `NO_PROVENANCE_NOTE` | info | No description/comment noting where the server came from |

Grading: each server starts at 100 and loses points per finding (critical
−25, high −15, medium −8, low −3, info −0), floored at 0. 90+ is an A, 75+ a
B, 60+ a C, 40+ a D, below that an F. The overall grade is the average
across all servers in the file.

## What it deliberately does *not* do

- No network calls, ever — it won't hit npm/PyPI to check if a package
  actually exists or has known CVEs. That's a reasonable follow-up (see
  below) but changes the trust model of the tool itself, so it's out of
  scope for v0.1.
- No execution of the scanned commands.
- No allowlist/denylist of "safe" MCP servers — the typosquat check is
  similarity-based, not a verdict.

## Development

```bash
python -m unittest discover -s tests -v
```

19 tests, stdlib `unittest` only (no `pytest` dependency required).

## Contributing

Issues and PRs welcome, especially new heuristic rules — see
`mcp_sentinel/rules.py` for the pattern (a rule is just a function that
takes a server name and its config dict and returns a `Finding` or `None`).

## License

MIT — see [LICENSE](./LICENSE).
