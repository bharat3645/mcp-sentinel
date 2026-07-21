# Contributing to mcp-sentinel

Thanks for looking under the hood. This project values small, verifiable changes.

## Ground rules

- **Every change ships with evidence.** Bug fix → a test that fails without it. Feature → tests that pin its behavior AND its failure modes. This repo documents what it *doesn't* do as carefully as what it does — PRs that quietly widen claims get asked to narrow them.
- **Zero new dependencies without an issue discussing why first.** The Python CLI is stdlib-only (Python 3.9+, no pip packages) — that's a deliberate feature, not an oversight. The Rust CLI already depends on `serde_json`, `sha2`, and `regex` (see `rust/Cargo.toml`), so it isn't dependency-free, but the same bar applies: any *new* crate needs a reason on record before a PR adds it.
- **Honest docs.** If your change has a limitation, the README states it. "Documented honestly" beats "silently best-effort".

## Getting started

This repo has two implementations of the same CLI — a Python package (`mcp_sentinel/`) and a Rust port (`rust/`). Run both test suites before opening a PR.

Python:

```sh
python -m unittest discover -s tests -v
```

Rust:

```sh
cd rust && cargo test --all-targets
```

CI runs the same two commands (plus a lock/verify dogfood roundtrip, `cargo clippy --all-targets -- -D warnings`, a Rust binary smoke test, and a live cross-language diff job that checks the two CLIs against each other); green CI is required, no exceptions (including for maintainers — check the history: it's how the whole repo was built).

## Good first issues

Issues tagged `good-first-issue` are scoped to be completable without deep context; each states the acceptance evidence expected. If you want one and it's unclear, comment — you'll get a response, not silence.

## Reporting security issues

Email 404ghost.2@gmail.com rather than opening a public issue. You'll get an acknowledgment within 48h and honest handling: if it's real, it ships as a fix with credit; if it's out of threat model, the threat-model doc gets clearer about why.
