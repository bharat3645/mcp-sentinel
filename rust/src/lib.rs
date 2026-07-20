//! mcp-sentinel: offline risk scanner + lockfile for MCP client configs.
//!
//! This is a Rust port of the reference Python implementation
//! (`mcp_sentinel/` at the repo root). Same semantics, same JSON schema,
//! same lockfile format, same subcommands — a second, faster, single-binary
//! way to run the same tool. See `canonical.rs` for how hash-compatibility
//! with the Python lockfiles is maintained.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod lockfile;
pub mod rules;
pub mod scanner;

// Read from Cargo.toml at compile time rather than duplicated as a string
// literal - a hardcoded copy here is exactly how it drifted from the
// package version before (Cargo.toml said 0.3.0, this said 0.1.0, and
// `--version`/`generatedBy` both used this constant, not Cargo's).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
