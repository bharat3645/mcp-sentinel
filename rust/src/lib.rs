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

pub const VERSION: &str = "0.1.0";
