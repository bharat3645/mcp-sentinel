//! Load an MCP client config and grade its risk, server by server. Direct
//! port of `mcp_sentinel/scanner.py`.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::rules::{evaluate_entry, severity_weight, Finding};

/// Common config locations across MCP clients, checked in --auto mode.
/// Read-only, best-effort: a path that doesn't exist is silently skipped.
pub const COMMON_CONFIG_PATHS: &[&str] = &[
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.config/Claude/claude_desktop_config.json",
    "%APPDATA%/Claude/claude_desktop_config.json",
    ".cursor/mcp.json",
    "~/.cursor/mcp.json",
    ".vscode/mcp.json",
    ".mcp.json",
];

/// Raised when a file doesn't look like a recognizable MCP config, or
/// can't be read/parsed as JSON at all. Python's `load_config` lets a bare
/// I/O error propagate past `ConfigError`; here both collapse into one
/// type since the CLI layer prints either the same way regardless.
#[derive(Debug, Clone)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ConfigError {}

#[derive(Debug, Clone)]
pub struct ServerReport {
    pub name: String,
    pub findings: Vec<Finding>,
}

impl ServerReport {
    pub fn score(&self) -> i32 {
        let deduction: i32 = self.findings.iter().map(|f| severity_weight(&f.severity)).sum();
        (100 - deduction).max(0)
    }
    pub fn grade(&self) -> &'static str {
        score_to_grade(self.score())
    }
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub source: String,
    pub servers: Vec<ServerReport>,
}

impl ScanReport {
    pub fn overall_score(&self) -> i32 {
        if self.servers.is_empty() {
            return 100;
        }
        let sum: i32 = self.servers.iter().map(|s| s.score()).sum();
        round_half_even(sum as f64 / self.servers.len() as f64)
    }
    pub fn overall_grade(&self) -> &'static str {
        score_to_grade(self.overall_score())
    }
}

pub fn score_to_grade(score: i32) -> &'static str {
    if score >= 90 {
        "A"
    } else if score >= 75 {
        "B"
    } else if score >= 60 {
        "C"
    } else if score >= 40 {
        "D"
    } else {
        "F"
    }
}

/// Python's builtin `round()` uses round-half-to-even ("banker's
/// rounding"), unlike Rust's `f64::round()` which rounds half away from
/// zero. `overall_score` needs the Python behavior so grade boundaries
/// land identically between the two implementations for the same input.
fn round_half_even(x: f64) -> i32 {
    let floor = x.floor();
    let diff = x - floor;
    let floor_i = floor as i64;
    let rounded = if diff < 0.5 {
        floor_i
    } else if diff > 0.5 {
        floor_i + 1
    } else if floor_i % 2 == 0 {
        floor_i
    } else {
        floor_i + 1
    };
    rounded as i32
}

/// Support the two shapes MCP clients commonly use.
pub fn find_server_entries(config: &Value) -> Result<Map<String, Value>, ConfigError> {
    if let Some(Value::Object(m)) = config.get("mcpServers") {
        return Ok(m.clone());
    }
    if let Some(Value::Object(m)) = config.get("servers") {
        return Ok(m.clone());
    }
    Err(ConfigError(
        "No 'mcpServers' or 'servers' object found -- doesn't look like an MCP client \
         config."
            .to_string(),
    ))
}

pub fn load_config(path: &Path) -> Result<Value, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError(format!("{e}")))?;
    serde_json::from_str(&text).map_err(|e| ConfigError(format!("Not valid JSON: {e}")))
}

pub fn scan_file(path: &Path) -> Result<ScanReport, ConfigError> {
    let config = load_config(path)?;
    let entries = find_server_entries(&config)?;
    let mut report = ScanReport {
        source: path.display().to_string(),
        servers: Vec::new(),
    };
    // entries iterates in sorted-key order (see canonical.rs), not the
    // source file's order -- harmless: the CLI always re-sorts servers by
    // score before printing, same as Python's _print_report.
    for (name, entry) in entries.iter() {
        let Value::Object(entry) = entry else { continue };
        let findings = evaluate_entry(name, entry);
        report.servers.push(ServerReport {
            name: name.clone(),
            findings,
        });
    }
    Ok(report)
}

/// Best-effort `~`/`%APPDATA%` expansion followed by an existence check.
/// A path that doesn't resolve or doesn't exist is silently skipped, same
/// as the Python version.
pub fn discover_config_paths() -> Vec<PathBuf> {
    let home = std::env::var("HOME").ok();
    let appdata = std::env::var("APPDATA").ok();
    let mut found = Vec::new();
    for raw in COMMON_CONFIG_PATHS {
        let mut expanded = (*raw).to_string();
        if let Some(h) = &home {
            if let Some(rest) = expanded.strip_prefix("~/") {
                expanded = format!("{h}/{rest}");
            } else if expanded == "~" {
                expanded = h.clone();
            }
        }
        if let Some(a) = &appdata {
            expanded = expanded.replace("%APPDATA%", a);
        }
        let p = PathBuf::from(expanded);
        if p.is_file() {
            found.push(p);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    #[test]
    fn clean_config_grades_a() {
        let report = scan_file(&fixtures_dir().join("clean.json")).unwrap();
        assert_eq!(report.servers.len(), 1);
        assert_eq!(report.overall_grade(), "A");
        assert_eq!(report.servers[0].score(), 100);
    }

    #[test]
    fn risky_config_has_low_grade_and_findings() {
        let report = scan_file(&fixtures_dir().join("risky.json")).unwrap();
        assert_eq!(report.servers.len(), 3);
        let by_name = |n: &str| report.servers.iter().find(|s| s.name == n).unwrap();

        assert!(by_name("shell-wrapper").score() < 50);
        let ids: Vec<_> = by_name("shell-wrapper").findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"SHELL_INDIRECTION"));
        assert!(ids.contains(&"SHELL_METACHARACTERS"));
        assert!(ids.contains(&"INLINE_SECRET"));

        let sketchy_ids: Vec<_> = by_name("sketchy-fs").findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(sketchy_ids.contains(&"BROAD_FS_SCOPE"));
        assert!(sketchy_ids.contains(&"POSSIBLE_TYPOSQUAT"));

        let floating_ids: Vec<_> = by_name("floating").findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(floating_ids.contains(&"LATEST_TAG"));

        assert!(report.overall_score() < 75);
        assert!(matches!(report.overall_grade(), "C" | "D" | "F"));
    }

    #[test]
    fn missing_mcp_servers_key_errors() {
        // A hand-rolled temp file (no tempfile crate: keep dev deps minimal
        // too) -- process id + a fixed suffix is unique enough for a
        // single-process test run, and we clean up unconditionally.
        let path = std::env::temp_dir().join(format!("mcp-sentinel-test-{}.json", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            write!(f, "{{\"not_mcp\": true}}").unwrap();
        }
        let err = scan_file(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(err.0.contains("mcpServers"));
    }

    #[test]
    fn score_to_grade_boundaries() {
        assert_eq!(score_to_grade(100), "A");
        assert_eq!(score_to_grade(90), "A");
        assert_eq!(score_to_grade(89), "B");
        assert_eq!(score_to_grade(75), "B");
        assert_eq!(score_to_grade(74), "C");
        assert_eq!(score_to_grade(60), "C");
        assert_eq!(score_to_grade(59), "D");
        assert_eq!(score_to_grade(40), "D");
        assert_eq!(score_to_grade(39), "F");
        assert_eq!(score_to_grade(0), "F");
    }

    #[test]
    fn round_half_even_matches_python_round() {
        // Python: round(84.5) == 84 (rounds to even), round(85.5) == 86.
        assert_eq!(round_half_even(84.5), 84);
        assert_eq!(round_half_even(85.5), 86);
        assert_eq!(round_half_even(85.4), 85);
        assert_eq!(round_half_even(85.6), 86);
    }
}
