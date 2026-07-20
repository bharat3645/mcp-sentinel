//! Integration tests that spawn the actual compiled `mcp-sentinel` binary
//! -- a direct port of `tests/test_cli.py` plus a lock/verify/tamper
//! round-trip (the Python equivalent lives in `TestLockVerifyCli`). Uses
//! `CARGO_BIN_EXE_mcp-sentinel`, which Cargo sets automatically to the
//! path of the just-built binary for tests in this crate.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mcp-sentinel"))
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run mcp-sentinel binary")
}

#[test]
fn scan_clean_exits_zero() {
    let clean = fixtures_dir().join("clean.json");
    let out = run(&["scan", clean.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("grade A"), "stdout: {stdout}");
}

#[test]
fn scan_fail_under_trips_on_risky_config() {
    let risky = fixtures_dir().join("risky.json");
    let out = run(&["scan", risky.to_str().unwrap(), "--fail-under", "70"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn scan_missing_file_exits_nonzero() {
    let missing = fixtures_dir().join("does-not-exist.json");
    let out = run(&["scan", missing.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn scan_no_paths_and_no_auto_exits_nonzero() {
    let out = run(&["scan"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn version_flag_prints_version() {
    let out = run(&["--version"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("mcp-sentinel"));
}

#[test]
fn unknown_command_exits_2() {
    let out = run(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
}

/// Direct port of Python's TestLockVerifyCli.test_lock_then_verify_roundtrip_and_tamper:
/// lock a config, verify clean, tamper with a version pin (the rug-pull
/// shape), verify catches it as args-changed.
#[test]
fn lock_then_verify_roundtrip_and_tamper() {
    let dir = std::env::temp_dir().join(format!("mcp-sentinel-rs-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("mcp.json");
    let tools_path = dir.join("fs-tools.json");
    let lock_path = dir.join("mcp-sentinel.lock");

    let entries_v1 = serde_json::json!({
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@2.1.0", "./project"],
                "description": "official",
            },
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github@1.0.0"],
                "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
            }
        }
    });
    std::fs::write(&cfg, serde_json::to_string(&entries_v1).unwrap()).unwrap();

    let tools_doc = serde_json::json!({
        "tools": [
            {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
            {"name": "write_file", "description": "Write a file", "inputSchema": {"type": "object"}},
        ]
    });
    std::fs::write(&tools_path, serde_json::to_string(&tools_doc).unwrap()).unwrap();

    let lock_out = run(&[
        "lock",
        cfg.to_str().unwrap(),
        "-o",
        lock_path.to_str().unwrap(),
        "--tools",
        &format!("filesystem={}", tools_path.display()),
    ]);
    assert!(lock_out.status.success(), "{}", String::from_utf8_lossy(&lock_out.stderr));
    assert!(lock_path.is_file());
    let lock_text = std::fs::read_to_string(&lock_path).unwrap();
    let lock_json: serde_json::Value = serde_json::from_str(&lock_text).unwrap();
    assert!(!lock_json["servers"]["filesystem"]["toolsHash"].is_null());

    let verify_out = run(&[
        "verify",
        cfg.to_str().unwrap(),
        "--lock",
        lock_path.to_str().unwrap(),
        "--tools",
        &format!("filesystem={}", tools_path.display()),
    ]);
    assert!(verify_out.status.success(), "{}", String::from_utf8_lossy(&verify_out.stderr));
    assert!(String::from_utf8_lossy(&verify_out.stdout).contains("no drift"));

    // tamper: silently swap the package version (rug-pull shape)
    let entries_v2 = serde_json::json!({
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@2.1.1", "./project"],
                "description": "official",
            },
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github@1.0.0"],
                "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
            }
        }
    });
    std::fs::write(&cfg, serde_json::to_string(&entries_v2).unwrap()).unwrap();

    let tamper_out = run(&["verify", cfg.to_str().unwrap(), "--lock", lock_path.to_str().unwrap()]);
    assert_eq!(tamper_out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&tamper_out.stdout).contains("args-changed"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_missing_lockfile_exits_2() {
    let dir = std::env::temp_dir().join(format!("mcp-sentinel-rs-cli-test2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("mcp.json");
    std::fs::write(
        &cfg,
        serde_json::to_string(&serde_json::json!({"mcpServers": {}})).unwrap(),
    )
    .unwrap();
    let out = run(&["verify", cfg.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lock_rejects_bad_tools_argument() {
    let dir = std::env::temp_dir().join(format!("mcp-sentinel-rs-cli-test3-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("mcp.json");
    std::fs::write(
        &cfg,
        serde_json::to_string(&serde_json::json!({"mcpServers": {}})).unwrap(),
    )
    .unwrap();
    let out = run(&["lock", cfg.to_str().unwrap(), "--tools", "malformed"]);
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}
