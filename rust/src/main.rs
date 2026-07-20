//! Command-line entrypoint: `mcp-sentinel scan|lock|verify`.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use mcp_sentinel::lockfile::{self, LockError, DEFAULT_LOCKFILE_NAME};
use mcp_sentinel::scanner::{self, ConfigError, ScanReport};
use mcp_sentinel::VERSION;

const SEVERITY_ORDER: [&str; 5] = ["critical", "high", "medium", "low", "info"];

const USAGE: &str = "\
mcp-sentinel - offline risk scanner + lockfile for MCP client configs

Reads local JSON files only -- no network calls, ever.

USAGE:
  mcp-sentinel scan [paths...] [--auto] [--fail-under N]
      Scan one or more MCP config files.

  mcp-sentinel lock <config> [-o|--output PATH] [--tools NAME=PATH ...]
      Pin every configured server (and optionally its tool schemas) to a
      lockfile.

  mcp-sentinel verify <config> [--lock PATH] [--tools NAME=PATH ...]
      Detect drift between a config (and optional tools captures) and the
      lockfile; exit 1 on drift.

  mcp-sentinel --version | --help
";

fn severity_icon(sev: &str) -> &'static str {
    match sev {
        "critical" => "[CRIT]",
        "high" => "[HIGH]",
        "medium" => "[MED] ",
        "low" => "[LOW] ",
        "info" => "[INFO]",
        _ => "[????]",
    }
}

fn severity_rank(sev: &str) -> usize {
    SEVERITY_ORDER.iter().position(|s| *s == sev).unwrap_or(SEVERITY_ORDER.len())
}

fn print_report(report: &ScanReport) {
    println!("\n{}", report.source);
    println!("{}", "=".repeat(report.source.chars().count()));
    if report.servers.is_empty() {
        println!("No MCP server entries found.");
        return;
    }
    let mut servers = report.servers.clone();
    servers.sort_by_key(|s| s.score());
    for server in &servers {
        println!("\n{}  ->  grade {} ({}/100)", server.name, server.grade(), server.score());
        if server.findings.is_empty() {
            println!("   no issues found");
            continue;
        }
        let mut findings = server.findings.clone();
        findings.sort_by_key(|f| severity_rank(&f.severity));
        for f in &findings {
            println!("   {} {}: {}", severity_icon(&f.severity), f.rule_id, f.message);
        }
    }
    println!("\nOverall: grade {} ({}/100)", report.overall_grade(), report.overall_score());
}

fn parse_tools_args(pairs: &[String]) -> Result<Map<String, Value>, LockError> {
    let mut docs = Map::new();
    for pair in pairs {
        let bad = || {
            LockError(format!(
                "--tools expects NAME=PATH (a server name and a JSON file of its tools/list \
                 response), got: {pair:?}"
            ))
        };
        let Some((name, raw_path)) = pair.split_once('=') else {
            return Err(bad());
        };
        if name.is_empty() || raw_path.is_empty() {
            return Err(bad());
        }
        let text = std::fs::read_to_string(raw_path)
            .map_err(|e| LockError(format!("Cannot read tools capture {raw_path}: {e}")))?;
        let doc: Value = serde_json::from_str(&text)
            .map_err(|e| LockError(format!("Cannot read tools capture {raw_path}: {e}")))?;
        docs.insert(name.to_string(), doc);
    }
    Ok(docs)
}

fn cmd_scan(args: &[String]) -> i32 {
    let mut paths: Vec<String> = Vec::new();
    let mut auto = false;
    let mut fail_under: Option<i32> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--auto" => {
                auto = true;
                i += 1;
            }
            "--fail-under" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("mcp-sentinel: --fail-under requires a value");
                    return 2;
                };
                match v.parse::<i32>() {
                    Ok(n) => fail_under = Some(n),
                    Err(_) => {
                        eprintln!("mcp-sentinel: --fail-under expects an integer, got {v:?}");
                        return 2;
                    }
                }
                i += 2;
            }
            other => {
                paths.push(other.to_string());
                i += 1;
            }
        }
    }

    let mut targets: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
    if auto {
        targets.extend(scanner::discover_config_paths());
    }
    if targets.is_empty() {
        eprintln!(
            "No config paths given and none found via --auto. Pass a path, e.g.: \
             mcp-sentinel scan ./mcp.json"
        );
        return 2;
    }

    let mut worst_score = 100;
    let mut any_ok = false;
    for path in &targets {
        if !path.is_file() {
            eprintln!("\n{}: file not found, skipping", path.display());
            continue;
        }
        match scanner::scan_file(path) {
            Ok(report) => {
                print_report(&report);
                worst_score = worst_score.min(report.overall_score());
                any_ok = true;
            }
            Err(ConfigError(msg)) => {
                eprintln!("\n{}: {msg}", path.display());
            }
        }
    }

    if !any_ok {
        return 2;
    }
    if let Some(threshold) = fail_under {
        if worst_score < threshold {
            return 1;
        }
    }
    0
}

fn cmd_lock(args: &[String]) -> i32 {
    let mut config: Option<String> = None;
    let mut output: Option<String> = None;
    let mut tools_pairs: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                let Some(v) = args.get(i + 1) else {
                    return usage_err("lock: -o/--output requires a value");
                };
                output = Some(v.clone());
                i += 2;
            }
            "--tools" => {
                let Some(v) = args.get(i + 1) else {
                    return usage_err("lock: --tools requires a value");
                };
                tools_pairs.push(v.clone());
                i += 2;
            }
            other if config.is_none() => {
                config = Some(other.to_string());
                i += 1;
            }
            other => return usage_err(&format!("lock: unexpected argument {other:?}")),
        }
    }
    let Some(config) = config else {
        return usage_err("lock: requires a config path");
    };
    let config_path = PathBuf::from(&config);

    let result: Result<(Value, PathBuf), String> = (|| {
        let cfg = scanner::load_config(&config_path).map_err(|e| e.to_string())?;
        let entries = scanner::find_server_entries(&cfg).map_err(|e| e.to_string())?;
        let tools_docs = parse_tools_args(&tools_pairs).map_err(|e| e.to_string())?;
        let lock = lockfile::build_lock(&entries, &tools_docs, VERSION).map_err(|e| e.to_string())?;
        let out = match &output {
            Some(o) => PathBuf::from(o),
            None => config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(DEFAULT_LOCKFILE_NAME),
        };
        Ok((lock, out))
    })();

    match result {
        Ok((lock, out)) => {
            if let Err(e) = lockfile::write_lock(&lock, &out) {
                eprintln!("mcp-sentinel lock: {e}");
                return 2;
            }
            let servers = lock.get("servers").and_then(Value::as_object).cloned().unwrap_or_default();
            let pinned = servers
                .values()
                .filter(|s| !matches!(s.get("toolsHash"), None | Some(Value::Null)))
                .count();
            println!(
                "Locked {} server(s) -> {} ({pinned} with tool-schema hashes)",
                servers.len(),
                out.display()
            );
            if pinned < servers.len() {
                println!(
                    "Tip: pass --tools NAME=tools.json (a captured tools/list response) to \
                     also pin tool schemas -- that's what catches rug-pull tool mutations."
                );
            }
            0
        }
        Err(e) => {
            eprintln!("mcp-sentinel lock: {e}");
            2
        }
    }
}

fn cmd_verify(args: &[String]) -> i32 {
    let mut config: Option<String> = None;
    let mut lock_path_arg: Option<String> = None;
    let mut tools_pairs: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--lock" => {
                let Some(v) = args.get(i + 1) else {
                    return usage_err("verify: --lock requires a value");
                };
                lock_path_arg = Some(v.clone());
                i += 2;
            }
            "--tools" => {
                let Some(v) = args.get(i + 1) else {
                    return usage_err("verify: --tools requires a value");
                };
                tools_pairs.push(v.clone());
                i += 2;
            }
            other if config.is_none() => {
                config = Some(other.to_string());
                i += 1;
            }
            other => return usage_err(&format!("verify: unexpected argument {other:?}")),
        }
    }
    let Some(config) = config else {
        return usage_err("verify: requires a config path");
    };
    let config_path = PathBuf::from(&config);
    let lock_path = match &lock_path_arg {
        Some(p) => PathBuf::from(p),
        None => config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(DEFAULT_LOCKFILE_NAME),
    };

    let result: Result<Vec<lockfile::Drift>, String> = (|| {
        let cfg = scanner::load_config(&config_path).map_err(|e| e.to_string())?;
        let entries = scanner::find_server_entries(&cfg).map_err(|e| e.to_string())?;
        let lock = lockfile::read_lock(&lock_path).map_err(|e| e.to_string())?;
        let tools_docs = parse_tools_args(&tools_pairs).map_err(|e| e.to_string())?;
        lockfile::verify_lock(&entries, &lock, &tools_docs).map_err(|e| e.to_string())
    })();

    let mut drifts = match result {
        Ok(d) => d,
        Err(e) => {
            eprintln!("mcp-sentinel verify: {e}");
            return 2;
        }
    };

    if drifts.is_empty() {
        println!("OK: {} matches {} -- no drift.", config_path.display(), lock_path.display());
        return 0;
    }

    println!("DRIFT: {} no longer matches {}:\n", config_path.display(), lock_path.display());
    drifts.sort_by_key(|d| severity_rank(d.severity()));
    for d in &drifts {
        println!("   {} {}: {}", severity_icon(d.severity()), d.kind, d.message);
    }
    println!(
        "\nIf these changes are expected and reviewed, re-pin with: mcp-sentinel lock {}",
        config_path.display()
    );
    if drifts.iter().any(|d| d.severity() != "info") {
        1
    } else {
        0
    }
}

fn usage_err(msg: &str) -> i32 {
    eprintln!("mcp-sentinel: {msg}\n");
    eprint!("{USAGE}");
    2
}

fn main() {
    std::process::exit(real_main());
}

fn real_main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("scan") => cmd_scan(&args[1..]),
        Some("lock") => cmd_lock(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        Some("--version") | Some("-V") => {
            println!("mcp-sentinel {VERSION}");
            0
        }
        Some("--help") | Some("-h") | None => {
            print!("{USAGE}");
            if args.is_empty() {
                2
            } else {
                0
            }
        }
        Some(other) => {
            eprintln!("mcp-sentinel: unknown command {other:?}\n");
            print!("{USAGE}");
            2
        }
    }
}
