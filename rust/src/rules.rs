//! Heuristic risk rules for a single MCP server config entry — a direct
//! port of `mcp_sentinel/rules.py`. Each rule is a plain function:
//! `(name, entry) -> Option<Finding>`. All rules are purely local/string
//! based: no network access, no execution of the scanned commands. That
//! is a deliberate design constraint so the tool itself can never become
//! a supply-chain risk.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

pub const SEVERITY_CRITICAL: &str = "critical";
pub const SEVERITY_HIGH: &str = "high";
pub const SEVERITY_MEDIUM: &str = "medium";
pub const SEVERITY_INFO: &str = "info";

/// A server config entry: whatever object the config's `mcpServers`/
/// `servers` map holds for one server name.
pub type Entry = serde_json::Map<String, Value>;

pub fn severity_weight(sev: &str) -> i32 {
    match sev {
        "critical" => 25,
        "high" => 15,
        "medium" => 8,
        "low" => 3,
        _ => 0, // "info" and anything unrecognized
    }
}

/// A small curated list of well-known, legitimate MCP server package
/// names. Used only for typosquat *similarity* detection -- never treated
/// as an allowlist/denylist of what's safe to run.
pub const KNOWN_PACKAGES: &[&str] = &[
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@playwright/mcp",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub message: String,
}

impl Finding {
    fn new(rule_id: &str, severity: &str, message: String) -> Self {
        Finding {
            rule_id: rule_id.to_string(),
            severity: severity.to_string(),
            message,
        }
    }
}

fn command(entry: &Entry) -> String {
    entry
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Mirrors Python's `str(a)` for whatever JSON value shows up in an args
/// array: strings pass through as-is; anything else (rare, but valid
/// JSON: a number, bool, null, nested value) gets a textual form so a
/// malformed-but-valid config can't panic the rules.
fn value_to_arg_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn args(entry: &Entry) -> Vec<String> {
    entry
        .get("args")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(value_to_arg_string).collect())
        .unwrap_or_default()
}

fn command_line(entry: &Entry) -> String {
    let mut parts = vec![command(entry)];
    parts.extend(args(entry));
    parts.join(" ").trim().to_string()
}

fn secret_like() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(sk-|ghp_|gho_|ghu_|github_pat_|xox[baprs]-|AKIA|AIza|glpat-)[A-Za-z0-9_\-]{10,}$")
            .expect("SECRET_LIKE pattern is a fixed literal")
    })
}

fn shell_metachars() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[;&|`]|\$\(").expect("SHELL_METACHARS pattern is a fixed literal"))
}

fn latest_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"@latest\b").expect("fixed literal"))
}

fn version_digit_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"@\d").expect("fixed literal"))
}

fn strip_version_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"@(latest|\d[\w.\-]*)$").expect("fixed literal"))
}

fn rule_latest_tag(name: &str, entry: &Entry) -> Option<Finding> {
    let line = command_line(entry);
    if latest_tag_re().is_match(&line) {
        Some(Finding::new(
            "LATEST_TAG",
            SEVERITY_HIGH,
            format!(
                "'{name}' pins its package to @latest, so the exact code that runs can \
                 change silently on every launch with no review step."
            ),
        ))
    } else {
        None
    }
}

fn rule_unpinned_version(name: &str, entry: &Entry) -> Option<Finding> {
    let cmd = command(entry);
    if !matches!(cmd.as_str(), "npx" | "uvx" | "pipx") {
        return None;
    }
    let a = args(entry);
    let pkg = a.iter().find(|s| !s.starts_with('-'))?;
    if pkg.contains("@latest") {
        return None; // already covered by rule_latest_tag
    }
    let has_version = version_digit_re().is_match(pkg) || pkg.contains("==");
    if has_version {
        return None;
    }
    Some(Finding::new(
        "UNPINNED_VERSION",
        SEVERITY_MEDIUM,
        format!(
            "'{name}' launches '{pkg}' via {cmd} with no version pin, so it resolves to \
             whatever is newest at launch time."
        ),
    ))
}

fn rule_inline_secret(name: &str, entry: &Entry) -> Option<Finding> {
    let env = entry.get("env").and_then(Value::as_object)?;
    for (key, value) in env {
        let Some(value) = value.as_str() else {
            continue;
        };
        if value.starts_with('$') {
            continue; // references an external var/secret store, not inline
        }
        if secret_like().is_match(value.trim()) {
            return Some(Finding::new(
                "INLINE_SECRET",
                SEVERITY_CRITICAL,
                format!(
                    "'{name}' has what looks like a live credential hardcoded directly in \
                     env['{key}'] instead of referencing an environment variable or secret \
                     store."
                ),
            ));
        }
    }
    None
}

fn rule_shell_indirection(name: &str, entry: &Entry) -> Option<Finding> {
    let cmd = command(entry);
    if matches!(
        cmd.as_str(),
        "sh" | "bash" | "zsh" | "cmd" | "cmd.exe" | "powershell"
    ) {
        Some(Finding::new(
            "SHELL_INDIRECTION",
            SEVERITY_HIGH,
            format!(
                "'{name}' launches through a shell ({cmd}) instead of invoking the server \
                 binary directly, which hides the real command from anyone reviewing the \
                 config at a glance."
            ),
        ))
    } else {
        None
    }
}

fn rule_command_injection_chars(name: &str, entry: &Entry) -> Option<Finding> {
    let line = command_line(entry);
    if shell_metachars().is_match(&line) {
        Some(Finding::new(
            "SHELL_METACHARACTERS",
            SEVERITY_HIGH,
            format!(
                "'{name}' contains shell metacharacters (;, &, |, or `$(...)`) in its \
                 command/args, which usually means multiple commands are being chained \
                 where only one server launch is expected."
            ),
        ))
    } else {
        None
    }
}

fn rule_broad_filesystem_scope(name: &str, entry: &Entry) -> Option<Finding> {
    const RISKY_ROOTS: &[&str] = &["/", "~", "C:\\", "/etc", "/Users", "/home"];
    for a in args(entry) {
        if RISKY_ROOTS.contains(&a.as_str()) {
            return Some(Finding::new(
                "BROAD_FS_SCOPE",
                SEVERITY_MEDIUM,
                format!(
                    "'{name}' is granted '{a}' as a filesystem root, which is far broader \
                     than most MCP filesystem servers need -- scope it to a specific \
                     project directory instead."
                ),
            ));
        }
    }
    None
}

/// Ratcliff/Obershelp "longest matching block, recursively" similarity
/// ratio -- a from-scratch reimplementation of the algorithm behind
/// Python's `difflib.SequenceMatcher(None, a, b).ratio()` for the
/// `junk=None` / non-autojunk case (autojunk only engages above 200
/// elements, far longer than any package name here).
///
/// Differentially tested against the real `difflib.SequenceMatcher`
/// across 3000 random string pairs plus every KNOWN_PACKAGES typosquat
/// case (0 mismatches) before being ported to Rust -- see the cycle
/// report for the validation script.
fn seq_ratio(a: &str, b: &str) -> f64 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let total = a.len() + b.len();
    if total == 0 {
        return 1.0;
    }
    let mut blocks = Vec::new();
    find_matching_blocks(&a, &b, 0, a.len(), 0, b.len(), &mut blocks);
    let matches: usize = blocks.iter().map(|(_, _, k)| k).sum();
    2.0 * matches as f64 / total as f64
}

fn find_longest_match(
    a: &[char],
    b: &[char],
    alo: usize,
    ahi: usize,
    blo: usize,
    bhi: usize,
) -> (usize, usize, usize) {
    let mut best_i = alo;
    let mut best_j = blo;
    let mut best_size = 0usize;
    for i in alo..ahi {
        for j in blo..bhi {
            let mut k = 0usize;
            while i + k < ahi && j + k < bhi && a[i + k] == b[j + k] {
                k += 1;
            }
            if k > best_size {
                best_i = i;
                best_j = j;
                best_size = k;
            }
        }
    }
    (best_i, best_j, best_size)
}

fn find_matching_blocks(
    a: &[char],
    b: &[char],
    alo: usize,
    ahi: usize,
    blo: usize,
    bhi: usize,
    out: &mut Vec<(usize, usize, usize)>,
) {
    let (i, j, k) = find_longest_match(a, b, alo, ahi, blo, bhi);
    if k > 0 {
        if alo < i && blo < j {
            find_matching_blocks(a, b, alo, i, blo, j, out);
        }
        out.push((i, j, k));
        if i + k < ahi && j + k < bhi {
            find_matching_blocks(a, b, i + k, ahi, j + k, bhi, out);
        }
    }
}

fn rule_typosquat_similarity(name: &str, entry: &Entry) -> Option<Finding> {
    let a = args(entry);
    let pkg_raw = a.iter().find(|s| !s.starts_with('-'))?;
    let pkg = strip_version_suffix_re().replace(pkg_raw, "").into_owned();
    if KNOWN_PACKAGES.contains(&pkg.as_str()) {
        return None;
    }
    for known in KNOWN_PACKAGES {
        let ratio = seq_ratio(&pkg, known);
        if (0.80..1.0).contains(&ratio) {
            return Some(Finding::new(
                "POSSIBLE_TYPOSQUAT",
                SEVERITY_HIGH,
                format!(
                    "'{name}' uses package '{pkg}', which is suspiciously similar to the \
                     well-known '{known}' ({:.0}% match) but not identical -- verify this \
                     isn't a typosquat.",
                    ratio * 100.0
                ),
            ));
        }
    }
    None
}

/// Python truthiness for a JSON-loaded value: mirrors what `not v` means
/// for whatever `entry.get(key)` returned (missing key, JSON null, empty
/// string/array/object, zero, or false are all falsy).
fn is_falsy(v: Option<&Value>) -> bool {
    match v {
        None => true,
        Some(Value::Null) => true,
        Some(Value::Bool(b)) => !b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f == 0.0).unwrap_or(false),
        Some(Value::String(s)) => s.is_empty(),
        Some(Value::Array(a)) => a.is_empty(),
        Some(Value::Object(o)) => o.is_empty(),
    }
}

fn rule_missing_description(name: &str, entry: &Entry) -> Option<Finding> {
    if is_falsy(entry.get("description")) && is_falsy(entry.get("_comment")) {
        Some(Finding::new(
            "NO_PROVENANCE_NOTE",
            SEVERITY_INFO,
            format!(
                "'{name}' has no description/comment noting where it came from or why \
                 it's trusted -- harmless, but makes future review harder."
            ),
        ))
    } else {
        None
    }
}

const ALL_RULES: &[fn(&str, &Entry) -> Option<Finding>] = &[
    rule_latest_tag,
    rule_unpinned_version,
    rule_inline_secret,
    rule_shell_indirection,
    rule_command_injection_chars,
    rule_broad_filesystem_scope,
    rule_typosquat_similarity,
    rule_missing_description,
];

pub fn evaluate_entry(name: &str, entry: &Entry) -> Vec<Finding> {
    ALL_RULES.iter().filter_map(|rule| rule(name, entry)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(v: Value) -> Entry {
        match v {
            Value::Object(m) => m,
            _ => panic!("test entry must be an object"),
        }
    }

    #[test]
    fn clean_entry_has_no_findings() {
        let e = entry(json!({
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@2.1.0", "./proj"],
            "description": "official",
        }));
        assert!(evaluate_entry("filesystem", &e).is_empty());
    }

    #[test]
    fn latest_tag_flagged() {
        let e = entry(json!({"command": "npx", "args": ["-y", "some-tool@latest"]}));
        let ids: Vec<_> = evaluate_entry("floating", &e).into_iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"LATEST_TAG".to_string()));
    }

    #[test]
    fn unpinned_version_flagged_without_latest_duplicate() {
        let e = entry(json!({"command": "npx", "args": ["-y", "some-tool"]}));
        let ids: Vec<_> = evaluate_entry("unpinned", &e).into_iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"UNPINNED_VERSION".to_string()));
        assert!(!ids.contains(&"LATEST_TAG".to_string()));
    }

    #[test]
    fn inline_secret_flagged() {
        let e = entry(json!({
            "command": "node",
            "args": ["server.js"],
            "env": {"GITHUB_TOKEN": "ghp_1234567890abcdefghijklmnopqrstuvwx"},
        }));
        let ids: Vec<_> = evaluate_entry("secret-leak", &e).into_iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"INLINE_SECRET".to_string()));
    }

    #[test]
    fn env_var_reference_not_flagged_as_secret() {
        let e = entry(json!({
            "command": "node",
            "args": ["server.js"],
            "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
        }));
        let ids: Vec<_> = evaluate_entry("ok-secret", &e).into_iter().map(|f| f.rule_id).collect();
        assert!(!ids.contains(&"INLINE_SECRET".to_string()));
    }

    #[test]
    fn shell_indirection_flagged() {
        let e = entry(json!({"command": "bash", "args": ["-c", "run.sh"]}));
        let ids: Vec<_> = evaluate_entry("shell", &e).into_iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"SHELL_INDIRECTION".to_string()));
    }

    #[test]
    fn shell_metacharacters_flagged() {
        let e = entry(json!({"command": "bash", "args": ["-c", "a.sh && curl x | sh"]}));
        let ids: Vec<_> = evaluate_entry("chained", &e).into_iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"SHELL_METACHARACTERS".to_string()));
    }

    #[test]
    fn broad_filesystem_scope_flagged() {
        let e = entry(json!({
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@2.0.0", "/"],
        }));
        let ids: Vec<_> = evaluate_entry("broad-fs", &e).into_iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"BROAD_FS_SCOPE".to_string()));
    }

    #[test]
    fn typosquat_similarity_flagged() {
        let e = entry(json!({
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesytem"],
        }));
        let ids: Vec<_> = evaluate_entry("typo", &e).into_iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"POSSIBLE_TYPOSQUAT".to_string()));
    }

    #[test]
    fn exact_known_package_not_flagged_as_typosquat() {
        let e = entry(json!({
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@2.0.0"],
        }));
        let ids: Vec<_> = evaluate_entry("legit", &e).into_iter().map(|f| f.rule_id).collect();
        assert!(!ids.contains(&"POSSIBLE_TYPOSQUAT".to_string()));
    }

    #[test]
    fn missing_description_is_info_only() {
        let e = entry(json!({
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@2.0.0", "./x"],
        }));
        let findings = evaluate_entry("no-desc", &e);
        let info: Vec<_> = findings.iter().filter(|f| f.rule_id == "NO_PROVENANCE_NOTE").collect();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].severity, "info");
    }

    /// Cross-language vectors: exact typosquat-similarity percentages
    /// generated by real Python difflib against every KNOWN_PACKAGES
    /// entry (see the cycle report script). Confirms the from-scratch
    /// seq_ratio port, not just its pass/fail threshold behavior.
    #[test]
    fn seq_ratio_matches_python_difflib_vectors() {
        let cases: &[(&str, &str, f64)] = &[
            (
                "@modelcontextprotocol/server-filesytem",
                "@modelcontextprotocol/server-filesystem",
                0.987012987012987,
            ),
            (
                "@modelcontextprotocol/server-fllesystem",
                "@modelcontextprotocol/server-filesystem",
                0.9743589743589743,
            ),
            (
                "@modelcontextprotocol/server-github2",
                "@modelcontextprotocol/server-github",
                0.9859154929577465,
            ),
            ("@playwrite/mcp", "@playwright/mcp", 0.896551724137931),
        ];
        for (a, b, expected) in cases {
            let got = seq_ratio(a, b);
            assert!(
                (got - expected).abs() < 1e-9,
                "seq_ratio({a:?}, {b:?}) = {got}, want {expected}"
            );
        }
    }
}
