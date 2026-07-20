//! Canonical JSON serialization matching Python's
//! `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
//! byte-for-byte, so a lockfile hash produced by this crate is identical to
//! the hash the Python implementation would produce for the same input.
//! That equivalence is what makes `mcp-sentinel.lock` files interchangeable
//! between the two implementations — pin with one, verify with the other.
//!
//! Object key ordering falls out for free: this crate does not enable
//! serde_json's `preserve_order` feature (see Cargo.toml), so
//! `serde_json::Map` is backed by a `BTreeMap` and already iterates in
//! sorted-key order.
//!
//! Number formatting is a documented, narrow exception: JSON integers are
//! already in their own canonical form (the JSON grammar forbids leading
//! zeros/plus signs), so those round-trip byte-exact through both
//! implementations. Fractional/exponent numbers go through Rust's `f64`
//! formatting, which is not guaranteed to produce the identical digit
//! string Python's float repr would for every possible value — see the
//! crate README for the practical impact (tool schemas overwhelmingly use
//! plain integers for things like `minLength`/`maxLength`).

use std::fmt::Write as _;

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Serialize `v` the way Python's canonical `json.dumps` call in
/// `lockfile.py`'s `_canonical()` would.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_value(v, &mut out);
    out
}

/// `sha256:` + lowercase hex digest of `text`, matching `_sha256()` in the
/// Python implementation.
pub fn sha256_prefixed(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::from("sha256:");
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let _ = write!(out, "{n}");
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(v, out);
            }
            out.push('}');
        }
    }
}

/// Escape a string exactly the way Python's json module does with
/// ensure_ascii=True: keep printable ASCII (0x20-0x7E) as-is except `"`
/// and `\`; give `\b \t \n \f \r` their named escapes; everything else
/// (other control chars, DEL 0x7F, and any codepoint above 0x7E) becomes
/// `\uXXXX`, with codepoints above U+FFFF split into a UTF-16 surrogate
/// pair (verified empirically against `json.dumps` — see rust/tests).
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{9}' => out.push_str("\\t"),
            '\u{a}' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\u{d}' => out.push_str("\\r"),
            c if (' '..='~').contains(&c) => out.push(c),
            c => {
                let cp = c as u32;
                if cp <= 0xFFFF {
                    let _ = write!(out, "\\u{cp:04x}");
                } else {
                    let cp = cp - 0x10000;
                    let hi = 0xD800 + (cp >> 10);
                    let lo = 0xDC00 + (cp & 0x3FF);
                    let _ = write!(out, "\\u{hi:04x}\\u{lo:04x}");
                }
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn escapes_match_python_json_dumps_ensure_ascii() {
        // Each pair is (input, Python's json.dumps(input, ensure_ascii=True)),
        // captured directly from CPython -- see the cycle report for the
        // generating script.
        let cases: &[(&str, &str)] = &[
            ("\u{0}", "\"\\u0000\""),
            ("\u{1}", "\"\\u0001\""),
            ("\u{8}", "\"\\b\""),
            ("\t", "\"\\t\""),
            ("\n", "\"\\n\""),
            ("\u{c}", "\"\\f\""),
            ("\r", "\"\\r\""),
            ("\u{1f}", "\"\\u001f\""),
        ];
        for (input, expected) in cases {
            assert_eq!(canonical_json(&json!(input)), *expected, "input {input:?}");
        }
        assert_eq!(canonical_json(&json!(" ")), "\" \"");
        assert_eq!(canonical_json(&json!("~")), "\"~\"");
        assert_eq!(canonical_json(&json!("\u{7f}")), "\"\\u007f\"");
        assert_eq!(canonical_json(&json!("\u{e9}")), "\"\\u00e9\""); // 'é'
        assert_eq!(canonical_json(&json!("\u{2603}")), "\"\\u2603\""); // '☃'
        assert_eq!(
            canonical_json(&json!("\u{1F600}")),
            "\"\\ud83d\\ude00\"" // '😀' astral -> surrogate pair
        );
        assert_eq!(canonical_json(&json!("\"")), "\"\\\"\"");
        assert_eq!(canonical_json(&json!("\\")), "\"\\\\\"");
        assert_eq!(canonical_json(&json!("/")), "\"/\""); // NOT escaped
    }

    #[test]
    fn object_keys_sort_without_preserve_order_feature() {
        let v = json!({"z": 1, "a": 2, "m": 3});
        assert_eq!(canonical_json(&v), r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn compact_separators_no_whitespace() {
        let v = json!({"a": [1, 2, 3], "b": "x"});
        assert_eq!(canonical_json(&v), r#"{"a":[1,2,3],"b":"x"}"#);
    }

    #[test]
    fn integers_are_already_canonical() {
        assert_eq!(canonical_json(&json!(0)), "0");
        assert_eq!(canonical_json(&json!(100)), "100");
        assert_eq!(canonical_json(&json!(-5)), "-5");
    }

    #[test]
    fn sha256_prefixed_matches_known_vector() {
        // sha256("") -- FIPS 180-4 / well-known empty-string vector.
        assert_eq!(
            sha256_prefixed(""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // sha256("abc") -- FIPS 180-4 test vector.
        assert_eq!(
            sha256_prefixed("abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
