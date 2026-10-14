//! Append-only audit hash chain (tamper evidence).
//!
//! Parity with `app/core/audit.py`: each row commits to the previous one via
//! `row_hash = sha256(prev_hash + canonical_json(fields))`, where
//! `canonical_json` is Python's `json.dumps(fields, sort_keys=True,
//! separators=(",", ":"), default=str)` — keys sorted at every level, compact
//! separators, `\uXXXX` escapes for non-ASCII (Python `ensure_ascii=True`).

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Chain anchor for the first entry (Python `GENESIS_HASH`).
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One audit row: the fields it commits to, its predecessor's hash and its own.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub prev_hash: String,
    pub row_hash: String,
    pub fields: Value,
}

/// Canonical JSON of the fields, byte-compatible with
/// `json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)`.
pub fn canonical(fields: &Value) -> String {
    let mut out = String::new();
    write_canonical(fields, &mut out);
    out
}

/// `row_hash = sha256_hex(prev_hash + canonical(fields))` (lowercase hex).
pub fn compute_row_hash(prev_hash: &str, fields: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical(fields).as_bytes());
    crate::security::hex_encode(&hasher.finalize())
}

/// Recompute every row hash and confirm the chain is intact.
pub fn verify_chain(entries: &[AuditEntry]) -> bool {
    let mut prev = GENESIS_HASH.to_string();
    for entry in entries {
        if entry.prev_hash != prev || entry.row_hash != compute_row_hash(&prev, &entry.fields) {
            return false;
        }
        prev = entry.row_hash.clone();
    }
    true
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_py_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // sort_keys=True, recursively.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_py_json_string(key, out);
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
    }
}

/// JSON string literal as Python's `json.dumps` writes it (ensure_ascii=True:
/// every code point above U+007F becomes a `\uXXXX` escape).
fn write_py_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7f => {
                let v = c as u32;
                if v > 0xffff {
                    let v = v - 0x10000;
                    out.push_str(&format!(
                        "\\u{:04x}\\u{:04x}",
                        0xd800 + (v >> 10),
                        0xdc00 + (v & 0x3ff)
                    ));
                } else {
                    out.push_str(&format!("\\u{v:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../security_vectors.json")).unwrap()
    }

    fn audit_vectors() -> serde_json::Value {
        vectors()["audit_chain"].clone()
    }

    fn entry_from(value: &Value) -> AuditEntry {
        serde_json::from_value(value.clone()).unwrap()
    }

    #[test]
    fn genesis_matches_python() {
        assert_eq!(GENESIS_HASH, audit_vectors()["genesis"].as_str().unwrap());
        assert_eq!(GENESIS_HASH.len(), 64);
    }

    /// Canonical form of the Python entry is byte-identical.
    #[test]
    fn canonical_matches_python() {
        let a = audit_vectors();
        assert_eq!(
            canonical(&a["entry1"]["fields"]),
            a["canonical_form_of_entry1"].as_str().unwrap()
        );
    }

    #[test]
    fn canonical_sorts_keys_recursively_and_escapes() {
        assert_eq!(
            canonical(&serde_json::json!({"b": 1, "a": {"d": 2, "c": 3}})),
            r#"{"a":{"c":3,"d":2},"b":1}"#
        );
        assert_eq!(
            canonical(&serde_json::json!([1, true, null, "x"])),
            "[1,true,null,\"x\"]"
        );
        // Python `ensure_ascii=True` escapes non-ASCII.
        assert_eq!(
            canonical(&serde_json::json!({"k": "caf\u{e9} \u{1f600}"})),
            r#"{"k":"caf\u00e9 \ud83d\ude00"}"#
        );
    }

    #[test]
    fn row_hashes_match_python() {
        let a = audit_vectors();
        for name in ["entry1", "entry2"] {
            let entry = entry_from(&a[name]);
            assert_eq!(
                compute_row_hash(&entry.prev_hash, &entry.fields),
                entry.row_hash,
                "row_hash of {name}"
            );
        }
    }

    #[test]
    fn verify_chain_accepts_python_chain() {
        let a = audit_vectors();
        let chain = vec![entry_from(&a["entry1"]), entry_from(&a["entry2"])];
        assert!(verify_chain(&chain));
        // Empty chain is trivially intact.
        assert!(verify_chain(&[]));
    }

    #[test]
    fn verify_chain_detects_tampering() {
        let a = audit_vectors();
        let chain = vec![entry_from(&a["entry1"]), entry_from(&a["entry2"])];

        // Tampered fields (row_hash no longer matches).
        let mut tampered = chain.clone();
        tampered[1].fields["event_type"] = Value::String("tampered".to_owned());
        assert!(!verify_chain(&tampered));

        // Rewritten row_hash.
        let mut rewritten = chain.clone();
        rewritten[1].row_hash = "0".repeat(64);
        assert!(!verify_chain(&rewritten));

        // Broken link to the previous row.
        let mut unlinked = chain.clone();
        unlinked[1].prev_hash = "1".repeat(64);
        assert!(!verify_chain(&unlinked));

        // Out-of-order rows.
        let reversed = vec![chain[1].clone(), chain[0].clone()];
        assert!(!verify_chain(&reversed));

        // Dropping the head breaks the chain.
        assert!(!verify_chain(&chain[1..]));
    }
}
