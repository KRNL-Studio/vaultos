//! Canonical JSON and record hashes, matching `crypto.js` `canonicalJson` and `model.js`
//! `recordHash`: keys sorted, and null, empty strings and empty arrays left out.

use crate::crypto::sha256_hex;
use crate::model::Record;
use serde_json::{Map, Value};

const RECORD_FIELDS: [&str; 19] = [
    "id",
    "key",
    "value",
    "provider",
    "note",
    "username",
    "email",
    "password",
    "url",
    "permission",
    "expiresAt",
    "owner",
    "createdBy",
    "modifiedBy",
    "editableBy",
    "injectApproved",
    "createdAt",
    "updatedAt",
    "rev",
];

/// A line-for-line port: null becomes "", arrays keep every element, and an object drops
/// properties whose canonical value is "" or an empty array.
fn canonicalize(v: &Value) -> Value {
    match v {
        Value::Null => Value::String(String::new()),
        Value::Array(a) => Value::Array(a.iter().map(canonicalize).collect()),
        Value::Object(o) => {
            let mut out = Map::new();
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            for k in keys {
                let c = canonicalize(&o[k]);
                let empty = match &c {
                    Value::String(s) => s.is_empty(),
                    Value::Array(a) => a.is_empty(),
                    _ => false,
                };
                if !empty {
                    out.insert(k.clone(), c);
                }
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

pub fn canonical_json(v: &Value) -> String {
    serde_json::to_string(&canonicalize(v)).unwrap_or_default()
}

pub fn record_hash(r: &Record) -> String {
    let full = serde_json::to_value(r).unwrap_or(Value::Null);
    let mut picked = Map::new();
    if let Value::Object(o) = full {
        for f in RECORD_FIELDS {
            if let Some(v) = o.get(f) {
                picked.insert(f.to_owned(), v.clone());
            }
        }
    }
    sha256_hex(canonical_json(&Value::Object(picked)).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn drops_empties_and_sorts() {
        let v = json!({"b": 1, "a": "", "c": [], "d": null, "e": {"z": true, "y": ""}});
        assert_eq!(canonical_json(&v), r#"{"b":1,"e":{"z":true}}"#);
    }

    #[test]
    fn matches_javascript_for_a_record() {
        // Computed with model.js recordHash() on the same synthetic record.
        let r: Record = serde_json::from_value(json!({
            "id": "0011223344556677", "key": "DEMO_API_KEY", "value": "synthetic-demo-only",
            "provider": "custom", "owner": "human", "createdBy": "human", "modifiedBy": "human",
            "editableBy": [], "injectApproved": true, "createdAt": "2026-01-01T00:00:00.000Z",
            "updatedAt": "2026-01-01T00:00:00.000Z", "rev": 1
        }))
        .unwrap();
        assert_eq!(
            record_hash(&r),
            include_str!("../tests/fixtures/record-hash.txt").trim()
        );
    }
}
