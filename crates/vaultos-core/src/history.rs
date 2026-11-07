//! Change history for Undo. Entry metadata (action, project, key, actor) is readable while
//! unlocked; the before and after records, which hold values, stay sealed per entry and are
//! opened only to revert. The whole list is sealed again on disk.

use crate::crypto::Sealed;
use crate::error::Result;
use crate::format::{aad, open_json, seal_json};
use crate::model::Extra;
use crate::secret::Key32;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_ENTRIES: usize = 2000;
pub const MAX_BYTES: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub ts: String,
    pub actor: String,
    pub action: String,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default, rename = "ref")]
    pub reference: Option<String>,
    #[serde(default)]
    pub reverted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Sealed>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Payload {
    #[serde(default)]
    pub before: Option<Value>,
    #[serde(default)]
    pub after: Option<Value>,
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Payload(<redacted>)")
    }
}

pub fn seal_payload(vk: &Key32, vault_id: &str, entry_id: &str, p: &Payload) -> Result<Sealed> {
    seal_json(vk, &aad("history-entry", &[vault_id, entry_id]), p)
}

pub fn open_payload(vk: &Key32, vault_id: &str, e: &Entry) -> Result<Payload> {
    match &e.payload {
        None => Ok(Payload::default()),
        Some(s) => open_json(s, vk, &aad("history-entry", &[vault_id, &e.id])),
    }
}

/// Drops the oldest entries past 2,000 or past 1 MiB of stored entries, as `store.js` does.
pub fn trim(entries: &mut Vec<Entry>) {
    if entries.len() > MAX_ENTRIES {
        let drop = entries.len() - MAX_ENTRIES;
        entries.drain(..drop);
    }
    let sizes: Vec<usize> = entries
        .iter()
        .map(|e| serde_json::to_vec(e).map_or(0, |v| v.len() + 1))
        .collect();
    let mut total: usize = sizes.iter().sum();
    let mut drop = 0;
    while total > MAX_BYTES && drop + 1 < entries.len() {
        total -= sizes[drop];
        drop += 1;
    }
    entries.drain(..drop);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: usize, payload: Option<Sealed>) -> Entry {
        Entry {
            id: format!("{i:016x}"),
            ts: String::new(),
            actor: "human".into(),
            action: "update_secret".into(),
            project: None,
            key: None,
            reference: None,
            reverted: false,
            payload,
            extra: Extra::new(),
        }
    }

    #[test]
    fn trims_by_count_and_size() {
        let mut v: Vec<Entry> = (0..2100).map(|i| entry(i, None)).collect();
        trim(&mut v);
        assert_eq!(v.len(), MAX_ENTRIES);
        assert_eq!(v[0].id, format!("{:016x}", 100));

        let k = Key32::random();
        let big = Sealed::seal(&k, b"x", &vec![b'a'; 300 * 1024]);
        let mut v: Vec<Entry> = (0..5).map(|i| entry(i, Some(big.clone()))).collect();
        trim(&mut v);
        assert!(v.len() < 5 && !v.is_empty());
        assert_eq!(
            v.last().unwrap().id,
            format!("{:016x}", 4),
            "the newest entry is kept"
        );
    }
}
