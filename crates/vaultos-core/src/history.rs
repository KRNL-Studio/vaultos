//! Change history for Undo. Entry metadata (action, project, key, actor) is readable while
//! unlocked; the before and after records, which hold values, stay sealed per entry and are
//! opened only to revert. The whole list is sealed again on disk.

use crate::crypto::Sealed;
use crate::error::Result;
use crate::format::{aad, open_json, seal_json};
use crate::model::{Extra, HistoryEntryV3};
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
    /// The entry's size as the JavaScript app measures it (its JSON with the before and
    /// after records in the clear), so the size cap keeps what that app would keep.
    #[serde(default)]
    pub size: u64,
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

/// The size `store.js` counts for an entry: its JSON with the payload in the clear.
pub fn logical_size(e: &HistoryEntryV3) -> u64 {
    serde_json::to_vec(e).map_or(0, |v| v.len() as u64)
}

/// How many of the oldest entries `store.js` would drop: those past 2,000, then while the
/// list's JSON exceeds 1 MiB, always keeping the newest.
pub fn trim_count(sizes: &[u64]) -> usize {
    let mut drop = sizes.len().saturating_sub(MAX_ENTRIES);
    // The JSON of the list: brackets, entries and the commas between them.
    let mut total: u64 = 1 + sizes[drop..].iter().map(|s| s + 1).sum::<u64>();
    while total > MAX_BYTES as u64 && drop + 1 < sizes.len() {
        total -= sizes[drop] + 1;
        drop += 1;
    }
    drop
}

/// Drops the oldest entries as `store.js` does (see `trim_count`).
pub fn trim(entries: &mut Vec<Entry>) {
    let sizes: Vec<u64> = entries.iter().map(Entry::counted_size).collect();
    let drop = trim_count(&sizes);
    entries.drain(..drop);
}

impl Entry {
    /// The recorded logical size, or for an entry without one, its stored size.
    pub fn counted_size(&self) -> u64 {
        if self.size > 0 {
            return self.size;
        }
        serde_json::to_vec(self).map_or(0, |v| v.len() as u64)
    }
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
            size: 0,
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

    #[test]
    fn the_size_rule_matches_the_javascript_app() {
        // store.js: JSON.stringify(history) over 1 MiB drops the oldest; the newest stays.
        assert_eq!(trim_count(&[]), 0);
        assert_eq!(trim_count(&[10, 20]), 0);
        let half = (MAX_BYTES as u64) / 2;
        // "[" + a + "," + b + "]" is exactly 1 MiB: kept. One byte more: the oldest goes.
        assert_eq!(trim_count(&[half, half - 3]), 0);
        assert_eq!(trim_count(&[half, half - 2]), 1);
        assert_eq!(
            trim_count(&[MAX_BYTES as u64 * 3]),
            0,
            "never drops the newest"
        );
        assert_eq!(trim_count(&vec![1; MAX_ENTRIES + 7]), 7);
    }
}
