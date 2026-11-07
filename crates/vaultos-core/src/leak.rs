//! Finding the vault's values where they should not be: in files, staged changes and Git
//! history. The scanner never holds the values. It holds keyed hashes of them (HMAC-SHA256
//! under a random key, cut to 128 bits) and hashes each candidate word in the text of the
//! same length. The index can be saved as `leak-index.json` (mode 0600) so `vaultos scan`
//! and a pre-commit hook work while the vault is locked; it names items only by their ids.
//!
//! A word is a run of characters other than whitespace, quotes, backticks and brackets,
//! also taken after its first `=` or `:` and without trailing `,` `;` or `.`. So values in
//! `.env` files, JSON, YAML, shell and source code are found; values containing spaces are
//! not. Values shorter than [`MIN_LEN`] are left out: they would match ordinary text.

use crate::crypto::{b64, hex, hmac_sha256, random_array, unb64_array};
use crate::error::{Error, Result};
use crate::secret::Key32;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

pub const INDEX_FILE: &str = "leak-index.json";
pub const MIN_LEN: usize = 8;
/// Values longer than this are not indexed (certificates and keys are found by their lines).
const MAX_LEN: usize = 4096;
/// Files larger than this are skipped.
pub const MAX_FILE: u64 = 8 * 1024 * 1024;

/// Where an indexed value lives: ids only, so the index names nothing.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub project_id: String,
    pub item_id: String,
    /// `value`, `password`, or a secret field's id.
    pub field: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndexFile {
    version: u32,
    vault_id: String,
    created_at: String,
    key: String,
    entries: Vec<(String, Vec<Source>)>,
}

pub struct Index {
    key: Key32,
    pub vault_id: String,
    pub created_at: String,
    lengths: BTreeSet<usize>,
    entries: HashMap<[u8; 16], Vec<Source>>,
}

impl std::fmt::Debug for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Index")
            .field("values", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// One value found: where (1-based line and column, in bytes) and from which item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hit {
    pub line: usize,
    pub column: usize,
    pub sources: Vec<Source>,
}

fn is_break(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b'"' | b'\'' | b'`' | b'(' | b')' | b'[' | b']' | b'{' | b'}' | b'<' | b'>'
        )
}

impl Index {
    pub fn new(vault_id: &str) -> Index {
        Index {
            key: Key32::from_bytes(random_array::<32>()),
            vault_id: vault_id.to_owned(),
            created_at: crate::model::now_iso(),
            lengths: BTreeSet::new(),
            entries: HashMap::new(),
        }
    }

    fn tag(&self, value: &[u8]) -> [u8; 16] {
        let full = hmac_sha256(&self.key, value);
        let mut t = [0u8; 16];
        t.copy_from_slice(&full[..16]);
        t
    }

    /// Adds a value, unless it is too short or too long to index. Leading and trailing
    /// whitespace is not part of a word, so it is not part of the value either.
    pub fn add(&mut self, value: &str, source: Source) {
        let v = value.trim();
        if v.len() < MIN_LEN || v.len() > MAX_LEN {
            return;
        }
        // A multi-line value (a key or certificate) is found by its longest lines.
        if v.contains('\n') {
            for line in v.lines().map(str::trim).filter(|l| l.len() >= 24) {
                self.add(line, source.clone());
            }
            return;
        }
        if v.bytes().any(is_break) {
            return;
        }
        self.lengths.insert(v.len());
        let sources = self.entries.entry(self.tag(v.as_bytes())).or_default();
        if !sources.contains(&source) {
            sources.push(source);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every indexed value found in `text`.
    pub fn scan(&self, text: &[u8]) -> Vec<Hit> {
        let mut hits = Vec::new();
        if self.entries.is_empty() {
            return hits;
        }
        let (mut line, mut line_start) = (1, 0);
        let mut i = 0;
        while i < text.len() {
            if text[i] == b'\n' {
                line += 1;
                line_start = i + 1;
                i += 1;
                continue;
            }
            if is_break(text[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < text.len() && !is_break(text[i]) {
                i += 1;
            }
            let word = &text[start..i];
            let mut found = |from: usize, w: &[u8]| {
                let w = trim_end(w);
                if self.lengths.contains(&w.len()) {
                    if let Some(sources) = self.entries.get(&self.tag(w)) {
                        hits.push(Hit {
                            line,
                            column: start + from - line_start + 1,
                            sources: sources.clone(),
                        });
                        return true;
                    }
                }
                false
            };
            if !found(0, word) {
                if let Some(at) = word.iter().position(|b| matches!(b, b'=' | b':')) {
                    found(at + 1, &word[at + 1..]);
                }
            }
        }
        hits
    }

    pub fn save(&self, data_dir: &Path) -> Result<()> {
        let mut entries: Vec<(String, Vec<Source>)> = self
            .entries
            .iter()
            .map(|(t, s)| (hex(t), s.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let file = IndexFile {
            version: 1,
            vault_id: self.vault_id.clone(),
            created_at: self.created_at.clone(),
            key: b64(self.key.expose()),
            entries,
        };
        let text = serde_json::to_vec(&file).map_err(|e| Error::Format(e.to_string()))?;
        crate::fs_safe::atomic_write(&data_dir.join(INDEX_FILE), &text)
    }

    pub fn load(data_dir: &Path) -> Result<Option<Index>> {
        let path = data_dir.join(INDEX_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = crate::fs_safe::read_regular(&path, 64 * 1024 * 1024)?;
        let file: IndexFile = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Format("the leak index is damaged; update it".into()))?;
        if file.version != 1 {
            return Err(Error::Format(
                "the leak index has an unknown version; update it".into(),
            ));
        }
        let mut index = Index {
            key: Key32::from_bytes(unb64_array::<32>(&file.key, "leak index key")?),
            vault_id: file.vault_id,
            created_at: file.created_at,
            lengths: BTreeSet::new(),
            entries: HashMap::new(),
        };
        for (tag, sources) in file.entries {
            let mut t = [0u8; 16];
            let raw = (0..tag.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(tag.get(i..i + 2).unwrap_or("zz"), 16))
                .collect::<std::result::Result<Vec<u8>, _>>()
                .ok()
                .filter(|r| r.len() == 16)
                .ok_or_else(|| Error::Format("the leak index is damaged; update it".into()))?;
            t.copy_from_slice(&raw);
            index.entries.insert(t, sources);
        }
        // Lengths are not stored; any length up to the longest a value may have is tried.
        index.lengths = (MIN_LEN..=MAX_LEN).collect();
        Ok(Some(index))
    }
}

fn trim_end(w: &[u8]) -> &[u8] {
    let mut end = w.len();
    while end > 0 && matches!(w[end - 1], b',' | b';' | b'.') {
        end -= 1;
    }
    &w[..end]
}

/// Whether bytes look like text: no NUL in the first 8 KiB.
pub fn is_text(bytes: &[u8]) -> bool {
    !bytes[..bytes.len().min(8192)].contains(&0)
}

/// A value found in a file, or in a commit's added lines.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    pub line: usize,
    pub column: usize,
    pub sources: Vec<Source>,
}

/// Folders a tree scan does not enter: version control and installed dependencies.
const SKIPPED: [&str; 2] = [".git", "node_modules"];
/// A scan stops after this many files or findings.
pub const MAX_FILES: usize = 200_000;
pub const MAX_FINDINGS: usize = 1000;

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeScan {
    pub findings: Vec<Finding>,
    pub files: usize,
    /// Larger than [`MAX_FILE`], unreadable, or not text.
    pub skipped: usize,
    /// The file or finding limit was reached.
    pub incomplete: bool,
}

/// Scans the text files under `root` (or `root` itself), without following symbolic links
/// and never entering `avoid` (the vault's data folder).
pub fn scan_tree(index: &Index, root: &Path, avoid: &Path) -> Result<TreeScan> {
    let mut out = TreeScan::default();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        if out.files >= MAX_FILES || out.findings.len() >= MAX_FINDINGS {
            out.incomplete = true;
            break;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            out.skipped += 1;
            continue;
        };
        if path.starts_with(avoid) {
            continue;
        }
        if meta.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path != root && SKIPPED.contains(&name) {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&path) else {
                out.skipped += 1;
                continue;
            };
            let mut children: Vec<_> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
            children.sort();
            stack.extend(children.into_iter().rev());
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        out.files += 1;
        if meta.len() > MAX_FILE {
            out.skipped += 1;
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            out.skipped += 1;
            continue;
        };
        let bytes = zeroize::Zeroizing::new(bytes);
        if !is_text(&bytes) {
            out.skipped += 1;
            continue;
        }
        let shown = path.to_string_lossy().into_owned();
        for h in index.scan(&bytes) {
            out.findings.push(Finding {
                path: shown.clone(),
                commit: None,
                line: h.line,
                column: h.column,
                sources: h.sources,
            });
        }
    }
    out.findings.truncate(MAX_FINDINGS);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]
    use super::*;

    fn src(id: &str) -> Source {
        Source {
            project_id: "p".into(),
            item_id: id.into(),
            field: "value".into(),
        }
    }

    #[test]
    fn finds_values_as_words() {
        let mut ix = Index::new("v");
        ix.add("synthetic-token-1234", src("a"));
        ix.add("short", src("b"));
        ix.add("dGhpcyBpcyBzeW50aGV0aWM=", src("c"));
        assert_eq!(ix.len(), 2);
        let text = b"API_KEY=synthetic-token-1234\nx = \"dGhpcyBpcyBzeW50aGV0aWM=\",\nnot synthetic-token-12345 here\nshort\n";
        let hits = ix.scan(text);
        let at: Vec<(usize, usize, &str)> = hits
            .iter()
            .map(|h| (h.line, h.column, h.sources[0].item_id.as_str()))
            .collect();
        assert_eq!(at, [(1, 9, "a"), (2, 6, "c")]);
        assert!(ix.scan(b"key: synthetic-token-1234;").len() == 1);
    }

    #[test]
    fn saved_indexes_scan_the_same_and_hold_no_values() {
        let dir = tempfile::tempdir().unwrap();
        let mut ix = Index::new("vault-1");
        ix.add("synthetic-saved-value", src("a"));
        ix.add(
            "-----BEGIN SYNTHETIC KEY-----\nAAAAB3NzaC1yc2EAAAADAQABAAABAQCsynthetic\n-----END SYNTHETIC KEY-----",
            src("k"),
        );
        ix.save(dir.path()).unwrap();
        let text = std::fs::read_to_string(dir.path().join(INDEX_FILE)).unwrap();
        assert!(!text.contains("synthetic"));
        let back = Index::load(dir.path()).unwrap().unwrap();
        assert_eq!(back.vault_id, "vault-1");
        let hits =
            back.scan(b"token = synthetic-saved-value\nAAAAB3NzaC1yc2EAAAADAQABAAABAQCsynthetic\n");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[1].sources[0].item_id, "k");
    }
}
