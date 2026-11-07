//! A tamper-evident activity log. Each line is one JSON entry that names the hash of the line
//! before it and is signed with an Ed25519 key whose seed is sealed in the vault. The vault
//! records the newest entry it has seen (its "head") at every save, so cutting the log short
//! or rewriting it is detected; only entries written after the last save can be lost unnoticed.
//! Entries hold names, actions and actors, never values.

use crate::crypto::{b64, sha256_hex, signing_key, unb64, unb64_array, verify_ed25519};
use crate::error::{Error, Result};
use crate::format::AuditHead;
use crate::fs_safe::{read_regular, regular_file};
use crate::model::now_iso;
use crate::secret::Key32;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub const FILE: &str = "audit-v4.log";
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_LOG_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub seq: u64,
    pub at: String,
    pub actor: String,
    pub action: String,
    pub detail: String,
    pub prev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

fn signed_bytes(vault_id: &str, e: &Entry) -> Result<Vec<u8>> {
    let mut unsigned = e.clone();
    unsigned.sig = None;
    let mut out = format!("vaultos/v4/audit\0{vault_id}\0").into_bytes();
    out.extend(serde_json::to_vec(&unsigned).map_err(|e| Error::Audit(e.to_string()))?);
    Ok(out)
}

fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(1024)
        .collect()
}

pub fn public_key(seed: &Key32) -> [u8; 32] {
    signing_key(seed).verifying_key().to_bytes()
}

/// Appends one entry after `head` and returns the new head.
pub fn append(
    dir: &Path,
    vault_id: &str,
    seed: &Key32,
    head: Option<&AuditHead>,
    actor: &str,
    action: &str,
    detail: &str,
) -> Result<AuditHead> {
    let path = dir.join(FILE);
    regular_file(&path, true, MAX_LOG_BYTES)?;
    let mut e = Entry {
        seq: head.map_or(1, |h| h.seq + 1),
        at: now_iso(),
        actor: clean(actor),
        action: clean(action),
        detail: clean(detail),
        prev: head.map_or_else(|| GENESIS.to_owned(), |h| h.hash.clone()),
        sig: None,
    };
    let sig = signing_key(seed).sign(&signed_bytes(vault_id, &e)?);
    e.sig = Some(b64(&sig.to_bytes()));
    let line = serde_json::to_string(&e).map_err(|e| Error::Audit(e.to_string()))?;
    let mut opts = OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(&path)
        .map_err(Error::io("cannot open the audit log"))?;
    f.write_all(format!("{line}\n").as_bytes())
        .map_err(Error::io("cannot write the audit log"))?;
    Ok(AuditHead {
        seq: e.seq,
        hash: sha256_hex(line.as_bytes()),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub entries: u64,
    pub head: Option<AuditHead>,
    /// Whether the vault's recorded head was found in the chain (None when not checked).
    pub anchored: Option<bool>,
}

/// How many signatures `verify` checks. Links are always checked from the first entry: any
/// change at or before the anchor alters the anchored hash, so after an anchor has been
/// checked once, signatures are needed only for the entries written since.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signatures {
    All,
    AfterAnchor,
}

/// Reads and checks the chain: sequence, links and signatures. With `anchor` (the head the
/// vault recorded), also requires that entry to be present and unchanged.
pub fn verify(
    dir: &Path,
    vault_id: &str,
    public: &str,
    anchor: Option<&AuditHead>,
) -> Result<(Report, Vec<Entry>)> {
    verify_with(dir, vault_id, public, anchor, Signatures::All)
}

pub fn verify_with(
    dir: &Path,
    vault_id: &str,
    public: &str,
    anchor: Option<&AuditHead>,
    signatures: Signatures,
) -> Result<(Report, Vec<Entry>)> {
    let public: [u8; 32] =
        unb64_array(public, "audit key").map_err(|_| Error::Audit("bad public key".into()))?;
    let path = dir.join(FILE);
    let bytes = match regular_file(&path, true, MAX_LOG_BYTES)? {
        None => Vec::new(),
        Some(_) => read_regular(&path, MAX_LOG_BYTES)?,
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::Audit("not UTF-8".into()))?;
    let mut entries = Vec::new();
    let mut prev = GENESIS.to_owned();
    let mut head = None;
    let mut anchored = anchor.map(|_| false);
    for (i, line) in text.lines().enumerate() {
        let n = i as u64 + 1;
        let e: Entry = serde_json::from_str(line)
            .map_err(|_| Error::Audit(format!("entry {n} is malformed")))?;
        if e.seq != n {
            return Err(Error::Audit(format!("entry {n} is out of sequence")));
        }
        if e.prev != prev {
            return Err(Error::Audit(format!(
                "entry {n} does not follow entry {}",
                n - 1
            )));
        }
        let check = signatures == Signatures::All || anchor.is_none_or(|a| n > a.seq);
        if check {
            let sig = unb64(e.sig.as_deref().unwrap_or(""), "signature")
                .map_err(|_| Error::Audit(format!("entry {n} is unsigned")))?;
            if !verify_ed25519(&public, &signed_bytes(vault_id, &e)?, &sig) {
                return Err(Error::Audit(format!("entry {n} has an invalid signature")));
            }
        }
        prev = sha256_hex(line.as_bytes());
        if let Some(a) = anchor {
            if a.seq == n {
                if a.hash != prev {
                    return Err(Error::Audit(format!(
                        "entry {n} was rewritten after the vault recorded it"
                    )));
                }
                anchored = Some(true);
            }
        }
        head = Some(AuditHead {
            seq: n,
            hash: prev.clone(),
        });
        entries.push(e);
    }
    if anchored == Some(false) {
        return Err(Error::Audit(
            "entries the vault recorded are missing; the log was cut short or replaced".into(),
        ));
    }
    Ok((
        Report {
            entries: entries.len() as u64,
            head,
            anchored,
        },
        entries,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Key32, String) {
        let d = tempfile::tempdir().unwrap();
        let seed = Key32::random();
        let public = b64(&public_key(&seed));
        (d, seed, public)
    }

    #[test]
    fn a_chain_verifies_and_detects_edits() {
        let (d, seed, public) = setup();
        let vid = "00".repeat(16);
        let h1 = append(d.path(), &vid, &seed, None, "human", "reveal", "App/KEY").unwrap();
        let h2 = append(
            d.path(),
            &vid,
            &seed,
            Some(&h1),
            "agent:x",
            "inject",
            "App/KEY",
        )
        .unwrap();
        let (r, entries) = verify(d.path(), &vid, &public, Some(&h2)).unwrap();
        assert_eq!(r.entries, 2);
        assert_eq!(entries[1].actor, "agent:x");

        let path = d.path().join(FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("agent:x", "agent:y")).unwrap();
        assert!(
            verify(d.path(), &vid, &public, None).is_err(),
            "an edited entry fails its signature"
        );

        std::fs::write(&path, text.lines().next().unwrap().to_owned() + "\n").unwrap();
        assert!(
            verify(d.path(), &vid, &public, None).is_ok(),
            "a shortened log is still a valid chain"
        );
        assert!(
            verify(d.path(), &vid, &public, Some(&h2)).is_err(),
            "but not one the vault anchored further"
        );
    }

    #[test]
    fn a_different_key_or_vault_fails() {
        let (d, seed, _) = setup();
        let vid = "00".repeat(16);
        append(d.path(), &vid, &seed, None, "human", "reveal", "App/KEY").unwrap();
        let other = b64(&public_key(&Key32::random()));
        assert!(verify(d.path(), &vid, &other, None).is_err());
        let (_, _, public) = (0, 0, b64(&public_key(&seed)));
        assert!(verify(d.path(), &"11".repeat(16), &public, None).is_err());
    }

    #[test]
    fn control_characters_cannot_forge_lines() {
        let (d, seed, public) = setup();
        let vid = "00".repeat(16);
        append(
            d.path(),
            &vid,
            &seed,
            None,
            "human",
            "reveal",
            "x\n{\"seq\":2}",
        )
        .unwrap();
        let (r, _) = verify(d.path(), &vid, &public, None).unwrap();
        assert_eq!(r.entries, 1);
    }
}
