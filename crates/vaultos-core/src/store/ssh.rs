//! The SSH agent's keys: Ed25519 private keys kept as the value of `ssh_key` items. Only
//! the owner's SSH agent, after the human confirms, signs with them; agents never do.

use super::*;
use crate::ssh::SshKey;

/// A key the SSH agent offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshIdentity {
    pub project: String,
    pub item: String,
    pub blob: Vec<u8>,
    pub fingerprint: String,
}

impl Store {
    fn ssh_keys(&self) -> Result<Vec<(SshIdentity, SshKey)>> {
        let st = self.state()?;
        let k = &self.open()?.keys;
        let mut out = Vec::new();
        for p in &st.projects {
            for i in &p.items {
                let m = &i.meta;
                if m.kind() != "ssh_key" || !m.has_value || m.archived || !m.trashed_at.is_empty() {
                    continue;
                }
                let Ok(key) = SshKey::parse(&k.open_secret(p, i)?.value) else {
                    continue;
                };
                let id = SshIdentity {
                    project: p.meta.name.clone(),
                    item: m.key.clone(),
                    blob: key.public_blob(),
                    fingerprint: key.fingerprint(),
                };
                out.push((id, key));
            }
        }
        Ok(out)
    }

    /// The Ed25519 keys of `ssh_key` items that are not archived or trashed. Keys in other
    /// formats, or with a passphrase, are left out.
    pub fn ssh_identities(&self) -> Result<Vec<SshIdentity>> {
        Ok(self.ssh_keys()?.into_iter().map(|(id, _)| id).collect())
    }

    /// Signs `data` with the key whose public blob is `blob`, for `client` (the program that
    /// asked, as the human confirmed it). Recorded in the audit log.
    pub fn ssh_sign(&mut self, blob: &[u8], data: &[u8], client: &str) -> Result<Vec<u8>> {
        let (id, key) = self
            .ssh_keys()?
            .into_iter()
            .find(|(id, _)| id.blob == blob)
            .ok_or_else(|| Error::not_found("That SSH key is not in the vault"))?;
        let signature = key.sign(data);
        self.audit(
            "ssh-sign",
            &format!("{}/{} for {client}", id.project, id.item),
            HUMAN,
        )?;
        Ok(signature)
    }

    /// Changes whenever the vault is locked.
    pub fn lock_count(&self) -> u64 {
        self.locks
    }
}
