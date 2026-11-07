//! The v4 store: projects and items with ownership, delegation and approvals, history with
//! Undo, the audit chain, and safe saving (stale-write detection, atomic replacement, the
//! JavaScript app's lock files). Semantics follow `store.js`; storage is format v4.
//!
//! While unlocked, metadata is decrypted and item secrets stay sealed; `reveal` opens one.
//! Every change is made on a copy of the state and kept only if it was saved, so a failed
//! write never leaves memory and disk disagreeing.

use crate::audit::{self, Signatures};
use crate::canon::record_hash;
use crate::crypto::{b64, random_id, sha256_hex, KdfParams, Sealed};
use crate::env;
use crate::error::{Error, Result};
use crate::format::{
    aad, account_unlock_key, check_id, mac_key, new_vault_id, open_audit_seed, open_json,
    seal_audit_seed, seal_json, AuditHead, Item, ItemFile, KdfHeader, ProjectFile, ProjectMeta,
    SecretKeyHeader, VaultFile, VaultMeta,
};
use crate::fs_safe::{
    self, atomic_write, claim, private_dir, read_regular, read_with_id, FileId, MAX_VAULT_BYTES,
};
use crate::history::{self, Payload};
use crate::model::{
    agent_ref, is_agent, now_iso, ItemMeta, ItemSecret, ProjectV3, Record, Tombstone, VaultV3,
    HUMAN,
};
use crate::secret::{Key32, SecretString};
use crate::secret_key::SecretKey;
use crate::validate::{self, Fields};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const VAULT_FILE: &str = "vault.enc";

#[derive(Clone)]
pub(crate) struct Keys {
    pub vault_id: String,
    pub kdf: KdfHeader,
    pub secret_key: Option<SecretKeyHeader>,
    pub wrapped_vk: Sealed,
    pub audit_public: String,
    pub sealed_audit_seed: Sealed,
    pub auk: Key32,
    pub vk: Key32,
    pub mac: Key32,
    pub audit_seed: Key32,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("vault_id", &self.vault_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Project {
    pub id: String,
    pub pk: Key32,
    pub wrapped_pk: Sealed,
    pub meta: ProjectMeta,
    pub sealed_meta: Option<Sealed>,
    pub items: Vec<Item>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct State {
    pub meta: VaultMeta,
    pub projects: Vec<Project>,
    pub history: Vec<history::Entry>,
    pub sealed_history: Option<Sealed>,
    pub history_grew: bool,
}

#[derive(Debug)]
struct Open {
    keys: Keys,
    state: State,
    /// The newest audit entry, including ones written since the last save.
    audit_head: Option<AuditHead>,
    /// The head the vault file on disk records.
    saved_anchor: Option<AuditHead>,
    audit_problem: Option<String>,
    /// When this session unlocked: a reset of a damaged log made by another process after
    /// this is adopted rather than redone.
    opened_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSummary {
    pub id: String,
    pub name: String,
    pub secret_count: usize,
    pub agent_key_count: usize,
    pub pending_count: usize,
    pub providers: Vec<String>,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    pub id: String,
    pub key: String,
    pub provider: String,
    pub note: String,
    pub username: String,
    pub email: String,
    pub url: String,
    pub permission: String,
    pub expires_at: String,
    /// `none`, `active`, `expiring` (7 days or fewer) or `expired`.
    pub expiry_status: String,
    pub days_left: Option<i64>,
    pub owner: String,
    pub created_by: String,
    pub editable_by: Vec<String>,
    pub inject_approved: bool,
    pub has_value: bool,
    pub has_password: bool,
    pub updated_at: String,
    pub rev: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Saved {
    pub id: String,
    pub key: String,
    pub provider: String,
    pub owner: String,
    pub inject_approved: bool,
}

#[derive(Debug)]
pub struct Revealed {
    pub key: String,
    pub value: SecretString,
    pub password: SecretString,
    pub provider: String,
    pub username: String,
    pub email: String,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pending {
    pub project: String,
    pub key: String,
    pub owner: String,
    pub owner_name: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistorySummary {
    pub id: String,
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub project: Option<String>,
    pub key: Option<String>,
    #[serde(rename = "ref")]
    pub reference: Option<String>,
    pub reverted: bool,
}

fn forbidden_unless_human(actor: &str, what: &str) -> Result<()> {
    if actor != HUMAN {
        return Err(Error::forbidden(format!(
            "{what} is human-only, in the VaultOS app"
        )));
    }
    Ok(())
}

fn can_edit(meta: &ItemMeta, actor: &str) -> Result<()> {
    if actor == HUMAN {
        return Ok(());
    }
    if !is_agent(actor) {
        return Err(Error::forbidden("unknown caller"));
    }
    if meta.owner == actor || meta.editable_by.iter().any(|a| a == actor) {
        return Ok(());
    }
    if meta.owner == HUMAN {
        return Err(Error::forbidden(format!(
            "\"{}\" is yours, not the agent's. Delegate it in VaultOS if you want the agent to manage it.",
            meta.key
        )));
    }
    Err(Error::forbidden(format!(
        "\"{}\" belongs to {}; a different agent cannot change it.",
        meta.key, meta.owner
    )))
}

fn can_delete(meta: &ItemMeta, actor: &str) -> Result<()> {
    if actor == HUMAN || meta.owner == actor {
        return Ok(());
    }
    Err(Error::forbidden(format!(
        "only the owner ({}) or you can delete \"{}\".",
        meta.owner, meta.key
    )))
}

impl Keys {
    fn item_secret_aad(&self, project_id: &str, item_id: &str) -> Vec<u8> {
        aad("item-secret", &[&self.vault_id, project_id, item_id])
    }

    fn seal_secret(&self, p: &Project, item_id: &str, s: &ItemSecret) -> Result<Sealed> {
        seal_json(&p.pk, &self.item_secret_aad(&p.id, item_id), s)
    }

    fn open_secret(&self, p: &Project, item: &Item) -> Result<ItemSecret> {
        open_json(&item.secret, &p.pk, &self.item_secret_aad(&p.id, &item.id))
    }

    fn record(&self, p: &Project, item: &Item) -> Result<Record> {
        Ok(Record::join(
            &item.id,
            item.rev,
            &item.meta,
            &self.open_secret(p, item)?,
        ))
    }

    fn new_project_key(&self, project_id: &str) -> (Key32, Sealed) {
        let pk = Key32::random();
        let wrapped = Sealed::seal_key(
            &self.vk,
            &aad("project-key", &[&self.vault_id, project_id]),
            &pk,
        );
        (pk, wrapped)
    }

    /// Builds the item for a full record, sealing its secret under the project's key.
    fn item_from_record(&self, p: &Project, r: &Record) -> Result<Item> {
        check_id(&r.id)?;
        let (meta, secret) = r.split();
        Ok(Item {
            id: r.id.clone(),
            rev: r.rev,
            secret: self.seal_secret(p, &r.id, &secret)?,
            meta,
            sealed_meta: None,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one field per history entry column"
    )]
    pub(crate) fn history_entry(
        &self,
        st: &mut State,
        actor: &str,
        action: &str,
        project: Option<&str>,
        key: Option<&str>,
        payload: Payload,
        reference: Option<String>,
    ) -> Result<String> {
        let id = random_id();
        let ts = now_iso();
        let size = history::logical_size(&crate::model::HistoryEntryV3 {
            id: id.clone(),
            ts: ts.clone(),
            actor: actor.to_owned(),
            action: action.to_owned(),
            project: project.map(str::to_owned),
            key: key.map(str::to_owned),
            before: payload.before.clone(),
            after: payload.after.clone(),
            reference: reference.clone(),
            reverted: false,
            extra: Map::new(),
        });
        let sealed = if payload.before.is_some() || payload.after.is_some() {
            Some(history::seal_payload(
                &self.vk,
                &self.vault_id,
                &id,
                &payload,
            )?)
        } else {
            None
        };
        st.history.push(history::Entry {
            id: id.clone(),
            ts,
            actor: actor.to_owned(),
            action: action.to_owned(),
            project: project.map(str::to_owned),
            key: key.map(str::to_owned),
            reference,
            reverted: false,
            payload: sealed,
            size,
            extra: Map::new(),
        });
        if st.history.len() > history::MAX_ENTRIES {
            let drop = st.history.len() - history::MAX_ENTRIES;
            st.history.drain(..drop);
        }
        st.history_grew = true;
        st.sealed_history = None;
        Ok(id)
    }
}

fn to_value<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

impl State {
    fn project_index(&self, id_or_name: &str) -> Option<usize> {
        let lower = id_or_name.to_lowercase();
        self.projects
            .iter()
            .position(|p| p.id == id_or_name)
            .or_else(|| {
                self.projects
                    .iter()
                    .position(|p| p.meta.name.to_lowercase() == lower)
            })
    }

    fn project(&self, id_or_name: &str) -> Result<usize> {
        self.project_index(id_or_name)
            .ok_or_else(|| Error::not_found("project not found"))
    }

    fn item(&self, pi: usize, key_or_id: &str) -> Result<usize> {
        self.projects[pi]
            .items
            .iter()
            .position(|i| i.meta.key == key_or_id || i.id == key_or_id)
            .ok_or_else(|| Error::not_found("secret not found"))
    }

    fn tombstone(&mut self, reference: String, actor: &str, label: Map<String, Value>) {
        self.meta.tombstones.retain(|t| t.reference != reference);
        self.meta.tombstones.push(Tombstone {
            reference,
            deleted_at: now_iso(),
            by: actor.to_owned(),
            extra: label,
        });
    }

    fn untombstone(&mut self, reference: &str) {
        self.meta.tombstones.retain(|t| t.reference != reference);
    }
}

fn label(pairs: &[(&str, &str)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), Value::String((*v).to_owned())))
        .collect()
}

/// Serialises the state as a signed v4 file, reusing sealed boxes that have not changed.
fn encode(keys: &Keys, st: &mut State, audit_head: Option<&AuditHead>) -> Result<Vec<u8>> {
    if st.history_grew {
        history::trim(&mut st.history);
        st.history_grew = false;
        st.sealed_history = None;
    }
    let vid = keys.vault_id.as_str();
    let mut projects = Vec::with_capacity(st.projects.len());
    for p in &mut st.projects {
        if p.sealed_meta.is_none() {
            p.sealed_meta = Some(seal_json(&p.pk, &aad("project", &[vid, &p.id]), &p.meta)?);
        }
        let mut items = Vec::with_capacity(p.items.len());
        for i in &mut p.items {
            if i.sealed_meta.is_none() {
                i.sealed_meta = Some(seal_json(
                    &p.pk,
                    &aad("item-meta", &[vid, &p.id, &i.id]),
                    &i.meta,
                )?);
            }
            items.push(ItemFile {
                id: i.id.clone(),
                rev: i.rev,
                meta: i.sealed_meta.clone().unwrap_or_else(|| unreachable!()),
                secret: i.secret.clone(),
            });
        }
        projects.push(ProjectFile {
            id: p.id.clone(),
            key: p.wrapped_pk.clone(),
            meta: p.sealed_meta.clone().unwrap_or_else(|| unreachable!()),
            items,
        });
    }
    if st.sealed_history.is_none() {
        st.sealed_history = Some(seal_json(&keys.vk, &aad("history", &[vid]), &st.history)?);
    }
    let mut meta = st.meta.clone();
    meta.audit_head = audit_head.cloned();
    let mut file = VaultFile {
        v: crate::format::VERSION,
        vault_id: keys.vault_id.clone(),
        kdf: keys.kdf.clone(),
        secret_key: keys.secret_key.clone(),
        vault_key: keys.wrapped_vk.clone(),
        audit_key: keys.audit_public.clone(),
        audit_seed: keys.sealed_audit_seed.clone(),
        meta: seal_json(&keys.vk, &aad("meta", &[vid]), &meta)?,
        projects,
        history: st.sealed_history.clone().unwrap_or_else(|| unreachable!()),
        mac: None,
    };
    file.signed_bytes(&keys.mac)
}

/// Opens a parsed file with an Account Unlock Key. A key that does not unwrap the Vault Key is
/// a wrong password or Secret Key; anything failing after that is a modified file.
pub(crate) fn decode(file: &VaultFile, auk: Key32) -> Result<(Keys, State)> {
    let vid = file.vault_id.as_str();
    let vk = file
        .vault_key
        .open_key(&auk, &aad("vault-key", &[vid]))
        .map_err(|_| Error::Unlock)?;
    let mac = mac_key(&vk, vid)?;
    file.verify(&mac)?;
    let audit_seed = open_audit_seed(&file.audit_seed, &vk, vid)?;
    if b64(&audit::public_key(&audit_seed)) != file.audit_key {
        return Err(Error::Integrity);
    }
    let mut meta: VaultMeta = open_json(&file.meta, &vk, &aad("meta", &[vid]))?;
    let head = meta.audit_head.take();
    let mut projects = Vec::with_capacity(file.projects.len());
    let mut seen = std::collections::HashSet::new();
    for pf in &file.projects {
        if !seen.insert(pf.id.clone()) {
            return Err(Error::Integrity);
        }
        let pk = pf.key.open_key(&vk, &aad("project-key", &[vid, &pf.id]))?;
        let pmeta: ProjectMeta = open_json(&pf.meta, &pk, &aad("project", &[vid, &pf.id]))?;
        let mut items = Vec::with_capacity(pf.items.len());
        let mut item_ids = std::collections::HashSet::new();
        for itf in &pf.items {
            if !item_ids.insert(itf.id.clone()) {
                return Err(Error::Integrity);
            }
            let imeta: ItemMeta =
                open_json(&itf.meta, &pk, &aad("item-meta", &[vid, &pf.id, &itf.id]))?;
            items.push(Item {
                id: itf.id.clone(),
                rev: itf.rev,
                meta: imeta,
                secret: itf.secret.clone(),
                sealed_meta: Some(itf.meta.clone()),
            });
        }
        projects.push(Project {
            id: pf.id.clone(),
            pk,
            wrapped_pk: pf.key.clone(),
            meta: pmeta,
            sealed_meta: Some(pf.meta.clone()),
            items,
        });
    }
    let hist: Vec<history::Entry> = open_json(&file.history, &vk, &aad("history", &[vid]))?;
    let keys = Keys {
        vault_id: file.vault_id.clone(),
        kdf: file.kdf.clone(),
        secret_key: file.secret_key.clone(),
        wrapped_vk: file.vault_key.clone(),
        audit_public: file.audit_key.clone(),
        sealed_audit_seed: file.audit_seed.clone(),
        auk,
        vk,
        mac,
        audit_seed,
    };
    meta.audit_head = head;
    Ok((
        keys,
        State {
            meta,
            projects,
            history: hist,
            sealed_history: Some(file.history.clone()),
            history_grew: false,
        },
    ))
}

fn new_keys(
    password: &SecretString,
    secret_key: Option<&SecretKey>,
    params: KdfParams,
) -> Result<Keys> {
    let vault_id = new_vault_id();
    let kdf = KdfHeader::new(params);
    let auk = account_unlock_key(password, secret_key, &kdf, &vault_id)?;
    let vk = Key32::random();
    let mac = mac_key(&vk, &vault_id)?;
    let audit_seed = Key32::random();
    Ok(Keys {
        wrapped_vk: Sealed::seal_key(&auk, &aad("vault-key", &[&vault_id]), &vk),
        audit_public: b64(&audit::public_key(&audit_seed)),
        sealed_audit_seed: seal_audit_seed(&vk, &vault_id, &audit_seed)?,
        secret_key: secret_key.map(|k| SecretKeyHeader { id: k.id() }),
        vault_id,
        kdf,
        auk,
        vk,
        mac,
        audit_seed,
    })
}

/// Keys for the same Vault Key under a new password and/or Secret Key.
fn rewrap(
    keys: &Keys,
    password: &SecretString,
    secret_key: Option<&SecretKey>,
    params: KdfParams,
) -> Result<Keys> {
    let kdf = KdfHeader::new(params);
    let auk = account_unlock_key(password, secret_key, &kdf, &keys.vault_id)?;
    let mut next = keys.clone();
    next.wrapped_vk = Sealed::seal_key(&auk, &aad("vault-key", &[&keys.vault_id]), &keys.vk);
    next.kdf = kdf;
    next.secret_key = secret_key.map(|k| SecretKeyHeader { id: k.id() });
    next.auk = auk;
    Ok(next)
}

fn check_secret_key(header: Option<&SecretKeyHeader>, given: Option<&SecretKey>) -> Result<()> {
    match (header, given) {
        (Some(_), None) => Err(Error::SecretKeyRequired),
        (Some(h), Some(k)) if h.id != k.id() => {
            Err(Error::SecretKeyFormat("it belongs to a different vault"))
        }
        (None, Some(_)) => Err(Error::invalid("This vault does not use a Secret Key")),
        _ => Ok(()),
    }
}

#[derive(Debug)]
pub struct Store {
    data_dir: PathBuf,
    vault_path: PathBuf,
    open: Option<Open>,
    /// The version of `vault.enc` last read or written: its hash, and its inode, size and
    /// time, which answer "unchanged?" without reading the file.
    disk_hash: Option<String>,
    disk_id: Option<FileId>,
    batching: bool,
    pending: Option<State>,
}

impl Store {
    pub fn new(data_dir: impl AsRef<Path>) -> Result<Store> {
        let data_dir = data_dir.as_ref().to_path_buf();
        private_dir(&data_dir)?;
        Ok(Store {
            vault_path: data_dir.join(VAULT_FILE),
            data_dir,
            open: None,
            disk_hash: None,
            disk_id: None,
            batching: false,
            pending: None,
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn exists(&self) -> bool {
        self.vault_path.exists()
    }

    pub fn is_unlocked(&self) -> bool {
        self.open.is_some()
    }

    /// The file's envelope version: 1 or 2 for the JavaScript app's format v3, 4 for this one.
    pub fn file_version(&self) -> Result<u64> {
        crate::v3::envelope_version(&read_regular(&self.vault_path, MAX_VAULT_BYTES)?)
    }

    /// The id of the Secret Key this vault needs, if any, read without unlocking.
    pub fn secret_key_id(&self) -> Result<Option<String>> {
        let bytes = read_regular(&self.vault_path, MAX_VAULT_BYTES)?;
        Ok(VaultFile::parse(&bytes)?.secret_key.map(|h| h.id))
    }

    fn open(&self) -> Result<&Open> {
        self.open.as_ref().ok_or(Error::Locked)
    }

    fn state(&self) -> Result<&State> {
        let open = self.open()?;
        Ok(self.pending.as_ref().unwrap_or(&open.state))
    }

    pub fn vault_id(&self) -> Result<&str> {
        Ok(&self.open()?.keys.vault_id)
    }

    pub fn create(
        &mut self,
        password: &SecretString,
        secret_key: Option<&SecretKey>,
        params: KdfParams,
    ) -> Result<()> {
        validate::password(password.expose())?;
        if self.exists() {
            return Err(Error::Exists);
        }
        let keys = new_keys(password, secret_key, params)?;
        let state = State {
            meta: VaultMeta {
                created_at: now_iso(),
                ..Default::default()
            },
            ..Default::default()
        };
        self.disk_hash = None;
        self.disk_id = None;
        self.open = Some(Open {
            keys,
            state: State::default(),
            audit_head: None,
            saved_anchor: None,
            audit_problem: None,
            opened_at: now_iso(),
        });
        if let Err(e) = self.commit(state) {
            if !matches!(e, Error::Unconfirmed(_)) {
                self.open = None;
            }
            return Err(e);
        }
        Ok(())
    }

    pub fn unlock(
        &mut self,
        password: &SecretString,
        secret_key: Option<&SecretKey>,
    ) -> Result<()> {
        let (bytes, id) = read_with_id(&self.vault_path, MAX_VAULT_BYTES)?;
        match crate::v3::envelope_version(&bytes)? {
            1 | 2 => return Err(Error::NeedsUpgrade),
            _ => {}
        }
        let file = VaultFile::parse(&bytes)?;
        check_secret_key(file.secret_key.as_ref(), secret_key)?;
        let auk = account_unlock_key(password, secret_key, &file.kdf, &file.vault_id)?;
        let (keys, state) = decode(&file, auk)?;
        self.install(keys, state, &bytes, id);
        Ok(())
    }

    /// Takes a decoded vault and finds where the audit chain really ends: the head the vault
    /// recorded, or later entries written after its last save.
    fn install(&mut self, keys: Keys, mut state: State, bytes: &[u8], id: Option<FileId>) {
        let opened_at = now_iso();
        let anchor = state.meta.audit_head.take();
        let (head, problem) = match audit::verify_with(
            &self.data_dir,
            &keys.vault_id,
            &keys.audit_public,
            anchor.as_ref(),
            Signatures::AfterAnchor,
        ) {
            Ok((report, _)) => (report.head, None),
            Err(e) => (None, Some(e.to_string())),
        };
        self.disk_hash = Some(sha256_hex(bytes));
        self.disk_id = id;
        self.pending = None;
        self.batching = false;
        self.open = Some(Open {
            keys,
            state,
            audit_head: head,
            saved_anchor: anchor,
            audit_problem: problem,
            opened_at,
        });
    }

    pub fn lock(&mut self) {
        self.open = None;
        self.pending = None;
        self.batching = false;
        self.disk_hash = None;
        self.disk_id = None;
    }

    /// A problem found in the audit log at unlock. The log is set aside and a new chain starts
    /// at the next entry, so the problem stays visible and nothing is lost.
    pub fn audit_problem(&self) -> Option<&str> {
        self.open.as_ref().and_then(|o| o.audit_problem.as_deref())
    }

    /// Whether `vault.enc` is still the version this store last read or wrote. The file is
    /// read and hashed only when its inode, size or time differ.
    fn disk_unchanged(&self) -> Result<bool> {
        let Some(meta) = fs_safe::regular_file(&self.vault_path, true, MAX_VAULT_BYTES)? else {
            return Ok(self.disk_hash.is_none());
        };
        if self.disk_id.is_some() && FileId::of(&meta) == self.disk_id {
            return Ok(true);
        }
        let current = sha256_hex(&read_regular(&self.vault_path, MAX_VAULT_BYTES)?);
        Ok(self.disk_hash.as_deref() == Some(current.as_str()))
    }

    fn commit(&mut self, mut next: State) -> Result<()> {
        // A save records the audit head; one must never record "no head" over a log that
        // failed verification, or the next unlock would accept a cut-short log.
        self.reset_audit_if_needed()?;
        let bytes = {
            let open = self.open.as_ref().ok_or(Error::Locked)?;
            encode(&open.keys, &mut next, open.audit_head.as_ref())?
        };
        let _write = claim_with_retry(&self.data_dir)?;
        if !self.disk_unchanged()? {
            return Err(Error::Stale);
        }
        // `Unconfirmed` means the new file is in place: adopt it, then report.
        let written = atomic_write(&self.vault_path, &bytes);
        if let Err(e) = written {
            if !matches!(e, Error::Unconfirmed(_)) {
                return Err(e);
            }
            self.installed(next, &bytes)?;
            return Err(e);
        }
        self.installed(next, &bytes)
    }

    /// Records that `bytes` (encoding `next`) is now the file on disk.
    fn installed(&mut self, next: State, bytes: &[u8]) -> Result<()> {
        self.disk_hash = Some(sha256_hex(bytes));
        // Unknown means the next check reads the file instead.
        self.disk_id = fs_safe::file_id(&self.vault_path).ok().flatten();
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.saved_anchor.clone_from(&open.audit_head);
        open.state = next;
        Ok(())
    }

    fn mutate<R>(&mut self, f: impl FnOnce(&Keys, &mut State) -> Result<R>) -> Result<R> {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let mut next = self.pending.as_ref().unwrap_or(&open.state).clone();
        let r = f(&open.keys, &mut next)?;
        if self.batching {
            self.pending = Some(next);
            return Ok(r);
        }
        self.commit(next)?;
        Ok(r)
    }

    /// Runs `f` with every save inside it deferred to one save at the end. If `f` fails, or
    /// that save fails, none of its changes are kept.
    pub fn batch<R>(&mut self, f: impl FnOnce(&mut Store) -> Result<R>) -> Result<R> {
        if self.batching {
            return f(self);
        }
        self.open()?;
        self.batching = true;
        self.pending = None;
        let r = f(self);
        self.batching = false;
        let pending = self.pending.take();
        let r = r?;
        if let Some(next) = pending {
            self.commit(next)?;
        }
        Ok(r)
    }

    /// Reloads the vault if another process saved it. Refuses while a batch holds unsaved
    /// changes. A file now under a different password or Secret Key needs a new unlock.
    pub fn reload_if_changed(&mut self) -> Result<bool> {
        if self.open.is_none() || self.disk_unchanged()? {
            return Ok(false);
        }
        if self.batching {
            return Err(Error::Conflict(
                "unsaved changes in progress; the vault changed on disk".into(),
            ));
        }
        let _write = claim_with_retry(&self.data_dir)?;
        let (bytes, id) = read_with_id(&self.vault_path, MAX_VAULT_BYTES)?;
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let file = VaultFile::parse(&bytes)?;
        if file.vault_id != open.keys.vault_id {
            return Err(Error::Integrity);
        }
        if file.kdf != open.keys.kdf || file.secret_key != open.keys.secret_key {
            return Err(Error::Unlock);
        }
        let (keys, state) = decode(&file, open.keys.auk.clone())?;
        self.install(keys, state, &bytes, id);
        Ok(true)
    }

    fn verify_current(
        &self,
        password: &SecretString,
        secret_key: Option<&SecretKey>,
    ) -> Result<()> {
        let keys = &self.open()?.keys;
        check_secret_key(keys.secret_key.as_ref(), secret_key)?;
        let auk = account_unlock_key(password, secret_key, &keys.kdf, &keys.vault_id)?;
        if auk != keys.auk {
            return Err(Error::Unlock);
        }
        Ok(())
    }

    /// Saves new wrapping keys together with the history entry that records the change, in one
    /// write. If that write fails, the old keys stay in place, so the caller's error is true:
    /// the vault still opens with the old password and Secret Key.
    fn save_keys(&mut self, next_keys: Keys, action: &str) -> Result<()> {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let mut state = self.pending.as_ref().unwrap_or(&open.state).clone();
        next_keys.history_entry(
            &mut state,
            HUMAN,
            action,
            None,
            None,
            Payload::default(),
            None,
        )?;
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        let previous = std::mem::replace(&mut open.keys, next_keys);
        let r = self.commit(state);
        // After `Unconfirmed` the file on disk needs the new keys, so they stay.
        if r.as_ref()
            .is_err_and(|e| !matches!(e, Error::Unconfirmed(_)))
        {
            if let Some(o) = self.open.as_mut() {
                o.keys = previous;
            }
        }
        r
    }

    /// Changes the master password. Only the Vault Key is re-wrapped; nothing else is
    /// re-encrypted. Needs the current Secret Key when the vault uses one.
    pub fn change_password(
        &mut self,
        old: &SecretString,
        new: &SecretString,
        secret_key: Option<&SecretKey>,
    ) -> Result<()> {
        validate::password(new.expose())?;
        if self.batching {
            return Err(Error::Conflict("finish the batch first".into()));
        }
        self.verify_current(old, secret_key)?;
        let keys = &self.open()?.keys;
        let params = KdfHeader::params(&keys.kdf).unwrap_or(KdfParams::DEFAULT);
        let next = rewrap(keys, new, secret_key, params)?;
        self.save_keys(next, "change_password")
    }

    /// Adds, replaces (`Some`) or removes (`None`) the Secret Key.
    pub fn set_secret_key(
        &mut self,
        password: &SecretString,
        current: Option<&SecretKey>,
        next: Option<&SecretKey>,
    ) -> Result<()> {
        if self.batching {
            return Err(Error::Conflict("finish the batch first".into()));
        }
        self.verify_current(password, current)?;
        let keys = &self.open()?.keys;
        let params = KdfHeader::params(&keys.kdf).unwrap_or(KdfParams::DEFAULT);
        let rewrapped = rewrap(keys, password, next, params)?;
        let action = if next.is_some() {
            "set_secret_key"
        } else {
            "remove_secret_key"
        };
        self.save_keys(rewrapped, action)
    }

    /// If unlock found the audit log damaged, sets it aside and starts a new chain whose first
    /// entry records the problem. The problem is cleared only once that entry is written.
    fn reset_audit_if_needed(&mut self) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        let Some(problem) = open.audit_problem.clone() else {
            return Ok(());
        };
        let head = audit::reset(
            &self.data_dir,
            &open.keys.vault_id,
            &open.keys.audit_seed,
            &problem,
            &open.opened_at,
        )?;
        open.audit_head = Some(head);
        // The recorded head belonged to the log just set aside; the next save records the
        // new chain's.
        open.saved_anchor = None;
        open.audit_problem = None;
        Ok(())
    }

    /// Appends to the audit chain. The vault records the new head at its next save.
    pub fn audit(&mut self, action: &str, detail: &str, actor: &str) -> Result<()> {
        self.reset_audit_if_needed()?;
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.audit_head = Some(audit::append(
            &self.data_dir,
            &open.keys.vault_id,
            &open.keys.audit_seed,
            open.audit_head.as_ref(),
            actor,
            action,
            detail,
        )?);
        Ok(())
    }

    /// Checks every signature and link in the audit log against this vault, and that the
    /// newest entry the vault file recorded is still there.
    pub fn verify_audit(&self) -> Result<(audit::Report, Vec<audit::Entry>)> {
        let open = self.open()?;
        audit::verify(
            &self.data_dir,
            &open.keys.vault_id,
            &open.keys.audit_public,
            open.saved_anchor.as_ref(),
        )
    }

    // ── Projects ────────────────────────────────────────────────────────────────────────

    pub fn list_projects(&self) -> Result<Vec<ProjectSummary>> {
        Ok(self
            .state()?
            .projects
            .iter()
            .map(|p| {
                let mut providers: Vec<String> = Vec::new();
                for i in &p.items {
                    if !i.meta.provider.is_empty() && !providers.contains(&i.meta.provider) {
                        providers.push(i.meta.provider.clone());
                    }
                }
                ProjectSummary {
                    id: p.id.clone(),
                    name: p.meta.name.clone(),
                    secret_count: p.items.len(),
                    agent_key_count: p.items.iter().filter(|i| is_agent(&i.meta.owner)).count(),
                    pending_count: p.items.iter().filter(|i| !i.meta.inject_approved).count(),
                    providers,
                    updated_at: if p.meta.updated_at.is_empty() {
                        p.meta.created_at.clone()
                    } else {
                        p.meta.updated_at.clone()
                    },
                }
            })
            .collect())
    }

    pub fn create_project(&mut self, name: &str, actor: &str) -> Result<(String, String)> {
        validate::text(name, "project name", 256, false)?;
        let name = name.trim().to_owned();
        self.mutate(|k, st| {
            if st.project_index(&name).is_some() {
                return Err(Error::Conflict("Project already exists".into()));
            }
            let id = random_id();
            let (pk, wrapped_pk) = k.new_project_key(&id);
            let now = now_iso();
            st.projects.push(Project {
                id: id.clone(),
                pk,
                wrapped_pk,
                meta: ProjectMeta {
                    name: name.clone(),
                    owner: actor.to_owned(),
                    created_at: now.clone(),
                    updated_at: now,
                    extra: Map::new(),
                },
                sealed_meta: None,
                items: Vec::new(),
            });
            let after = json!({"id": id, "name": name});
            k.history_entry(
                st,
                actor,
                "create_project",
                Some(&name),
                None,
                Payload {
                    before: None,
                    after: Some(after),
                },
                None,
            )?;
            Ok((id, name.clone()))
        })
    }

    pub fn delete_project(&mut self, id_or_name: &str, actor: &str) -> Result<(String, String)> {
        forbidden_unless_human(actor, "deleting a project")?;
        self.mutate(|k, st| {
            let pi = st.project(id_or_name)?;
            let before = to_value(&project_v3(k, &st.projects[pi])?);
            let p = st.projects.remove(pi);
            for i in &p.items {
                st.tombstone(
                    format!("{}:{}", p.id, i.id),
                    actor,
                    label(&[("project", &p.meta.name), ("key", &i.meta.key)]),
                );
            }
            st.tombstone(
                format!("project:{}", p.id),
                actor,
                label(&[("project", &p.meta.name)]),
            );
            k.history_entry(
                st,
                actor,
                "delete_project",
                Some(&p.meta.name),
                None,
                Payload {
                    before: Some(before),
                    after: None,
                },
                None,
            )?;
            Ok((p.id.clone(), p.meta.name.clone()))
        })
    }

    // ── Items ───────────────────────────────────────────────────────────────────────────

    pub fn list_items(&self, project: &str) -> Result<Vec<ItemSummary>> {
        let st = self.state()?;
        let p = &st.projects[st.project(project)?];
        Ok(p.items.iter().map(summary).collect())
    }

    /// A project's id and name, by id or case-insensitive name.
    pub fn find_project(&self, id_or_name: &str) -> Result<Option<(String, String)>> {
        let st = self.state()?;
        Ok(st
            .project_index(id_or_name)
            .map(|i| (st.projects[i].id.clone(), st.projects[i].meta.name.clone())))
    }

    /// One item's metadata, by key or id.
    pub fn find_item(&self, project: &str, key_or_id: &str) -> Result<Option<ItemSummary>> {
        let st = self.state()?;
        let p = &st.projects[st.project(project)?];
        Ok(p.items
            .iter()
            .find(|i| i.meta.key == key_or_id || i.id == key_or_id)
            .map(summary))
    }

    /// Projects whose name, and items whose key or provider, contain `q` (case-insensitive).
    pub fn search(&self, q: &str) -> Result<Vec<SearchHit>> {
        let q = q.to_lowercase();
        let mut out = Vec::new();
        for p in &self.state()?.projects {
            if p.meta.name.to_lowercase().contains(&q) {
                out.push(SearchHit::Project {
                    project: p.meta.name.clone(),
                });
            }
            for i in &p.items {
                if i.meta.key.to_lowercase().contains(&q)
                    || i.meta.provider.to_lowercase().contains(&q)
                {
                    out.push(SearchHit::Secret {
                        project: p.meta.name.clone(),
                        key: i.meta.key.clone(),
                        provider: i.meta.provider.clone(),
                        owner: i.meta.owner.clone(),
                    });
                }
            }
        }
        Ok(out)
    }

    /// Each record's hash (`model.js` `recordHash`), for comparing two vaults without values.
    pub fn fingerprints(&self) -> Result<Vec<Fingerprint>> {
        let keys = &self.open()?.keys;
        let mut out = Vec::new();
        for p in &self.state()?.projects {
            for i in &p.items {
                out.push(Fingerprint {
                    project: p.meta.name.clone(),
                    project_id: p.id.clone(),
                    key: i.meta.key.clone(),
                    hash: record_hash(&keys.record(p, i)?),
                    owner: i.meta.owner.clone(),
                    updated_at: i.meta.updated_at.clone(),
                });
            }
        }
        out.sort_by(|a, b| {
            let (x, y) = (
                format!("{}{}", a.project, a.key),
                format!("{}{}", b.project, b.key),
            );
            x.to_lowercase().cmp(&y.to_lowercase()).then(x.cmp(&y))
        });
        Ok(out)
    }

    /// Writes a project's approved values to `target`, as `store.js` `inject` does. Keys an
    /// agent created that still await approval are left out and named in the result.
    pub fn inject(
        &mut self,
        project: &str,
        target: &Path,
        format: env::Format,
        merge: bool,
        keys: Option<&[String]>,
        actor: &str,
    ) -> Result<Injected> {
        if !target.is_absolute() {
            return Err(Error::invalid("target_path must be absolute"));
        }
        let resolved = crate::agents::resolve_lexically(target);
        if resolved.starts_with(&self.data_dir) {
            return Err(Error::invalid("Cannot export over vault data"));
        }
        let (pname, pairs, held) = {
            let st = self.state()?;
            let k = &self.open()?.keys;
            let p = &st.projects[st.project(project)?];
            let with_value = p.items.iter().filter(|i| i.meta.has_value);
            let held: Vec<String> = with_value
                .clone()
                .filter(|i| !i.meta.inject_approved)
                .map(|i| i.meta.key.clone())
                .collect();
            let mut pairs = Vec::new();
            for i in with_value.filter(|i| i.meta.inject_approved) {
                if keys.is_some_and(|ks| !ks.contains(&i.meta.key)) {
                    continue;
                }
                let secret = k.open_secret(p, i)?;
                pairs.push((i.meta.key.clone(), Zeroizing::new(secret.value.clone())));
            }
            (p.meta.name.clone(), pairs, held)
        };
        let shown = target.to_string_lossy().into_owned();
        self.audit(
            "inject",
            &format!(
                "{pname} -> {shown} ({} keys, {})",
                pairs.len(),
                format.as_str()
            ),
            actor,
        )?;
        env::write_env(target, &pairs, format, merge)?;
        Ok(Injected {
            project: pname,
            target: shown,
            count: pairs.len(),
            format: format.as_str().to_owned(),
            held_for_approval: held,
        })
    }

    /// Records that an agent was seen, in memory only: it is saved with the next change, as
    /// in the JavaScript app, so a read does not rewrite the vault.
    pub fn note_agent_seen(&mut self, id: &str) {
        let now = Value::String(now_iso());
        let Some(open) = self.open.as_mut() else {
            return;
        };
        for st in std::iter::once(&mut open.state).chain(self.pending.as_mut()) {
            for a in &mut st.meta.agents {
                if a.get("id").and_then(Value::as_str) == Some(id) {
                    if let Some(o) = a.as_object_mut() {
                        o.insert("lastSeenAt".into(), now.clone());
                    }
                }
            }
        }
    }

    /// Creates or updates an item. On update, fields left `None` keep their values.
    pub fn set_item(&mut self, project: &str, fields: &Fields, actor: &str) -> Result<Saved> {
        validate::fields(fields)?;
        self.mutate(|k, st| {
            let pi = st.project(project)?;
            let now = now_iso();
            let existing = st.projects[pi]
                .items
                .iter()
                .position(|i| i.meta.key == fields.key || i.id == fields.key);
            if let Some(ii) = existing {
                let p = &st.projects[pi];
                can_edit(&p.items[ii].meta, actor)?;
                let before = k.record(p, &p.items[ii])?;
                let mut after = before.clone();
                let set = |slot: &mut String, v: &Option<String>| {
                    if let Some(v) = v {
                        slot.clone_from(v);
                    }
                };
                if let Some(v) = &fields.value {
                    after.value = v.expose().to_owned();
                }
                if let Some(v) = &fields.password {
                    after.password = v.expose().to_owned();
                }
                set(&mut after.provider, &fields.provider);
                set(&mut after.note, &fields.note);
                set(&mut after.username, &fields.username);
                set(&mut after.email, &fields.email);
                set(&mut after.url, &fields.url);
                set(&mut after.permission, &fields.permission);
                set(&mut after.expires_at, &fields.expires_at);
                after.modified_by = actor.to_owned();
                after.updated_at.clone_from(&now);
                after.rev += 1;
                let item = k.item_from_record(p, &after)?;
                let saved = Saved {
                    id: after.id.clone(),
                    key: after.key.clone(),
                    provider: after.provider.clone(),
                    owner: after.owner.clone(),
                    inject_approved: after.inject_approved,
                };
                let pname = p.meta.name.clone();
                let p = &mut st.projects[pi];
                p.items[ii] = item;
                p.meta.updated_at = now;
                p.sealed_meta = None;
                let payload = Payload {
                    before: Some(to_value(&before)),
                    after: Some(to_value(&after)),
                };
                k.history_entry(
                    st,
                    actor,
                    "update_secret",
                    Some(&pname),
                    Some(&saved.key),
                    payload,
                    None,
                )?;
                return Ok(saved);
            }
            let owner = if actor == HUMAN {
                HUMAN.to_owned()
            } else {
                actor.to_owned()
            };
            let provider = fields
                .provider
                .clone()
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| crate::providers::match_key(&fields.key));
            let r = Record {
                id: random_id(),
                key: fields.key.clone(),
                value: fields
                    .value
                    .as_ref()
                    .map(|v| v.expose().to_owned())
                    .unwrap_or_default(),
                provider,
                note: fields.note.clone().unwrap_or_default(),
                username: fields.username.clone().unwrap_or_default(),
                email: fields.email.clone().unwrap_or_default(),
                password: fields
                    .password
                    .as_ref()
                    .map(|v| v.expose().to_owned())
                    .unwrap_or_default(),
                url: fields.url.clone().unwrap_or_default(),
                permission: fields.permission.clone().unwrap_or_default(),
                expires_at: fields.expires_at.clone().unwrap_or_default(),
                inject_approved: owner == HUMAN,
                owner,
                created_by: actor.to_owned(),
                modified_by: actor.to_owned(),
                editable_by: Vec::new(),
                created_at: now.clone(),
                updated_at: now.clone(),
                rev: 1,
                extra: Map::new(),
            };
            let item = k.item_from_record(&st.projects[pi], &r)?;
            let pid = st.projects[pi].id.clone();
            let pname = st.projects[pi].meta.name.clone();
            let p = &mut st.projects[pi];
            p.items.push(item);
            p.meta.updated_at = now;
            p.sealed_meta = None;
            st.untombstone(&format!("{pid}:{}", r.id));
            let saved = Saved {
                id: r.id.clone(),
                key: r.key.clone(),
                provider: r.provider.clone(),
                owner: r.owner.clone(),
                inject_approved: r.inject_approved,
            };
            k.history_entry(
                st,
                actor,
                "create_secret",
                Some(&pname),
                Some(&r.key),
                Payload {
                    before: None,
                    after: Some(to_value(&r)),
                },
                None,
            )?;
            Ok(saved)
        })
    }

    pub fn delete_item(&mut self, project: &str, key: &str, actor: &str) -> Result<String> {
        self.mutate(|k, st| {
            let pi = st.project(project)?;
            let ii = st.item(pi, key)?;
            can_delete(&st.projects[pi].items[ii].meta, actor)?;
            let before = k.record(&st.projects[pi], &st.projects[pi].items[ii])?;
            let p = &mut st.projects[pi];
            p.items.remove(ii);
            p.meta.updated_at = now_iso();
            p.sealed_meta = None;
            let (pid, pname) = (p.id.clone(), p.meta.name.clone());
            st.tombstone(
                format!("{pid}:{}", before.id),
                actor,
                label(&[("project", &pname), ("key", &before.key)]),
            );
            k.history_entry(
                st,
                actor,
                "delete_secret",
                Some(&pname),
                Some(&before.key),
                Payload {
                    before: Some(to_value(&before)),
                    after: None,
                },
                None,
            )?;
            Ok(before.key.clone())
        })
    }

    /// Applies `change` to one item's metadata as the human, bumping its revision and
    /// recording the change for Undo. The sealed secret is kept as it is, never opened.
    fn change_meta(
        &mut self,
        project: &str,
        key: &str,
        change: impl FnOnce(&mut ItemMeta),
    ) -> Result<ItemMeta> {
        self.mutate(|k, st| {
            let pi = st.project(project)?;
            let ii = st.item(pi, key)?;
            let p = &mut st.projects[pi];
            let pname = p.meta.name.clone();
            let item = &mut p.items[ii];
            let before = json!({"rev": item.rev, "meta": to_value(&item.meta)});
            change(&mut item.meta);
            item.meta.updated_at = now_iso();
            item.rev += 1;
            item.sealed_meta = None;
            let after = json!({"rev": item.rev, "meta": to_value(&item.meta)});
            let meta = item.meta.clone();
            k.history_entry(
                st,
                HUMAN,
                "update_meta",
                Some(&pname),
                Some(&meta.key),
                Payload {
                    before: Some(before),
                    after: Some(after),
                },
                None,
            )?;
            Ok(meta)
        })
    }

    pub fn delegate(
        &mut self,
        project: &str,
        key: &str,
        agent: &str,
        on: bool,
    ) -> Result<Vec<String>> {
        let reference = if is_agent(agent) {
            agent.to_owned()
        } else {
            agent_ref(agent)
        };
        let r = self.change_meta(project, key, |r| {
            if on && !r.editable_by.contains(&reference) {
                r.editable_by.push(reference.clone());
            }
            if !on {
                r.editable_by.retain(|a| *a != reference);
            }
        })?;
        Ok(r.editable_by.clone())
    }

    pub fn adopt(&mut self, project: &str, key: &str) -> Result<()> {
        self.change_meta(project, key, |r| {
            r.owner = HUMAN.to_owned();
            r.editable_by.clear();
            r.inject_approved = true;
        })
        .map(|_| ())
    }

    pub fn approve_inject(&mut self, project: &str, key: &str, approved: bool) -> Result<bool> {
        self.change_meta(project, key, |r| r.inject_approved = approved)
            .map(|r| r.inject_approved)
    }

    pub fn move_item(&mut self, from: &str, key: &str, to: &str, actor: &str) -> Result<bool> {
        forbidden_unless_human(actor, "moving a key between projects")?;
        self.mutate(|k, st| {
            let si = st
                .project_index(from)
                .ok_or_else(|| Error::not_found(format!("project not found: {from}")))?;
            let di = st
                .project_index(to)
                .ok_or_else(|| Error::not_found(format!("project not found: {to}")))?;
            if si == di {
                return Ok(false);
            }
            let ii = st.projects[si]
                .items
                .iter()
                .position(|i| i.meta.key == key || i.id == key)
                .ok_or_else(|| Error::not_found(format!("secret not found: {key}")))?;
            let before = k.record(&st.projects[si], &st.projects[si].items[ii])?;
            if st.projects[di]
                .items
                .iter()
                .any(|i| i.meta.key == before.key)
            {
                return Err(Error::Conflict(format!(
                    "\"{}\" already exists in \"{}\" — resolve the collision first",
                    before.key, st.projects[di].meta.name
                )));
            }
            let mut after = before.clone();
            after.updated_at = now_iso();
            after.rev += 1;
            let item = k.item_from_record(&st.projects[di], &after)?;
            let (src_id, src_name, dst_name) = (
                st.projects[si].id.clone(),
                st.projects[si].meta.name.clone(),
                st.projects[di].meta.name.clone(),
            );
            st.projects[si].items.remove(ii);
            st.tombstone(
                format!("{src_id}:{}", before.id),
                actor,
                label(&[
                    ("project", &src_name),
                    ("key", &before.key),
                    ("movedTo", &dst_name),
                ]),
            );
            st.projects[di].items.push(item);
            for i in [si, di] {
                st.projects[i].meta.updated_at.clone_from(&after.updated_at);
                st.projects[i].sealed_meta = None;
            }
            let payload = Payload {
                before: Some(to_value(&before)),
                after: Some(to_value(&after)),
            };
            k.history_entry(
                st,
                actor,
                "move_secret",
                Some(&dst_name),
                Some(&after.key),
                payload,
                Some(src_name),
            )?;
            Ok(true)
        })
    }

    pub fn pending_approvals(&self) -> Result<Vec<Pending>> {
        let st = self.state()?;
        let names: std::collections::HashMap<String, String> = st
            .meta
            .agents
            .iter()
            .filter_map(|a| {
                Some((
                    agent_ref(a.get("id")?.as_str()?),
                    a.get("name")?.as_str()?.to_owned(),
                ))
            })
            .collect();
        let mut out = Vec::new();
        for p in &st.projects {
            for i in p.items.iter().filter(|i| !i.meta.inject_approved) {
                out.push(Pending {
                    project: p.meta.name.clone(),
                    key: i.meta.key.clone(),
                    owner: i.meta.owner.clone(),
                    owner_name: names.get(&i.meta.owner).cloned(),
                    created_at: i.meta.created_at.clone(),
                });
            }
        }
        Ok(out)
    }

    /// Decrypts one item's secret and records the reveal in the audit chain.
    pub fn reveal(&mut self, project: &str, key: &str, actor: &str) -> Result<Revealed> {
        let (revealed, detail) = {
            let st = self.state()?;
            let keys = &self.open()?.keys;
            let pi = st.project(project)?;
            let ii = st.item(pi, key)?;
            let p = &st.projects[pi];
            let i = &p.items[ii];
            let secret = keys.open_secret(p, i)?;
            (
                Revealed {
                    key: i.meta.key.clone(),
                    value: SecretString::new(secret.value.clone()),
                    password: SecretString::new(secret.password.clone()),
                    provider: i.meta.provider.clone(),
                    username: i.meta.username.clone(),
                    email: i.meta.email.clone(),
                    url: i.meta.url.clone(),
                },
                format!("{}/{}", p.meta.name, i.meta.key),
            )
        };
        self.audit("reveal", &detail, actor)?;
        Ok(revealed)
    }

    // ── History ─────────────────────────────────────────────────────────────────────────

    pub fn list_history(&self, limit: usize) -> Result<Vec<HistorySummary>> {
        let st = self.state()?;
        Ok(st
            .history
            .iter()
            .rev()
            .take(if limit == 0 { usize::MAX } else { limit })
            .map(|e| HistorySummary {
                id: e.id.clone(),
                ts: e.ts.clone(),
                actor: e.actor.clone(),
                action: e.action.clone(),
                project: e.project.clone(),
                key: e.key.clone(),
                reference: e.reference.clone(),
                reverted: e.reverted,
            })
            .collect())
    }

    /// Undoes one change if nothing changed the record since, as `store.js` `revert` does.
    pub fn revert(&mut self, history_id: &str, actor: &str) -> Result<String> {
        if actor != HUMAN {
            return Err(Error::forbidden("undo is human-only, in the VaultOS app"));
        }
        self.mutate(|k, st| {
            let hi = st.history.iter().position(|e| e.id == history_id).ok_or_else(|| Error::not_found("history entry not found"))?;
            let entry = st.history[hi].clone();
            if entry.reverted {
                return Err(Error::Conflict("this change was already undone".into()));
            }
            let payload = history::open_payload(&k.vk, &k.vault_id, &entry)?;
            let refuse = || Error::Conflict("This record changed after that operation; undo would overwrite newer work".into());
            let pi = entry.project.as_deref().and_then(|n| st.project_index(n));
            let current = match (pi, entry.key.as_deref()) {
                (Some(pi), Some(key)) => st.projects[pi].items.iter().position(|i| i.meta.key == key || i.id == key).map(|ii| (pi, ii)),
                _ => None,
            };
            let rec = |v: &Option<Value>| -> Result<Record> {
                v.clone().ok_or_else(refuse).and_then(|v| serde_json::from_value(v).map_err(|_| refuse()))
            };
            let restore = |r: Record, current_rev: u64, after_rev: u64| -> Record {
                let mut r = r;
                r.rev = r.rev.max(current_rev).max(after_rev) + 1;
                r.updated_at = now_iso();
                r.modified_by = HUMAN.to_owned();
                r
            };
            match entry.action.as_str() {
                "create_secret" => {
                    let (pi, ii) = current.ok_or_else(refuse)?;
                    let cur = k.record(&st.projects[pi], &st.projects[pi].items[ii])?;
                    if record_hash(&cur) != record_hash(&rec(&payload.after)?) {
                        return Err(refuse());
                    }
                    let pid = st.projects[pi].id.clone();
                    st.projects[pi].items.remove(ii);
                    st.tombstone(format!("{pid}:{}", cur.id), actor, Map::new());
                }
                "update_secret" => {
                    let (pi, ii) = current.ok_or_else(refuse)?;
                    let cur = k.record(&st.projects[pi], &st.projects[pi].items[ii])?;
                    let after = rec(&payload.after)?;
                    if record_hash(&cur) != record_hash(&after) {
                        return Err(refuse());
                    }
                    let restored = restore(rec(&payload.before)?, cur.rev, after.rev);
                    st.projects[pi].items[ii] = k.item_from_record(&st.projects[pi], &restored)?;
                }
                "update_meta" => {
                    let (pi, ii) = current.ok_or_else(refuse)?;
                    let field = |v: &Option<Value>, name: &str| v.as_ref().and_then(|v| v.get(name)).cloned();
                    let item = &st.projects[pi].items[ii];
                    let after_rev = field(&payload.after, "rev").and_then(|v| v.as_u64());
                    if after_rev != Some(item.rev) || field(&payload.after, "meta") != Some(to_value(&item.meta)) {
                        return Err(refuse());
                    }
                    let mut meta: ItemMeta = field(&payload.before, "meta")
                        .and_then(|v| serde_json::from_value(v).ok())
                        .ok_or_else(refuse)?;
                    if meta.key != item.meta.key {
                        return Err(refuse());
                    }
                    meta.updated_at = now_iso();
                    meta.modified_by = HUMAN.to_owned();
                    let item = &mut st.projects[pi].items[ii];
                    item.meta = meta;
                    item.rev += 1;
                    item.sealed_meta = None;
                }
                "delete_secret" => {
                    let pi = pi.ok_or_else(refuse)?;
                    if current.is_some() {
                        return Err(refuse());
                    }
                    let before = rec(&payload.before)?;
                    let restored = restore(before, 0, 0);
                    let item = k.item_from_record(&st.projects[pi], &restored)?;
                    let pid = st.projects[pi].id.clone();
                    st.projects[pi].items.push(item);
                    st.untombstone(&format!("{pid}:{}", restored.id));
                }
                "create_project" => {
                    let pi = pi.ok_or_else(refuse)?;
                    let after_id = payload.after.as_ref().and_then(|a| a.get("id")).and_then(Value::as_str).unwrap_or("");
                    if st.projects[pi].id != after_id || !st.projects[pi].items.is_empty() {
                        return Err(refuse());
                    }
                    let p = st.projects.remove(pi);
                    st.tombstone(format!("project:{}", p.id), actor, Map::new());
                }
                "delete_project" => {
                    if pi.is_some() {
                        return Err(refuse());
                    }
                    let before: ProjectV3 = payload
                        .before
                        .clone()
                        .ok_or_else(refuse)
                        .and_then(|v| serde_json::from_value(v).map_err(|_| refuse()))?;
                    let p = project_from_v3(k, &before, |r| restore(r, 0, 0))?;
                    let pid = p.id.clone();
                    st.projects.push(p);
                    st.meta.tombstones.retain(|t| t.reference != format!("project:{pid}") && !t.reference.starts_with(&format!("{pid}:")));
                }
                "update_settings" => {
                    return Err(Error::invalid("Change settings explicitly; security settings cannot be undone through history"))
                }
                _ => return Err(Error::invalid("This action cannot be undone")),
            }
            st.history[hi].reverted = true;
            st.sealed_history = None;
            k.history_entry(st, actor, "revert", entry.project.as_deref(), entry.key.as_deref(), Payload::default(), Some(entry.id.clone()))?;
            Ok(entry.action.clone())
        })
    }

    // ── Settings, agents, tombstones ────────────────────────────────────────────────────

    pub fn settings(&self) -> Result<&Map<String, Value>> {
        Ok(&self.state()?.meta.settings)
    }

    /// Merges top-level settings. Which settings exist and who may change them is decided by
    /// the caller (the API layer), as in the JavaScript app.
    pub fn update_settings(&mut self, patch: Map<String, Value>, actor: &str) -> Result<()> {
        forbidden_unless_human(actor, "changing settings")?;
        self.mutate(|k, st| {
            let before = Value::Object(st.meta.settings.clone());
            for (key, v) in patch {
                if v.is_null() {
                    st.meta.settings.remove(&key);
                } else {
                    st.meta.settings.insert(key, v);
                }
            }
            let after = Value::Object(st.meta.settings.clone());
            k.history_entry(
                st,
                actor,
                "update_settings",
                None,
                None,
                Payload {
                    before: Some(before),
                    after: Some(after),
                },
                None,
            )?;
            Ok(())
        })
    }

    pub fn agents(&self) -> Result<&[Value]> {
        Ok(&self.state()?.meta.agents)
    }

    pub fn set_agents(&mut self, agents: Vec<Value>) -> Result<()> {
        self.mutate(|_, st| {
            st.meta.agents = agents;
            Ok(())
        })
    }

    pub fn tombstones(&self) -> Result<&[Tombstone]> {
        Ok(&self.state()?.meta.tombstones)
    }

    /// Everything decrypted, in the JavaScript app's shape: used to verify an upgrade, by
    /// tests, and by sync. Holds every value; drop it as soon as possible.
    pub fn export_v3(&self) -> Result<VaultV3> {
        let open = self.open()?;
        let st = self.state()?;
        export_v3(&open.keys, st)
    }
}

fn claim_with_retry(dir: &Path) -> Result<fs_safe::LockFile> {
    let mut last = Error::Busy;
    for _ in 0..40 {
        match claim(dir, "write.lock") {
            Ok(l) => return Ok(l),
            Err(Error::Busy) => {
                last = Error::Busy;
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SearchHit {
    Project {
        project: String,
    },
    Secret {
        project: String,
        key: String,
        provider: String,
        owner: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fingerprint {
    pub project: String,
    pub project_id: String,
    pub key: String,
    pub hash: String,
    pub owner: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Injected {
    pub project: String,
    pub target: String,
    pub count: usize,
    pub format: String,
    pub held_for_approval: Vec<String>,
}

/// `store.js` `expiryInfo`: none, active, expiring (7 days or fewer) or expired.
pub(crate) fn expiry_info(expires_at: &str) -> (String, Option<i64>) {
    if expires_at.is_empty() {
        return ("none".into(), None);
    }
    let parsed = crate::model::parse_iso(expires_at).or_else(|| {
        (expires_at.len() == 10)
            .then(|| crate::model::parse_iso(&format!("{expires_at}T00:00:00Z")))
            .flatten()
    });
    let Some(t) = parsed else {
        return ("active".into(), None);
    };
    let ms = (t - time::OffsetDateTime::now_utc()).whole_milliseconds();
    let days = (ms as f64 / 86_400_000.0).ceil() as i64;
    let status = if ms <= 0 {
        "expired"
    } else if days <= 7 {
        "expiring"
    } else {
        "active"
    };
    (status.into(), Some(days))
}

fn summary(i: &Item) -> ItemSummary {
    let (expiry_status, days_left) = expiry_info(&i.meta.expires_at);
    ItemSummary {
        id: i.id.clone(),
        key: i.meta.key.clone(),
        provider: i.meta.provider.clone(),
        note: i.meta.note.clone(),
        username: i.meta.username.clone(),
        email: i.meta.email.clone(),
        url: i.meta.url.clone(),
        permission: i.meta.permission.clone(),
        expires_at: i.meta.expires_at.clone(),
        expiry_status,
        days_left,
        owner: i.meta.owner.clone(),
        created_by: i.meta.created_by.clone(),
        editable_by: i.meta.editable_by.clone(),
        inject_approved: i.meta.inject_approved,
        has_value: i.meta.has_value,
        has_password: i.meta.has_password,
        updated_at: i.meta.updated_at.clone(),
        rev: i.rev,
    }
}

pub(crate) fn project_v3(k: &Keys, p: &Project) -> Result<ProjectV3> {
    Ok(ProjectV3 {
        id: p.id.clone(),
        name: p.meta.name.clone(),
        secrets: p
            .items
            .iter()
            .map(|i| k.record(p, i))
            .collect::<Result<_>>()?,
        owner: p.meta.owner.clone(),
        created_at: p.meta.created_at.clone(),
        updated_at: p.meta.updated_at.clone(),
        extra: p.meta.extra.clone(),
    })
}

pub(crate) fn project_from_v3(
    k: &Keys,
    v: &ProjectV3,
    fix: impl Fn(Record) -> Record,
) -> Result<Project> {
    check_id(&v.id)?;
    let (pk, wrapped_pk) = k.new_project_key(&v.id);
    let mut p = Project {
        id: v.id.clone(),
        pk,
        wrapped_pk,
        meta: ProjectMeta {
            name: v.name.clone(),
            owner: v.owner.clone(),
            created_at: v.created_at.clone(),
            updated_at: v.updated_at.clone(),
            extra: v.extra.clone(),
        },
        sealed_meta: None,
        items: Vec::new(),
    };
    let mut ids = std::collections::HashSet::new();
    for r in &v.secrets {
        if !ids.insert(r.id.clone()) {
            return Err(Error::Format(format!(
                "duplicate record id in project \"{}\"",
                v.name
            )));
        }
        let item = k.item_from_record(&p, &fix(r.clone()))?;
        p.items.push(item);
    }
    Ok(p)
}

pub(crate) fn export_v3(k: &Keys, st: &State) -> Result<VaultV3> {
    let history = st
        .history
        .iter()
        .map(|e| {
            let p = history::open_payload(&k.vk, &k.vault_id, e)?;
            Ok(crate::model::HistoryEntryV3 {
                id: e.id.clone(),
                ts: e.ts.clone(),
                actor: e.actor.clone(),
                action: e.action.clone(),
                project: e.project.clone(),
                key: e.key.clone(),
                before: p.before.clone(),
                after: p.after.clone(),
                reference: e.reference.clone(),
                reverted: e.reverted,
                extra: e.extra.clone(),
            })
        })
        .collect::<Result<_>>()?;
    Ok(VaultV3 {
        format_version: None,
        min_reader_version: None,
        projects: st
            .projects
            .iter()
            .map(|p| project_v3(k, p))
            .collect::<Result<_>>()?,
        agents: st.meta.agents.clone(),
        tombstones: st.meta.tombstones.clone(),
        history,
        settings: st.meta.settings.clone(),
        sync_trust: st.meta.sync_trust.clone(),
        extra: st.meta.extra.clone(),
    })
}

/// Builds a v4 vault from a decrypted v3 one, for the upgrade.
pub(crate) fn from_v3(
    v3: &VaultV3,
    password: &SecretString,
    secret_key: Option<&SecretKey>,
    params: KdfParams,
) -> Result<(Keys, State)> {
    let keys = new_keys(password, secret_key, params)?;
    let mut st = State {
        meta: VaultMeta {
            settings: v3.settings.clone(),
            agents: v3.agents.clone(),
            tombstones: v3.tombstones.clone(),
            sync_trust: v3.sync_trust.clone(),
            audit_head: None,
            created_at: now_iso(),
            extra: v3.extra.clone(),
        },
        ..Default::default()
    };
    let mut ids = std::collections::HashSet::new();
    for p in &v3.projects {
        if !ids.insert(p.id.clone()) {
            return Err(Error::Format("duplicate project id".into()));
        }
        st.projects.push(project_from_v3(&keys, p, |r| r)?);
    }
    for e in &v3.history {
        check_id(&e.id)?;
        let payload = Payload {
            before: e.before.clone(),
            after: e.after.clone(),
        };
        let sealed = if payload.before.is_some() || payload.after.is_some() {
            Some(history::seal_payload(
                &keys.vk,
                &keys.vault_id,
                &e.id,
                &payload,
            )?)
        } else {
            None
        };
        st.history.push(history::Entry {
            id: e.id.clone(),
            ts: e.ts.clone(),
            actor: e.actor.clone(),
            action: e.action.clone(),
            project: e.project.clone(),
            key: e.key.clone(),
            reference: e.reference.clone(),
            reverted: e.reverted,
            payload: sealed,
            size: history::logical_size(e),
            extra: e.extra.clone(),
        });
    }
    Ok((keys, st))
}

pub(crate) fn encode_new(
    keys: &Keys,
    st: &mut State,
    audit_head: Option<&AuditHead>,
) -> Result<Vec<u8>> {
    encode(keys, st, audit_head)
}
