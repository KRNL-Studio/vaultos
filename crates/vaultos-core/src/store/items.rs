//! Typed-item operations: the Trash, attachments, per-item history, Watchtower, one-time
//! codes and importing from other password managers.

use super::*;
use crate::crypto::{open_raw, seal_raw};
use crate::generator::estimate_bits;
use crate::import::{Imported, Report};
use crate::model::{parse_iso, Attachment};
use crate::secret::SecretBytes;
use crate::totp::Totp;
use std::collections::{HashMap, HashSet};

pub const MAX_ATTACHMENTS: usize = 20;
pub const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;
/// Items stay in the Trash this long before they and their history are purged.
pub const TRASH_DAYS: i64 = 30;
const ATTACHMENTS_DIR: &str = "attachments";
/// A password unchanged for longer than this is reported as old.
const OLD_DAYS: i64 = 365;
const WEAK_BITS: f64 = 40.0;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashedItem {
    pub project: String,
    pub item: ItemSummary,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemVersion {
    #[serde(flatten)]
    pub entry: HistorySummary,
    /// Whether [`Store::restore_version`] can bring this version back.
    pub restorable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub project: String,
    pub key: String,
    pub kind: String,
    /// `weak`, `reused`, `old`, `expiring` or `expired`.
    pub problem: &'static str,
    pub detail: String,
}

pub struct Otp {
    pub code: SecretString,
    pub remaining: u64,
    pub period: u64,
}

impl std::fmt::Debug for Otp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Otp")
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub project: String,
    pub imported: usize,
    /// Items saved under a different key than their title, because the key was taken.
    pub renamed: Vec<String>,
    pub skipped: Vec<String>,
}

fn attachment_aad(vault: &str, project: &str, item: &str, id: &str) -> Vec<u8> {
    aad("attachment", &[vault, project, item, id])
}

fn days_since(ts: &str) -> Option<i64> {
    let t = parse_iso(ts)?;
    Some((time::OffsetDateTime::now_utc() - t).whole_days())
}

impl Store {
    fn attachment_file(&self, id: &str) -> PathBuf {
        self.data_dir
            .join(ATTACHMENTS_DIR)
            .join(format!("{id}.bin"))
    }

    pub(super) fn drop_attachment_files(&self, ids: &[String]) {
        for id in ids {
            let _ = std::fs::remove_file(self.attachment_file(id));
        }
    }

    /// Removes attachment files no item refers to (after a purge or a project deletion).
    pub(super) fn prune_attachment_files(&self) {
        if self.batching || self.pending.is_some() {
            return;
        }
        let Ok(st) = self.state() else {
            return;
        };
        let keep: HashSet<String> = st
            .projects
            .iter()
            .flat_map(|p| &p.items)
            .flat_map(|i| i.meta.attachments.iter().map(|a| format!("{}.bin", a.id)))
            .collect();
        let Ok(dir) = std::fs::read_dir(self.data_dir.join(ATTACHMENTS_DIR)) else {
            return;
        };
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".bin") && !keep.contains(&name) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    fn read_attachment(&self, a: &Attachment) -> Result<Vec<u8>> {
        let file = self.attachment_file(&a.id);
        if !file.exists() {
            return Err(Error::not_found(
                "This attachment is not on this device; attachments are not synced",
            ));
        }
        let sealed = fs_safe::read_regular(&file, MAX_ATTACHMENT_BYTES as u64 + 64)?;
        if sha256_hex(&sealed) != a.sha256 {
            return Err(Error::Integrity);
        }
        Ok(sealed)
    }

    /// For [`Store::move_item`]: the item's attachments sealed again under the destination
    /// project as new files, and the ids of the files they replace.
    pub(super) fn reseal_attachments(
        &self,
        from: &str,
        key: &str,
        to: &str,
    ) -> Result<(Vec<Attachment>, Vec<String>)> {
        let st = self.state()?;
        let k = &self.open()?.keys;
        let (Some(si), Some(di)) = (st.project_index(from), st.project_index(to)) else {
            return Ok((Vec::new(), Vec::new()));
        };
        let Some(item) = st.projects[si]
            .items
            .iter()
            .find(|i| i.meta.key == key || i.id == key)
        else {
            return Ok((Vec::new(), Vec::new()));
        };
        let (src, dst) = (&st.projects[si], &st.projects[di]);
        let mut fresh = Vec::new();
        let mut old = Vec::new();
        let written = |list: &[Attachment]| list.iter().map(|a| a.id.clone()).collect::<Vec<_>>();
        for a in &item.meta.attachments {
            // One that is not on this device keeps its entry, unreadable here as before.
            let Ok(sealed) = self.read_attachment(a) else {
                fresh.push(a.clone());
                continue;
            };
            let plain = open_raw(
                &src.pk,
                &attachment_aad(&k.vault_id, &src.id, &item.id, &a.id),
                &sealed,
            )?;
            let id = random_id();
            let resealed = seal_raw(
                &dst.pk,
                &attachment_aad(&k.vault_id, &dst.id, &item.id, &id),
                plain.expose(),
            );
            if let Err(e) = fs_safe::atomic_write(&self.attachment_file(&id), &resealed) {
                if !matches!(e, Error::Unconfirmed(_)) {
                    self.drop_attachment_files(&written(&fresh));
                    return Err(e);
                }
            }
            fresh.push(Attachment {
                id,
                sha256: sha256_hex(&resealed),
                ..a.clone()
            });
            old.push(a.id.clone());
        }
        Ok((fresh, old))
    }

    // ── Trash ───────────────────────────────────────────────────────────────────────────

    pub fn list_trash(&self) -> Result<Vec<TrashedItem>> {
        let st = self.state()?;
        Ok(st
            .projects
            .iter()
            .flat_map(|p| {
                p.items
                    .iter()
                    .filter(|i| !i.meta.trashed_at.is_empty())
                    .map(|i| TrashedItem {
                        project: p.meta.name.clone(),
                        item: summary(i),
                    })
            })
            .collect())
    }

    pub fn restore_item(&mut self, project: &str, key: &str, actor: &str) -> Result<String> {
        forbidden_unless_human(actor, "restoring from the Trash")?;
        {
            let st = self.state()?;
            let pi = st.project(project)?;
            if st.projects[pi].items[st.item(pi, key)?]
                .meta
                .trashed_at
                .is_empty()
            {
                return Err(Error::invalid("This item is not in the Trash"));
            }
        }
        let meta = self.change_meta_as(project, key, actor, "restore_secret", |m| {
            m.trashed_at.clear();
            m.modified_by = HUMAN.to_owned();
        })?;
        Ok(meta.key)
    }

    /// Permanently deletes one item from the Trash, with its history and attachments.
    pub fn purge_item(&mut self, project: &str, key: &str, actor: &str) -> Result<String> {
        forbidden_unless_human(actor, "deleting permanently")?;
        let (pid, id, name) = {
            let st = self.state()?;
            let pi = st.project(project)?;
            let i = &st.projects[pi].items[st.item(pi, key)?];
            if i.meta.trashed_at.is_empty() {
                return Err(Error::invalid("Move the item to the Trash first"));
            }
            (st.projects[pi].id.clone(), i.id.clone(), i.meta.key.clone())
        };
        self.purge_where(actor, |p, i| p == pid && i.id == id)?;
        Ok(name)
    }

    pub fn empty_trash(&mut self, actor: &str) -> Result<usize> {
        forbidden_unless_human(actor, "emptying the Trash")?;
        self.purge_where(actor, |_, i| !i.meta.trashed_at.is_empty())
    }

    /// Purges what has been in the Trash for [`TRASH_DAYS`] days. The app calls it after a
    /// human unlock; nothing is saved when nothing is due.
    pub fn purge_expired_trash(&mut self) -> Result<usize> {
        self.purge_where(HUMAN, |_, i| {
            days_since(&i.meta.trashed_at).is_some_and(|d| d >= TRASH_DAYS)
        })
    }

    fn purge_where(&mut self, actor: &str, pick: impl Fn(&str, &Item) -> bool) -> Result<usize> {
        let due = self
            .state()?
            .projects
            .iter()
            .any(|p| p.items.iter().any(|i| pick(&p.id, i)));
        if !due {
            return Ok(0);
        }
        let n = self.mutate(|k, st| {
            let mut gone: Vec<(String, String, String, String)> = Vec::new();
            for p in &mut st.projects {
                let (pid, pname) = (p.id.clone(), p.meta.name.clone());
                let before = p.items.len();
                p.items.retain(|i| {
                    let purge = pick(&pid, i);
                    if purge {
                        gone.push((pid.clone(), pname.clone(), i.id.clone(), i.meta.key.clone()));
                    }
                    !purge
                });
                if p.items.len() != before {
                    p.meta.updated_at = now_iso();
                    p.sealed_meta = None;
                }
            }
            // The values went with the item; so does every earlier version of it.
            st.history.retain(|e| {
                !gone.iter().any(|(_, pname, _, key)| {
                    e.key.as_deref() == Some(key.as_str())
                        && (e.project.as_deref() == Some(pname.as_str())
                            || e.reference.as_deref() == Some(pname.as_str()))
                })
            });
            st.sealed_history = None;
            for (pid, pname, id, key) in &gone {
                st.tombstone(
                    format!("{pid}:{id}"),
                    actor,
                    label(&[("project", pname), ("key", key)]),
                );
                k.history_entry(
                    st,
                    actor,
                    "purge_secret",
                    Some(pname),
                    Some(key),
                    Payload::default(),
                    None,
                )?;
            }
            Ok(gone.len())
        })?;
        self.prune_attachment_files();
        Ok(n)
    }

    // ── Attachments ─────────────────────────────────────────────────────────────────────

    pub fn add_attachment(
        &mut self,
        project: &str,
        key: &str,
        name: &str,
        bytes: &[u8],
        actor: &str,
    ) -> Result<Attachment> {
        forbidden_unless_human(actor, "attaching files")?;
        if bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(Error::invalid("Attachments can be up to 25 MB each"));
        }
        let name = Path::new(name.trim())
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        validate::text(&name, "file name", 255, false)?;
        let id = random_id();
        let sealed = {
            let st = self.state()?;
            let k = &self.open()?.keys;
            let pi = st.project(project)?;
            let p = &st.projects[pi];
            let i = &p.items[st.item(pi, key)?];
            if i.meta.attachments.len() >= MAX_ATTACHMENTS {
                return Err(Error::invalid(format!(
                    "An item can have up to {MAX_ATTACHMENTS} attachments"
                )));
            }
            seal_raw(
                &p.pk,
                &attachment_aad(&k.vault_id, &p.id, &i.id, &id),
                bytes,
            )
        };
        private_dir(&self.data_dir.join(ATTACHMENTS_DIR))?;
        match fs_safe::atomic_write(&self.attachment_file(&id), &sealed) {
            Ok(()) | Err(Error::Unconfirmed(_)) => {}
            Err(e) => return Err(e),
        }
        let att = Attachment {
            id: id.clone(),
            name,
            size: bytes.len() as u64,
            sha256: sha256_hex(&sealed),
            added_at: now_iso(),
        };
        let added = att.clone();
        let saved = self.mutate(|k, st| {
            let pi = st.project(project)?;
            let ii = st.item(pi, key)?;
            let p = &mut st.projects[pi];
            let pname = p.meta.name.clone();
            let item = &mut p.items[ii];
            item.meta.attachments.push(added);
            item.meta.updated_at = now_iso();
            item.rev += 1;
            item.sealed_meta = None;
            let key = item.meta.key.clone();
            p.sealed_meta = None;
            k.history_entry(
                st,
                actor,
                "add_attachment",
                Some(&pname),
                Some(&key),
                Payload::default(),
                None,
            )
        });
        if saved.is_err() {
            self.drop_attachment_files(&[id]);
        }
        saved.map(|_| att)
    }

    /// An attachment's name and contents. Opening one is recorded in the audit log.
    pub fn open_attachment(
        &mut self,
        project: &str,
        key: &str,
        id: &str,
        actor: &str,
    ) -> Result<(String, SecretBytes)> {
        forbidden_unless_human(actor, "opening attachments")?;
        let (name, plain, detail) = {
            let st = self.state()?;
            let k = &self.open()?.keys;
            let pi = st.project(project)?;
            let p = &st.projects[pi];
            let i = &p.items[st.item(pi, key)?];
            let a = i
                .meta
                .attachments
                .iter()
                .find(|a| a.id == id)
                .ok_or_else(|| Error::not_found("attachment not found"))?;
            let sealed = self.read_attachment(a)?;
            let plain = open_raw(
                &p.pk,
                &attachment_aad(&k.vault_id, &p.id, &i.id, &a.id),
                &sealed,
            )?;
            (
                a.name.clone(),
                plain,
                format!("{}/{}/{}", p.meta.name, i.meta.key, a.name),
            )
        };
        self.audit("attachment", &detail, actor)?;
        Ok((name, plain))
    }

    /// Removes an attachment and deletes its file. This cannot be undone.
    pub fn remove_attachment(
        &mut self,
        project: &str,
        key: &str,
        id: &str,
        actor: &str,
    ) -> Result<()> {
        forbidden_unless_human(actor, "removing attachments")?;
        self.mutate(|k, st| {
            let pi = st.project(project)?;
            let ii = st.item(pi, key)?;
            let p = &mut st.projects[pi];
            let pname = p.meta.name.clone();
            let item = &mut p.items[ii];
            let before = item.meta.attachments.len();
            item.meta.attachments.retain(|a| a.id != id);
            if item.meta.attachments.len() == before {
                return Err(Error::not_found("attachment not found"));
            }
            item.meta.updated_at = now_iso();
            item.rev += 1;
            item.sealed_meta = None;
            let key = item.meta.key.clone();
            p.sealed_meta = None;
            k.history_entry(
                st,
                actor,
                "remove_attachment",
                Some(&pname),
                Some(&key),
                Payload::default(),
                None,
            )
        })?;
        if !self.batching {
            self.drop_attachment_files(&[id.to_owned()]);
        }
        Ok(())
    }

    // ── Per-item history ────────────────────────────────────────────────────────────────

    /// The changes to one item, newest first, including from before a move.
    pub fn item_history(&self, project: &str, key: &str) -> Result<Vec<ItemVersion>> {
        let st = self.state()?;
        let pi = st.project(project)?;
        let pname = st.projects[pi].meta.name.as_str();
        let key = st
            .item(pi, key)
            .map(|ii| st.projects[pi].items[ii].meta.key.clone())
            .unwrap_or_else(|_| key.to_owned());
        Ok(st
            .history
            .iter()
            .rev()
            .filter(|e| {
                e.key.as_deref() == Some(key.as_str())
                    && (e.project.as_deref() == Some(pname)
                        || e.reference.as_deref() == Some(pname))
            })
            .map(|e| ItemVersion {
                restorable: e.payload.is_some()
                    && matches!(
                        e.action.as_str(),
                        "create_secret" | "update_secret" | "move_secret" | "delete_secret"
                    ),
                entry: HistorySummary {
                    id: e.id.clone(),
                    ts: e.ts.clone(),
                    actor: e.actor.clone(),
                    action: e.action.clone(),
                    project: e.project.clone(),
                    key: e.key.clone(),
                    reference: e.reference.clone(),
                    reverted: e.reverted,
                },
            })
            .collect())
    }

    /// Makes the item as it was after the change `history_id` (before it, for a deletion) its
    /// current version. Who owns it, which agents may edit it and its approval stay as they
    /// are now, and so do its attachments. The restore is itself a change that Undo reverts.
    pub fn restore_version(&mut self, history_id: &str, actor: &str) -> Result<String> {
        forbidden_unless_human(actor, "restoring a version")?;
        self.mutate(|k, st| {
            let e = st
                .history
                .iter()
                .find(|e| e.id == history_id)
                .cloned()
                .ok_or_else(|| Error::not_found("history entry not found"))?;
            let payload = history::open_payload(&k.vk, &k.vault_id, &e)?;
            let side = if e.action == "delete_secret" {
                payload.before.clone()
            } else {
                payload.after.clone()
            };
            let version: Record = side
                .filter(|_| {
                    matches!(
                        e.action.as_str(),
                        "create_secret" | "update_secret" | "move_secret" | "delete_secret"
                    )
                })
                .and_then(|v| serde_json::from_value(v).ok())
                .ok_or_else(|| Error::invalid("This change has no version to restore"))?;
            let now = now_iso();
            let found = st.projects.iter().enumerate().find_map(|(pi, p)| {
                p.items
                    .iter()
                    .position(|i| i.id == version.id)
                    .map(|ii| (pi, ii))
            });
            let mut next = version.clone();
            next.updated_at.clone_from(&now);
            next.modified_by = HUMAN.to_owned();
            next.trashed_at.clear();
            let (pi, before, action) = match found {
                Some((pi, ii)) => {
                    let p = &st.projects[pi];
                    let cur = k.record(p, &p.items[ii])?;
                    next.key.clone_from(&cur.key);
                    next.rev = cur.rev.max(version.rev) + 1;
                    next.owner.clone_from(&cur.owner);
                    next.editable_by.clone_from(&cur.editable_by);
                    next.inject_approved = cur.inject_approved;
                    next.attachments.clone_from(&cur.attachments);
                    next.secret_changed_at = if secret_changed(&cur, &next) {
                        now.clone()
                    } else {
                        cur.secret_changed_at.clone()
                    };
                    let item = k.item_from_record(p, &next)?;
                    st.projects[pi].items[ii] = item;
                    (pi, Some(to_value(&cur)), "update_secret")
                }
                None => {
                    let pi = e
                        .project
                        .as_deref()
                        .and_then(|n| st.project_index(n))
                        .ok_or_else(|| Error::not_found("The item's project no longer exists"))?;
                    if st.projects[pi]
                        .items
                        .iter()
                        .any(|i| i.meta.key == version.key)
                    {
                        return Err(Error::Conflict(format!(
                            "\"{}\" already exists in \"{}\"",
                            version.key, st.projects[pi].meta.name
                        )));
                    }
                    next.rev = version.rev + 1;
                    // Their files went with the item.
                    next.attachments.clear();
                    let item = k.item_from_record(&st.projects[pi], &next)?;
                    let pid = st.projects[pi].id.clone();
                    st.projects[pi].items.push(item);
                    st.untombstone(&format!("{pid}:{}", next.id));
                    (pi, None, "create_secret")
                }
            };
            let pname = st.projects[pi].meta.name.clone();
            st.projects[pi].meta.updated_at.clone_from(&now);
            st.projects[pi].sealed_meta = None;
            k.history_entry(
                st,
                actor,
                action,
                Some(&pname),
                Some(&next.key),
                Payload {
                    before,
                    after: Some(to_value(&next)),
                },
                None,
            )?;
            Ok(next.key.clone())
        })
    }

    // ── Watchtower ──────────────────────────────────────────────────────────────────────

    /// Weak and reused passwords, secrets not changed in a year, and expiring or expired
    /// items, across every project. Archived items and the Trash are left out.
    pub fn watchtower(&mut self, actor: &str) -> Result<Vec<Finding>> {
        forbidden_unless_human(actor, "Watchtower")?;
        let mut out = Vec::new();
        {
            let st = self.state()?;
            let k = &self.open()?.keys;
            let mut by_password: HashMap<String, Vec<(String, String, String)>> = HashMap::new();
            for p in &st.projects {
                for i in p
                    .items
                    .iter()
                    .filter(|i| !i.meta.archived && i.meta.trashed_at.is_empty())
                {
                    let m = &i.meta;
                    let finding = |problem, detail: String| Finding {
                        project: p.meta.name.clone(),
                        key: m.key.clone(),
                        kind: m.kind().to_owned(),
                        problem,
                        detail,
                    };
                    let (status, days) = expiry_info(&m.expires_at);
                    match (status.as_str(), days) {
                        ("expired", _) => out.push(finding(
                            "expired",
                            format!("Expired on {}", &m.expires_at[..m.expires_at.len().min(10)]),
                        )),
                        ("expiring", Some(d)) => {
                            out.push(finding("expiring", format!("Expires in {d} day(s)")))
                        }
                        _ => {}
                    }
                    let changed = if m.secret_changed_at.is_empty() {
                        &m.created_at
                    } else {
                        &m.secret_changed_at
                    };
                    if (m.has_value || m.has_password)
                        && days_since(changed).is_some_and(|d| d > OLD_DAYS)
                    {
                        out.push(finding(
                            "old",
                            format!("Not changed since {}", &changed[..changed.len().min(10)]),
                        ));
                    }
                    if m.has_password {
                        let secret = k.open_secret(p, i)?;
                        if estimate_bits(&secret.password) < WEAK_BITS {
                            out.push(finding("weak", "Easy to guess".into()));
                        }
                        by_password
                            .entry(sha256_hex(secret.password.as_bytes()))
                            .or_default()
                            .push((p.meta.name.clone(), m.key.clone(), m.kind().to_owned()));
                    }
                }
            }
            for same in by_password.values().filter(|v| v.len() > 1) {
                for (project, key, kind) in same {
                    out.push(Finding {
                        project: project.clone(),
                        key: key.clone(),
                        kind: kind.clone(),
                        problem: "reused",
                        detail: format!("Same password as {} other item(s)", same.len() - 1),
                    });
                }
            }
        }
        out.sort_by(|a, b| (a.problem, &a.project, &a.key).cmp(&(b.problem, &b.project, &b.key)));
        self.audit("watchtower", &format!("{} findings", out.len()), actor)?;
        Ok(out)
    }

    /// The SHA-1 of each password (upper-case hex), for the opt-in breach check, which sends
    /// only the first five characters of each. Archived items and the Trash are left out.
    pub fn password_sha1s(&mut self, actor: &str) -> Result<Vec<(String, String, String)>> {
        forbidden_unless_human(actor, "the breach check")?;
        use sha1::Digest;
        let mut out = Vec::new();
        {
            let st = self.state()?;
            let k = &self.open()?.keys;
            for p in &st.projects {
                for i in p.items.iter().filter(|i| {
                    i.meta.has_password && !i.meta.archived && i.meta.trashed_at.is_empty()
                }) {
                    let secret = k.open_secret(p, i)?;
                    let hash = crate::crypto::hex(&sha1::Sha1::digest(secret.password.as_bytes()))
                        .to_ascii_uppercase();
                    out.push((p.meta.name.clone(), i.meta.key.clone(), hash));
                }
            }
        }
        self.audit("breach-check", &format!("{} passwords", out.len()), actor)?;
        Ok(out)
    }

    // ── One-time codes ──────────────────────────────────────────────────────────────────

    /// The current code of the item's first one-time code field.
    pub fn otp(&self, project: &str, key: &str, actor: &str) -> Result<Otp> {
        forbidden_unless_human(actor, "one-time codes")?;
        let st = self.state()?;
        let k = &self.open()?.keys;
        let pi = st.project(project)?;
        let p = &st.projects[pi];
        let i = &p.items[st.item(pi, key)?];
        let field = i
            .meta
            .fields
            .iter()
            .find(|f| f.kind == "otp" && f.has_value)
            .ok_or_else(|| Error::not_found("This item has no one-time code"))?;
        let secret = k.open_secret(p, i)?;
        let uri = secret
            .fields
            .iter()
            .find(|s| s.id == field.id)
            .ok_or_else(|| Error::not_found("This item has no one-time code"))?;
        let totp = Totp::parse(&uri.value)?;
        let now = Totp::now();
        Ok(Otp {
            code: SecretString::new(totp.code(now)),
            remaining: totp.remaining(now),
            period: totp.period,
        })
    }

    // ── Import ──────────────────────────────────────────────────────────────────────────

    /// Saves imported items into a project as the human, in one save. Each item's key is
    /// its title, made unique in the project. Recorded as one history entry, without values.
    pub fn import_items(
        &mut self,
        project: &str,
        report: Report,
        actor: &str,
    ) -> Result<ImportResult> {
        forbidden_unless_human(actor, "importing")?;
        let mut skipped = report.skipped;
        self.mutate(|k, st| {
            let pi = st.project(project)?;
            let mut taken: HashSet<String> = st.projects[pi]
                .items
                .iter()
                .map(|i| i.meta.key.clone())
                .collect();
            let (mut imported, mut renamed) = (0, Vec::new());
            let now = now_iso();
            for it in report.items {
                let title = clean_title(&it.title);
                let key = unique_key(&title, &taken);
                let r = match imported_record(&it, &key, &now) {
                    Ok(r) => r,
                    Err(e) => {
                        skipped.push(format!("\"{title}\": {e}"));
                        continue;
                    }
                };
                if key != title {
                    renamed.push(key.clone());
                }
                let item = k.item_from_record(&st.projects[pi], &r)?;
                st.projects[pi].items.push(item);
                taken.insert(key);
                imported += 1;
            }
            let pname = st.projects[pi].meta.name.clone();
            st.projects[pi].meta.updated_at.clone_from(&now);
            st.projects[pi].sealed_meta = None;
            k.history_entry(
                st,
                actor,
                "import_items",
                Some(&pname),
                None,
                Payload::default(),
                Some(format!("{imported} items")),
            )?;
            Ok(ImportResult {
                project: pname,
                imported,
                renamed,
                skipped: std::mem::take(&mut skipped),
            })
        })
    }
}

/// A title usable as a key: one line, at most 200 characters.
fn clean_title(t: &str) -> String {
    let one_line: String = t
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let short: String = one_line.chars().take(200).collect();
    if short.is_empty() || validate::key_name(&short).is_err() {
        "Imported item".to_owned()
    } else {
        short
    }
}

fn unique_key(title: &str, taken: &HashSet<String>) -> String {
    if !taken.contains(title) {
        return title.to_owned();
    }
    (2..)
        .map(|n| format!("{title} ({n})"))
        .find(|k| !taken.contains(k))
        .unwrap_or_else(|| unreachable!())
}

fn imported_record(it: &Imported, key: &str, now: &str) -> Result<Record> {
    let fields: Vec<validate::FieldInput> = it
        .fields
        .iter()
        .take(validate::MAX_FIELDS)
        .map(|f| validate::FieldInput {
            id: String::new(),
            section: f.section.chars().take(256).collect(),
            label: f.label.chars().take(256).collect(),
            kind: f.kind.to_owned(),
            value: Some(SecretString::new(f.value.expose())),
        })
        .collect();
    let mut input = Fields {
        key: key.to_owned(),
        value: Some(SecretString::new(it.value.expose())),
        password: Some(SecretString::new(it.password.expose())),
        note: Some(it.notes.clone()),
        username: Some(it.username.clone()),
        email: Some(it.email.clone()),
        url: Some(it.url.clone()),
        kind: Some(it.kind.to_owned()),
        tags: Some(
            it.tags
                .iter()
                .take(validate::MAX_TAGS)
                .map(|t| t.chars().take(64).collect())
                .collect(),
        ),
        favorite: Some(it.favorite),
        archived: Some(it.archived),
        fields: Some(fields),
        ..Default::default()
    };
    // A one-time code a manager stored in a form this build cannot read stays as text.
    if let Some(fs) = input.fields.as_mut() {
        for f in fs.iter_mut().filter(|f| f.kind == "otp") {
            if f.value
                .as_ref()
                .is_some_and(|v| Totp::parse(v.expose()).is_err())
            {
                f.kind = "concealed".into();
            }
        }
    }
    validate::fields(&input)?;
    let mut r = Record::default();
    r.id = random_id();
    r.key = key.to_owned();
    r.provider = if it.kind == "api_key" {
        crate::providers::match_key(key)
    } else {
        String::new()
    };
    r.owner = HUMAN.to_owned();
    r.created_by = HUMAN.to_owned();
    r.modified_by = HUMAN.to_owned();
    r.inject_approved = true;
    r.created_at = now.to_owned();
    r.updated_at = now.to_owned();
    r.rev = 1;
    r.value = it.value.expose().to_owned();
    r.password = it.password.expose().to_owned();
    r.note.clone_from(&it.notes);
    r.username.clone_from(&it.username);
    r.email.clone_from(&it.email);
    r.url.clone_from(&it.url);
    apply_typed(&mut r, &Record::default(), &input);
    if secret_changed(&Record::default(), &r) {
        r.secret_changed_at = now.to_owned();
    }
    Ok(r)
}
