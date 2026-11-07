//! What sync needs from the store: every record with its hash, the trusted peers, this
//! machine's sync keys (sealed in the vault with everything else, never in files beside it),
//! and one save that applies a merge.

use super::*;
use crate::canon::canonical_json;

/// A record as sync carries it: with its project, and the hash peers compare.
#[derive(Clone, Debug)]
pub struct SyncRecord {
    pub project_id: String,
    pub project_name: String,
    pub record: Record,
    pub hash: String,
}

/// A merge, applied in one save or not at all.
#[derive(Clone, Debug, Default)]
pub struct SyncChanges {
    /// Records to add or replace, each in the project it names.
    pub upsert: Vec<SyncRecord>,
    /// `project:record` references deleted elsewhere, with who deleted them.
    pub delete: Vec<(String, String)>,
    /// Projects deleted elsewhere; each is removed here once it holds no records.
    pub delete_projects: Vec<String>,
}

/// The rules a record from a peer must meet, as for one typed here.
pub fn check_record(r: &Record) -> Result<()> {
    check_id(&r.id)?;
    let opt = |s: &str| Some(s.to_owned());
    validate::fields(&Fields {
        key: r.key.clone(),
        value: Some(SecretString::new(r.value.as_str())),
        password: Some(SecretString::new(r.password.as_str())),
        note: opt(&r.note),
        username: opt(&r.username),
        email: opt(&r.email),
        url: opt(&r.url),
        provider: opt(&r.provider),
        permission: opt(&r.permission),
        expires_at: opt(&r.expires_at),
    })?;
    for (name, v) in [
        ("owner", &r.owner),
        ("creator", &r.created_by),
        ("modifier", &r.modified_by),
    ] {
        validate::text(v, name, 256, false)?;
    }
    if r.rev == 0 {
        return Err(Error::invalid("Invalid record revision"));
    }
    Ok(())
}

impl Store {
    /// Every record, values included. Drop the result as soon as possible.
    pub fn sync_records(&self) -> Result<Vec<SyncRecord>> {
        let keys = &self.open()?.keys;
        let mut out = Vec::new();
        for p in &self.state()?.projects {
            for i in &p.items {
                let record = keys.record(p, i)?;
                out.push(SyncRecord {
                    project_id: p.id.clone(),
                    project_name: p.meta.name.clone(),
                    hash: record_hash(&record),
                    record,
                });
            }
        }
        Ok(out)
    }

    /// One hash over every record, equal on two devices holding the same records.
    pub fn content_fingerprint(&self) -> Result<String> {
        let mut rows: Vec<Value> = self
            .sync_records()?
            .into_iter()
            .map(|r| json!([r.project_id, r.record.key, r.hash]))
            .collect();
        rows.sort_by_key(|v| v.to_string());
        Ok(sha256_hex(
            canonical_json(&json!({ "records": rows })).as_bytes(),
        ))
    }

    /// The peers this vault trusts, by machine id.
    pub fn sync_trust(&self) -> Result<Map<String, Value>> {
        Ok(match &self.state()?.meta.sync_trust {
            Some(Value::Object(m)) => m.clone(),
            _ => Map::new(),
        })
    }

    pub fn set_sync_trust(&mut self, trust: Map<String, Value>) -> Result<()> {
        self.mutate(|_, st| {
            st.meta.sync_trust = Some(Value::Object(trust));
            Ok(())
        })
    }

    /// This machine's sync identity and private keys, if it has joined a sync group.
    pub fn sync_keys(&self) -> Result<Option<Value>> {
        Ok(self.state()?.meta.sync_keys.clone())
    }

    pub fn set_sync_keys(&mut self, keys: Value) -> Result<()> {
        self.mutate(|_, st| {
            st.meta.sync_keys = Some(keys);
            Ok(())
        })
    }

    /// Applies a merge in one save. A record whose project or key name is already taken by a
    /// different project or record is refused, and then nothing changes. Returns the projects
    /// removed, as (id, name).
    pub fn apply_sync(&mut self, changes: &SyncChanges) -> Result<Vec<(String, String)>> {
        for r in &changes.upsert {
            check_record(&r.record)?;
            check_id(&r.project_id)?;
            validate::text(&r.project_name, "project name", 256, false)?;
        }
        self.mutate(|k, st| {
            let now = now_iso();
            for inc in &changes.upsert {
                let pi = match st.projects.iter().position(|p| p.id == inc.project_id) {
                    Some(i) => i,
                    None => {
                        let lower = inc.project_name.to_lowercase();
                        if st
                            .projects
                            .iter()
                            .any(|p| p.meta.name.to_lowercase() == lower)
                        {
                            return Err(Error::Conflict(
                                "Project name collision; resolve it before merging".into(),
                            ));
                        }
                        let (pk, wrapped_pk) = k.new_project_key(&inc.project_id);
                        st.projects.push(Project {
                            id: inc.project_id.clone(),
                            pk,
                            wrapped_pk,
                            meta: ProjectMeta {
                                name: inc.project_name.clone(),
                                owner: HUMAN.to_owned(),
                                created_at: now.clone(),
                                updated_at: now.clone(),
                                extra: Map::new(),
                            },
                            sealed_meta: None,
                            items: Vec::new(),
                        });
                        st.projects.len() - 1
                    }
                };
                let item = k.item_from_record(&st.projects[pi], &inc.record)?;
                let p = &mut st.projects[pi];
                match p.items.iter().position(|i| i.id == inc.record.id) {
                    Some(ii) => p.items[ii] = item,
                    None if p.items.iter().any(|i| i.meta.key == inc.record.key) => {
                        return Err(Error::Conflict(
                            "Secret name collision; resolve it before merging".into(),
                        ));
                    }
                    None => p.items.push(item),
                }
                p.meta.updated_at = now.clone();
                p.sealed_meta = None;
            }
            for (reference, by) in &changes.delete {
                if let Some((pid, rid)) = reference.split_once(':') {
                    if let Some(p) = st.projects.iter_mut().find(|p| p.id == pid) {
                        let before = p.items.len();
                        p.items.retain(|i| i.id != rid);
                        if p.items.len() != before {
                            p.meta.updated_at = now.clone();
                            p.sealed_meta = None;
                        }
                    }
                }
                st.tombstone(reference.clone(), by, label(&[("via", "pull")]));
            }
            let mut removed = Vec::new();
            for pid in &changes.delete_projects {
                let Some(i) = st
                    .projects
                    .iter()
                    .position(|p| p.id == *pid && p.items.is_empty())
                else {
                    continue;
                };
                let p = st.projects.remove(i);
                st.tombstone(
                    format!("project:{pid}"),
                    "sync",
                    label(&[("project", &p.meta.name), ("via", "pull")]),
                );
                removed.push((p.id, p.meta.name));
            }
            Ok(removed)
        })
    }
}
