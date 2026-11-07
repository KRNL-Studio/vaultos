//! Values for programs: resolving `vault://` references and the environment `vaultos run`
//! and `run_with_secrets` give a command.

use super::*;
use crate::refs::{SecretRef, MAX_REFS};
use crate::totp::Totp;

/// A project's values for a program's environment.
#[derive(Debug)]
pub struct EnvValues {
    pub project: String,
    pub pairs: Vec<(String, Zeroizing<String>)>,
    /// Keys an agent created that still await the human's approval, left out.
    pub held_for_approval: Vec<String>,
}

impl Store {
    /// Resolves references in order, with one audit entry for all of them. Agents cannot
    /// see archived or trashed items, nor read one-time codes; their scopes are checked by
    /// the caller.
    pub fn resolve_refs(
        &mut self,
        refs: &[SecretRef],
        purpose: &str,
        actor: &str,
    ) -> Result<Vec<Zeroizing<String>>> {
        if refs.len() > MAX_REFS {
            return Err(Error::invalid(format!(
                "At most {MAX_REFS} references at a time"
            )));
        }
        let mut out = Vec::with_capacity(refs.len());
        let mut named = Vec::with_capacity(refs.len());
        {
            let st = self.state()?;
            let k = &self.open()?.keys;
            for r in refs {
                let missing = || Error::not_found(format!("{} was not found", r.to_uri()));
                let pi = st.project(&r.project).map_err(|_| missing())?;
                let p = &st.projects[pi];
                let i = &p.items[st.item(pi, &r.item).map_err(|_| missing())?];
                if is_agent(actor) && (i.meta.archived || !i.meta.trashed_at.is_empty()) {
                    return Err(missing());
                }
                let value = match r.field.as_str() {
                    "username" => i.meta.username.clone(),
                    "email" => i.meta.email.clone(),
                    "url" => i.meta.url.clone(),
                    "note" => i.meta.note.clone(),
                    "value" | "password" | "otp" => {
                        let s = k.open_secret(p, i)?;
                        match r.field.as_str() {
                            "value" if s.value.is_empty() => s.password.clone(),
                            "value" => s.value.clone(),
                            "password" => s.password.clone(),
                            _ => {
                                forbidden_unless_human(actor, "Reading one-time codes")?;
                                let f = i
                                    .meta
                                    .fields
                                    .iter()
                                    .find(|f| f.kind == "otp" && f.has_value)
                                    .ok_or_else(missing)?;
                                let uri =
                                    s.fields.iter().find(|x| x.id == f.id).ok_or_else(missing)?;
                                Totp::parse(&uri.value)?.code(Totp::now())
                            }
                        }
                    }
                    label => {
                        let f = i
                            .meta
                            .fields
                            .iter()
                            .find(|f| f.id == label)
                            .or_else(|| {
                                i.meta
                                    .fields
                                    .iter()
                                    .find(|f| f.label.eq_ignore_ascii_case(label))
                            })
                            .ok_or_else(missing)?;
                        if f.is_secret() {
                            if f.kind == "otp" {
                                forbidden_unless_human(actor, "Reading one-time codes")?;
                            }
                            let s = k.open_secret(p, i)?;
                            let v = s.fields.iter().find(|x| x.id == f.id).ok_or_else(missing)?;
                            if f.kind == "otp" {
                                Totp::parse(&v.value)?.code(Totp::now())
                            } else {
                                v.value.clone()
                            }
                        } else {
                            f.value.clone()
                        }
                    }
                };
                named.push(format!("{}/{}/{}", p.meta.name, i.meta.key, r.field));
                out.push(Zeroizing::new(value));
            }
        }
        named.dedup();
        self.audit(
            "resolve",
            &format!("{purpose}: {}", named.join(", ")),
            actor,
        )?;
        Ok(out)
    }

    /// A project's approved values, chosen as [`Store::inject`] chooses them, for a
    /// program's environment. Recorded as one audit entry naming the purpose (the command).
    pub fn env_values(
        &mut self,
        project: &str,
        keys: Option<&[String]>,
        purpose: &str,
        actor: &str,
    ) -> Result<EnvValues> {
        let values = {
            let st = self.state()?;
            let k = &self.open()?.keys;
            let p = &st.projects[st.project(project)?];
            let with_value = p
                .items
                .iter()
                .filter(|i| i.meta.has_value && !i.meta.archived && i.meta.trashed_at.is_empty());
            let held_for_approval = with_value
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
            if let Some(ks) = keys {
                if let Some(k) = ks.iter().find(|k| !pairs.iter().any(|(n, _)| n == *k)) {
                    return Err(Error::not_found(format!(
                        "{k} has no value that can be given to programs in {}",
                        p.meta.name
                    )));
                }
            }
            EnvValues {
                project: p.meta.name.clone(),
                pairs,
                held_for_approval,
            }
        };
        self.audit(
            "run",
            &format!(
                "{} ({} keys): {purpose}",
                values.project,
                values.pairs.len()
            ),
            actor,
        )?;
        Ok(values)
    }
}
