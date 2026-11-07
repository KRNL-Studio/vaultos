//! Decisions on agent-created keys that wait for approval before injection, and the optional
//! approval relay, ported from `approvals.js`. Every decision is the human's and is audited.

use crate::agents::{new_token, token_hash};
use crate::crypto::ct_eq;
use crate::error::{Error, Result};
use crate::model::HUMAN;
use crate::secret::SecretString;
use crate::store::Store;
use crate::validate;
use serde::Serialize;
use serde_json::{Map, Value};

const APPROVER_SETTING: &str = "approverTokenHash";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub project: String,
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inject_approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Approved {
    pub project: String,
    pub key: String,
}

fn is_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Store {
    /// The project and key names of an item that is waiting for approval.
    fn pending_item(&self, project: &str, key: &str) -> Result<(String, String)> {
        validate::text(project, "project", 256, false)?;
        validate::text(key, "key name", 256, false)?;
        let (_, pname) = self
            .find_project(project)?
            .ok_or_else(|| Error::not_found("project not found"))?;
        let item = self
            .find_item(&pname, key)?
            .ok_or_else(|| Error::not_found("secret not found"))?;
        if item.inject_approved {
            return Err(Error::Conflict(format!(
                "\"{}\" is not awaiting approval",
                item.key
            )));
        }
        Ok((pname, item.key))
    }

    pub fn approve_pending(&mut self, project: &str, key: &str, via: &str) -> Result<Decision> {
        let (p, k) = self.pending_item(project, key)?;
        // One batch: if the audit entry cannot be written, the decision is not saved either.
        self.batch(|s| {
            s.approve_inject(&p, &k, true)?;
            s.audit("approve_inject", &format!("{p}/{k} via {via}"), HUMAN)
        })?;
        Ok(Decision {
            project: p,
            key: k,
            inject_approved: Some(true),
            denied: None,
            removed: None,
        })
    }

    /// Denying removes the key: it was never approved for use.
    pub fn deny_pending(&mut self, project: &str, key: &str, via: &str) -> Result<Decision> {
        let (p, k) = self.pending_item(project, key)?;
        self.batch(|s| {
            s.delete_item(&p, &k, HUMAN)?;
            s.audit("deny_inject", &format!("{p}/{k} via {via}"), HUMAN)
        })?;
        Ok(Decision {
            project: p,
            key: k,
            inject_approved: None,
            denied: Some(true),
            removed: Some(true),
        })
    }

    pub fn approve_all_pending(
        &mut self,
        via: &str,
        project: Option<&str>,
    ) -> Result<Vec<Approved>> {
        let wanted = match project {
            Some(p) => Some(
                self.find_project(p)?
                    .ok_or_else(|| Error::not_found("project not found"))?
                    .1,
            ),
            None => None,
        };
        let pending = self.pending_approvals()?;
        self.batch(|s| {
            let mut out = Vec::new();
            for item in pending {
                if wanted.as_ref().is_some_and(|w| *w != item.project) {
                    continue;
                }
                let d = s.approve_pending(&item.project, &item.key, via)?;
                out.push(Approved {
                    project: d.project,
                    key: d.key,
                });
            }
            Ok(out)
        })
    }

    pub fn approver_configured(&self) -> Result<bool> {
        Ok(self
            .settings()?
            .get(APPROVER_SETTING)
            .and_then(Value::as_str)
            .is_some_and(is_hash))
    }

    /// Sets (`Some`) or clears (`None`) the approval relay's token hash.
    pub fn set_approver_hash(&mut self, hash: Option<&str>) -> Result<bool> {
        if hash.is_some_and(|h| !is_hash(h)) {
            return Err(Error::invalid("Invalid approver hash"));
        }
        let mut patch = Map::new();
        patch.insert(
            APPROVER_SETTING.to_owned(),
            hash.map_or(Value::Null, |h| Value::String(h.to_owned())),
        );
        self.update_settings(patch, HUMAN)?;
        self.audit(
            if hash.is_some() {
                "set_approver"
            } else {
                "clear_approver"
            },
            "approval relay",
            HUMAN,
        )?;
        Ok(hash.is_some())
    }

    /// A new relay token; only its hash is stored.
    pub fn issue_approver_token(&mut self) -> Result<SecretString> {
        let token = new_token();
        self.set_approver_hash(Some(&token_hash(token.expose())))?;
        Ok(token)
    }

    pub fn verify_approver(&self, presented: &str) -> Result<bool> {
        if !self.approver_configured()? || presented.is_empty() || presented.len() > 512 {
            return Ok(false);
        }
        let stored = self
            .settings()?
            .get(APPROVER_SETTING)
            .and_then(Value::as_str)
            .unwrap_or("");
        Ok(ct_eq(token_hash(presented).as_bytes(), stored.as_bytes()))
    }

    /// A decision sent by the configured approval relay.
    pub fn relay_decision(
        &mut self,
        presented: &str,
        project: &str,
        key: &str,
        approve: bool,
    ) -> Result<Decision> {
        if !self.approver_configured()? {
            return Err(Error::forbidden("The approval relay is not configured"));
        }
        if !self.verify_approver(presented)? {
            return Err(Error::forbidden(
                "Only the configured approval relay can decide pending keys",
            ));
        }
        if approve {
            self.approve_pending(project, key, "approval relay")
        } else {
            self.deny_pending(project, key, "approval relay")
        }
    }
}
