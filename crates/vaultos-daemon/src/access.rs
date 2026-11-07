//! Just-in-time access: an agent asks for scopes on one project for a few minutes
//! (`POST /access/request`), and the human confirms it in the app (Touch ID, or the app's
//! dialog). A grant applies only to that project, lives only in the owner's memory and ends
//! when it expires, when the vault locks, when the human ends it, or when the owner stops.
//! The vault records the grant in the audit log and nothing else.

use crate::api::Reply;
use crate::human::{clean, Peer};
use crate::server::{Confirm, Confirming, Shared};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use vaultos_core::agents::ALL_SCOPES;
use vaultos_core::model::{agent_ref, HUMAN};

pub const DEFAULT_MINUTES: u64 = 15;
pub const MAX_MINUTES: u64 = 60;
/// After the human declines, that agent waits this long before asking again.
const DECLINED_PAUSE: Duration = Duration::from_secs(60);

/// Temporary scopes for one agent on one project.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub agent_id: String,
    pub agent: String,
    pub project_id: String,
    pub project: String,
    pub scopes: Vec<String>,
    pub expires_at: String,
    #[serde(skip)]
    until: Instant,
    #[serde(skip)]
    locks: u64,
}

impl Grant {
    pub fn allows(&self, project_id: &str, scope: &str) -> bool {
        self.project_id == project_id && self.scopes.iter().any(|s| s == scope)
    }
}

#[derive(Default)]
pub(crate) struct Access {
    grants: Mutex<Vec<Grant>>,
    declined: Mutex<HashMap<String, Instant>>,
    confirm: Mutex<Option<Confirm>>,
}

impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Access")
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Access {
    /// The grants still in force while the vault's lock count is `locks`.
    pub(crate) fn live(&self, locks: u64) -> Vec<Grant> {
        let mut g = lock(&self.grants);
        g.retain(|g| g.locks == locks && g.until > Instant::now());
        g.clone()
    }

    pub(crate) fn set_confirm(&self, confirm: Option<Confirm>) {
        *lock(&self.confirm) = confirm;
    }

    /// Ends an agent's grants (all of them, or one project's).
    pub(crate) fn end(&self, agent_id: &str, project_id: Option<&str>) -> usize {
        let mut g = lock(&self.grants);
        let before = g.len();
        g.retain(|g| g.agent_id != agent_id || project_id.is_some_and(|p| p != g.project_id));
        before - g.len()
    }
}

struct Ask {
    project: String,
    scopes: Vec<String>,
    minutes: u64,
    reason: String,
}

fn parse(body: &[u8]) -> Result<Ask, Reply> {
    let bad = |m: &str| Reply::error(400, m);
    let b: Value = serde_json::from_slice(body).map_err(|_| bad("Invalid JSON body"))?;
    let project = b["project"]
        .as_str()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| bad("project is required"))?
        .to_owned();
    let mut scopes: Vec<String> = b["scopes"]
        .as_array()
        .and_then(|a| a.iter().map(|s| s.as_str().map(str::to_owned)).collect())
        .filter(|s: &Vec<String>| !s.is_empty())
        .ok_or_else(|| bad("scopes must be a list, like [\"read\"]"))?;
    if let Some(s) = scopes.iter().find(|s| !ALL_SCOPES.contains(&s.as_str())) {
        return Err(bad(&format!("Unknown scope {}", clean(s))));
    }
    scopes.sort();
    scopes.dedup();
    let minutes = match &b["minutes"] {
        Value::Null => DEFAULT_MINUTES,
        v => v
            .as_u64()
            .filter(|m| (1..=MAX_MINUTES).contains(m))
            .ok_or_else(|| bad("minutes must be 1 to 60"))?,
    };
    let reason = b["reason"].as_str().map(clean).unwrap_or_default();
    if reason.is_empty() {
        return Err(bad("reason is required: say what the access is for"));
    }
    Ok(Ask {
        project,
        scopes,
        minutes,
        reason,
    })
}

/// `POST /access/request`, with this agent's token.
pub(crate) async fn request(
    shared: Arc<Shared>,
    token: String,
    body: Vec<u8>,
    pid: Option<i32>,
) -> Reply {
    let ask = match parse(&body) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let s = shared.clone();
    let project = ask.project.clone();
    let found = tokio::task::spawn_blocking(move || {
        s.with_store(|store| {
            if !store.is_unlocked() {
                return Err(Reply::error(423, "Vault is locked. Unlock the app."));
            }
            let agent = match store.authenticate_agent(&token) {
                Ok(Some(a)) => a,
                _ => {
                    return Err(Reply::error(
                        403,
                        "An enrolled, active agent token is required",
                    ))
                }
            };
            let found = store.find_project(&project).ok().flatten();
            Ok((agent, found, store.lock_count()))
        })
    })
    .await
    .unwrap_or_else(|_| Err(Reply::error(500, "Internal error")));
    let (agent, found, locks) = match found {
        Ok(f) => f,
        Err(r) => return r,
    };
    let not_granted = || Reply::error(403, "The human did not grant this access");
    let Some((project_id, project)) = found else {
        return not_granted();
    };
    if let Some(at) = lock(&shared.access.declined).get(&agent.id) {
        if at.elapsed() < DECLINED_PAUSE {
            return Reply::error(
                429,
                "The human declined this agent's last request; wait a minute before asking again",
            );
        }
    }
    let Some(confirm) = lock(&shared.access.confirm).clone() else {
        return Reply::error(
            503,
            "No one can confirm access requests here. Ask the human to grant access in the app or with `vaultos agents grant`",
        );
    };
    if shared.confirming.swap(true, Ordering::SeqCst) {
        return Reply::error(429, "Another request is waiting for confirmation");
    }
    let _one = Confirming(&shared.confirming);
    let reason = format!(
        "give agent “{}” {} access to {} for {} minutes, for “{}” ({})",
        clean(&agent.name),
        ask.scopes.join(", "),
        clean(&project),
        ask.minutes,
        ask.reason,
        Peer::of(pid).shown(),
    );
    let answer = tokio::task::spawn_blocking(move || (confirm.0)(&reason))
        .await
        .ok()
        .flatten();
    if answer != Some(true) {
        lock(&shared.access.declined).insert(agent.id.clone(), Instant::now());
        return not_granted();
    }
    let ttl = Duration::from_secs(ask.minutes * 60);
    let grant = Grant {
        agent_id: agent.id.clone(),
        agent: agent.name.clone(),
        project_id,
        project,
        scopes: ask.scopes,
        expires_at: vaultos_core::model::iso_after(ttl),
        until: Instant::now() + ttl,
        locks,
    };
    let s = shared.clone();
    let g = grant.clone();
    let recorded = tokio::task::spawn_blocking(move || {
        s.with_store(|store| {
            if store.lock_count() != g.locks || !store.is_unlocked() {
                return false;
            }
            let detail = format!(
                "{} ({}): {} on {} for {} min: {}",
                g.agent,
                agent_ref(&g.agent_id),
                g.scopes.join(", "),
                g.project,
                ask.minutes,
                ask.reason
            );
            store.audit("access-grant", &detail, HUMAN).is_ok()
        })
    })
    .await
    .unwrap_or(false);
    if !recorded {
        return not_granted();
    }
    lock(&shared.access.declined).remove(&agent.id);
    lock(&shared.access.grants).push(grant.clone());
    Reply::ok(json!({
        "granted": true,
        "project": grant.project,
        "scopes": grant.scopes,
        "minutes": ask.minutes,
        "expiresAt": grant.expires_at,
    }))
}
