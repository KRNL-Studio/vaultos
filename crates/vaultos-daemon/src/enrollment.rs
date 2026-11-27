//! Desktop-reviewed enrollment. The session token lets local clients ask. Only a
//! fresh desktop approval authorizes issuing a credential.

use crate::api::{self, Reply};
use crate::human::Peer;
use crate::server::Shared;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};
use vaultos_core::agents::{Enrollment, EnrollmentPlan};
use vaultos_core::{Error, Store};

pub const REVIEW_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_REVIEW_CHARS: usize = 2000;

pub type ReviewFn = dyn Fn(&str, Instant) -> Option<bool> + Send + Sync;

#[derive(Clone)]
pub struct Review(pub Arc<ReviewFn>);

impl std::fmt::Debug for Review {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnrollmentReview")
    }
}

fn shown(values: &[String]) -> String {
    match values {
        [] => "None".into(),
        _ => values
            .iter()
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn caller(who: &Peer) -> String {
    if let Some(exe) = &who.exe {
        return format!("{:?}", exe.to_string_lossy());
    }
    // Linux hides /proc/PID/exe for hardened clients. Their kernel-reported comm is
    // still available, but it is a process name rather than a verified executable path.
    #[cfg(target_os = "linux")]
    if let Some(pid) = who.pid {
        if let Ok(name) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            return format!(
                "Executable unavailable (process name {:?})",
                name.trim_end()
            );
        }
    }
    "Executable unavailable".into()
}

fn prepare(
    store: &Store,
    ask: &Enrollment,
    caller: &str,
    pid: &str,
) -> Result<(EnrollmentPlan, String), Error> {
    let plan = store.prepare_enrollment(ask)?;
    let projects = plan
        .projects
        .iter()
        .map(|id| {
            Ok(store
                .find_project(id)?
                .map_or_else(|| id.clone(), |(_, name)| name))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let action = if plan.reissued() {
        "reissue this agent's token (the old token stops working)"
    } else {
        "enroll this agent"
    };
    let details = format!(
        "{action}\n\nAgent: {:?}\nCaller: {caller}\nProcess ID: {pid}\n\nScopes: {}\nProjects: {}\nFolder roots: {}\nAllowed commands: {}\n\nThe requesting process receives the new token",
        plan.name,
        shown(&plan.scopes),
        if plan.wildcards.all_projects { "All projects, including future projects".into() } else { shown(&projects) },
        if plan.wildcards.any_root { "Any folder".into() } else { shown(&plan.roots) },
        shown(&plan.run_commands),
    );
    if details.chars().count() > MAX_REVIEW_CHARS {
        return Err(Error::Invalid(
            "The grants are too long for desktop review. Use Settings → Agents.".into(),
        ));
    }
    Ok((plan, details))
}

/// Owns the prompt slot while either the operation or its native dialog is still active.
struct ReviewSlot(Arc<Shared>);

impl Drop for ReviewSlot {
    fn drop(&mut self) {
        self.0.confirming.store(false, Ordering::SeqCst);
    }
}

fn timed_out() -> Reply {
    Reply::error(
        408,
        "Enrollment approval timed out. Request enrollment again.",
    )
}

pub(crate) async fn request(shared: Arc<Shared>, body: Vec<u8>, pid: Option<i32>) -> Reply {
    let Ok(ask) = serde_json::from_slice::<Enrollment>(&body) else {
        return Reply::error(400, "Invalid enrollment request");
    };
    if !shared.unlocked.load(Ordering::SeqCst) {
        return Reply::from_error(&Error::Locked);
    }
    let review = shared
        .enrollment_review
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let Some((review, timeout)) = review else {
        return Reply::error(503, "Open and unlock VaultOS.app to approve enrollment.");
    };
    if shared.confirming.swap(true, Ordering::SeqCst) {
        return Reply::error(429, "Another request is waiting for confirmation");
    }
    let slot = Arc::new(ReviewSlot(shared.clone()));
    let who = Peer::of(pid);
    let caller = caller(&who);
    let pid = pid.map_or_else(|| "unavailable".into(), |p| p.to_string());
    let s = shared.clone();
    let snapshot = tokio::task::spawn_blocking(move || {
        let snapshot = s.with_store(|store| {
            api::ready(store)?;
            Ok((store.lock_count(), prepare(store, &ask, &caller, &pid)))
        });
        (ask, caller, pid, snapshot)
    })
    .await;
    let Ok((ask, caller, pid, snapshot)) = snapshot else {
        return Reply::error(500, "Internal error");
    };
    let (locks, prepared) = match snapshot {
        Ok(snapshot) => snapshot,
        Err(reply) => return reply,
    };
    // A failed grant lookup must not reveal whether a project or agent exists without
    // human participation. No credential is issued when this review cannot be prepared.
    let details = prepared.as_ref().map_or(
        "review an enrollment request with invalid or unavailable grants. No token can be issued",
        |(_, text)| text.as_str(),
    ).to_owned();
    let deadline = Instant::now() + timeout;
    let dialog_slot = slot.clone();
    let prompt = tokio::task::spawn_blocking(move || {
        let _slot = dialog_slot;
        (review.0)(&details, deadline)
    });
    match tokio::time::timeout_at(deadline.into(), prompt).await {
        Err(_) => return timed_out(),
        Ok(_) if Instant::now() >= deadline => return timed_out(),
        Ok(Ok(Some(true))) => {}
        Ok(Ok(Some(false))) => return Reply::error(403, "The human declined enrollment"),
        _ => return Reply::error(503, "Desktop enrollment confirmation is unavailable. Unlock VaultOS or enroll in Settings → Agents."),
    }
    let approval = match prepared {
        Ok(prepared) => prepared,
        Err(e) => return Reply::from_error(&e),
    };
    let s = shared.clone();
    let reply = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        s.with_store(|store| {
            if Instant::now() >= deadline {
                return timed_out();
            }
            if !store.is_unlocked() || store.lock_count() != locks {
                return Reply::error(
                    409,
                    "The vault locked during review. Request enrollment again.",
                );
            }
            if let Err(reply) = api::ready(store) {
                return reply;
            }
            let current = match prepare(store, &ask, &caller, &pid) {
                Ok(current) if current == approval => current,
                _ => {
                    return Reply::error(
                        409,
                        "Enrollment grants changed during review. Request enrollment again.",
                    )
                }
            };
            if Instant::now() >= deadline {
                return timed_out();
            }
            let via = format!("desktop enrollment by {}", who.named());
            match store.issue_enrollment(&current.0, &via) {
                Ok((issued, summary)) => {
                    s.access.end(&issued.id, None);
                    let mut body = json!(summary);
                    body["reissued"] = Value::Bool(current.0.reissued());
                    body["token"] = json!(issued.token.expose());
                    Reply::ok(body)
                }
                Err(e) => Reply::from_error(&e),
            }
        })
    })
    .await
    .unwrap_or_else(|_| Reply::error(500, "Internal error"));
    if reply.status == 200 {
        shared.touch();
        shared.autosync.poke();
    }
    reply
}
