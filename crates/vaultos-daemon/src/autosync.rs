//! Automatic sync, run by the daemon while the vault is unlocked and the human turned it on
//! (setting `autoSync.enabled`, off by default). A few seconds after a change and on a fixed
//! interval it pulls, then pushes, with every check of the sync engine intact. It never
//! accepts conflicts: a pull that needs acceptance, or any verification failure, halts it
//! until the human runs `vaultos sync now`. Ported from `autosync.js`.
//!
//! A round holds the vault only for its local steps; Git waits on the network without it, so
//! agents are served meanwhile.

use crate::server::Shared;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::Instant;
use vaultos_core::model::now_iso;
use vaultos_core::Store;
use vaultos_sync::{Sync, SyncError};

const DEBOUNCE: Duration = Duration::from_secs(5);
const START_DELAY: Duration = Duration::from_millis(1500);
const DEFAULT_INTERVAL: u64 = 120;
const RECHECK: Duration = Duration::from_secs(10);

/// Network trouble is retried on the next round. Every other failure needs a human.
const TRANSIENT: [&str; 4] = [
    "REMOTE_UNREACHABLE",
    "PUSH_REJECTED",
    "RECEIPT_UNVERIFIED",
    "VAULT_BUSY",
];
/// A failed local commit is retried too, since the next round first commits what it left.
/// One that fails this many rounds running (a stale index.lock, no Git identity) halts.
const COMMIT_ATTEMPTS: u32 = 3;
const IDLE: [&str; 5] = [
    "STOPPED",
    "SCHEDULED",
    "DISABLED",
    "PAUSED_LOCKED",
    "NOT_CONFIGURED",
];

#[derive(Debug)]
struct State {
    state: String,
    enabled: bool,
    interval: u64,
    last_sync_at: Option<String>,
    last_attempt_at: Option<String>,
    error: Option<String>,
    received: Option<Value>,
    sent: Option<usize>,
    conflicts: usize,
    peer_problems: Vec<String>,
    running: bool,
    /// The daemon is stopping: no new round starts.
    stopping: bool,
    rerun: bool,
    halted: bool,
    commit_failures: u32,
    soon: Option<Instant>,
    next: Option<Instant>,
}

#[derive(Debug)]
pub struct AutoSync {
    repo: PathBuf,
    state: Mutex<State>,
    wake: Notify,
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(500).collect()
}

/// `autoSync` from the vault's settings: off unless the human turned it on.
fn settings(store: &Store) -> (bool, u64) {
    let Some(a) = store
        .settings()
        .ok()
        .and_then(|s| s.get("autoSync"))
        .cloned()
    else {
        return (false, DEFAULT_INTERVAL);
    };
    let interval = a
        .get("intervalSeconds")
        .and_then(Value::as_u64)
        .filter(|s| (30..=86_400).contains(s))
        .unwrap_or(DEFAULT_INTERVAL);
    (a.get("enabled") == Some(&json!(true)), interval)
}

impl AutoSync {
    pub fn new(repo: PathBuf) -> AutoSync {
        AutoSync {
            repo,
            state: Mutex::new(State {
                state: "STOPPED".into(),
                enabled: false,
                interval: DEFAULT_INTERVAL,
                last_sync_at: None,
                last_attempt_at: None,
                error: None,
                received: None,
                sent: None,
                conflicts: 0,
                peer_problems: Vec::new(),
                running: false,
                stopping: false,
                rerun: false,
                halted: false,
                commit_failures: 0,
                soon: None,
                next: None,
            }),
            wake: Notify::new(),
        }
    }

    fn st(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The vault changed (a save, a lock or an unlock): one more round soon, after the one
    /// running if any, instead of a second alongside it.
    pub fn poke(&self) {
        let mut s = self.st();
        if s.running {
            s.rerun = true;
        } else if s.next.is_some() {
            s.soon = Some(Instant::now() + DEBOUNCE);
        }
        drop(s);
        self.wake.notify_one();
    }

    /// Everything, for the owner.
    pub fn status(&self) -> Value {
        let s = self.st();
        json!({
            "enabled": s.enabled,
            "intervalSeconds": s.interval,
            "halted": s.halted,
            "running": s.running,
            "state": s.state,
            "lastSyncAt": s.last_sync_at,
            "lastAttemptAt": s.last_attempt_at,
            "error": s.error,
            "received": s.received,
            "sent": s.sent,
            "conflicts": s.conflicts,
            "peerStalled": !s.peer_problems.is_empty(),
            "peerProblems": s.peer_problems,
        })
    }

    /// What `/status` shows without the session token: no messages or peer labels.
    pub fn public_status(&self) -> Value {
        let s = self.st();
        json!({
            "enabled": s.enabled,
            "state": s.state,
            "halted": s.halted,
            "lastSyncAt": s.last_sync_at,
            "peerStalled": !s.peer_problems.is_empty(),
        })
    }

    /// Whether the next round should try again after this one failed with `code`.
    fn retry(s: &mut State, code: Option<&str>) -> bool {
        s.commit_failures = if code == Some("COMMIT_FAILED") {
            s.commit_failures + 1
        } else {
            0
        };
        code.is_some_and(|c| {
            TRANSIENT.contains(&c) || (c == "COMMIT_FAILED" && s.commit_failures < COMMIT_ATTEMPTS)
        })
    }

    fn halt(&self, shared: &Shared, state: &str, error: &str) {
        let mut s = self.st();
        s.halted = true;
        s.next = None;
        s.soon = None;
        drop(s);
        eprintln!("vaultosd: autosync halted ({state}): {error}");
        // Otherwise sync can stop for good with nothing saying why.
        shared.with_store(|store| {
            let _ = store.audit("sync_halted", &format!("{state}: {error}"), "autosync");
        });
    }

    /// Re-reads the settings and the lock state, and names the idle state.
    fn refresh(&self, shared: &Shared) {
        let repo = self.repo.clone();
        let (unlocked, (enabled, interval), configured) = shared.with_store(|store| {
            let configured = Sync::new(store.data_dir(), &repo).configured(store);
            (store.is_unlocked(), settings(store), configured)
        });
        let mut s = self.st();
        s.enabled = enabled;
        s.interval = interval;
        let idle = IDLE.contains(&s.state.as_str());
        let eligible = unlocked && enabled && !s.halted && configured;
        if !eligible {
            s.next = None;
            s.soon = None;
        }
        if !unlocked {
            s.state = "PAUSED_LOCKED".into();
        } else if !enabled {
            if idle {
                s.state = "DISABLED".into();
            }
        } else if s.halted {
        } else if !configured {
            s.state = "NOT_CONFIGURED".into();
            s.error = Some(
                "Initialize sync on this device first: vaultos sync init <machine-label>".into(),
            );
        } else if s.next.is_none() {
            let now = Instant::now();
            s.next = Some(now + Duration::from_secs(interval));
            s.soon = Some(now + START_DELAY);
            if idle {
                s.state = "SCHEDULED".into();
                s.error = None;
            }
        }
    }

    /// Lets no new round start and waits for a running one to finish. Every Git command in a
    /// round is killed at its own time limit, so this ends; stopping sooner would release the
    /// vault while Git still works in the checkout, where another owner could start.
    pub(crate) fn stop(&self) {
        self.st().stopping = true;
        if self.st().running {
            eprintln!("vaultosd: waiting for the sync round in progress to finish");
        }
        while self.st().running {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Runs until the daemon stops: waits for the next round, or for a change to look again.
    pub(crate) async fn run_loop(shared: std::sync::Arc<Shared>) {
        loop {
            let s2 = shared.clone();
            let _ = tokio::task::spawn_blocking(move || s2.autosync.refresh(&s2)).await;
            let due = {
                let s = shared.autosync.st();
                match (s.next, s.soon) {
                    (Some(n), Some(soon)) => Some(n.min(soon)),
                    (n, soon) => n.or(soon),
                }
            };
            let wait = due.unwrap_or_else(|| Instant::now() + RECHECK);
            tokio::select! {
                _ = tokio::time::sleep_until(wait) => {}
                _ = shared.autosync.wake.notified() => continue,
            }
            if due.is_none_or(|d| Instant::now() < d) {
                continue;
            }
            {
                let mut s = shared.autosync.st();
                s.soon = None;
                s.next = Some(Instant::now() + Duration::from_secs(s.interval));
            }
            let s2 = shared.clone();
            let _ = tokio::task::spawn_blocking(move || s2.autosync.round(&s2, false)).await;
        }
    }

    /// One pull-then-push round; `manual` is `vaultos sync now`, which also clears a halt.
    /// Errors only for a manual round that cannot start.
    pub(crate) fn round(&self, shared: &Shared, manual: bool) -> Result<Value, SyncError> {
        let (unlocked, (enabled, _), configured) = shared.with_store(|store| {
            let configured = Sync::new(store.data_dir(), &self.repo).configured(store);
            (store.is_unlocked(), settings(store), configured)
        });
        {
            let mut s = self.st();
            if s.stopping {
                drop(s);
                return if manual {
                    Err(SyncError {
                        status: 503,
                        ..SyncError::new("VAULT_BUSY", "vaultosd is stopping")
                    })
                } else {
                    Ok(self.status())
                };
            }
            if s.running {
                drop(s);
                return Ok(self.status());
            }
            if !unlocked {
                if manual {
                    return Err(SyncError {
                        status: 423,
                        ..SyncError::new("PAUSED_LOCKED", "Vault is locked")
                    });
                }
                return Ok(self.status_locked(s));
            }
            if !manual && (s.halted || !enabled) {
                drop(s);
                return Ok(self.status());
            }
            if manual && !configured {
                return Err(SyncError::new(
                    "NOT_CONFIGURED",
                    "Sync is not initialized on this device: vaultos sync init <machine-label>",
                ));
            }
            s.running = true;
        }
        let was_halted = self.st().halted;
        let attempt_at = now_iso();
        let outcome = self.attempt(shared);
        let unlocked = shared.with_store(|store| store.is_unlocked());
        let mut s = self.st();
        s.running = false;
        s.last_attempt_at = Some(attempt_at.clone());
        let mut halt = None;
        match outcome {
            Ok((plan, pushed, problems)) => {
                let delivered = pushed["delivered"] == json!(true);
                let failure = (!delivered).then(|| {
                    pushed["code"]
                        .as_str()
                        .or(pushed["transport"].as_str())
                        .unwrap_or("PUSH_NOT_DELIVERED")
                        .to_owned()
                });
                let retried = Self::retry(&mut s, failure.as_deref());
                s.state = if delivered {
                    "OK"
                } else {
                    "PUSH_NOT_DELIVERED"
                }
                .into();
                if delivered {
                    s.last_sync_at = Some(attempt_at);
                    s.error = None;
                } else {
                    let why = pushed["error"]
                        .as_str()
                        .or(pushed["warning"].as_str())
                        .unwrap_or_default();
                    s.error = Some(first_line(if why.is_empty() {
                        failure.as_deref().unwrap_or("")
                    } else {
                        why
                    }));
                }
                let sent = pushed["written"].as_u64().unwrap_or(0) as usize;
                s.received = Some(json!({
                    "added": plan.added.len(),
                    "updated": plan.updated.len(),
                    "deleted": plan.deleted.len(),
                }));
                s.sent = Some(sent);
                s.conflicts = 0;
                s.peer_problems = problems;
                if !unlocked {
                    s.state = "PAUSED_LOCKED".into();
                }
                if manual {
                    s.halted = false;
                }
                if let Some(f) = failure.filter(|_| !retried) {
                    halt = Some((f, s.error.clone().unwrap_or_default()));
                }
                if plan.changes() || sent > 0 {
                    eprintln!(
                        "vaultosd: synced: +{} ~{} -{} in, {sent} out",
                        plan.added.len(),
                        plan.updated.len(),
                        plan.deleted.len()
                    );
                }
            }
            Err(e) if !unlocked => {
                let _ = e;
                s.state = "PAUSED_LOCKED".into();
            }
            Err(e) => {
                s.state = e.code.into();
                s.error = Some(first_line(&e.message));
                s.conflicts = e.conflicts;
                if manual {
                    s.halted = false;
                }
                if Self::retry(&mut s, Some(e.code)) {
                    eprintln!("vaultosd: sync failed: {}", first_line(&e.message));
                } else {
                    halt = Some((e.code.to_owned(), first_line(&e.message)));
                }
            }
        }
        let rerun = std::mem::take(&mut s.rerun);
        if rerun && s.next.is_some() {
            s.soon = Some(Instant::now() + DEBOUNCE);
        }
        drop(s);
        if let Some((state, error)) = halt {
            self.halt(shared, &state, &error);
        } else if manual && was_halted {
            self.wake.notify_one();
        }
        if rerun {
            self.wake.notify_one();
        }
        Ok(self.status())
    }

    fn status_locked(&self, mut s: std::sync::MutexGuard<'_, State>) -> Value {
        s.state = "PAUSED_LOCKED".into();
        drop(s);
        self.status()
    }

    /// The round itself: commit leftovers, fetch (no vault held), merge, write and commit
    /// the push, deliver it (no vault held), then read the peers' heartbeats.
    fn attempt(
        &self,
        shared: &Shared,
    ) -> Result<(vaultos_sync::Plan, Value, Vec<String>), SyncError> {
        let data_dir = shared.data_dir.clone();
        let sync = Sync::new(&data_dir, &self.repo);
        let _held = sync.hold();
        shared.with_store(|store| -> Result<(), SyncError> {
            // Another process replaced vault.enc but still holds write.lock: sync its copy on
            // a later round, not the stale one in memory.
            match store.reload_if_changed() {
                Err(vaultos_core::Error::Busy) => Err(SyncError::new(
                    "VAULT_BUSY",
                    "Another process is still saving the vault; the next round syncs its copy",
                )),
                Err(e) => Err(e.into()),
                Ok(_) => sync.commit_leftovers(store),
            }
        })?;
        sync.fetch()?;
        let plan = shared.with_store(|store| sync.reload_and_pull(store, false))?;
        let staged = shared.with_store(|store| -> Result<_, SyncError> {
            let id = sync.identity(store)?["id"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            sync.stage_push(store, Some(&format!("autosync from {id}")))
        })?;
        let pushed = sync.deliver(&staged);
        let problems = shared.with_store(|store| sync.peer_problems(store));
        Ok((plan, pushed, problems))
    }
}
