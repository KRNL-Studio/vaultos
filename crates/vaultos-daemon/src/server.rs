//! The daemon's transport: HTTP/1.1 over a Unix socket in the private data folder. Only
//! processes of the same user can connect (checked with the peer's credentials, on top of
//! the folder's 0700 mode), and every request except `/status` needs the session token from
//! `daemon.json`. Browsers cannot reach a Unix socket; requests carrying browser headers are
//! refused anyway.

use crate::api::{self, Reply, Request, MAX_BODY};
use crate::autosync::AutoSync;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ORIGIN};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::Value;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::net::UnixListener;
use tokio::sync::Notify;
use vaultos_core::crypto::{ct_eq, hex, random_array};
use vaultos_core::fs_safe::{claim, LockFile};
use vaultos_core::session::{prepare_socket_dir, socket_path, Session};
use vaultos_core::{Error, Store};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const GUARD_INTERVAL: Duration = Duration::from_secs(10);
const FAILED_UNLOCK_DELAY: Duration = Duration::from_secs(1);
/// The longest a connection is served: a manual sync round is the slowest request.
const ROUND_LIMIT: Duration = Duration::from_secs(150);

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    /// Lock after this long without a successful request.
    pub idle_lock: Option<Duration>,
    /// Wait for the vault's owner (the app) to quit instead of failing, then take over.
    pub wait_for_owner: bool,
    /// The sync checkout; by default `VAULTOS_SYNC_REPO`, else `sync-repository` in the
    /// data folder.
    pub sync_repo: Option<PathBuf>,
}

pub(crate) struct Shared {
    store: Mutex<Store>,
    unlocked: AtomicBool,
    token: String,
    session: Session,
    pub(crate) data_dir: PathBuf,
    last_used: Mutex<Instant>,
    shutdown: Notify,
    pub(crate) autosync: AutoSync,
}

/// Never prints the session token.
impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("data_dir", &self.data_dir)
            .field("unlocked", &self.unlocked)
            .finish_non_exhaustive()
    }
}

impl Shared {
    pub(crate) fn with_store<R>(&self, f: impl FnOnce(&mut Store) -> R) -> R {
        let mut store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        let r = f(&mut store);
        self.unlocked.store(store.is_unlocked(), Ordering::SeqCst);
        r
    }

    fn touch(&self) {
        *self
            .last_used
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.last_used
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .elapsed()
    }
}

/// Claims the vault: `owner.lock`, which the app also takes, so the app and the daemon never
/// serve one vault at once.
async fn claim_owner(cfg: &Config) -> Result<LockFile, Error> {
    loop {
        match claim(&cfg.data_dir, "owner.lock") {
            Err(Error::Busy) if cfg.wait_for_owner => {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(Error::Busy) => {
                return Err(Error::Conflict(
                    "Another VaultOS process (the app or a daemon) owns this vault".into(),
                ))
            }
            other => return other,
        }
    }
}

fn remove_stale_socket(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(Error::io("cannot remove the old socket"))
        }
        Ok(_) => Err(Error::Conflict(format!(
            "{} exists and is not a socket; inspect it before removing it",
            path.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io("cannot inspect the socket path")(e)),
    }
}

fn my_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The embedding process's way in (the desktop app). It reaches the same store the API serves
/// without the session token, so it can act as the human in-process; it is never handed to
/// anything an agent controls.
#[derive(Clone, Debug)]
pub struct Handle(Arc<Shared>);

impl Handle {
    pub fn with_store<R>(&self, f: impl FnOnce(&mut Store) -> R) -> R {
        self.0.with_store(f)
    }

    pub fn is_unlocked(&self) -> bool {
        self.0.unlocked.load(Ordering::SeqCst)
    }

    /// After a change the embedder made: autosync delivers it a few seconds later.
    pub fn changed(&self) {
        self.0.autosync.poke();
    }

    /// Asks the server to stop. `run_embedded` then locks the vault and releases it.
    pub fn shutdown(&self) {
        self.0.shutdown.notify_one();
    }

    pub fn sync_status(&self) -> Value {
        self.0.autosync.status()
    }

    /// Runs one sync round now, as `POST /sync` does. Blocks; call it off the UI thread.
    pub fn sync_round(&self) -> Result<Value, vaultos_sync::SyncError> {
        self.0.autosync.round(&self.0, true)
    }
}

/// Runs until `/shutdown`, SIGTERM or SIGINT. Returns once the socket and session file are
/// removed and the vault is released.
pub async fn run(cfg: Config) -> Result<(), Error> {
    serve(cfg, true, |_| {}).await
}

/// For an app that owns the vault: serves agents like `run`, and hands `ready` a [`Handle`]
/// once the vault is claimed and the socket is listening. Signals are left to the app; the
/// server stops at `/shutdown` or [`Handle::shutdown`].
pub async fn run_embedded(cfg: Config, ready: impl FnOnce(Handle) + Send) -> Result<(), Error> {
    serve(cfg, false, ready).await
}

async fn serve(cfg: Config, signals: bool, ready: impl FnOnce(Handle) + Send) -> Result<(), Error> {
    vaultos_core::fs_safe::private_dir(&cfg.data_dir)?;
    let sync_repo = match cfg.sync_repo.clone() {
        Some(r) => r,
        None => vaultos_sync::default_repo(&cfg.data_dir).map_err(|e| Error::Invalid(e.message))?,
    };
    let socket = socket_path(&cfg.data_dir)?;
    let owner_lock = claim_owner(&cfg).await?;
    let store = Store::new(&cfg.data_dir)?;
    prepare_socket_dir(&socket, &cfg.data_dir)?;
    remove_stale_socket(&socket)?;
    let listener = UnixListener::bind(&socket).map_err(Error::io("cannot listen on the socket"))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(Error::io("cannot restrict the socket"))?;
    }
    let token = hex(&random_array::<32>());
    let session = Session::new(socket.clone(), token.clone());
    session.write(&cfg.data_dir)?;
    let shared = Arc::new(Shared {
        store: Mutex::new(store),
        unlocked: AtomicBool::new(false),
        token,
        session,
        data_dir: cfg.data_dir.clone(),
        last_used: Mutex::new(Instant::now()),
        shutdown: Notify::new(),
        autosync: AutoSync::new(sync_repo),
    });

    let guard = tokio::spawn(guard_loop(shared.clone(), cfg.idle_lock));
    let autosync = tokio::spawn(AutoSync::run_loop(shared.clone()));
    ready(Handle(shared.clone()));
    let result = accept_loop(&listener, shared.clone(), signals).await;
    guard.abort();
    autosync.abort();

    // A round already running is a blocking task that abort cannot stop. Wait for it, so no
    // Git command of this daemon still runs in the checkout once another process owns the
    // vault. Then lock before releasing anything, and remove what clients use to find it.
    let s = shared.clone();
    let _ = tokio::task::spawn_blocking(move || {
        s.autosync.stop();
        s.with_store(Store::lock)
    })
    .await;
    let _ = std::fs::remove_file(&socket);
    shared.session.remove_if_ours(&shared.data_dir);
    drop(owner_lock);
    result
}

async fn accept_loop(
    listener: &UnixListener,
    shared: Arc<Shared>,
    signals: bool,
) -> Result<(), Error> {
    use tokio::signal::unix::{signal, SignalKind};
    let (mut term, mut int) = if signals {
        (
            Some(signal(SignalKind::terminate()).map_err(Error::io("cannot handle signals"))?),
            Some(signal(SignalKind::interrupt()).map_err(Error::io("cannot handle signals"))?),
        )
    } else {
        (None, None)
    };
    let uid = my_uid();
    // Connections end with the loop: a request still being answered when the server stops
    // gets no reply, so nothing reaches a client after a Lock.
    let mut conns = tokio::task::JoinSet::new();
    loop {
        let stream = tokio::select! {
            _ = shared.shutdown.notified() => return Ok(()),
            Some(_) = conns.join_next() => continue,
            Some(()) = recv(&mut term) => return Ok(()),
            Some(()) = recv(&mut int) => return Ok(()),
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(_) => continue,
            },
        };
        if stream.peer_cred().map(|c| c.uid()).ok() != Some(uid) {
            continue;
        }
        let shared = shared.clone();
        conns.spawn(async move {
            let service = service_fn(move |req| {
                let shared = shared.clone();
                async move { Ok::<_, Infallible>(respond(shared, req).await) }
            });
            let conn = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .max_buf_size(16 * 1024)
                .serve_connection(TokioIo::new(stream), service);
            // Sync rounds may take up to two minutes; nothing else comes close.
            let _ = tokio::time::timeout(ROUND_LIMIT, conn).await;
        });
    }
}

/// A signal stream that may be absent (embedded); then it never fires.
async fn recv(s: &mut Option<tokio::signal::unix::Signal>) -> Option<()> {
    match s {
        Some(s) => s.recv().await,
        None => std::future::pending().await,
    }
}

fn header(req: &hyper::Request<Incoming>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

async fn respond(
    shared: Arc<Shared>,
    req: hyper::Request<Incoming>,
) -> hyper::Response<Full<Bytes>> {
    let reply = route(shared, req).await;
    let body = serde_json::to_vec(&reply.body).unwrap_or_default();
    let mut res = hyper::Response::new(Full::new(Bytes::from(body)));
    *res.status_mut() = hyper::StatusCode::from_u16(reply.status)
        .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    let h = res.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    res
}

async fn route(shared: Arc<Shared>, req: hyper::Request<Incoming>) -> Reply {
    if req.headers().contains_key(ORIGIN) || req.headers().contains_key("sec-fetch-site") {
        return Reply::error(403, "Browser requests are not allowed");
    }
    let method = req.method().as_str().to_owned();
    let target = req
        .uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    let expected = format!("Bearer {}", shared.token);
    let presented = header(&req, AUTHORIZATION.as_str()).unwrap_or_default();
    let authorized = ct_eq(presented.as_bytes(), expected.as_bytes());
    if method == "GET" && target == "/status" {
        let sync = if authorized {
            shared.autosync.status()
        } else {
            shared.autosync.public_status()
        };
        return Reply::ok(api::status(shared.unlocked.load(Ordering::SeqCst), sync));
    }
    if !authorized {
        return Reply::error(401, "Unauthorized");
    }
    let agent_token = header(&req, "x-vault-agent-token");
    if method == "POST" && target == "/shutdown" {
        if agent_token.is_some() {
            return Reply::error(403, "Agents cannot stop the daemon");
        }
        let s = shared.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            s.shutdown.notify_one();
        });
        return Reply::ok(serde_json::json!({ "ok": true }));
    }
    // Owner control, like /shutdown: the session token alone, never an agent. It cannot
    // accept conflicts or return values; it runs the same round autosync would.
    if method == "POST" && target == "/sync" {
        if agent_token.is_some() {
            return Reply::error(403, "Agents cannot trigger sync");
        }
        let s = shared.clone();
        return match tokio::task::spawn_blocking(move || s.autosync.round(&s, true)).await {
            Ok(Ok(status)) => {
                let ok = status["state"] == serde_json::json!("OK");
                let mut body = serde_json::json!({ "ok": ok });
                if let (Some(b), Value::Object(s)) = (body.as_object_mut(), status) {
                    b.extend(s);
                }
                Reply::ok(body)
            }
            Ok(Err(e)) => Reply::error(e.status, &e.message),
            Err(_) => Reply::error(500, "Internal error"),
        };
    }
    let content_type = header(&req, CONTENT_TYPE.as_str());
    let approver = header(&req, "x-vault-approver");
    let collected = tokio::time::timeout(
        REQUEST_TIMEOUT,
        Limited::new(req.into_body(), MAX_BODY).collect(),
    )
    .await;
    let body = match collected {
        Err(_) => return Reply::error(408, "Request timed out"),
        Ok(Err(e))
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some() =>
        {
            return Reply::error(413, "Request too large")
        }
        Ok(Err(_)) => return Reply::error(400, "Incomplete request"),
        Ok(Ok(c)) => c.to_bytes().to_vec(),
    };
    let method_changes = method != "GET";
    let request = Request {
        method,
        target,
        agent_token,
        approver,
        content_type,
        body,
    };
    let s = shared.clone();
    let reply = tokio::task::spawn_blocking(move || {
        s.with_store(|store| {
            let reply = api::owner(store, &request).unwrap_or_else(|| api::handle(store, &request));
            if request.target == "/unlock" && reply.status == 401 {
                // Held with the store, so guesses are one a second however many clients try.
                std::thread::sleep(FAILED_UNLOCK_DELAY);
            }
            reply
        })
    })
    .await
    .unwrap_or_else(|_| Reply::error(500, "Internal error"));
    if reply.status == 200 {
        shared.touch();
        if method_changes {
            shared.autosync.poke();
        }
    }
    reply
}

/// Every few seconds: put `daemon.json` back if something removed or replaced it, pick up
/// saves from other processes (or lock if the file can no longer be opened with this
/// session's keys), and lock after the idle timeout.
async fn guard_loop(shared: Arc<Shared>, idle_lock: Option<Duration>) {
    let mut tick = tokio::time::interval(GUARD_INTERVAL);
    tick.tick().await;
    loop {
        tick.tick().await;
        if Session::read(&shared.data_dir).as_ref() != Some(&shared.session) {
            let _ = shared.session.write(&shared.data_dir);
        }
        if !shared.unlocked.load(Ordering::SeqCst) {
            continue;
        }
        let idle = idle_lock.is_some_and(|limit| shared.idle_for() >= limit);
        let s = shared.clone();
        let changed = tokio::task::spawn_blocking(move || {
            s.with_store(|store| {
                if idle {
                    store.lock();
                    return true;
                }
                match store.reload_if_changed() {
                    Ok(reloaded) => reloaded,
                    Err(Error::Busy | Error::Io { .. } | Error::Conflict(_)) => false,
                    Err(_) => {
                        store.lock();
                        true
                    }
                }
            })
        })
        .await;
        if changed.unwrap_or(false) {
            shared.autosync.poke();
        }
    }
}
