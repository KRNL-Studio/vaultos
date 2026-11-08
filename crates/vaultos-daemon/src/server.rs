//! The daemon's transport: HTTP/1.1 over a Unix socket in the private data folder. Only
//! processes of the same user can connect (checked with the peer's credentials, on top of
//! the folder's 0700 mode), and every request except `/status` needs the session token from
//! `daemon.json`. Browsers cannot reach a Unix socket; requests carrying browser headers are
//! refused anyway.

use crate::access::{self, Access, Grant};
use crate::api::{self, Reply, Request, MAX_BODY};
use crate::autosync::AutoSync;
use crate::browser;
use crate::human;
use crate::ssh_agent::{self, SshAgent};
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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::net::UnixListener;
use tokio::sync::Notify;
use vaultos_core::crypto::{ct_eq, hex, random_array};
use vaultos_core::fs_safe::{claim, LockFile};
use vaultos_core::session::{prepare_socket_dir, socket_path, Session};
use vaultos_core::{Error, Store};
use zeroize::Zeroizing;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const GUARD_INTERVAL: Duration = Duration::from_secs(10);
const FAILED_UNLOCK_DELAY: Duration = Duration::from_secs(1);
/// The longest a connection is served: an agent's command may run for ten minutes.
const CONNECTION_LIMIT: Duration = Duration::from_secs(api::RUN_MAX_TIMEOUT + 30);
/// Agents' commands running at once; more are refused.
const MAX_RUNS: usize = 4;
/// The stdout and stderr kept of each, masked.
const MAX_RUN_OUTPUT: usize = 64 * 1024;

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
    /// How the app confirms a request for the human's values (`/human/values`) without the
    /// password: Touch ID. `None`, or a callback that answers `None`, asks for the password.
    pub confirm: Option<Confirm>,
}

/// Shows the system confirmation for `reason` ("VaultOS is trying to …") and blocks until
/// it is answered: `Some(true)` confirmed, `Some(false)` declined, `None` unavailable.
pub type ConfirmFn = dyn Fn(&str) -> Option<bool> + Send + Sync;

#[derive(Clone)]
pub struct Confirm(pub Arc<ConfirmFn>);

impl std::fmt::Debug for Confirm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Confirm")
    }
}

pub(crate) struct Shared {
    store: Mutex<Store>,
    pub(crate) unlocked: AtomicBool,
    token: String,
    session: Session,
    pub(crate) data_dir: PathBuf,
    last_used: Mutex<Instant>,
    shutdown: Notify,
    pub(crate) autosync: AutoSync,
    /// Touch ID, for `/human/values` and passkeys' user verification.
    pub(crate) confirm: Option<Confirm>,
    /// One confirmation sheet at a time; others are refused rather than queued.
    pub(crate) confirming: AtomicBool,
    pub(crate) ssh: SshAgent,
    pub(crate) access: Access,
    pub(crate) runtime: tokio::runtime::Handle,
    runs: AtomicUsize,
    /// How the app asks the human to pair a browser extension; without one, it cannot.
    pub(crate) browser_confirm: Mutex<Option<Confirm>>,
    /// When the human last declined pairing a browser.
    pub(crate) browser_declined: Mutex<Option<Instant>>,
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

    pub(crate) fn touch(&self) {
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

pub(crate) fn remove_stale_socket(path: &Path) -> Result<(), Error> {
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

    /// Starts the SSH agent (see [`crate::ssh_agent`]), which asks `confirm` before each
    /// signature it has not been allowed recently. Returns its socket.
    pub fn start_ssh_agent(&self, confirm: Confirm) -> Result<PathBuf, Error> {
        ssh_agent::start(&self.0, confirm)
    }

    pub fn stop_ssh_agent(&self) {
        ssh_agent::stop(&self.0);
    }

    pub fn ssh_agent_socket(&self) -> Option<PathBuf> {
        ssh_agent::socket(&self.0)
    }

    /// How the app asks the human about an agent's request for just-in-time access (see
    /// [`crate::access`]). Without one, such requests are refused.
    pub fn set_access_confirm(&self, confirm: Option<Confirm>) {
        self.0.access.set_confirm(confirm);
    }

    /// How the app asks the human to pair a browser extension (see [`crate::browser`]).
    /// Without one, pairing is refused.
    pub fn set_browser_confirm(&self, confirm: Option<Confirm>) {
        *self
            .0
            .browser_confirm
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = confirm;
    }

    /// The just-in-time grants in force.
    pub fn access_grants(&self) -> Vec<Grant> {
        let locks = self.0.with_store(|s| s.lock_count());
        self.0.access.live(locks)
    }

    /// Ends an agent's grants: all of them, or one project's. Returns how many ended.
    pub fn end_access(&self, agent_id: &str, project_id: Option<&str>) -> usize {
        self.0.access.end(agent_id, project_id)
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
        confirm: cfg.confirm.clone(),
        confirming: AtomicBool::new(false),
        ssh: SshAgent::default(),
        access: Access::default(),
        runtime: tokio::runtime::Handle::current(),
        runs: AtomicUsize::new(0),
        browser_confirm: Mutex::new(None),
        browser_declined: Mutex::new(None),
    });

    let guard = tokio::spawn(guard_loop(shared.clone(), cfg.idle_lock));
    let autosync = tokio::spawn(AutoSync::run_loop(shared.clone()));
    ready(Handle(shared.clone()));
    let result = accept_loop(&listener, shared.clone(), signals).await;
    guard.abort();
    autosync.abort();
    ssh_agent::stop(&shared);
    // Ending the connections stopped the agents' commands; wait for them to go, so none that
    // this process gave values to is still running once another process owns the vault.
    let until = std::time::Instant::now() + Duration::from_secs(10);
    while shared.runs.load(Ordering::SeqCst) > 0 && std::time::Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

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
        let Ok(cred) = stream.peer_cred() else {
            continue;
        };
        if cred.uid() != uid {
            continue;
        }
        let pid = cred.pid();
        let shared = shared.clone();
        conns.spawn(async move {
            let service = service_fn(move |req| {
                let shared = shared.clone();
                async move { Ok::<_, Infallible>(respond(shared, req, pid).await) }
            });
            let conn = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .max_buf_size(16 * 1024)
                .serve_connection(TokioIo::new(stream), service);
            let _ = tokio::time::timeout(CONNECTION_LIMIT, conn).await;
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
    pid: Option<i32>,
) -> hyper::Response<Full<Bytes>> {
    let reply = route(shared, req, pid).await;
    let body = encode(&reply.body);
    let mut res = hyper::Response::new(Full::new(Bytes::from_owner(Wiped(body))));
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

/// A reply's bytes, zeroed when hyper is done with them: replies can carry values.
struct Wiped(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for Wiped {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The reply as JSON, in a buffer sized up front so growing it leaves no copies behind.
fn encode(v: &Value) -> Zeroizing<Vec<u8>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut n = Count(0);
    let _ = serde_json::to_writer(&mut n, v);
    let mut out = Zeroizing::new(Vec::with_capacity(n.0));
    let _ = serde_json::to_writer(&mut *out, v);
    out
}

async fn route(shared: Arc<Shared>, req: hyper::Request<Incoming>, pid: Option<i32>) -> Reply {
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
    let browser_key = header(&req, "x-vault-browser-key");
    let browser_origin = header(&req, "x-vault-browser-origin");
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    if method == "POST" && target == "/human/values" {
        if agent_token.is_some() {
            return Reply::error(403, "Agents cannot use the human's own route");
        }
        return human_values(shared, body, pid).await;
    }
    if target.starts_with("/browser/") {
        if agent_token.is_some() {
            return Reply::error(403, "Agents cannot use the browser extension's routes");
        }
        return browser::route(
            shared,
            method,
            target,
            browser_key,
            browser_origin,
            body,
            pid,
        )
        .await;
    }
    if method == "POST" && target == "/access/request" {
        let Some(token) = agent_token else {
            return Reply::error(403, "Only an enrolled agent can request access");
        };
        return access::request(shared, token, body, pid).await;
    }
    let method_changes = method != "GET";
    let run = method == "POST" && target == "/run";
    let request = Request {
        method,
        target,
        agent_token,
        approver,
        content_type,
        body,
        grants: Vec::new(),
    };
    if run {
        return run_command(shared, request).await;
    }
    let s = shared.clone();
    let reply = tokio::task::spawn_blocking(move || {
        let mut request = request;
        s.with_store(|store| {
            request.grants = s.access.live(store.lock_count());
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

/// A place among the [`MAX_RUNS`] commands running, given back when dropped.
struct RunSlot(Arc<Shared>);

impl RunSlot {
    fn take(shared: &Arc<Shared>) -> Option<Self> {
        let slot = Self(shared.clone());
        (shared.runs.fetch_add(1, Ordering::SeqCst) < MAX_RUNS).then_some(slot)
    }
}

impl Drop for RunSlot {
    fn drop(&mut self) {
        self.0.runs.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Raised when the request is dropped unanswered (the server stopping, or the connection
/// ending), which stops the command.
struct Abandon(Arc<AtomicBool>);

impl Drop for Abandon {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// `POST /run`: the run scope. The plan is checked and the values read under the store
/// (`api::run_plan`); this process then starts the command without holding it, and the
/// agent gets the exit code and masked output, never the values. The command is stopped at
/// its timeout, when this request is dropped, or when the vault locks; its output is then
/// withheld.
async fn run_command(shared: Arc<Shared>, mut request: Request) -> Reply {
    if request.agent_token.is_none() {
        return Reply::error(403, "An enrolled, active agent token is required");
    }
    let Some(slot) = RunSlot::take(&shared) else {
        return Reply::error(
            429,
            "Four commands are already running; try again when one finishes",
        );
    };
    let s = shared.clone();
    let plan = tokio::task::spawn_blocking(move || {
        s.with_store(|store| {
            let locks = store.lock_count();
            request.grants = s.access.live(locks);
            api::run_plan(store, &request).map(|p| (p, locks))
        })
    })
    .await;
    let (plan, locks) = match plan {
        Ok(Ok(p)) => p,
        Ok(Err(r)) => return r,
        Err(_) => return Reply::error(500, "Internal error"),
    };
    shared.touch();
    let api::RunPlan {
        program,
        timeout,
        project,
        held_for_approval,
        too_short,
    } = plan;
    let abandoned = Arc::new(AtomicBool::new(false));
    let _abandon = Abandon(abandoned.clone());
    let s = shared.clone();
    let out = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        vaultos_client::run::capture_until(&program, timeout, MAX_RUN_OUTPUT, &|| {
            abandoned.load(Ordering::SeqCst) || !s.unlocked.load(Ordering::SeqCst)
        })
    })
    .await;
    shared.touch();
    // Locked while it ran (even if unlocked again since): the command keeps no value past a
    // lock, and nor does its reply.
    let s = shared.clone();
    let relocked = tokio::task::spawn_blocking(move || {
        s.with_store(|store| store.lock_count() != locks || !store.is_unlocked())
    })
    .await
    .unwrap_or(true);
    if relocked {
        return Reply::error(
            423,
            "VaultOS locked while the command ran; its output is withheld",
        );
    }
    match out {
        Ok(Ok(c)) => Reply::ok(serde_json::json!({
            "project": project,
            "exitCode": c.exit_code,
            "timedOut": c.timed_out,
            "truncated": c.truncated,
            "stdout": c.stdout,
            "stderr": c.stderr,
            "heldForApproval": held_for_approval,
            "tooShortToMask": too_short,
        })),
        Ok(Err(e)) => Reply::error(400, format!("The command could not be started: {e}")),
        Err(_) => Reply::error(500, "Internal error"),
    }
}

async fn read_body(req: hyper::Request<Incoming>) -> Result<Vec<u8>, Reply> {
    let collected = tokio::time::timeout(
        REQUEST_TIMEOUT,
        Limited::new(req.into_body(), MAX_BODY).collect(),
    )
    .await;
    match collected {
        Err(_) => Err(Reply::error(408, "Request timed out")),
        Ok(Err(e))
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some() =>
        {
            Err(Reply::error(413, "Request too large"))
        }
        Ok(Err(_)) => Err(Reply::error(400, "Incomplete request")),
        Ok(Ok(c)) => Ok(c.to_bytes().to_vec()),
    }
}

/// Clears the one-confirmation-at-a-time flag however the confirmation ends.
pub(crate) struct Confirming<'a>(pub(crate) &'a AtomicBool);

impl Drop for Confirming<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// `POST /human/values`: confirmed with the password, else by the app (Touch ID); see
/// `human.rs`. The store is not held while the sheet is up.
async fn human_values(shared: Arc<Shared>, body: Vec<u8>, pid: Option<i32>) -> Reply {
    let mut ask = match human::Ask::parse(&body) {
        Ok(a) => a,
        Err(r) => return r,
    };
    drop(body);
    if !shared.unlocked.load(Ordering::SeqCst) {
        return Reply::error(423, "Vault is locked. Unlock the app.");
    }
    let who = human::Peer::of(pid);
    if let Some(password) = ask.password.take() {
        let secret_key = ask.secret_key.take();
        let s = shared.clone();
        let checked = tokio::task::spawn_blocking(move || {
            s.with_store(|store| {
                let r = store.verify_password(&password, secret_key.as_ref());
                if matches!(r, Err(Error::Unlock | Error::SecretKeyRequired)) {
                    std::thread::sleep(FAILED_UNLOCK_DELAY);
                }
                r
            })
        })
        .await;
        match checked {
            Ok(Ok(())) => {}
            Ok(Err(Error::Locked)) => return Reply::error(423, "Vault is locked. Unlock the app."),
            Ok(Err(e)) => return Reply::error(401, e.to_string()),
            Err(_) => return Reply::error(500, "Internal error"),
        }
    } else {
        let need_password = || Reply {
            status: 401,
            body: serde_json::json!({
                "error": "Confirm with the master password",
                "needPassword": true,
            }),
        };
        let Some(confirm) = shared.confirm.clone() else {
            return need_password();
        };
        if shared.confirming.swap(true, Ordering::SeqCst) {
            return Reply::error(429, "Another request is waiting for confirmation");
        }
        let _one = Confirming(&shared.confirming);
        let reason = ask.reason(&who);
        let answer = tokio::task::spawn_blocking(move || (confirm.0)(&reason))
            .await
            .ok()
            .flatten();
        match answer {
            None => return need_password(),
            Some(false) => return Reply::error(403, "The request was not confirmed"),
            Some(true) => {}
        }
    }
    let s = shared.clone();
    let reply =
        tokio::task::spawn_blocking(move || s.with_store(|store| human::values(store, &ask, &who)))
            .await
            .unwrap_or_else(|_| Reply::error(500, "Internal error"));
    if reply.status == 200 {
        shared.touch();
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
