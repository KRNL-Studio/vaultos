//! The desktop's state and lock rules.
//!
//! The app owns the vault only while it is unlocked: unlocking claims `owner.lock` by starting
//! the daemon's server in-process (so enrolled agents keep working), and a full Lock stops it,
//! which locks the vault and releases it for a headless `vaultosd`. A soft lock only locks the
//! window. The window's own calls reach the store through the server's [`Handle`], never the
//! socket: the session token there is readable by any process of this user.
//!
//! Every lock bumps a generation. An unlock notes the generation when it is asked for, so one
//! still waiting (for its turn, for Touch ID, for another process to hand over the vault)
//! cannot finish after a later Lock.

use crate::keyring::{self, Keyring};
use crate::platform::{self, Clipboard};
use crate::prefs::{self, Prefs};
use crate::{settings, ui};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use vaultos_core::fs_safe::{atomic_write, claim};
use vaultos_core::store::VAULT_FILE;
use vaultos_core::{Error, KdfParams, SecretKey, SecretString, Store};
use vaultos_daemon::server::{run_embedded, Config, Confirm, Handle};

/// Proof of presence (Touch ID, a typed password or an unlock) lasts this long.
const GRACE: Duration = Duration::from_secs(30);
pub const IDLE_LOCK: Duration = Duration::from_secs(15 * 60);
const COPY_CLEAR: Duration = Duration::from_secs(30);
pub const NEED_PASSWORD: &str = "NEED_PASSWORD";
pub const LOCKED_FILE: &str = "locked";
const TOUCH_ID_HINT: &str = "touch-id";

pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Runs blocking work (Argon2id, file I/O, Git) off the async threads.
pub async fn blocking<R: Send + 'static>(
    f: impl FnOnce() -> R + Send + 'static,
) -> Result<R, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|_| "Internal error".to_string())
}

pub fn refused(error: impl Into<String>) -> Value {
    json!({ "ok": false, "error": error.into() })
}

#[derive(Debug, Default)]
struct Backoff {
    failed: u32,
    until: Option<Instant>,
}

impl Backoff {
    fn waiting(&self) -> bool {
        self.until.is_some_and(|t| Instant::now() < t)
    }

    fn fail(&mut self) {
        self.failed = self.failed.saturating_add(1);
        let ms = (500u64 << self.failed.min(6)).min(30_000);
        self.until = Some(Instant::now() + Duration::from_millis(ms));
    }

    fn reset(&mut self) {
        self.failed = 0;
    }
}

#[derive(Debug, Default)]
struct Proof {
    last: Option<Instant>,
    epoch: u64,
    confirm: Backoff,
}

#[derive(Debug)]
pub struct App {
    pub data_dir: PathBuf,
    pub keyring: Keyring,
    pub clipboard: Clipboard,
    pub prefs: Mutex<Prefs>,
    pub shortcut_error: Mutex<String>,
    pub ssh_error: Mutex<String>,
    pub pending_command: Mutex<Option<Value>>,
    pub quitting: AtomicBool,
    pub prompting: AtomicUsize,
    pub last_pending: AtomicUsize,
    pub expiry_day: Mutex<String>,
    pub tauri: OnceLock<AppHandle>,
    server: Mutex<Option<(u64, Handle)>>,
    servers: AtomicU64,
    running: AtomicUsize,
    human: AtomicBool,
    generation: AtomicU64,
    /// Held by a Lock and by an unlock's last step, so a Lock either stops the unlock or
    /// undoes it.
    finishing: Mutex<()>,
    unlocks: tokio::sync::Mutex<()>,
    proving: tokio::sync::Mutex<()>,
    retry: Mutex<Backoff>,
    proof: Mutex<Proof>,
    password: Mutex<Option<SecretString>>,
    secret_key: Mutex<Option<SecretKey>>,
    last_used: Mutex<Instant>,
    copies: AtomicU64,
}

/// Why an unlock did not open the vault.
enum Refusal {
    NeedsUpgrade,
    NeedsSecretKey,
    Failed(Option<String>),
}

impl App {
    pub fn new(data_dir: PathBuf) -> App {
        App {
            keyring: Keyring::new(&data_dir),
            clipboard: Clipboard::default(),
            prefs: Mutex::new(prefs::load(&data_dir)),
            shortcut_error: Mutex::default(),
            ssh_error: Mutex::default(),
            pending_command: Mutex::default(),
            quitting: AtomicBool::new(false),
            prompting: AtomicUsize::new(0),
            last_pending: AtomicUsize::new(0),
            expiry_day: Mutex::default(),
            tauri: OnceLock::new(),
            server: Mutex::default(),
            servers: AtomicU64::new(0),
            running: AtomicUsize::new(0),
            human: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            finishing: Mutex::default(),
            unlocks: tokio::sync::Mutex::new(()),
            proving: tokio::sync::Mutex::new(()),
            retry: Mutex::default(),
            proof: Mutex::default(),
            password: Mutex::default(),
            secret_key: Mutex::default(),
            last_used: Mutex::new(Instant::now()),
            copies: AtomicU64::new(0),
            data_dir,
        }
    }

    pub fn emit(&self, window: &str, event: &str) {
        if let Some(h) = self.tauri.get() {
            let _ = h.emit_to(window, event, ());
        }
    }

    fn handle(&self) -> Option<Handle> {
        lock(&self.server).as_ref().map(|(_, h)| h.clone())
    }

    /// Starts or stops the SSH agent to match the preference, once the app owns the vault.
    /// Signing asks for Touch ID, or this app's dialog where Touch ID is not available.
    pub fn apply_ssh_agent(&self) {
        let Some(h) = self.handle() else {
            return;
        };
        let mut error = lock(&self.ssh_error);
        error.clear();
        if !lock(&self.prefs).ssh_agent {
            h.stop_ssh_agent();
            return;
        }
        if let Err(e) = h.start_ssh_agent(self.ask_human("Allow this signature?")) {
            *error = e.to_string();
        }
    }

    /// Touch ID, or this app's dialog (titled `title`) where Touch ID is not available.
    fn ask_human(&self, title: &'static str) -> Confirm {
        let tauri = self.tauri.get().cloned();
        Confirm(Arc::new(move |reason: &str| {
            if platform::touch_id_available() {
                return Some(platform::touch_id_prompt(reason));
            }
            tauri
                .as_ref()
                .map(|t| crate::ui::ask_allow(t, title, reason))
        }))
    }

    pub fn access_grants(&self) -> Vec<vaultos_daemon::access::Grant> {
        self.handle().map(|h| h.access_grants()).unwrap_or_default()
    }

    pub fn end_access(&self, agent_id: &str) -> usize {
        self.handle().map_or(0, |h| h.end_access(agent_id, None))
    }

    pub fn ssh_socket(&self) -> Option<PathBuf> {
        self.handle().and_then(|h| h.ssh_agent_socket())
    }

    pub fn store_unlocked(&self) -> bool {
        self.handle().is_some_and(|h| h.is_unlocked())
    }

    /// The window is unlocked: the human proved the password (or Touch ID) since the last lock.
    pub fn human_unlocked(&self) -> bool {
        self.human.load(Ordering::SeqCst) && self.store_unlocked()
    }

    pub fn exists(&self) -> bool {
        self.data_dir.join(VAULT_FILE).exists()
    }

    fn file_version(&self) -> Option<u64> {
        Store::new(&self.data_dir).ok()?.file_version().ok()
    }

    /// The vault needs a Secret Key this device does not hold: none, or an earlier one that
    /// `vaultos secret-key` has since replaced.
    fn secret_key_missing(&self) -> bool {
        Store::new(&self.data_dir)
            .ok()
            .and_then(|s| s.secret_key_id().ok())
            .flatten()
            .is_some_and(|id| keyring::stored_secret_key(&self.keyring, &id).is_none())
    }

    /// Runs `f` on the open store.
    pub fn with_store<R>(
        &self,
        f: impl FnOnce(&mut Store) -> Result<R, Error>,
    ) -> Result<R, String> {
        let h = self.handle().ok_or("Vault is locked")?;
        h.with_store(f).map_err(|e| e.to_string())
    }

    pub fn changed(&self) {
        if let Some(h) = self.handle() {
            h.changed();
        }
        if let Some(app) = self.tauri.get() {
            ui::refresh_tray(app);
        }
    }

    pub fn sync_status(&self) -> Option<Value> {
        self.handle().map(|h| h.sync_status())
    }

    pub fn touch(&self) {
        *lock(&self.last_used) = Instant::now();
    }

    pub fn idle_for(&self) -> Duration {
        lock(&self.last_used).elapsed()
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    fn locked_since(&self, generation: u64) -> bool {
        self.generation() != generation
    }

    fn retry_wait(&self) -> Option<Value> {
        lock(&self.retry)
            .waiting()
            .then(|| refused("Wait a moment before trying again"))
    }

    /// Stops the server (which locks the vault and releases it).
    fn release(&self) {
        if let Some((_, h)) = lock(&self.server).take() {
            h.shutdown();
        }
    }

    /// Gives back ownership this attempt gained, unless the vault is open: a window-only lock
    /// keeps serving agents, so it keeps the vault.
    fn abandon(&self) -> Value {
        if !self.store_unlocked() {
            self.release();
        }
        refused("VaultOS was locked while unlocking. Unlock again.")
    }

    fn forget_proof(&self) {
        let mut p = lock(&self.proof);
        p.last = None;
        p.epoch += 1;
    }

    fn mark_proven(&self) {
        lock(&self.proof).last = Some(Instant::now());
    }

    fn fresh(&self) -> bool {
        lock(&self.proof).last.is_some_and(|t| t.elapsed() < GRACE)
    }

    /// A full Lock: the window, Quick Access, the copied value, the proof, the server. With
    /// `forget` (Lock, screen lock, sleep, idle) the remembered password is removed too and the
    /// next unlock must be typed.
    pub fn lock(&self, forget: bool) {
        let _gate = lock(&self.finishing);
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.human.store(false, Ordering::SeqCst);
        if let Some(app) = self.tauri.get() {
            ui::lock_quick(app);
        }
        self.clipboard.clear();
        self.forget_proof();
        if forget {
            // Either one keeps background access from unlocking again.
            let blocked = atomic_write(&self.data_dir.join(LOCKED_FILE), b"").is_ok();
            let forgotten = self.keyring.clear(keyring::PASSWORD).is_ok();
            if !blocked && !forgotten {
                if let Some(app) = self.tauri.get() {
                    ui::notify(
                        app,
                        "VaultOS could not record the Lock",
                        "Background access may unlock the vault again. Turn off Remember password in Settings.",
                    );
                }
            }
        }
        *lock(&self.password) = None;
        *lock(&self.secret_key) = None;
        self.release();
        self.emit("main", "vault:locked");
        if let Some(app) = self.tauri.get() {
            ui::refresh_tray(app);
        }
    }

    /// Locks only the window: the human must unlock again to see or change anything, while
    /// this process keeps the vault open for enrolled agents.
    pub fn lock_window(&self) {
        let _gate = lock(&self.finishing);
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.human.store(false, Ordering::SeqCst);
        if let Some(app) = self.tauri.get() {
            ui::lock_quick(app);
        }
        self.clipboard.clear();
        self.forget_proof();
        self.emit("main", "vault:locked");
        if let Some(app) = self.tauri.get() {
            ui::refresh_tray(app);
        }
    }

    /// Screen lock, sleep and idle follow the vault's lock policy: hard unless the human
    /// chose soft.
    pub fn auto_lock(&self) {
        if !self.human.load(Ordering::SeqCst) && !self.store_unlocked() {
            // An unlock may still be waiting for its turn, Touch ID or the key derivation.
            self.lock(false);
            return;
        }
        let soft = self
            .with_store(|s| Ok(settings::soft_lock(s.settings()?)))
            .unwrap_or(false);
        if soft {
            self.lock_window();
        } else {
            self.lock(true);
        }
    }

    /// Notices a server that stopped (`vaultos` asked it to, or it failed) or a vault locked
    /// behind the window's back, and shows the lock screen.
    pub fn check_server(&self) {
        // An unlock starts the server before it opens the vault; leave that alone.
        let Ok(_turn) = self.unlocks.try_lock() else {
            return;
        };
        let (present, open) = match lock(&self.server).as_ref() {
            Some((_, h)) => (true, h.is_unlocked()),
            None => (false, false),
        };
        if self.human.load(Ordering::SeqCst) && !open {
            self.lock(false);
        } else if present && !open {
            // Locked while serving agents behind a locked window: give the vault back.
            self.release();
        }
    }

    pub fn server_running(&self) -> bool {
        self.running.load(Ordering::SeqCst) > 0
    }

    /// Asks a headless daemon serving this vault to stop, then waits for `owner.lock`.
    fn hand_over(data_dir: &Path) -> Result<(), String> {
        let client = vaultos_client::Client::with_token(data_dir.to_path_buf(), None)
            .with_busy_wait(Duration::from_secs(2));
        if client.live(Duration::from_millis(1500)).is_some() {
            let _ = client.owner("POST", "/shutdown", None);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match claim(data_dir, "owner.lock") {
                Ok(held) => {
                    drop(held);
                    return Ok(());
                }
                Err(Error::Busy) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(Error::Busy) => {
                    return Err("Close the other VaultOS instance before unlocking".into())
                }
                Err(e) => return Err(e.to_string()),
            }
        }
    }

    /// Claims the vault and starts the agent API, once.
    async fn own(self: &Arc<Self>) -> Result<Handle, String> {
        if let Some(h) = self.handle() {
            return Ok(h);
        }
        let dir = self.data_dir.clone();
        blocking(move || App::hand_over(&dir)).await??;
        let id = self.servers.fetch_add(1, Ordering::SeqCst) + 1;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let cfg = Config {
            data_dir: self.data_dir.clone(),
            idle_lock: None,
            wait_for_owner: false,
            sync_repo: None,
            // `vaultos read`, `render` and `run` while the app owns the vault: Touch ID each time.
            confirm: Some(Confirm(Arc::new(|reason: &str| {
                platform::touch_id_available().then(|| platform::touch_id_prompt(reason))
            }))),
        };
        let me = self.clone();
        self.running.fetch_add(1, Ordering::SeqCst);
        tauri::async_runtime::spawn(async move {
            let result = run_embedded(cfg, move |h| {
                let _ = ready_tx.send(h);
            })
            .await;
            {
                let mut server = lock(&me.server);
                if server.as_ref().is_some_and(|(n, _)| *n == id) {
                    *server = None;
                }
            }
            me.running.fetch_sub(1, Ordering::SeqCst);
            let _ = done_tx.send(result);
        });
        match ready_rx.await {
            Ok(h) => {
                *lock(&self.server) = Some((id, h.clone()));
                h.set_access_confirm(Some(self.ask_human("Allow this agent's access?")));
                self.apply_ssh_agent();
                Ok(h)
            }
            Err(_) => Err(match done_rx.await {
                Ok(Err(e)) => e.to_string(),
                _ => "The vault could not be opened".into(),
            }),
        }
    }

    fn secret_key_for(
        &self,
        store: &Store,
        typed: Option<&str>,
    ) -> Result<Option<SecretKey>, Refusal> {
        let Some(id) = store
            .secret_key_id()
            .map_err(|e| Refusal::Failed(Some(e.to_string())))?
        else {
            return Ok(None);
        };
        match typed.filter(|t| !t.trim().is_empty()) {
            Some(t) => SecretKey::parse(t.trim())
                .map(Some)
                .map_err(|e| Refusal::Failed(Some(e.to_string()))),
            None => keyring::stored_secret_key(&self.keyring, &id)
                .map(Some)
                .ok_or(Refusal::NeedsSecretKey),
        }
    }

    /// Opens the vault with a password (or checks it, when the server already has it open).
    fn open_vault(
        &self,
        h: &Handle,
        password: &SecretString,
        typed_key: Option<&str>,
    ) -> Result<Option<SecretKey>, Refusal> {
        h.with_store(|s| {
            if s.file_version()
                .map_err(|e| Refusal::Failed(Some(e.to_string())))?
                < 4
            {
                return Err(Refusal::NeedsUpgrade);
            }
            let key = self.secret_key_for(s, typed_key)?;
            let r = if s.is_unlocked() {
                s.verify_password(password, key.as_ref())
            } else {
                s.unlock(password, key.as_ref())
            };
            match r {
                Ok(()) => Ok(key),
                Err(Error::NeedsUpgrade) => Err(Refusal::NeedsUpgrade),
                Err(Error::SecretKeyRequired) => Err(Refusal::NeedsSecretKey),
                Err(e @ Error::SecretKeyFormat(_)) => Err(Refusal::Failed(Some(e.to_string()))),
                Err(_) => Err(Refusal::Failed(None)),
            }
        })
    }

    fn write_touch_id_hint(&self, s: &Map<String, Value>) {
        let file = self.data_dir.join(TOUCH_ID_HINT);
        let t = settings::touch_id(s);
        if t["unlock"] == json!(true) && settings::remember(s) {
            let hint = json!({ "unlock": true, "autoPrompt": t["autoPrompt"] });
            let _ = atomic_write(&file, hint.to_string().as_bytes());
        } else if std::fs::symlink_metadata(&file).is_ok_and(|m| m.is_file()) {
            let _ = std::fs::remove_file(&file);
        }
    }

    fn touch_id_hint(&self) -> Value {
        let file = self.data_dir.join(TOUCH_ID_HINT);
        let saved = std::fs::symlink_metadata(&file)
            .ok()
            .filter(|m| m.is_file() && m.len() < 4096)
            .and_then(|_| std::fs::read(&file).ok())
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .unwrap_or(Value::Null);
        let unlock = saved["unlock"] == json!(true);
        json!({ "unlock": unlock, "autoPrompt": unlock && saved["autoPrompt"] == json!(true) })
    }

    /// After a human unlock: remembered password, hint, proof, idle timer.
    fn opened(&self, password: SecretString, key: Option<SecretKey>, typed_key: bool) {
        let _ = std::fs::remove_file(self.data_dir.join(LOCKED_FILE));
        if let (true, Some(k)) = (typed_key, key.as_ref()) {
            // The Secret Key stays on this device, so later unlocks need only the password.
            let _ = self.keyring.set(keyring::SECRET_KEY, &k.display());
        }
        if let Ok(s) = self.with_store(|s| Ok(s.settings()?.clone())) {
            if settings::remember(&s) {
                let _ = self.keyring.ensure(keyring::PASSWORD, &password);
            }
            self.write_touch_id_hint(&s);
        }
        *lock(&self.password) = Some(password);
        *lock(&self.secret_key) = key;
        self.human.store(true, Ordering::SeqCst);
        self.mark_proven();
        lock(&self.retry).reset();
        self.touch();
    }

    /// Opens the window unless a Lock came after `generation`.
    fn finish(
        &self,
        generation: u64,
        password: SecretString,
        key: Option<SecretKey>,
        typed_key: bool,
    ) -> bool {
        let _gate = lock(&self.finishing);
        if self.locked_since(generation) {
            return false;
        }
        self.opened(password, key, typed_key);
        true
    }

    fn after_unlock(&self) {
        // What has been in the Trash for 30 days goes, with its history.
        let _ = self.with_store(|s| s.purge_expired_trash(vaultos_core::model::HUMAN));
        self.emit("main", "vault:unlocked");
        if let Some(app) = self.tauri.get() {
            ui::refresh_tray(app);
            ui::notify_expiring(app);
        }
    }

    fn failed_unlock(&self, refusal: Refusal) -> Value {
        if !self.store_unlocked() {
            self.release();
        }
        match refusal {
            Refusal::NeedsUpgrade => json!({
                "ok": false,
                "needsUpgrade": true,
                "error": "This vault was made by an earlier VaultOS. Upgrade it to open it here; the earlier file is kept as a backup.",
            }),
            Refusal::NeedsSecretKey => json!({
                "ok": false,
                "needsSecretKey": true,
                "error": "This vault uses a Secret Key. Enter it once; VaultOS keeps it in this device's keychain.",
            }),
            Refusal::Failed(detail) => {
                lock(&self.retry).fail();
                refused(detail.unwrap_or_else(|| {
                    "Could not unlock. Check the password and vault file.".into()
                }))
            }
        }
    }

    pub async fn unlock_password(
        self: &Arc<Self>,
        pw: Option<String>,
        typed_key: Option<String>,
    ) -> Value {
        let Some(pw) = pw.filter(|p| !p.is_empty() && p.len() <= 1024) else {
            return refused("Invalid password");
        };
        let generation = self.generation();
        let r = {
            let _turn = self.unlocks.lock().await;
            self.unlock_inner(generation, SecretString::new(pw), typed_key)
                .await
        };
        if r["ok"] == json!(true) {
            self.after_unlock();
        }
        r
    }

    async fn unlock_inner(
        self: &Arc<Self>,
        generation: u64,
        pw: SecretString,
        typed_key: Option<String>,
    ) -> Value {
        if self.locked_since(generation) {
            return self.abandon();
        }
        if let Some(wait) = self.retry_wait() {
            return wait;
        }
        let h = match self.own().await {
            Ok(h) => h,
            Err(e) => return refused(e),
        };
        if self.locked_since(generation) {
            return self.abandon();
        }
        let me = self.clone();
        let typed = typed_key.clone();
        let result = blocking(move || {
            let key = me.open_vault(&h, &pw, typed.as_deref());
            (key, pw)
        })
        .await;
        let (key, pw) = match result {
            Ok(r) => r,
            Err(e) => return refused(e),
        };
        match key {
            Ok(key) => {
                if !self.finish(generation, pw, key, typed_key.is_some()) {
                    return self.abandon();
                }
                json!({ "ok": true })
            }
            Err(refusal) => self.failed_unlock(refusal),
        }
    }

    /// Creates a new vault (format 4, no Secret Key; `vaultos secret-key` adds one).
    pub async fn create(self: &Arc<Self>, pw: Option<String>) -> Result<Value, String> {
        let pw = pw.ok_or("Invalid password")?;
        let generation = self.generation();
        let _turn = self.unlocks.lock().await;
        if self.locked_since(generation) {
            return Ok(self.abandon());
        }
        if let Some(wait) = self.retry_wait() {
            return Ok(wait);
        }
        let h = self.own().await?;
        if self.locked_since(generation) {
            return Ok(self.abandon());
        }
        let password = SecretString::new(pw);
        let pw2 = password.clone();
        let created =
            blocking(move || h.with_store(|s| s.create(&pw2, None, KdfParams::DEFAULT))).await?;
        if let Err(e) = created {
            self.lock(false);
            return Err(e.to_string());
        }
        if !self.finish(generation, password, None, false) {
            return Ok(self.abandon());
        }
        drop(_turn);
        self.after_unlock();
        Ok(json!({ "ok": true }))
    }

    /// Upgrades an earlier app's vault (an explicit choice), keeping the old file as a backup,
    /// then unlocks it.
    pub async fn upgrade(self: &Arc<Self>, pw: Option<String>) -> Value {
        let Some(pw) = pw.filter(|p| !p.is_empty() && p.len() <= 1024) else {
            return refused("Invalid password");
        };
        let generation = self.generation();
        let upgraded = {
            let _turn = self.unlocks.lock().await;
            if let Some(wait) = self.retry_wait() {
                return wait;
            }
            if let Err(e) = self.own().await {
                return refused(e);
            }
            if self.locked_since(generation) {
                return self.abandon();
            }
            let dir = self.data_dir.clone();
            let password = SecretString::new(pw.clone());
            match blocking(move || {
                vaultos_core::upgrade::upgrade(&dir, &password, None, KdfParams::DEFAULT)
            })
            .await
            {
                Ok(Ok(u)) => u,
                Ok(Err(Error::Unlock)) | Ok(Err(Error::Integrity)) => {
                    self.release();
                    lock(&self.retry).fail();
                    return refused("Could not upgrade. Check the password.");
                }
                Ok(Err(e)) => {
                    self.release();
                    return refused(e.to_string());
                }
                Err(e) => return refused(e),
            }
        };
        let mut r = self.unlock_password(Some(pw), None).await;
        r["backup"] = json!(upgraded.backup.display().to_string());
        r
    }

    pub fn touch_id_status(&self) -> Value {
        let available = platform::touch_id_available();
        let unlocked = self.store_unlocked();
        let (t, enabled) = if unlocked {
            let s = self
                .with_store(|s| Ok(s.settings()?.clone()))
                .unwrap_or_default();
            let t = settings::touch_id(&s);
            let enabled = t["unlock"] == json!(true) && settings::remember(&s);
            (t, enabled)
        } else {
            let t = self.touch_id_hint();
            let enabled = t["unlock"] == json!(true);
            (t, enabled)
        };
        let auto_prompt = enabled && t["autoPrompt"] == json!(true);
        let error = if !available {
            Some("Touch ID is not available right now. Enter the master password.")
        } else if !self.exists() || !enabled {
            Some("Touch ID unlock is off. Enter the master password.")
        } else if self.data_dir.join(LOCKED_FILE).exists() {
            Some("After Lock, enter the master password once.")
        } else {
            None
        };
        let mut out = json!({ "available": available, "enabled": enabled, "ready": error.is_none(), "autoPrompt": error.is_none() && auto_prompt });
        if let Some(e) = error {
            out["error"] = json!(e);
        }
        out
    }

    /// The lock screen's view: never anything from inside the vault.
    pub fn state(&self) -> Value {
        let prefs = lock(&self.prefs).clone();
        json!({
            "exists": self.exists(),
            "unlocked": self.human_unlocked(),
            "isMac": cfg!(target_os = "macos"),
            "dataDir": self.data_dir.display().to_string(),
            "shortcut": prefs.shortcut,
            "touchId": self.touch_id_status(),
            "needsUpgrade": self.exists() && self.file_version().is_some_and(|v| v < 4),
            "needsSecretKey": self.secret_key_missing(),
        })
    }

    /// Shows one Touch ID sheet at a time. `Err` when a Lock happened meanwhile.
    async fn prompt(self: &Arc<Self>, reason: &str) -> Result<bool, String> {
        if !platform::touch_id_available() {
            return Ok(false);
        }
        let epoch = lock(&self.proof).epoch;
        let _one = self.proving.lock().await;
        if lock(&self.proof).epoch != epoch {
            return Err("Vault is locked".into());
        }
        if self.fresh() {
            return Ok(true);
        }
        self.prompting.fetch_add(1, Ordering::SeqCst);
        let reason = reason.to_owned();
        let ok = blocking(move || platform::touch_id_prompt(&reason))
            .await
            .unwrap_or(false);
        self.prompting.fetch_sub(1, Ordering::SeqCst);
        if let Some(app) = self.tauri.get() {
            ui::refocus_quick(app);
        }
        if lock(&self.proof).epoch != epoch {
            return Err("Vault is locked".into());
        }
        if ok {
            self.mark_proven();
        }
        Ok(ok)
    }

    pub async fn unlock_touch_id(self: &Arc<Self>) -> Value {
        let r = self.unlock_touch_id_inner().await;
        if r["ok"] == json!(true) {
            self.after_unlock();
        }
        r
    }

    async fn unlock_touch_id_inner(self: &Arc<Self>) -> Value {
        if let Some(wait) = self.retry_wait() {
            return wait;
        }
        let status = self.touch_id_status();
        if status["ready"] != json!(true) {
            return refused(
                status["error"]
                    .as_str()
                    .unwrap_or("Touch ID is unavailable"),
            );
        }
        let generation = self.generation();
        if !matches!(self.prompt("unlock VaultOS").await, Ok(true)) {
            return json!({ "ok": false, "canceled": true, "error": "Touch ID was not confirmed. Enter the master password." });
        }
        let _turn = self.unlocks.lock().await;
        if self.locked_since(generation) {
            self.forget_proof();
            return self.abandon();
        }
        if let Some(wait) = self.retry_wait() {
            self.forget_proof();
            return wait;
        }
        let h = match self.own().await {
            Ok(h) => h,
            Err(e) => {
                self.forget_proof();
                return refused(e);
            }
        };
        if self.locked_since(generation) {
            self.forget_proof();
            return self.abandon();
        }
        let was_unlocked = h.is_unlocked();
        let me = self.clone();
        let h2 = h.clone();
        let opened = blocking(move || -> Option<(SecretString, Option<SecretKey>)> {
            if me.data_dir.join(LOCKED_FILE).exists() {
                return None;
            }
            let pw = me.keyring.get(keyring::PASSWORD)?;
            let key = me.open_vault(&h2, &pw, None).ok()?;
            let s = h2.with_store(|s| s.settings().cloned()).ok()?;
            let on = settings::touch_id(&s)["unlock"] == json!(true) && settings::remember(&s);
            on.then_some((pw, key))
        })
        .await
        .ok()
        .flatten();
        match opened {
            Some((pw, key)) => {
                if !self.finish(generation, pw, key, false) {
                    return self.abandon();
                }
                json!({ "ok": true })
            }
            None => {
                if !was_unlocked {
                    // Picks up a Touch ID setting turned off elsewhere before locking again.
                    let _ = h.with_store(|s| -> Result<(), Error> {
                        if let Ok(st) = s.settings() {
                            self.write_touch_id_hint(st);
                        }
                        s.lock();
                        Ok(())
                    });
                    self.release();
                }
                self.forget_proof();
                refused("Touch ID unlock is unavailable. Enter the master password.")
            }
        }
    }

    /// Human-only actions need a recent proof of presence when `touchId.humanActions` is on:
    /// Touch ID, else the master password (the renderer asks for it on NEED_PASSWORD).
    pub async fn require(
        self: &Arc<Self>,
        enabled: bool,
        reason: &str,
        password: Option<&str>,
    ) -> Result<(), String> {
        if !enabled || self.fresh() {
            return Ok(());
        }
        if self.prompt(reason).await? {
            return Ok(());
        }
        // An action that already carries the master password is confirmed by it.
        if let Some(pw) = password {
            if self.confirm_password(Some(pw.to_owned())).await["ok"] == json!(true) {
                return Ok(());
            }
        }
        Err(format!(
            "{NEED_PASSWORD}: Confirm with the master password to {reason}."
        ))
    }

    pub async fn gate(self: &Arc<Self>, reason: &str) -> Result<(), String> {
        let enabled = self
            .with_store(|s| Ok(settings::touch_id(s.settings()?)["humanActions"] == json!(true)))?;
        self.require(enabled, reason, None).await
    }

    /// Checks the master password without changing the vault.
    pub async fn confirm_password(self: &Arc<Self>, pw: Option<String>) -> Value {
        if lock(&self.proof).confirm.waiting() {
            return refused("Wait a moment before trying again");
        }
        let me = self.clone();
        let ok = match pw.filter(|p| p.len() <= 1024) {
            Some(pw) => blocking(move || {
                let key = lock(&me.secret_key).clone();
                me.with_store(|s| s.verify_password(&SecretString::new(pw), key.as_ref()))
                    .is_ok()
            })
            .await
            .unwrap_or(false),
            None => false,
        };
        let mut p = lock(&self.proof);
        if !ok {
            p.confirm.fail();
            return refused("Wrong password");
        }
        p.confirm.reset();
        p.last = Some(Instant::now());
        json!({ "ok": true })
    }

    pub fn password(&self) -> Option<SecretString> {
        lock(&self.password).clone()
    }

    pub fn secret_key(&self) -> Option<SecretKey> {
        lock(&self.secret_key).clone()
    }

    pub fn set_password(&self, pw: SecretString) {
        *lock(&self.password) = Some(pw);
    }

    pub fn rewrite_touch_id_hint(&self) {
        if let Ok(s) = self.with_store(|s| Ok(s.settings()?.clone())) {
            self.write_touch_id_hint(&s);
        }
    }

    /// Copies a value; it is cleared after 30 seconds if it is still on the clipboard. A Lock
    /// that came after the value was read wins: nothing is copied.
    pub fn copy_secret(self: &Arc<Self>, text: &str) -> Result<&'static str, String> {
        let mode = {
            let _gate = lock(&self.finishing);
            if !self.human_unlocked() {
                return Err("Vault is locked".into());
            }
            self.clipboard.write(text)?
        };
        let n = self.copies.fetch_add(1, Ordering::SeqCst) + 1;
        let me = self.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(COPY_CLEAR).await;
            if me.copies.load(Ordering::SeqCst) == n {
                me.clipboard.clear();
            }
        });
        Ok(mode)
    }

    /// Locks and waits briefly for the server to release the vault, before the process exits.
    pub async fn shut_down(&self) {
        self.quitting.store(true, Ordering::SeqCst);
        self.lock(false);
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.server_running() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
