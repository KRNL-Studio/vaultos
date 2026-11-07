//! `VaultOS --service`: background access without a window, for a login service the human
//! installs (`scripts/install-service-macos.sh`, `scripts/install-linux.sh --enable-service`).
//!
//! It serves agents only while the human has background access on (the password is
//! remembered in the keychain) and no manual lock blocks it. It never holds `owner.lock` while
//! waiting, so the window can always claim the vault first; when the window asks it to stop,
//! it waits and takes over again once the window lets go. It runs in this program because the
//! macOS Keychain gives the remembered password, without a prompt, only to the program that
//! saved it. It never starts the windowing toolkit.

use crate::keyring::{self, Keyring};
use std::path::{Path, PathBuf};

use std::time::{Duration, Instant};
use vaultos_core::fs_safe::claim;
use vaultos_core::{Error, SecretKey, Store};
use vaultos_daemon::server::{run_embedded, Config, Handle};

const POLL: Duration = Duration::from_secs(2);
const MAX_WAIT: Duration = Duration::from_secs(5 * 60);
/// At login the keychain may not be readable yet.
const KEYRING_GRACE: Duration = Duration::from_secs(60);
/// After stopping for the window, before trying to own the vault again.
const HANDOVER_DELAY: Duration = Duration::from_secs(10);
/// Stopping for something a restart cannot fix (no vault, background access off, a
/// remembered password that no longer opens the vault) exits 0, so neither launchd nor
/// systemd restarts the service in a loop; the log says why. Unexpected failures exit 1.
const GIVE_UP: i32 = 0;

const MANUAL_LOCK: &str = "a manual lock needs a human unlock in the app";
const OFF: &str = "background access is off (no remembered password). Turn it on in Settings, unlock once, then restart the service.";

fn log(message: &str) {
    eprintln!("VaultOS service: {message}");
}

enum Ready {
    Owned,
    Blocked(&'static str),
    NoPassword,
    Start(keyring::Remembered),
}

/// Reads the keychain, which can wait for the human (a locked keychain asks to be unlocked),
/// so it runs on a blocking thread while signals stay answered.
fn check(data_dir: &Path) -> Ready {
    let keyring = Keyring::new(data_dir);
    match claim(data_dir, "owner.lock") {
        Ok(probe) => drop(probe),
        Err(_) => return Ready::Owned,
    }
    if data_dir.join(crate::app::LOCKED_FILE).exists() {
        return Ready::Blocked(MANUAL_LOCK);
    }
    match keyring.remembered() {
        Some(r) => Ready::Start(r),
        None => Ready::NoPassword,
    }
}

pub fn run(data_dir: PathBuf) -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            log(&format!("cannot start: {e}"));
            return 1;
        }
    };
    runtime.block_on(serve_forever(data_dir))
}

async fn serve_forever(data_dir: PathBuf) -> i32 {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        log("cannot handle signals");
        return 1;
    };
    if !Keyring::new(&data_dir).secure() {
        log("background access needs the macOS Keychain or the Secret Service (secret-tool)");
        return GIVE_UP;
    }
    let started = Instant::now();
    let mut said = String::new();
    let mut wait = POLL;
    loop {
        if !Store::new(&data_dir).is_ok_and(|s| s.exists()) {
            log("no vault yet. Open VaultOS once to create one.");
            return GIVE_UP;
        }
        let probe = tokio::task::spawn_blocking({
            let d = data_dir.clone();
            move || check(&d)
        });
        let ready = tokio::select! {
            r = probe => match r {
                Ok(r) => r,
                Err(e) => {
                    log(&format!("cannot check the vault: {e}"));
                    return 1;
                }
            },
            _ = term.recv() => return 0,
            _ = int.recv() => return 0,
        };
        let (message, pause) = match ready {
            Ready::Owned => {
                wait = POLL;
                (
                    "another VaultOS process owns the vault; waiting to take over".into(),
                    POLL,
                )
            }
            Ready::Blocked(why) => {
                wait = (wait * 2).min(MAX_WAIT);
                (format!("waiting to unlock: {why}"), wait)
            }
            Ready::NoPassword if started.elapsed() < KEYRING_GRACE => {
                ("waiting for the remembered password".into(), POLL)
            }
            Ready::NoPassword => {
                log(OFF);
                return GIVE_UP;
            }
            Ready::Start(remembered) => {
                said.clear();
                wait = POLL;
                match serve_once(&data_dir, remembered, &mut term, &mut int).await {
                    // Whoever asked (the window) claims the vault next; stand back
                    // long enough for it to.
                    Served::HandedOver => {
                        ("the window took over; standing by".into(), HANDOVER_DELAY)
                    }
                    Served::Blocked(why) => {
                        wait = (wait * 2).min(MAX_WAIT);
                        (format!("waiting to unlock: {why}"), wait)
                    }
                    Served::Relocked => {
                        log("the vault locked; checking again");
                        continue;
                    }
                    Served::Signal => return 0,
                    Served::CannotUnlock(why) => {
                        log(&why);
                        return GIVE_UP;
                    }
                    Served::Failed(e) => {
                        log(&e);
                        ("could not serve; retrying".into(), POLL)
                    }
                }
            }
        };
        if message != said {
            log(&message);
            said = message;
        }
        tokio::select! {
            _ = term.recv() => return 0,
            _ = int.recv() => return 0,
            () = tokio::time::sleep(pause) => {}
        }
    }
}

/// Why the service did not open the vault once it owned it.
enum Refused {
    /// A Lock wrote its block while the keychain was being read.
    Locked,
    /// The vault's own settings no longer remember the password: a stale keychain entry.
    Off,
    Core(Error),
}

/// Unlocks the vault this process now owns, checking again what `check` saw before it did:
/// the manual lock block, and that the vault's encrypted settings still remember the password.
fn open_owned(
    h: &Handle,
    data_dir: &Path,
    remembered: &keyring::Remembered,
) -> Result<(), Refused> {
    if data_dir.join(crate::app::LOCKED_FILE).exists() {
        return Err(Refused::Locked);
    }
    // Only the key the header names: one replaced or removed since it was stored is ignored.
    let key = match h.with_store(|s| s.secret_key_id()).map_err(Refused::Core)? {
        None => None,
        Some(id) => Some(
            remembered
                .secret_key
                .as_ref()
                .and_then(|k| SecretKey::parse(k.expose().trim()).ok())
                .filter(|k| k.id() == id)
                .ok_or(Refused::Core(Error::SecretKeyRequired))?,
        ),
    };
    h.with_store(|s| s.unlock(&remembered.password, key.as_ref()))
        .map_err(Refused::Core)?;
    let on = h
        .with_store(|s| Ok::<_, Error>(crate::settings::remember(s.settings()?)))
        .unwrap_or(false);
    if !on {
        h.with_store(Store::lock);
        let _ = Keyring::new(data_dir).clear(keyring::PASSWORD);
        return Err(Refused::Off);
    }
    Ok(())
}

enum Served {
    Blocked(&'static str),
    HandedOver,
    Relocked,
    Signal,
    CannotUnlock(String),
    Failed(String),
}

async fn serve_once(
    data_dir: &Path,
    remembered: keyring::Remembered,
    term: &mut tokio::signal::unix::Signal,
    int: &mut tokio::signal::unix::Signal,
) -> Served {
    let cfg_dir = data_dir.to_path_buf();
    let cfg = Config {
        data_dir: data_dir.to_path_buf(),
        idle_lock: None,
        wait_for_owner: false,
        sync_repo: None,
        confirm: None,
    };
    let (unlocked_tx, unlocked_rx) = tokio::sync::oneshot::channel();
    let (handle_tx, handle_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(run_embedded(cfg, move |h| {
        let _ = handle_tx.send(h.clone());
        // The key derivation is slow; unlock beside the accept loop, which answers "locked"
        // until it is done.
        let dir = cfg_dir.clone();
        tokio::task::spawn_blocking(move || {
            let r = open_owned(&h, &dir, &remembered);
            if r.is_err() {
                h.shutdown();
            }
            let _ = unlocked_tx.send(r);
        });
    }));
    let Ok(handle) = handle_rx.await else {
        return match server.await {
            Ok(Err(e)) => Served::Failed(e.to_string()),
            _ => Served::Failed("the server stopped".into()),
        };
    };
    let refused = match unlocked_rx.await {
        Ok(Ok(())) => None,
        Ok(Err(Refused::Locked)) => Some(Served::Blocked(MANUAL_LOCK)),
        Ok(Err(Refused::Off)) => Some(Served::CannotUnlock(OFF.to_owned())),
        Ok(Err(Refused::Core(
            Error::Unlock | Error::SecretKeyRequired | Error::SecretKeyFormat(_),
        ))) => Some(Served::CannotUnlock(
            "the remembered password or Secret Key did not open the vault. Unlock in the app to remember the current ones.".to_owned(),
        )),
        Ok(Err(Refused::Core(Error::NeedsUpgrade))) => Some(Served::CannotUnlock(
            "this vault was made by an earlier VaultOS. Open the app to upgrade it.".to_owned(),
        )),
        Ok(Err(Refused::Core(e))) => Some(Served::CannotUnlock(format!("cannot unlock: {e}"))),
        Err(_) => Some(Served::CannotUnlock("the unlock did not finish".to_owned())),
    };
    let mut server = server;
    if let Some(served) = refused {
        handle.shutdown();
        let _ = (&mut server).await;
        return served;
    }
    log("unlocked; serving agents");
    let mut tick = tokio::time::interval(POLL);
    loop {
        tokio::select! {
            r = &mut server => return match r {
                // The server stops when the window asks it to hand over, or when it fails.
                Ok(Ok(())) => Served::HandedOver,
                Ok(Err(e)) => Served::Failed(e.to_string()),
                Err(e) => Served::Failed(e.to_string()),
            },
            _ = term.recv() => break,
            _ = int.recv() => break,
            _ = tick.tick() => {
                // Locked underneath (the vault changed on disk, say a new password): stop,
                // then check again with what the keychain holds now.
                if !handle.is_unlocked() {
                    handle.shutdown();
                    let _ = (&mut server).await;
                    return Served::Relocked;
                }
            }
        }
    }
    handle.shutdown();
    let _ = server.await;
    Served::Signal
}
