//! In-app updates on macOS: Tauri's updater reads `latest.json` from the `updates` release on
//! GitHub, and installs only an archive signed by the update key whose public half is in
//! `tauri.conf.json`, for the version the feed announces (`requireSignedVersion`). Installing
//! replaces this VaultOS.app and restarts it locked. Elsewhere it reports that updates are not
//! offered, and the Linux tarball is still updated by hand.

use serde_json::{json, Value};
use tauri::AppHandle;

/// Waits this long after launch before the first automatic check, then checks once a day.
#[cfg(target_os = "macos")]
const FIRST_CHECK: std::time::Duration = std::time::Duration::from_secs(120);
#[cfg(target_os = "macos")]
const EVERY: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

pub const SUPPORTED: bool = cfg!(target_os = "macos");

pub fn current_version(app: &AppHandle) -> String {
    app.package_info().version.to_string()
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use crate::app::{lock, App};
    use crate::ui;
    use std::sync::{Arc, Mutex};
    use tauri::Manager;
    use tauri_plugin_global_shortcut::GlobalShortcutExt;
    use tauri_plugin_updater::{Update, UpdaterExt};

    /// The update the last check found, so Install installs exactly what was shown, and the
    /// version already announced by a notification.
    #[derive(Default)]
    pub struct Updates {
        found: Mutex<Option<Update>>,
        announced: Mutex<Option<String>>,
        installing: tokio::sync::Mutex<()>,
    }

    impl std::fmt::Debug for Updates {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Updates").finish_non_exhaustive()
        }
    }

    pub fn plugin() -> tauri::plugin::TauriPlugin<tauri::Wry, tauri_plugin_updater::Config> {
        tauri_plugin_updater::Builder::new().build()
    }

    fn updates(app: &AppHandle) -> &Updates {
        app.state::<Updates>().inner()
    }

    fn describe(u: &Update) -> Value {
        json!({
            "version": u.version,
            "notes": u.body,
            "date": u.date.map(|d| d.to_string()),
        })
    }

    fn friendly(e: &tauri_plugin_updater::Error) -> String {
        use tauri_plugin_updater::Error as E;
        match e {
            E::ReleaseNotFound | E::Network(_) | E::Reqwest(_) => {
                "VaultOS could not reach the update feed. Check your connection and try again."
                    .into()
            }
            E::Minisign(_)
            | E::SignatureUtf8(_)
            | E::Base64(_)
            | E::SignedVersionMismatch { .. }
            | E::MissingSignedVersion => {
                "The update was not signed by VaultOS for this version, so it was not installed."
                    .into()
            }
            E::TargetNotFound(_) | E::TargetsNotFound(_) => {
                "The latest release has no update for this Mac yet.".into()
            }
            other => format!("Update failed: {other}"),
        }
    }

    pub async fn check(app: &AppHandle) -> Result<Value, String> {
        let updater = app.updater().map_err(|e| friendly(&e))?;
        let found = updater.check().await.map_err(|e| friendly(&e))?;
        let current = current_version(app);
        let reply = match &found {
            Some(u) => {
                let mut v = describe(u);
                v["available"] = json!(true);
                v["current"] = json!(current);
                v
            }
            None => json!({ "available": false, "current": current }),
        };
        *lock(&updates(app).found) = found;
        Ok(reply)
    }

    /// Downloads, verifies and installs the update the last check found, then quits the way
    /// Quit does (lock, release the vault) and starts the new version.
    pub async fn install(app: &AppHandle, state: &Arc<App>) -> Result<Value, String> {
        let u = updates(app);
        let Ok(_one) = u.installing.try_lock() else {
            return Err("An update is already being installed".into());
        };
        let update = lock(&u.found).clone().ok_or("Check for updates first")?;
        update
            .download_and_install(|_, _| {}, || {})
            .await
            .map_err(|e| friendly(&e))?;
        let handle = app.clone();
        let s = state.clone();
        tauri::async_runtime::spawn(async move {
            // Let the window show that it is restarting before the process goes.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            s.shut_down().await;
            let _ = handle.global_shortcut().unregister_all();
            handle.restart();
        });
        Ok(json!({ "ok": true, "version": update.version }))
    }

    /// The automatic check: once soon after launch, then daily, while the preference is on. A
    /// new version is announced once; installing waits for the human in Settings.
    pub fn watch(app: AppHandle) {
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(FIRST_CHECK).await;
            loop {
                let on = lock(&app.state::<Arc<App>>().prefs).check_updates;
                if on {
                    if let Ok(v) = check(&app).await {
                        if let Some(version) = v["version"].as_str() {
                            let mut announced = lock(&updates(&app).announced);
                            if announced.as_deref() != Some(version) {
                                *announced = Some(version.to_owned());
                                ui::notify(
                                    &app,
                                    "A VaultOS update is available",
                                    &format!(
                                        "Version {version} is ready. Open Settings to install it."
                                    ),
                                );
                            }
                        }
                    }
                }
                tokio::time::sleep(EVERY).await;
            }
        });
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;
    use crate::app::App;
    use std::sync::Arc;

    #[derive(Debug, Default)]
    pub struct Updates;

    const UNSUPPORTED: &str = "In-app updates are available on macOS. Download new versions from the GitHub releases page.";

    pub async fn check(_: &AppHandle) -> Result<Value, String> {
        Err(UNSUPPORTED.into())
    }

    pub async fn install(_: &AppHandle, _: &Arc<App>) -> Result<Value, String> {
        Err(UNSUPPORTED.into())
    }

    pub fn watch(_: AppHandle) {}
}

pub use imp::*;
