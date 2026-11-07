//! Hooks for the desktop UI test (`scripts/test-desktop-ui.mjs`). Built only with the
//! `ui-test` feature, which refuses release builds. The runner passes a script in
//! `VAULTOS_UI_TEST_SCRIPT`; it runs in both windows and drives the flow through `ui_test`.

#[cfg(not(debug_assertions))]
compile_error!("the ui-test feature is for debug builds only");

use crate::app::{lock, App};
use crate::ui;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, OnceLock};
use tauri::{AppHandle, Manager, State};

static SCRIPT: OnceLock<Option<String>> = OnceLock::new();
static PHASE: Mutex<String> = Mutex::new(String::new());

/// The test script, read once. A missing or unreadable file stops the app: the runner would
/// otherwise wait for a report that never comes.
pub fn script() -> Option<&'static str> {
    SCRIPT
        .get_or_init(|| {
            let path = std::env::var_os("VAULTOS_UI_TEST_SCRIPT")?;
            match std::fs::read_to_string(&path) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("ui-test: cannot read the script: {e}");
                    std::process::exit(3);
                }
            }
        })
        .as_deref()
}

/// `--ui-test-remember` (password on stdin) and `--ui-test-forget`: what turning background
/// access on and off does to the keychain, done by this program so that the service test
/// reads an item this program wrote, as it does for the human. Remembering also turns the
/// vault's own setting on when the password opens it. `--ui-test-background-off` (password
/// on stdin) turns only the vault's setting off, leaving the keychain item behind as a
/// failed deletion would.
pub fn keyring_flag(data_dir: &std::path::Path) -> Option<i32> {
    use crate::keyring::{Keyring, PASSWORD, SECRET_KEY};
    let keyring = Keyring::new(data_dir);
    let stdin_password = || {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok()?;
        Some(vaultos_core::SecretString::new(
            line.trim_end_matches(['\r', '\n']).to_owned(),
        ))
    };
    let background = |password: &vaultos_core::SecretString, on: bool| {
        let mut store = vaultos_core::Store::new(data_dir)?;
        store.unlock(password, None)?;
        let mut patch = serde_json::Map::new();
        patch.insert("rememberPassword".into(), json!(on));
        store.update_settings(patch, vaultos_core::model::HUMAN)
    };
    if std::env::args().any(|a| a == "--ui-test-remember") {
        let Some(password) = stdin_password() else {
            return Some(1);
        };
        let _ = background(&password, true);
        return Some(match keyring.set(PASSWORD, &password) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("ui-test: {e}");
                1
            }
        });
    }
    if std::env::args().any(|a| a == "--ui-test-background-off") {
        let Some(password) = stdin_password() else {
            return Some(1);
        };
        return Some(match background(&password, false) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("ui-test: {e}");
                1
            }
        });
    }
    if std::env::args().any(|a| a == "--ui-test-forget") {
        let _ = keyring.clear(PASSWORD);
        let _ = keyring.clear(SECRET_KEY);
        return Some(0);
    }
    None
}

#[tauri::command]
pub async fn ui_test(
    app: AppHandle,
    state: State<'_, Arc<App>>,
    action: String,
    arg: Value,
) -> Result<Value, String> {
    match action.as_str() {
        "phase" => Ok(json!(*lock(&PHASE))),
        "setPhase" => {
            *lock(&PHASE) = arg.as_str().unwrap_or_default().to_owned();
            Ok(Value::Null)
        }
        "pid" => Ok(json!(std::process::id())),
        "ownerLock" => Ok(std::fs::read_to_string(state.data_dir.join("owner.lock"))
            .map_or(Value::Null, Value::String)),
        "visible" => Ok(json!(app
            .webview_windows()
            .into_iter()
            .filter(|(_, w)| w.is_visible().unwrap_or(false))
            .map(|(label, _)| label)
            .collect::<Vec<_>>())),
        "showQuick" => {
            ui::show_quick(&app);
            Ok(Value::Null)
        }
        "closeMain" => {
            if let Some(w) = app.get_webview_window("main") {
                w.close().map_err(|e| e.to_string())?;
            }
            Ok(Value::Null)
        }
        // What the Dock icon does on macOS.
        "reopen" => {
            ui::show_main(&app, None);
            Ok(Value::Null)
        }
        "willSleep" => {
            #[cfg(target_os = "macos")]
            crate::platform::mac::post_will_sleep();
            Ok(json!(cfg!(target_os = "macos")))
        }
        "log" => {
            eprintln!("ui-test: {}", arg.as_str().unwrap_or_default());
            Ok(Value::Null)
        }
        "finish" => {
            let ok = arg["ok"] == json!(true);
            eprintln!("ui-test: {}", arg["report"].as_str().unwrap_or_default());
            state.shut_down().await;
            std::process::exit(if ok { 0 } else { 1 });
        }
        _ => Err(format!("ui-test: unknown action {action}")),
    }
}
