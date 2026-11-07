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
