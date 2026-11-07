//! VaultOS desktop: a Tauri v2 shell over the Rust core. It reuses the HTML/JS renderer and
//! serves the agent API in-process while the vault is unlocked. See `docs/ARCHITECTURE.md`.

mod app;
mod commands;
mod export;
mod keyring;
mod login;
mod platform;
mod prefs;
mod search;
mod settings;
mod ui;
#[cfg(feature = "ui-test")]
mod uitest;

use app::App;
use std::sync::Arc;
use tauri::{Manager, RunEvent};
use tauri_plugin_global_shortcut::ShortcutState;

fn data_dir() -> Result<std::path::PathBuf, String> {
    match std::env::var_os("VAULTOS_DATA_DIR") {
        Some(d) => {
            let d = std::path::PathBuf::from(d);
            if d.is_absolute() {
                Ok(d)
            } else {
                Err("VAULTOS_DATA_DIR must be an absolute path".into())
            }
        }
        None => vaultos_core::paths::default_data_dir().map_err(|e| e.to_string()),
    }
}

fn main() {
    vaultos_core::hardening::harden_process();
    let dir = match data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("VaultOS: {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = vaultos_core::fs_safe::private_dir(&dir) {
        eprintln!("VaultOS: {e}");
        std::process::exit(2);
    }
    let hidden = std::env::args().any(|a| a == "--hidden");
    let state = Arc::new(App::new(dir));
    let shortcut = tauri_plugin_global_shortcut::Builder::new()
        .with_handler(|app, _, event| {
            if event.state() == ShortcutState::Pressed {
                ui::toggle_quick(app);
            }
        })
        .build();
    let mut builder = tauri::Builder::default()
        .plugin(shortcut)
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init());
    // One app per vault folder. A custom VAULTOS_DATA_DIR (tests, a second vault) runs apart.
    if std::env::var_os("VAULTOS_DATA_DIR").is_none() {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _, _| {
            ui::show_main(app, None);
        }));
    }
    #[cfg(not(feature = "ui-test"))]
    let builder =
        builder.invoke_handler(tauri::generate_handler![commands::vault, commands::quick]);
    #[cfg(feature = "ui-test")]
    let builder = builder.invoke_handler(tauri::generate_handler![
        commands::vault,
        commands::quick,
        uitest::ui_test
    ]);
    let result = builder
        .manage(state.clone())
        .on_menu_event(|app, event| ui::menu_event(app, event.id().as_ref()))
        .setup(move |app| {
            let _ = state.tauri.set(app.handle().clone());
            ui::apply_prefs(app.handle());
            // Rewrites the login item if the app moved, or removes one the preferences no
            // longer ask for.
            let _ = ui::apply_login_item(&state);
            if hidden && ui::keep_running(app.handle()) {
                #[cfg(target_os = "macos")]
                app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            } else {
                ui::main_window(app.handle())?;
            }
            ui::watch(app.handle().clone());
            signals(app.handle().clone());
            Ok(())
        })
        .build(tauri::generate_context!());
    let app = match result {
        Ok(a) => a,
        Err(e) => {
            eprintln!("VaultOS could not start: {e}");
            std::process::exit(1);
        }
    };
    app.run(|handle, event| match event {
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => ui::show_main(handle, None),
        RunEvent::ExitRequested {
            code: None, api, ..
        } if ui::keep_running(handle) => {
            api.prevent_exit();
        }
        RunEvent::Exit => {
            // Last chance: lock and let the server release the vault.
            let s = handle.state::<Arc<App>>().inner().clone();
            tauri::async_runtime::block_on(s.shut_down());
        }
        _ => {}
    });
}

/// SIGTERM, SIGINT and SIGHUP quit cleanly: lock, release the vault, exit.
fn signals(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
            signal(SignalKind::hangup()),
        ) else {
            return;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
            _ = hup.recv() => {}
        }
        ui::quit(&app);
    });
}
