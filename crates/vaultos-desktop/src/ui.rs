//! Windows, the menu bar item, the app menu, the Quick Access shortcut, notifications and the
//! lock triggers (idle, screen lock, sleep).

use crate::app::{lock, App, IDLE_LOCK};
use crate::{login, platform};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tauri::image::Image;
use tauri::menu::{Menu, MenuBuilder, MenuItemBuilder, PredefinedMenuItem, SubmenuBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder, Wry};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut};

const TRAY: &str = "main";
const QUICK: &str = "quick";
const MAIN: &str = "main";

fn state(app: &AppHandle) -> Arc<App> {
    app.state::<Arc<App>>().inner().clone()
}

/// Only the app's own pages load; links and redirects never navigate a window.
fn app_url(url: &tauri::Url) -> bool {
    (url.scheme() == "tauri" && url.host_str() == Some("localhost"))
        || (url.scheme() == "http" && url.host_str() == Some("tauri.localhost"))
}

pub fn main_window(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    if let Some(w) = app.get_webview_window(MAIN) {
        return Ok(w);
    }
    let builder = WebviewWindowBuilder::new(app, MAIN, WebviewUrl::App("index.html".into()))
        .title("VaultOS")
        .inner_size(480.0, 740.0)
        .min_inner_size(380.0, 500.0)
        .background_color(tauri::window::Color(13, 13, 13, 255))
        .on_navigation(app_url)
        .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny);
    #[cfg(target_os = "macos")]
    let builder = builder
        .title_bar_style(tauri::TitleBarStyle::Overlay)
        .hidden_title(true)
        .traffic_light_position(tauri::LogicalPosition::new(14.0, 22.0));
    #[cfg(not(target_os = "macos"))]
    let builder = builder.menu(app_menu(app)?);
    #[cfg(feature = "ui-test")]
    let builder = match crate::uitest::script() {
        Some(s) => builder
            .initialization_script(s)
            .background_throttling(tauri::utils::config::BackgroundThrottlingPolicy::Disabled),
        None => builder,
    };
    let w = builder.build()?;
    let handle = app.clone();
    w.on_window_event(move |e| {
        if let tauri::WindowEvent::Destroyed = e {
            closed_main(&handle);
        }
    });
    Ok(w)
}

/// Closing the window always locks the vault. With the menu bar item on, the app then waits
/// there, locked, instead of quitting.
fn closed_main(app: &AppHandle) {
    let s = state(app);
    if s.quitting.load(Ordering::SeqCst) {
        return;
    }
    s.lock(false);
    if keep_running(app) {
        #[cfg(target_os = "macos")]
        let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
    } else {
        quit(app);
    }
}

pub fn keep_running(app: &AppHandle) -> bool {
    let s = state(app);
    !s.quitting.load(Ordering::SeqCst) && lock(&s.prefs).menu_bar && app.tray_by_id(TRAY).is_some()
}

pub fn has_tray(app: &App) -> bool {
    app.tauri
        .get()
        .is_some_and(|h| h.tray_by_id(TRAY).is_some())
}

/// Opens (or creates) the main window and asks it to go somewhere: the project holding an
/// item, Settings or the search box. A locked window keeps the request until unlock.
pub fn show_main(app: &AppHandle, command: Option<Value>) {
    let s = state(app);
    let has_command = command.is_some();
    if command.is_some() {
        *lock(&s.pending_command) = command;
    }
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
    if let Ok(w) = main_window(app) {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
    if has_command {
        s.emit(MAIN, "vault:command");
    }
}

fn quick_window(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    if let Some(w) = app.get_webview_window(QUICK) {
        return Ok(w);
    }
    let w = WebviewWindowBuilder::new(app, QUICK, WebviewUrl::App("quick.html".into()))
        .title("Quick Access")
        .inner_size(640.0, 420.0)
        .visible(false)
        .decorations(false)
        .resizable(false)
        .minimizable(false)
        .maximizable(false)
        .skip_taskbar(true)
        .always_on_top(true)
        .visible_on_all_workspaces(true)
        .transparent(true)
        .shadow(true)
        .on_navigation(app_url)
        .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny);
    #[cfg(feature = "ui-test")]
    let w = match crate::uitest::script() {
        Some(s) => w
            .initialization_script(s)
            .background_throttling(tauri::utils::config::BackgroundThrottlingPolicy::Disabled),
        None => w,
    };
    let w = w.build()?;
    let handle = app.clone();
    w.on_window_event(move |e| {
        if let tauri::WindowEvent::Focused(false) = e {
            // The Touch ID sheet takes focus; the panel stays while it is up.
            if state(&handle).prompting.load(Ordering::SeqCst) == 0 {
                hide_quick(&handle, true);
            }
        }
    });
    Ok(w)
}

/// Upper third of the display under the pointer, like Spotlight.
fn place_quick(app: &AppHandle, q: &WebviewWindow) {
    let Ok(cursor) = app.cursor_position() else {
        return;
    };
    let Ok(Some(monitor)) = app.monitor_from_point(cursor.x, cursor.y) else {
        return;
    };
    let (Ok(size), pos, area) = (q.outer_size(), monitor.position(), monitor.size()) else {
        return;
    };
    let x = pos.x + (i64::from(area.width) - i64::from(size.width)).max(0) as i32 / 2;
    let y = pos.y + (f64::from(area.height) * 0.2) as i32;
    let _ = q.set_position(tauri::PhysicalPosition::new(x, y));
}

pub fn show_quick(app: &AppHandle) {
    let Ok(q) = quick_window(app) else { return };
    place_quick(app, &q);
    state(app).emit(QUICK, "quick:show");
    let _ = q.show();
    let _ = q.set_focus();
}

pub fn hide_quick(app: &AppHandle, return_focus: bool) {
    let Some(q) = app.get_webview_window(QUICK) else {
        return;
    };
    if !q.is_visible().unwrap_or(false) {
        return;
    }
    let _ = q.hide();
    // Give focus back to the app the human was in, unless VaultOS has its own window open.
    #[cfg(target_os = "macos")]
    if return_focus
        && !app
            .get_webview_window(MAIN)
            .is_some_and(|w| w.is_visible().unwrap_or(false))
    {
        let _ = app.hide();
    }
    #[cfg(not(target_os = "macos"))]
    let _ = return_focus;
}

pub fn toggle_quick(app: &AppHandle) {
    let visible = app
        .get_webview_window(QUICK)
        .is_some_and(|q| q.is_visible().unwrap_or(false));
    if visible {
        hide_quick(app, true);
    } else {
        show_quick(app);
    }
}

pub fn refocus_quick(app: &AppHandle) {
    if let Some(q) = app.get_webview_window(QUICK) {
        if q.is_visible().unwrap_or(false) {
            let _ = q.set_focus();
        }
    }
}

/// Lock also hides Quick Access and tells it to forget its results.
pub fn lock_quick(app: &AppHandle) {
    state(app).emit(QUICK, "quick:locked");
    hide_quick(app, true);
}

fn tray_image(attention: bool) -> Option<Image<'static>> {
    #[cfg(target_os = "macos")]
    let bytes: &[u8] = if attention {
        include_bytes!("../../../build/tray/trayAttentionTemplate@2x.png")
    } else {
        include_bytes!("../../../build/tray/trayTemplate@2x.png")
    };
    #[cfg(not(target_os = "macos"))]
    let bytes: &[u8] = if attention {
        include_bytes!("../../../build/tray/trayAttentionLight.png")
    } else {
        include_bytes!("../../../build/tray/trayLight.png")
    };
    Image::from_bytes(bytes).ok()
}

fn sync_line(status: &Value) -> Option<String> {
    if status["enabled"] != json!(true) {
        return None;
    }
    if status["halted"] == json!(true) {
        return Some("Sync stopped: needs your attention".into());
    }
    if status["running"] == json!(true) {
        return Some("Syncing…".into());
    }
    Some(match status["lastSyncAt"].as_str() {
        Some(t) => format!("Synced {}", t.get(11..16).unwrap_or(t)),
        None => "Sync on".into(),
    })
}

fn notify(app: &AppHandle, title: &str, body: &str) {
    use tauri_plugin_notification::NotificationExt;
    let _ = app.notification().builder().title(title).body(body).show();
}

fn tray_menu(
    app: &AppHandle,
    unlocked: bool,
    human: bool,
    pending: usize,
    sync: Option<String>,
) -> tauri::Result<Menu<Wry>> {
    let shortcut = lock(&state(app).prefs).shortcut.clone();
    let status = if !unlocked {
        "Locked"
    } else if human {
        "Unlocked"
    } else {
        "Serving agents · window locked"
    };
    let mut m =
        MenuBuilder::new(app).item(&MenuItemBuilder::new(status).enabled(false).build(app)?);
    if pending > 0 {
        let s = if pending == 1 { "" } else { "s" };
        m = m.item(
            &MenuItemBuilder::with_id("pending", format!("{pending} key{s} awaiting approval…"))
                .build(app)?,
        );
    }
    if let Some(line) = sync {
        m = m.item(&MenuItemBuilder::new(line).enabled(false).build(app)?);
    }
    let mut quick = MenuItemBuilder::with_id("quick", "Quick Access…");
    if !shortcut.is_empty() {
        quick = quick.accelerator(shortcut);
    }
    m.separator()
        .item(&quick.build(app)?)
        .item(&MenuItemBuilder::with_id("open", "Open VaultOS").build(app)?)
        .item(
            &MenuItemBuilder::with_id("lock", "Lock Now")
                .enabled(unlocked)
                .build(app)?,
        )
        .separator()
        .item(&MenuItemBuilder::with_id("settings", "Settings…").build(app)?)
        .separator()
        .item(&MenuItemBuilder::with_id("quit", "Quit VaultOS").build(app)?)
        .build()
}

pub fn refresh_tray(app: &AppHandle) {
    let Some(tray) = app.tray_by_id(TRAY) else {
        return;
    };
    let s = state(app);
    let unlocked = s.store_unlocked();
    let pending = if unlocked {
        s.with_store(|st| st.pending_approvals())
            .map_or(0, |p| p.len())
    } else {
        0
    };
    let sync = s.sync_status().unwrap_or(Value::Null);
    let attention = pending > 0 || sync["halted"] == json!(true);
    let _ = tray.set_icon(tray_image(attention));
    #[cfg(target_os = "macos")]
    let _ = tray.set_icon_as_template(true);
    let tip = match (unlocked, pending) {
        (false, _) => "VaultOS: locked".to_owned(),
        (true, 0) => "VaultOS: unlocked".to_owned(),
        (true, n) => format!("VaultOS: {n} awaiting approval"),
    };
    let _ = tray.set_tooltip(Some(tip));
    let line = if unlocked { sync_line(&sync) } else { None };
    if let Ok(menu) = tray_menu(app, unlocked, s.human_unlocked(), pending, line) {
        let _ = tray.set_menu(Some(menu));
    }
    // Notifications name no keys: they can show on the lock screen.
    let last = s.last_pending.swap(pending, Ordering::SeqCst);
    if lock(&s.prefs).notify_approvals && pending > last {
        let body = if pending == 1 {
            "1 key is held back from .env until you approve.".to_owned()
        } else {
            format!("{pending} keys are held back from .env until you approve.")
        };
        notify(app, "Agent key awaiting approval", &body);
    }
}

pub fn notify_expiring(app: &AppHandle) {
    let s = state(app);
    if !lock(&s.prefs).notify_expiry {
        return;
    }
    let today = vaultos_core::model::now_iso()
        .chars()
        .take(10)
        .collect::<String>();
    {
        let mut day = lock(&s.expiry_day);
        if *day == today {
            return;
        }
        *day = today;
    }
    let count = s
        .with_store(|st| {
            let mut n = 0;
            for p in st.list_projects()? {
                n += st
                    .list_items(&p.name)?
                    .iter()
                    .filter(|i| !i.expires_at.is_empty() && i.days_left.is_some_and(|d| d <= 7))
                    .count();
            }
            Ok(n)
        })
        .unwrap_or(0);
    if count > 0 {
        let body = if count == 1 {
            "1 key expires within 7 days or already expired.".to_owned()
        } else {
            format!("{count} keys expire within 7 days or already expired.")
        };
        notify(app, "Keys expiring soon", &body);
    }
}

fn apply_shortcut(app: &AppHandle) {
    let s = state(app);
    let gs = app.global_shortcut();
    let _ = gs.unregister_all();
    let shortcut = lock(&s.prefs).shortcut.clone();
    let mut error = String::new();
    if !shortcut.is_empty() {
        match shortcut.parse::<Shortcut>() {
            Err(_) => error = "This shortcut can't be used. Choose a different one.".into(),
            Ok(sc) => {
                if gs.register(sc).is_err() {
                    error = "Another app is using this shortcut. Choose a different one.".into();
                }
            }
        }
    }
    *lock(&s.shortcut_error) = error;
}

fn apply_tray(app: &AppHandle) {
    let menu_bar = lock(&state(app).prefs).menu_bar;
    if !menu_bar {
        let _ = app.remove_tray_by_id(TRAY);
        return;
    }
    if app.tray_by_id(TRAY).is_none() {
        let mut b = TrayIconBuilder::with_id(TRAY).tooltip("VaultOS");
        if let Some(img) = tray_image(false) {
            b = b.icon(img);
        }
        #[cfg(target_os = "macos")]
        {
            b = b.icon_as_template(true);
        }
        if b.build(app).is_err() {
            return;
        }
    }
    refresh_tray(app);
}

pub fn apply_login_item(app: &App) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let command = vec![exe.to_string_lossy().into_owned(), "--hidden".into()];
    let custom = std::env::var_os("VAULTOS_DATA_DIR").is_some();
    let on = lock(&app.prefs).launch_at_login;
    login::set_enabled(on, &command, custom.then_some(app.data_dir.as_path()))
}

pub fn apply_prefs(app: &AppHandle) {
    apply_shortcut(app);
    apply_tray(app);
    #[cfg(target_os = "macos")]
    if let Ok(menu) = app_menu(app) {
        let _ = app.set_menu(menu);
    }
}

pub fn app_menu(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    let shortcut = lock(&state(app).prefs).shortcut.clone();
    let settings = MenuItemBuilder::with_id("settings", "Settings…")
        .accelerator("CmdOrCtrl+,")
        .build(app)?;
    let lock_item = MenuItemBuilder::with_id("lock", "Lock VaultOS")
        .accelerator("CmdOrCtrl+L")
        .build(app)?;
    let mut quick = MenuItemBuilder::with_id("quick", "Quick Access…");
    if !shortcut.is_empty() {
        quick = quick.accelerator(shortcut);
    }
    let quick = quick.build(app)?;
    let find = MenuItemBuilder::with_id("search", "Search…")
        .accelerator("CmdOrCtrl+F")
        .build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit VaultOS")
        .accelerator("CmdOrCtrl+Q")
        .build(app)?;
    let edit = SubmenuBuilder::new(app, "Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;
    let help = SubmenuBuilder::new(app, "Help")
        .item(&MenuItemBuilder::with_id("github", "VaultOS on GitHub").build(app)?)
        .item(&MenuItemBuilder::with_id("security", "Security Model").build(app)?)
        .build()?;
    let view = SubmenuBuilder::new(app, "View").item(&find).build()?;
    #[cfg(target_os = "macos")]
    {
        let main = SubmenuBuilder::new(app, "VaultOS")
            .about(None)
            .separator()
            .item(&settings)
            .item(&lock_item)
            .separator()
            .services()
            .separator()
            .hide()
            .hide_others()
            .show_all()
            .separator()
            .item(&quit)
            .build()?;
        let file = SubmenuBuilder::new(app, "File")
            .item(&quick)
            .separator()
            .item(&PredefinedMenuItem::close_window(app, None)?)
            .build()?;
        let window = SubmenuBuilder::new(app, "Window")
            .minimize()
            .maximize()
            .build()?;
        MenuBuilder::new(app)
            .items(&[&main, &file, &edit, &view, &window, &help])
            .build()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let file = SubmenuBuilder::new(app, "File")
            .item(&quick)
            .item(&settings)
            .item(&lock_item)
            .separator()
            .item(&quit)
            .build()?;
        MenuBuilder::new(app)
            .items(&[&file, &edit, &view, &help])
            .build()
    }
}

pub fn menu_event(app: &AppHandle, id: &str) {
    match id {
        "quick" => show_quick(app),
        "open" => show_main(app, None),
        "lock" => state(app).lock(true),
        "settings" => show_main(app, Some(json!({ "name": "settings" }))),
        "search" => show_main(app, Some(json!({ "name": "search" }))),
        "pending" => show_main(app, Some(json!({ "name": "projects" }))),
        "github" => {
            let _ = open_external("https://github.com/rohit3a/vaultos#readme");
        }
        "security" => {
            let _ = open_external("https://github.com/rohit3a/vaultos/blob/main/SECURITY.md");
        }
        "quit" => quit(app),
        _ => {}
    }
}

/// Opens an http(s) address in the default browser.
pub fn open_external(url: &str) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Only web addresses can be opened".into());
    }
    let opener = if cfg!(target_os = "macos") {
        "/usr/bin/open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener)
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(|_| "The browser could not be opened".into())
}

pub async fn choose_folder(app: &AppHandle) -> Result<Value, String> {
    use tauri_plugin_dialog::DialogExt;
    let dialog = app.dialog().file();
    let picked = crate::app::blocking(move || dialog.blocking_pick_folder()).await?;
    let Some(path) = picked.and_then(|p| p.into_path().ok()) else {
        return Ok(Value::Null);
    };
    let real = std::fs::canonicalize(path).map_err(|e| e.to_string())?;
    Ok(json!(real.to_string_lossy()))
}

/// Quits after the server has released the vault.
pub fn quit(app: &AppHandle) {
    let s = state(app);
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        s.shut_down().await;
        let _ = handle.global_shortcut().unregister_all();
        handle.exit(0);
    });
}

/// Every two seconds: the idle timer, screen lock, sleep (the wall clock jumps past the
/// monotonic one), a server stopped or a vault locked elsewhere, and the menu bar.
pub fn watch(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let s = state(&app);
        let mut was_locked = false;
        let (mut wall, mut mono) = (SystemTime::now(), Instant::now());
        let mut ticks: u64 = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            ticks += 1;
            let (now_wall, now_mono) = (SystemTime::now(), Instant::now());
            let wall_gap = now_wall.duration_since(wall).unwrap_or_default();
            let slept = wall_gap > now_mono.duration_since(mono) + Duration::from_secs(20);
            (wall, mono) = (now_wall, now_mono);
            if slept {
                s.auto_lock();
            }
            if s.human_unlocked() && s.idle_for() >= IDLE_LOCK {
                s.auto_lock();
            }
            // The UI test runs whether or not the screen is locked.
            let screen_poll =
                !cfg!(feature = "ui-test") && (cfg!(target_os = "macos") || ticks % 2 == 0);
            if screen_poll {
                let locked = blocking_screen_locked().await;
                if locked && !was_locked {
                    s.auto_lock();
                }
                was_locked = locked;
            }
            s.check_server();
            if ticks % 15 == 0 {
                refresh_tray(&app);
            }
        }
    });
}

async fn blocking_screen_locked() -> bool {
    crate::app::blocking(platform::screen_locked)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}
