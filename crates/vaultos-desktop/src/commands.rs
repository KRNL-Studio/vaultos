//! The window's calls, on the pages' `vault:` and `quick:` channels. A call is
//! accepted only from its own window at its own page, so Quick Access cannot reach settings,
//! agents or sync. Every non-public call needs the human's unlock and resets the idle timer.

use crate::app::{blocking, lock, App};
use crate::{export, items, keyring, login, platform, prefs, search, settings, ui};
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::{AppHandle, Manager, State, WebviewWindow};
use vaultos_core::agents::{Wildcards, ALL_SCOPES};
use vaultos_core::model::HUMAN;
use vaultos_core::validate::FieldInput;
use vaultos_core::{Error, Fields, SecretString, Store};
use vaultos_sync::Sync;

const PROVIDERS: &str = include_str!("providers.json");

type Reply = Result<Value, String>;

fn from_page(window: &WebviewWindow, label: &str, page: &str) -> bool {
    window.label() == label
        && window.url().is_ok_and(|u| {
            let local = (u.scheme() == "tauri" && u.host_str() == Some("localhost"))
                || (u.scheme() == "http" && u.host_str() == Some("tauri.localhost"));
            // Tauri serves index.html at the root (tauri://localhost has an empty path).
            let path = match u.path() {
                "" | "/" => "/index.html",
                p => p,
            };
            local && path == page
        })
}

struct Args(Vec<Value>);

impl Args {
    fn get(&self, i: usize) -> &Value {
        self.0.get(i).unwrap_or(&Value::Null)
    }

    fn str(&self, i: usize, what: &str) -> Result<String, String> {
        self.get(i)
            .as_str()
            .map(str::to_owned)
            .ok_or(format!("Invalid {what}"))
    }

    fn opt_str(&self, i: usize) -> Option<String> {
        self.get(i).as_str().map(str::to_owned)
    }

    fn bool(&self, i: usize) -> bool {
        self.get(i) == &json!(true)
    }

    fn strings(&self, i: usize, what: &str) -> Result<Vec<String>, String> {
        match self.get(i) {
            Value::Null => Ok(Vec::new()),
            Value::Array(a) => a
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or(format!("Invalid {what}"))
                })
                .collect(),
            _ => Err(format!("Invalid {what}")),
        }
    }

    fn wildcards(&self, i: usize) -> Wildcards {
        let w = self.get(i);
        Wildcards {
            all_projects: w["allProjects"] == json!(true),
            any_root: w["anyRoot"] == json!(true),
        }
    }
}

#[tauri::command]
pub async fn vault(
    window: WebviewWindow,
    state: State<'_, Arc<App>>,
    channel: String,
    args: Vec<Value>,
) -> Reply {
    if !from_page(&window, "main", "/index.html") {
        return Err("Untrusted IPC sender".into());
    }
    let app = state.inner().clone();
    let handle = window.app_handle().clone();
    let a = Args(args);
    match channel.as_str() {
        "state" => return Ok(app.state()),
        "providers" => return serde_json::from_str(PROVIDERS).map_err(|e| e.to_string()),
        "init" => return app.create(a.opt_str(0)).await,
        "unlock" => return Ok(app.unlock_password(a.opt_str(0), a.opt_str(1)).await),
        "unlockTouchId" => return Ok(app.unlock_touch_id().await),
        "upgrade" => return Ok(app.upgrade(a.opt_str(0)).await),
        "takeCommand" => return Ok(lock(&app.pending_command).take().unwrap_or(Value::Null)),
        "quit" => {
            ui::quit(&handle);
            return Ok(json!({ "ok": true }));
        }
        _ => {}
    }
    unlocked(&app)?;
    let r = main_call(&app, &handle, &channel, &a).await;
    if r.is_ok() && changes(&channel) {
        app.changed();
    }
    r
}

/// Calls that change the vault: autosync delivers them and the menu bar recounts.
fn changes(channel: &str) -> bool {
    !matches!(
        channel,
        "projects"
            | "secrets"
            | "reveal"
            | "copy"
            | "search"
            | "getSettings"
            | "getDesktopPrefs"
            | "agents"
            | "allScopes"
            | "pending"
            | "history"
            | "chooseFolder"
            | "syncStatus"
            | "syncIdentity"
            | "confirmHuman"
            | "trash"
            | "generate"
            | "generateSshKey"
            | "strength"
            | "otp"
            | "copyOtp"
            | "saveAttachment"
            | "itemHistory"
            | "watchtower"
            | "breachCheck"
            | "scanFolder"
            | "saveLeakIndex"
    )
}

fn unlocked(app: &App) -> Result<(), String> {
    if !app.human_unlocked() {
        return Err("Vault is locked".into());
    }
    app.touch();
    // Picks up a save another process made (the CLI, another device's sync).
    match app.with_store(|s| s.reload_if_changed()) {
        Ok(_) => Ok(()),
        Err(e) if e == Error::Busy.to_string() => Ok(()),
        Err(e) => Err(e),
    }
}

/// Runs a store call off the async threads.
async fn store<R: Send + 'static>(
    app: &Arc<App>,
    f: impl FnOnce(&mut Store) -> Result<R, Error> + Send + 'static,
) -> Result<R, String> {
    let me = app.clone();
    blocking(move || me.with_store(f)).await?
}

fn item_fields(v: &Value) -> Result<Fields, String> {
    let o = v.as_object().ok_or("Invalid key")?;
    let text = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_owned);
    let secret = |k: &str| text(k).map(SecretString::new);
    Ok(Fields {
        key: text("key").ok_or("Invalid key name")?,
        value: secret("value"),
        password: secret("password"),
        note: text("note"),
        username: text("username"),
        email: text("email"),
        url: text("url"),
        provider: text("provider"),
        permission: text("permission"),
        expires_at: text("expiresAt"),
        kind: text("kind"),
        tags: match o.get("tags") {
            None | Some(Value::Null) => None,
            Some(Value::Array(a)) => Some(
                a.iter()
                    .map(|t| t.as_str().map(str::to_owned).ok_or("Invalid tag"))
                    .collect::<Result<_, _>>()?,
            ),
            Some(_) => return Err("Invalid tags".into()),
        },
        favorite: o.get("favorite").and_then(Value::as_bool),
        archived: o.get("archived").and_then(Value::as_bool),
        fields: match o.get("fields") {
            None | Some(Value::Null) => None,
            Some(Value::Array(a)) => Some(a.iter().map(field_input).collect::<Result<_, _>>()?),
            Some(_) => return Err("Invalid fields".into()),
        },
    })
}

fn field_input(v: &Value) -> Result<FieldInput, String> {
    let o = v.as_object().ok_or("Invalid field")?;
    let text = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    Ok(FieldInput {
        id: text("id"),
        section: text("section"),
        label: text("label"),
        kind: text("kind"),
        value: match o.get("value") {
            None | Some(Value::Null) => None,
            Some(Value::String(v)) => Some(SecretString::new(v.as_str())),
            Some(_) => return Err("Invalid field value".into()),
        },
    })
}

fn revealed_json(r: &vaultos_core::store::Revealed) -> Value {
    json!({
        "key": r.key,
        "value": r.value.expose(),
        "password": r.password.expose(),
        "provider": r.provider,
        "username": r.username,
        "email": r.email,
        "url": r.url,
        "fields": r.fields.iter().map(|(id, v)| json!({ "id": id, "value": v.expose() })).collect::<Vec<_>>(),
    })
}

async fn reveal(
    app: &Arc<App>,
    project: String,
    key: String,
) -> Result<vaultos_core::store::Revealed, String> {
    store(app, move |s| s.reveal(&project, &key, HUMAN)).await
}

async fn copy_value(app: &Arc<App>, project: String, key: String) -> Reply {
    app.gate("copy a secret value").await?;
    let r = reveal(app, project, key).await?;
    let value = if r.value.expose().is_empty() {
        &r.password
    } else {
        &r.value
    };
    if value.expose().is_empty() {
        return Err("This key has no value to copy".into());
    }
    let mode = app.copy_secret(value.expose())?;
    Ok(json!({ "ok": true, "mode": mode }))
}

async fn search_items(app: &Arc<App>, q: &Value) -> Reply {
    let q = q
        .as_str()
        .filter(|q| q.len() <= 256)
        .ok_or("Invalid search")?
        .to_owned();
    let hits = store(app, move |s| {
        let mut all = Vec::new();
        for p in s.list_projects()? {
            let mut items = s.list_items(&p.name)?;
            items.retain(|i| !i.archived);
            all.push((p.name, items));
        }
        Ok(search::search(&all, &q, 100))
    })
    .await?;
    serde_json::to_value(hits).map_err(|e| e.to_string())
}

fn sync_for(app: &App) -> Result<Sync, String> {
    let repo = vaultos_sync::default_repo(&app.data_dir).map_err(|e| e.message)?;
    Ok(Sync::new(&app.data_dir, &repo))
}

async fn sync_call(
    app: &Arc<App>,
    f: impl FnOnce(&Sync, &mut Store) -> Result<Value, vaultos_sync::SyncError> + Send + 'static,
) -> Reply {
    let sync = sync_for(app)?;
    let me = app.clone();
    blocking(move || me.with_store(|s| Ok(f(&sync, s)))?.map_err(|e| e.message)).await?
}

pub fn prefs_state(app: &App) -> Value {
    let prefs = lock(&app.prefs).clone();
    let mut v = Value::Object(prefs.to_json());
    v["shortcutError"] = json!(lock(&app.shortcut_error).clone());
    v["trayAvailable"] = json!(!prefs.menu_bar || ui::has_tray(app));
    v["loginItemSupported"] = json!(login::item_path().is_some());
    v["sshSocket"] = json!(app.ssh_socket());
    v["sshSocketPath"] = json!(vaultos_core::session::ssh_socket_path(&app.data_dir).ok());
    v["sshSigner"] = json!(ui::helper("vaultos-ssh-sign"));
    v["sshError"] = json!(lock(&app.ssh_error).clone());
    v
}

async fn set_settings(app: &Arc<App>, patch: &Value) -> Reply {
    let current = store(app, |s| Ok(s.settings()?.clone())).await?;
    settings::check_touch_id(patch, &current, platform::touch_id_available())?;
    if settings::weakens_security(patch, &current) {
        app.gate("change security settings").await?;
    }
    let normalized = settings::normalize(patch, &current)?;
    match normalized.get("rememberPassword") {
        Some(v) if v == &json!(true) => {
            let pw = app
                .password()
                .ok_or("Unlock with the master password again first")?;
            let key = app.secret_key();
            let check = pw.clone();
            store(app, move |s| s.verify_password(&check, key.as_ref()))
                .await
                .map_err(|_| "Unlock with the master password again first")?;
            app.keyring.set(keyring::PASSWORD, &pw)?;
        }
        Some(_) => app.keyring.clear(keyring::PASSWORD),
        None => {}
    }
    store(app, move |s| s.update_settings(normalized, HUMAN)).await?;
    app.rewrite_touch_id_hint();
    let s = store(app, |s| Ok(s.settings()?.clone())).await?;
    Ok(settings::view(&s, app.keyring.describe()))
}

async fn change_password(app: &Arc<App>, a: &Args) -> Reply {
    let old = a.str(0, "password")?;
    let new = a.str(1, "password")?;
    app.require(
        app.with_store(|s| Ok(settings::touch_id(s.settings()?)["humanActions"] == json!(true)))?,
        "change the master password",
        Some(&old),
    )
    .await?;
    let key = app.secret_key();
    let (old_s, new_s) = (SecretString::new(old), SecretString::new(new));
    let new_c = new_s.clone();
    store(app, move |s| {
        s.change_password(&old_s, &new_c, key.as_ref())
    })
    .await?;
    app.set_password(new_s.clone());
    app.keyring.clear(keyring::PASSWORD);
    let remember = store(app, |s| Ok(settings::remember(s.settings()?))).await?;
    let updated = remember && app.keyring.set(keyring::PASSWORD, &new_s).is_ok();
    let mut ring = app.keyring.describe();
    ring["updated"] = json!(updated);
    Ok(json!({ "backups": [], "warnings": [], "keyring": ring }))
}

async fn main_call(app: &Arc<App>, handle: &AppHandle, channel: &str, a: &Args) -> Reply {
    match channel {
        "confirmHuman" => Ok(app.confirm_password(a.opt_str(0)).await),
        "lock" => {
            app.lock(true);
            Ok(json!({ "ok": true }))
        }
        "projects" => store(app, |s| s.list_projects())
            .await
            .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string())),
        "createProject" => {
            let name = a.str(0, "project name")?;
            let (id, name) = store(app, move |s| s.create_project(&name, HUMAN)).await?;
            Ok(json!({ "id": id, "name": name }))
        }
        "deleteProject" => {
            let id = a.str(0, "project")?;
            let (id, name) = store(app, move |s| s.delete_project(&id, HUMAN)).await?;
            Ok(json!({ "id": id, "name": name }))
        }
        "secrets" => {
            let p = a.str(0, "project")?;
            store(app, move |s| s.list_items(&p))
                .await
                .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string()))
        }
        "setSecret" => {
            let p = a.str(0, "project")?;
            let fields = item_fields(a.get(1))?;
            store(app, move |s| s.set_item(&p, &fields, HUMAN))
                .await
                .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string()))
        }
        "deleteSecret" => {
            let (p, k) = (a.str(0, "project")?, a.str(1, "key")?);
            store(app, move |s| s.delete_item(&p, &k, HUMAN)).await?;
            Ok(json!({ "ok": true }))
        }
        "reveal" => {
            app.gate("reveal a secret value").await?;
            let r = reveal(app, a.str(0, "project")?, a.str(1, "key")?).await?;
            Ok(revealed_json(&r))
        }
        "copy" => copy_value(app, a.str(0, "project")?, a.str(1, "key")?).await,
        "search" => search_items(app, a.get(0)).await,
        "trash" => items::trash(app).await,
        "restoreSecret" => items::restore(app, a.str(0, "project")?, a.str(1, "key")?).await,
        "purgeSecret" => items::purge(app, a.str(0, "project")?, a.str(1, "key")?).await,
        "emptyTrash" => items::empty_trash(app).await,
        "generate" => items::generate(a.get(0)),
        "generateSshKey" => items::generate_ssh_key(&a.str(0, "comment")?),
        "strength" => items::strength(&a.str(0, "password")?),
        "otp" => items::otp(app, a.str(0, "project")?, a.str(1, "key")?).await,
        "copyOtp" => items::copy_otp(app, a.str(0, "project")?, a.str(1, "key")?).await,
        "addAttachment" => {
            items::add_attachment(app, handle, a.str(0, "project")?, a.str(1, "key")?).await
        }
        "saveAttachment" => {
            let (p, k, id) = (a.str(0, "project")?, a.str(1, "key")?, a.str(2, "attachment")?);
            items::save_attachment(app, handle, p, k, id).await
        }
        "removeAttachment" => {
            let (p, k, id) = (a.str(0, "project")?, a.str(1, "key")?, a.str(2, "attachment")?);
            items::remove_attachment(app, p, k, id).await
        }
        "itemHistory" => items::item_history(app, a.str(0, "project")?, a.str(1, "key")?).await,
        "restoreVersion" => items::restore_version(app, a.str(0, "history entry")?).await,
        "watchtower" => items::watchtower(app).await,
        "breachCheck" => items::breach_check(app).await,
        "scanFolder" => items::scan_folder(app, handle).await,
        "saveLeakIndex" => items::save_leak_index(app).await,
        "importFile" => items::import_file(app, handle, a.str(0, "project")?).await,
        "getDesktopPrefs" => Ok(prefs_state(app)),
        "setDesktopPrefs" => {
            let patch = a.get(0).clone();
            let before = lock(&app.prefs).clone();
            let saved = prefs::save(&app.data_dir, &patch)?;
            *lock(&app.prefs) = saved;
            if patch.get("launchAtLogin").is_some() {
                if let Err(e) = ui::apply_login_item(app) {
                    let restore = json!({ "launchAtLogin": before.launch_at_login });
                    if let Ok(p) = prefs::save(&app.data_dir, &restore) {
                        *lock(&app.prefs) = p;
                    }
                    return Err(format!("Open at login could not be changed: {e}"));
                }
            }
            if patch.get("sshAgent").is_some() {
                app.apply_ssh_agent();
            }
            ui::apply_prefs(handle);
            Ok(prefs_state(app))
        }
        "getSettings" => {
            let s = store(app, |s| Ok(s.settings()?.clone())).await?;
            Ok(settings::view(&s, app.keyring.describe()))
        }
        "setSettings" => set_settings(app, a.get(0)).await,
        "changePassword" => change_password(app, a).await,
        "export" => export::export_project(app, handle, a.str(0, "project")?).await,
        "agents" => store(app, |s| s.list_agents())
            .await
            .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string())),
        "enrolAgent" => {
            app.gate("enrol an agent").await?;
            let name = a.str(0, "agent name")?;
            let scopes = a.strings(1, "scopes")?;
            let (projects, roots) = (a.strings(2, "projects")?, a.strings(3, "folders")?);
            let w = a.wildcards(4);
            let issued = store(app, move |s| s.enrol_agent(&name, Some(&scopes), &projects, &roots, w)).await?;
            Ok(json!({ "id": issued.id, "name": issued.name, "ref": issued.reference, "token": issued.token.expose() }))
        }
        "reissueAgent" => {
            app.gate("issue an agent token").await?;
            let id = a.str(0, "agent")?;
            let issued = store(app, move |s| s.reissue_agent(&id)).await?;
            Ok(json!({ "id": issued.id, "name": issued.name, "ref": issued.reference, "token": issued.token.expose() }))
        }
        "revokeAgent" => {
            app.gate("revoke an agent").await?;
            let id = a.str(0, "agent")?;
            store(app, move |s| s.revoke_agent(&id)).await?;
            Ok(json!({ "ok": true }))
        }
        "setAgentScopes" => {
            app.gate("change agent scopes").await?;
            let (id, scopes) = (a.str(0, "agent")?, a.strings(1, "scopes")?);
            store(app, move |s| s.set_agent_scopes(&id, &scopes)).await?;
            Ok(json!({ "ok": true }))
        }
        "setAgentAccess" => {
            app.gate("change agent access").await?;
            let id = a.str(0, "agent")?;
            let (projects, roots, w) = (a.strings(1, "projects")?, a.strings(2, "folders")?, a.wildcards(3));
            store(app, move |s| s.set_agent_access(&id, &projects, &roots, w)).await?;
            Ok(json!({ "ok": true }))
        }
        "setAgentRunCommands" => {
            app.gate("change the commands an agent may run").await?;
            let (id, commands) = (a.str(0, "agent")?, a.strings(1, "commands")?);
            store(app, move |s| s.set_agent_run_commands(&id, &commands)).await?;
            Ok(json!({ "ok": true }))
        }
        "chooseFolder" => ui::choose_folder(handle).await,
        "allScopes" => Ok(json!(ALL_SCOPES)),
        "delegate" => {
            app.gate("delegate a key to an agent").await?;
            let (p, k, agent) = (a.str(0, "project")?, a.str(1, "key")?, a.str(2, "agent")?);
            let on = a.bool(3);
            let editors = store(app, move |s| s.delegate(&p, &k, &agent, on)).await?;
            Ok(json!(editors))
        }
        "adopt" => {
            app.gate("adopt an agent's key").await?;
            let (p, k) = (a.str(0, "project")?, a.str(1, "key")?);
            store(app, move |s| s.adopt(&p, &k)).await?;
            Ok(json!({ "ok": true }))
        }
        "approveInject" => {
            app.gate("approve keys for .env").await?;
            let (p, k, on) = (a.str(0, "project")?, a.str(1, "key")?, a.bool(2));
            Ok(json!(store(app, move |s| s.approve_inject(&p, &k, on)).await?))
        }
        "approveInjectAll" => {
            let items: Vec<(String, String)> = a
                .get(0)
                .as_array()
                .filter(|v| v.len() <= 5000)
                .and_then(|v| {
                    v.iter()
                        .map(|i| Some((i["project"].as_str()?.to_owned(), i["key"].as_str()?.to_owned())))
                        .collect()
                })
                .ok_or("Invalid approval list")?;
            app.gate("approve keys for .env").await?;
            // One confirmation and one save: every listed key is approved, or none is.
            let done = store(app, move |s| {
                s.batch(|s| {
                    items
                        .iter()
                        .map(|(p, k)| s.approve_inject(p, k, true))
                        .collect::<Result<Vec<bool>, Error>>()
                })
            })
            .await?;
            Ok(json!(done))
        }
        "pending" => store(app, |s| s.pending_approvals())
            .await
            .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string())),
        "history" => {
            let limit = a.get(0).as_u64().unwrap_or(100).clamp(1, 1000) as usize;
            store(app, move |s| s.list_history(limit))
                .await
                .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string()))
        }
        "revert" => {
            let id = a.str(0, "history entry")?;
            let action = store(app, move |s| s.revert(&id, HUMAN)).await?;
            Ok(json!({ "ok": true, "action": action }))
        }
        "syncStatus" => {
            let mut v = sync_call(app, |sync, s| sync.status_remote(s)).await?;
            v["autoSync"] = app.sync_status().unwrap_or(Value::Null);
            Ok(v)
        }
        "syncPush" => sync_call(app, |sync, s| sync.push_remote(s, None)).await,
        "syncPull" => {
            let accept = a.bool(0);
            sync_call(app, move |sync, s| sync.pull_remote(s, accept)).await
        }
        "syncInit" => {
            let label = a.str(0, "machine label")?;
            sync_call(app, move |sync, s| sync.init(s, &label)).await
        }
        "syncIdentity" => sync_call(app, |sync, s| sync.identity(s)).await,
        "syncTrust" => {
            app.gate("trust a sync peer").await?;
            let identity = a.get(0).clone();
            sync_call(app, move |sync, s| sync.trust(s, &identity)).await
        }
        _ => Err("Unknown call".into()),
    }
    .map_err(|e| e.to_string())
}

/// Quick Access: unlock, search, copy, open. It never receives a secret value.
#[tauri::command]
pub async fn quick(
    window: WebviewWindow,
    state: State<'_, Arc<App>>,
    channel: String,
    args: Vec<Value>,
) -> Reply {
    if !from_page(&window, "quick", "/quick.html") {
        return Err("Untrusted IPC sender".into());
    }
    let app = state.inner().clone();
    let handle = window.app_handle().clone();
    let a = Args(args);
    match channel.as_str() {
        "state" => {
            let s = app.state();
            return Ok(json!({ "unlocked": s["unlocked"], "touchId": s["touchId"] }));
        }
        "unlock" => return Ok(app.unlock_password(a.opt_str(0), None).await),
        "unlockTouchId" => return Ok(app.unlock_touch_id().await),
        "hide" => {
            ui::hide_quick(&handle, true);
            return Ok(json!({ "ok": true }));
        }
        "openMain" => {
            ui::hide_quick(&handle, false);
            ui::show_main(&handle, None);
            return Ok(json!({ "ok": true }));
        }
        _ => {}
    }
    unlocked(&app)?;
    match channel.as_str() {
        "confirmHuman" => Ok(app.confirm_password(a.opt_str(0)).await),
        "search" => search_items(&app, a.get(0)).await,
        // The panel never receives the code itself.
        "copyOtp" => {
            let r = items::copy_otp(&app, a.str(0, "project")?, a.str(1, "key")?).await?;
            ui::hide_quick(&handle, true);
            Ok(r)
        }
        "copy" => {
            let (p, k) = (a.str(0, "project")?, a.str(1, "key")?);
            let field = a.opt_str(2).unwrap_or_else(|| "value".into());
            let r = match field.as_str() {
                "value" => copy_value(&app, p, k).await?,
                "username" | "email" => {
                    let item = quick_record(&app, p, k).await?;
                    let text = if field == "username" {
                        item.username
                    } else {
                        item.email
                    };
                    if text.is_empty() {
                        return Err(format!("This item has no {field}"));
                    }
                    app.clipboard.write_plain(&text)?;
                    json!({ "ok": true, "mode": "plain" })
                }
                _ => return Err("Unknown field".into()),
            };
            ui::hide_quick(&handle, true);
            Ok(r)
        }
        "openUrl" => {
            let item = quick_record(&app, a.str(0, "project")?, a.str(1, "key")?).await?;
            let url = web_address(&item.url).ok_or("This item has no web address to open")?;
            ui::hide_quick(&handle, true);
            ui::open_external(&url)?;
            Ok(json!({ "ok": true }))
        }
        "open" => {
            let (p, k) = (a.str(0, "project")?, a.str(1, "key")?);
            quick_record(&app, p.clone(), k.clone()).await?;
            ui::hide_quick(&handle, false);
            ui::show_main(
                &handle,
                Some(json!({ "name": "project", "project": p, "focusKey": k })),
            );
            Ok(json!({ "ok": true }))
        }
        _ => Err("Unknown call".into()),
    }
}

async fn quick_record(
    app: &Arc<App>,
    project: String,
    key: String,
) -> Result<vaultos_core::store::ItemSummary, String> {
    store(app, move |s| s.find_item(&project, &key))
        .await?
        .ok_or("That item no longer exists".into())
}

/// An item's URL as an http(s) address to open, or `None`.
pub fn web_address(url: &str) -> Option<String> {
    let has_scheme = url.split_once(':').is_some_and(|(s, _)| {
        !s.is_empty()
            && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
    });
    let candidate = if has_scheme {
        url.to_owned()
    } else {
        format!("https://{url}")
    };
    let parsed = tauri::Url::parse(&candidate).ok()?;
    (matches!(parsed.scheme(), "http" | "https")
        && parsed.host_str().is_some_and(|h| !h.is_empty()))
    .then(|| parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::{web_address, PROVIDERS};
    use serde_json::{json, Value};

    /// The core's key-name table (`vaultos_core::providers`) is this table's ids and keys.
    #[test]
    fn provider_tables_agree() {
        let desktop: Vec<Value> = serde_json::from_str(PROVIDERS).unwrap_or_default();
        let core: Value =
            serde_json::from_str(include_str!("../../vaultos-core/src/providers.json"))
                .unwrap_or_default();
        let keys: Vec<Value> = desktop
            .iter()
            .map(|p| json!({ "id": p["id"], "keys": p["keys"] }))
            .collect();
        assert!(!keys.is_empty());
        assert_eq!(
            Value::Array(keys),
            core,
            "update crates/vaultos-core/src/providers.json"
        );
    }

    #[test]
    fn opens_only_web_addresses() {
        assert_eq!(
            web_address("example.com/a").as_deref(),
            Some("https://example.com/a")
        );
        assert_eq!(
            web_address("http://x.test").as_deref(),
            Some("http://x.test/")
        );
        assert_eq!(web_address("javascript:alert(1)"), None);
        assert_eq!(web_address("file:///etc/passwd"), None);
        assert_eq!(web_address(""), None);
    }
}
