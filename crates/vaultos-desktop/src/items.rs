//! The window's typed-item calls: the Trash, the generator, one-time codes, attachments,
//! versions, Watchtower with its opt-in breach check, and importing other managers' exports.

use crate::app::{blocking, App};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt;
use vaultos_core::generator::{self, Recipe};
use vaultos_core::import::{self, Format, MAX_IMPORT_BYTES};
use vaultos_core::model::HUMAN;
use vaultos_core::store::MAX_ATTACHMENT_BYTES;
use vaultos_core::{Error, Store};

type Reply = Result<Value, String>;

async fn store<R: Send + 'static>(
    app: &Arc<App>,
    f: impl FnOnce(&mut Store) -> Result<R, Error> + Send + 'static,
) -> Result<R, String> {
    let me = app.clone();
    blocking(move || me.with_store(f)).await?
}

fn to_json<T: serde::Serialize>(v: T) -> Reply {
    serde_json::to_value(v).map_err(|e| e.to_string())
}

pub async fn trash(app: &Arc<App>) -> Reply {
    to_json(store(app, |s| s.list_trash(HUMAN)).await?)
}

pub async fn restore(app: &Arc<App>, project: String, key: String) -> Reply {
    let key = store(app, move |s| s.restore_item(&project, &key, HUMAN)).await?;
    Ok(json!({ "ok": true, "key": key }))
}

pub async fn purge(app: &Arc<App>, project: String, key: String) -> Reply {
    app.gate("delete an item permanently").await?;
    let key = store(app, move |s| s.purge_item(&project, &key, HUMAN)).await?;
    Ok(json!({ "ok": true, "key": key }))
}

pub async fn empty_trash(app: &Arc<App>) -> Reply {
    app.gate("empty the Trash").await?;
    let n = store(app, |s| s.empty_trash(HUMAN)).await?;
    Ok(json!({ "ok": true, "purged": n }))
}

pub fn generate(recipe: &Value) -> Reply {
    let recipe: Recipe = if recipe.is_null() {
        Recipe::default()
    } else {
        serde_json::from_value(recipe.clone()).map_err(|_| "Invalid generator settings")?
    };
    let g = generator::generate(&recipe).map_err(|e| e.to_string())?;
    Ok(json!({
        "value": g.value.expose(),
        "bits": g.bits.round(),
        "rating": generator::rating(g.bits),
    }))
}

pub fn strength(password: &str) -> Reply {
    if password.len() > 4096 {
        return Err("Invalid password".into());
    }
    let bits = generator::estimate_bits(password);
    Ok(json!({ "bits": bits.round(), "rating": generator::rating(bits) }))
}

pub async fn otp(app: &Arc<App>, project: String, key: String) -> Reply {
    let o = store(app, move |s| s.otp(&project, &key, HUMAN)).await?;
    Ok(json!({ "code": o.code.expose(), "remaining": o.remaining, "period": o.period }))
}

pub async fn copy_otp(app: &Arc<App>, project: String, key: String) -> Reply {
    let o = store(app, move |s| s.otp(&project, &key, HUMAN)).await?;
    let mode = app.copy_secret(o.code.expose())?;
    Ok(json!({ "ok": true, "mode": mode, "remaining": o.remaining }))
}

/// Reads a file the person picked, refusing anything but a regular file up to `max` bytes.
/// The limit holds while reading too, for a file that grows after the check.
fn read_picked(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let too_big = || format!("The file is larger than {} MB", max / (1024 * 1024));
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("Choose a regular file".into());
    }
    if meta.len() > max as u64 {
        return Err(too_big());
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > max {
        return Err(too_big());
    }
    Ok(bytes)
}

pub async fn add_attachment(
    app: &Arc<App>,
    handle: &AppHandle,
    project: String,
    key: String,
) -> Reply {
    let dialog = handle.dialog().file().set_title("Attach a file");
    let picked = blocking(move || dialog.blocking_pick_file()).await?;
    let Some(path) = picked.and_then(|p| p.into_path().ok()) else {
        return Ok(json!({ "ok": false, "canceled": true }));
    };
    if !app.human_unlocked() {
        return Err("Vault is locked".into());
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let bytes =
        zeroize::Zeroizing::new(blocking(move || read_picked(&path, MAX_ATTACHMENT_BYTES)).await??);
    let a = store(app, move |s| {
        s.add_attachment(&project, &key, &name, &bytes, HUMAN)
    })
    .await?;
    Ok(json!({ "ok": true, "attachment": a }))
}

pub async fn save_attachment(
    app: &Arc<App>,
    handle: &AppHandle,
    project: String,
    key: String,
    id: String,
) -> Reply {
    app.gate("save an attachment").await?;
    let name = {
        let (p, k, i) = (project.clone(), key.clone(), id.clone());
        store(app, move |s| {
            let item = s
                .find_item(&p, &k)?
                .ok_or_else(|| Error::NotFound("secret not found".into()))?;
            item.attachments
                .into_iter()
                .find(|a| a.id == i)
                .map(|a| a.name)
                .ok_or_else(|| Error::NotFound("attachment not found".into()))
        })
        .await?
    };
    let dialog = handle
        .dialog()
        .file()
        .set_title("Save attachment")
        .set_file_name(&name);
    let picked = blocking(move || dialog.blocking_save_file()).await?;
    let Some(target) = picked.and_then(|p| p.into_path().ok()) else {
        return Ok(json!({ "ok": false, "canceled": true }));
    };
    if !app.human_unlocked() {
        return Err("Vault is locked".into());
    }
    let me = app.clone();
    blocking(move || -> Result<(), String> {
        let (_, plain) = me.with_store(|s| s.open_attachment(&project, &key, &id, HUMAN))?;
        crate::export::write_file(&target, &me.data_dir, plain.expose())
    })
    .await??;
    Ok(json!({ "ok": true }))
}

pub async fn remove_attachment(app: &Arc<App>, project: String, key: String, id: String) -> Reply {
    store(app, move |s| {
        s.remove_attachment(&project, &key, &id, HUMAN)
    })
    .await?;
    Ok(json!({ "ok": true }))
}

pub async fn item_history(app: &Arc<App>, project: String, key: String) -> Reply {
    to_json(store(app, move |s| s.item_history(&project, &key, HUMAN)).await?)
}

pub async fn restore_version(app: &Arc<App>, id: String) -> Reply {
    let key = store(app, move |s| s.restore_version(&id, HUMAN)).await?;
    Ok(json!({ "ok": true, "key": key }))
}

pub async fn watchtower(app: &Arc<App>) -> Reply {
    to_json(store(app, |s| s.watchtower(HUMAN)).await?)
}

const CURL: [&str; 3] = ["/usr/bin/curl", "/bin/curl", "/usr/local/bin/curl"];

/// Have I Been Pwned's range API: only the first five characters of each password's SHA-1
/// leave the device, and padded replies hide how many suffixes matched.
fn pwned_range(prefix: &str) -> Result<String, String> {
    let curl = CURL
        .iter()
        .find(|c| Path::new(c).is_file())
        .ok_or("The breach check needs curl")?;
    // -q first: no ~/.curlrc, so only these options apply.
    let mut child = std::process::Command::new(curl)
        .args([
            "-q",
            "-fsS",
            "--max-filesize",
            "1048576",
            "--max-time",
            "20",
            "--proto",
            "=https",
            "-H",
            "Add-Padding: true",
            "-A",
            "VaultOS",
        ])
        .arg(format!("https://api.pwnedpasswords.com/range/{prefix}"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    // A reply is about 40 KB; read at most 1 MB of whatever comes back.
    const LIMIT: usize = 1 << 20;
    let mut body = Vec::new();
    if let Some(out) = child.stdout.take() {
        use std::io::Read;
        let _ = out.take(LIMIT as u64 + 1).read_to_end(&mut body);
    }
    if body.len() > LIMIT {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Unexpected reply from the breach check".into());
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("The breach check could not reach api.pwnedpasswords.com".into());
    }
    String::from_utf8(body).map_err(|_| "Unexpected reply from the breach check".into())
}

fn breach_counts(range: &str, suffix: &str) -> u64 {
    range
        .lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find(|(s, _)| s.eq_ignore_ascii_case(suffix))
        .and_then(|(_, n)| n.trim().parse().ok())
        .unwrap_or(0)
}

pub async fn breach_check(app: &Arc<App>) -> Reply {
    let hashes = store(app, |s| s.password_sha1s(HUMAN)).await?;
    let found = blocking(move || -> Result<Vec<Value>, String> {
        let mut by_prefix: BTreeMap<String, Vec<(String, String, String)>> = BTreeMap::new();
        for (project, key, hash) in hashes {
            by_prefix.entry(hash[..5].to_owned()).or_default().push((
                project,
                key,
                hash[5..].to_owned(),
            ));
        }
        let mut found = Vec::new();
        for (prefix, items) in by_prefix {
            let range = pwned_range(&prefix)?;
            for (project, key, suffix) in items {
                let count = breach_counts(&range, &suffix);
                if count > 0 {
                    found.push(json!({ "project": project, "key": key, "count": count }));
                }
            }
        }
        Ok(found)
    })
    .await??;
    Ok(json!({ "ok": true, "breached": found }))
}

pub async fn import_file(app: &Arc<App>, handle: &AppHandle, project: String) -> Reply {
    let dialog = handle
        .dialog()
        .file()
        .set_title("Import from another password manager")
        .add_filter("1Password, Bitwarden or CSV", &["1pux", "json", "csv"]);
    let picked = blocking(move || dialog.blocking_pick_file()).await?;
    let Some(path) = picked.and_then(|p| p.into_path().ok()) else {
        return Ok(json!({ "ok": false, "canceled": true }));
    };
    if !app.human_unlocked() {
        return Err("Vault is locked".into());
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let bytes =
        zeroize::Zeroizing::new(blocking(move || read_picked(&path, MAX_IMPORT_BYTES)).await??);
    let format = Format::detect(&name, &bytes)
        .ok_or("Choose a 1Password .1pux, a Bitwarden .json or a .csv export")?;
    let report = import::parse(format, &bytes).map_err(|e| e.to_string())?;
    let result = store(app, move |s| s.import_items(&project, report, HUMAN)).await?;
    Ok(json!({ "ok": true, "result": result }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_padded_range_replies() {
        let range = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:13\r\n";
        assert_eq!(
            breach_counts(range, "011053fd0102e94d6ae2f8b83d76faf94f6"),
            13
        );
        assert_eq!(
            breach_counts(range, "00D4F6E8FA6EECAD2A3AA415EEC418D38EC"),
            0,
            "padding"
        );
        assert_eq!(breach_counts(range, "FFFF"), 0);
    }

    #[test]
    fn generator_replies() {
        let v = generate(&json!({ "kind": "pin", "length": 6 })).unwrap();
        assert_eq!(v["value"].as_str().unwrap().len(), 6);
        assert!(generate(&json!({ "kind": "pin", "length": 2 })).is_err());
        assert!(generate(&json!({ "kind": "nope" })).is_err());
        assert_eq!(
            generate(&Value::Null).unwrap()["value"]
                .as_str()
                .unwrap()
                .len(),
            24
        );
        assert_eq!(strength("password").unwrap()["rating"], "weak");
    }
}
