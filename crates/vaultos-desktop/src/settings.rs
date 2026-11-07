//! The desktop's vault settings, kept encrypted in the vault as the JavaScript app kept them:
//! the export password, background access, the lock policy, autosync and Touch ID. This
//! module validates a patch and tells whether it makes the vault easier to use without the
//! human present (which then needs a confirmation).

use serde_json::{json, Map, Value};

/// Matches `vaultos-daemon`'s autosync default.
const AUTO_SYNC_DEFAULT_SECONDS: u64 = 120;
const KEYS: [&str; 5] = [
    "exportPassword",
    "rememberPassword",
    "lockPolicy",
    "autoSync",
    "touchId",
];
const TOUCH_ID_KEYS: [&str; 3] = ["unlock", "humanActions", "autoPrompt"];

fn flag(v: Option<&Value>) -> bool {
    v == Some(&json!(true))
}

pub fn remember(s: &Map<String, Value>) -> bool {
    flag(s.get("rememberPassword"))
}

pub fn soft_lock(s: &Map<String, Value>) -> bool {
    s.get("lockPolicy") == Some(&json!("soft"))
}

pub fn export_password(s: &Map<String, Value>) -> Option<&str> {
    s.get("exportPassword")
        .and_then(Value::as_str)
        .filter(|p| !p.is_empty())
}

pub fn touch_id(s: &Map<String, Value>) -> Value {
    let t = s.get("touchId");
    let get = |k: &str| flag(t.and_then(|t| t.get(k)));
    let unlock = get("unlock");
    json!({ "unlock": unlock, "humanActions": get("humanActions"), "autoPrompt": unlock && get("autoPrompt") })
}

pub fn auto_sync(s: &Map<String, Value>) -> Value {
    let a = s.get("autoSync");
    let interval = a
        .and_then(|a| a.get("intervalSeconds"))
        .and_then(Value::as_u64)
        .filter(|n| (30..=86_400).contains(n))
        .unwrap_or(AUTO_SYNC_DEFAULT_SECONDS);
    json!({ "enabled": flag(a.and_then(|a| a.get("enabled"))), "intervalSeconds": interval })
}

/// What the Settings page shows. Never the export password itself.
pub fn view(s: &Map<String, Value>, keyring: Value) -> Value {
    json!({
        "hasExportPassword": export_password(s).is_some(),
        "rememberPassword": remember(s),
        "lockPolicy": if soft_lock(s) { "soft" } else { "hard" },
        "autoSync": auto_sync(s),
        "touchId": touch_id(s),
        "keyring": keyring,
        "formatVersion": 4,
    })
}

fn object<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    v.as_object().ok_or(format!("Invalid {what}"))
}

/// Checks a patch and returns the complete values to store (nested objects merged with the
/// current ones, Touch ID unlock turned off with background access).
pub fn normalize(
    patch: &Value,
    current: &Map<String, Value>,
) -> Result<Map<String, Value>, String> {
    let patch = object(patch, "settings")?;
    if patch.keys().any(|k| !KEYS.contains(&k.as_str())) {
        return Err("Unknown setting".into());
    }
    let mut out = Map::new();
    if let Some(p) = patch.get("exportPassword") {
        let p = p.as_str().ok_or("Invalid export password")?;
        if !p.is_empty() {
            vaultos_core::validate::password(p).map_err(|e| e.to_string())?;
        }
        out.insert("exportPassword".into(), json!(p));
    }
    if let Some(r) = patch.get("rememberPassword") {
        out.insert(
            "rememberPassword".into(),
            json!(r.as_bool().ok_or("Invalid remember setting")?),
        );
    }
    if let Some(l) = patch.get("lockPolicy") {
        if l != "hard" && l != "soft" {
            return Err("Invalid lock policy".into());
        }
        out.insert("lockPolicy".into(), l.clone());
    }
    if let Some(a) = patch.get("autoSync") {
        let a = object(a, "autosync setting")?;
        let mut merged = auto_sync(current);
        for (k, v) in a {
            match k.as_str() {
                "enabled" if v.is_boolean() => {}
                "enabled" => return Err("Invalid autosync setting".into()),
                "intervalSeconds" if v.as_u64().is_some_and(|n| (30..=86_400).contains(&n)) => {}
                "intervalSeconds" => {
                    return Err("Autosync interval must be 30 to 86400 seconds".into())
                }
                _ => return Err("Unknown autosync setting".into()),
            }
            merged[k] = v.clone();
        }
        out.insert("autoSync".into(), merged);
    }
    if let Some(t) = patch.get("touchId") {
        let t = object(t, "Touch ID setting")?;
        let mut merged = touch_id(current);
        for (k, v) in t {
            if !TOUCH_ID_KEYS.contains(&k.as_str()) {
                return Err("Unknown Touch ID setting".into());
            }
            if !v.is_boolean() {
                return Err("Invalid Touch ID setting".into());
            }
            merged[k] = v.clone();
        }
        out.insert("touchId".into(), merged);
    }
    // Touch ID unlock reads the remembered password, so it cannot outlive that setting.
    let remembering = out
        .get("rememberPassword")
        .map_or_else(|| remember(current), |v| v == &json!(true));
    let touch = out
        .get("touchId")
        .cloned()
        .unwrap_or_else(|| touch_id(current));
    if !remembering && touch["unlock"] == json!(true) {
        let mut t = touch;
        t["unlock"] = json!(false);
        t["autoPrompt"] = json!(false);
        out.insert("touchId".into(), t);
    }
    Ok(out)
}

/// A patch that makes the vault easier to use without the human present.
pub fn weakens_security(patch: &Value, current: &Map<String, Value>) -> bool {
    let on = |v: &Value| v == &json!(true);
    let t = &patch["touchId"];
    let ct = touch_id(current);
    patch["exportPassword"]
        .as_str()
        .is_some_and(|p| !p.is_empty())
        || (on(&patch["rememberPassword"]) && !remember(current))
        || (patch["lockPolicy"] == "soft" && !soft_lock(current))
        || (on(&patch["autoSync"]["enabled"]) && !on(&auto_sync(current)["enabled"]))
        || (t["humanActions"] == json!(false) && on(&ct["humanActions"]))
        || (on(&t["unlock"]) && !on(&ct["unlock"]))
        || (on(&t["autoPrompt"]) && !on(&ct["autoPrompt"]))
}

/// Turning a Touch ID option on needs Touch ID and background access; turning one off
/// always works.
pub fn check_touch_id(
    patch: &Value,
    current: &Map<String, Value>,
    available: bool,
) -> Result<(), String> {
    let Some(t) = patch["touchId"].as_object() else {
        return Ok(());
    };
    let ct = touch_id(current);
    let turning_on = TOUCH_ID_KEYS
        .iter()
        .any(|k| t.get(*k) == Some(&json!(true)) && ct[*k] != json!(true));
    if !turning_on {
        return Ok(());
    }
    if !available {
        return Err("Touch ID is not available on this device".into());
    }
    let remembering = patch["rememberPassword"]
        .as_bool()
        .unwrap_or_else(|| remember(current));
    if !remembering {
        return Err("Touch ID needs background access (remembered password) to be on".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn touch_id_unlock_goes_with_background_access() {
        let current = map(
            json!({ "rememberPassword": true, "touchId": { "unlock": true, "autoPrompt": true } }),
        );
        let out = normalize(&json!({ "rememberPassword": false }), &current).expect("valid");
        assert_eq!(
            out["touchId"],
            json!({ "unlock": false, "humanActions": false, "autoPrompt": false })
        );
    }

    #[test]
    fn refuses_unknown_and_malformed_settings() {
        let current = Map::new();
        assert!(normalize(&json!({ "other": 1 }), &current).is_err());
        assert!(normalize(&json!({ "lockPolicy": "never" }), &current).is_err());
        assert!(normalize(&json!({ "autoSync": { "intervalSeconds": 5 } }), &current).is_err());
        assert!(normalize(&json!({ "touchId": { "unlock": "yes" } }), &current).is_err());
    }

    #[test]
    fn weakening_changes_need_confirmation() {
        let current = map(json!({ "touchId": { "humanActions": true } }));
        assert!(weakens_security(&json!({ "lockPolicy": "soft" }), &current));
        assert!(weakens_security(
            &json!({ "touchId": { "humanActions": false } }),
            &current
        ));
        assert!(!weakens_security(
            &json!({ "lockPolicy": "hard" }),
            &current
        ));
        assert!(!weakens_security(
            &json!({ "exportPassword": "" }),
            &current
        ));
    }

    #[test]
    fn touch_id_needs_background_access() {
        let current = Map::new();
        let patch = json!({ "touchId": { "unlock": true } });
        assert!(check_touch_id(&patch, &current, false).is_err());
        assert!(check_touch_id(&patch, &current, true).is_err());
        let with = json!({ "rememberPassword": true, "touchId": { "unlock": true } });
        assert!(check_touch_id(&with, &current, true).is_ok());
    }
}
