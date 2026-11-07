//! Desktop preferences that must work while the vault is locked (`desktop-prefs.js`): the
//! Quick Access shortcut, the menu bar item, open at login and notifications. They hold no
//! secrets, so they live in a small plaintext file beside the vault. Only the unlocked main
//! window can change them.

use serde_json::{json, Map, Value};
use std::path::Path;
use vaultos_core::fs_safe::{atomic_write, read_regular};

const FILE: &str = "desktop-prefs.json";
pub const DEFAULT_SHORTCUT: &str = "Shift+CommandOrControl+Space";
const BOOLEANS: [&str; 4] = [
    "menuBar",
    "launchAtLogin",
    "notifyApprovals",
    "notifyExpiry",
];
const MODIFIERS: [&str; 12] = [
    "Command",
    "Cmd",
    "Control",
    "Ctrl",
    "CommandOrControl",
    "CmdOrCtrl",
    "Alt",
    "Option",
    "AltGr",
    "Shift",
    "Super",
    "Meta",
];
const NAMED_KEYS: [&str; 18] = [
    "Space",
    "Tab",
    "Enter",
    "Return",
    "Backspace",
    "Delete",
    "Insert",
    "Home",
    "End",
    "PageUp",
    "PageDown",
    "Up",
    "Down",
    "Left",
    "Right",
    "Escape",
    "Esc",
    "Plus",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefs {
    pub menu_bar: bool,
    pub shortcut: String,
    pub launch_at_login: bool,
    pub notify_approvals: bool,
    pub notify_expiry: bool,
}

impl Default for Prefs {
    /// Linux trays depend on the desktop environment, so closing the window quits there
    /// unless the human turns the menu bar item on.
    fn default() -> Prefs {
        Prefs {
            menu_bar: cfg!(target_os = "macos"),
            shortcut: DEFAULT_SHORTCUT.into(),
            launch_at_login: false,
            notify_approvals: false,
            notify_expiry: false,
        }
    }
}

impl Prefs {
    pub fn to_json(&self) -> Map<String, Value> {
        let v = json!({
            "menuBar": self.menu_bar,
            "shortcut": self.shortcut,
            "launchAtLogin": self.launch_at_login,
            "notifyApprovals": self.notify_approvals,
            "notifyExpiry": self.notify_expiry,
        });
        v.as_object().cloned().unwrap_or_default()
    }

    fn set_bool(&mut self, k: &str, v: bool) {
        match k {
            "menuBar" => self.menu_bar = v,
            "launchAtLogin" => self.launch_at_login = v,
            "notifyApprovals" => self.notify_approvals = v,
            _ => self.notify_expiry = v,
        }
    }
}

/// Accelerator syntax limited to what makes sense as a global shortcut: modifiers and one
/// key, or a function key alone. "" turns the shortcut off.
pub fn valid_accelerator(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if value.len() > 64 {
        return false;
    }
    let mut parts: Vec<&str> = value.split('+').collect();
    let Some(key) = parts.pop() else { return false };
    let mut seen = std::collections::HashSet::new();
    if key.is_empty()
        || parts
            .iter()
            .any(|p| !MODIFIERS.contains(p) || !seen.insert(*p))
    {
        return false;
    }
    let function = key
        .strip_prefix('F')
        .and_then(|n| n.parse::<u8>().ok())
        .is_some_and(|n| (1..=24).contains(&n) && !key[1..].starts_with('0'));
    let single = key.chars().count() == 1
        && key.chars().all(|c| {
            c.is_ascii_uppercase()
                || c.is_ascii_digit()
                || ")!@#$%^&*(:;=<,_-.>?/~`{]|[}\"'".contains(c)
        });
    (function || NAMED_KEYS.contains(&key) || single) && (function || !parts.is_empty())
}

pub fn load(data_dir: &Path) -> Prefs {
    let mut prefs = Prefs::default();
    let file = data_dir.join(FILE);
    if !file.exists() {
        return prefs;
    }
    let Ok(saved) = read_regular(&file, 4096)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .ok_or(())
    else {
        return prefs;
    };
    for k in BOOLEANS {
        if let Some(v) = saved.get(k).and_then(Value::as_bool) {
            prefs.set_bool(k, v);
        }
    }
    if let Some(s) = saved.get("shortcut").and_then(Value::as_str) {
        if valid_accelerator(s) {
            prefs.shortcut = s.into();
        }
    }
    prefs
}

pub fn save(data_dir: &Path, patch: &Value) -> Result<Prefs, String> {
    let patch = patch.as_object().ok_or("Invalid desktop preferences")?;
    let mut prefs = load(data_dir);
    for (k, v) in patch {
        if BOOLEANS.contains(&k.as_str()) {
            prefs.set_bool(k, v.as_bool().ok_or(format!("Invalid {k} preference"))?);
        } else if k == "shortcut" {
            match v.as_str() {
                Some(s) if valid_accelerator(s) => prefs.shortcut = s.into(),
                _ => return Err(
                    "Use one or more modifier keys and one key, like Shift+CommandOrControl+Space"
                        .into(),
                ),
            }
        } else {
            return Err("Unknown desktop preference".into());
        }
    }
    let bytes = serde_json::to_vec(&prefs.to_json()).map_err(|e| e.to_string())?;
    atomic_write(&data_dir.join(FILE), &bytes).map_err(|e| e.to_string())?;
    Ok(prefs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_global_shortcuts() {
        assert!(valid_accelerator(DEFAULT_SHORTCUT));
        assert!(valid_accelerator(""));
        assert!(valid_accelerator("F5"));
        assert!(valid_accelerator("Alt+K"));
        assert!(!valid_accelerator("K"));
        assert!(!valid_accelerator("Shift+Shift+K"));
        assert!(!valid_accelerator("Hyper+K"));
        assert!(!valid_accelerator("F25"));
        assert!(!valid_accelerator("Alt+k"));
    }

    #[test]
    fn saves_and_reloads() {
        let dir = tempfile::tempdir().expect("temp dir");
        let p = save(
            dir.path(),
            &json!({ "menuBar": false, "shortcut": "Alt+Space" }),
        )
        .expect("saved");
        assert_eq!(p, load(dir.path()));
        assert!(save(dir.path(), &json!({ "shortcut": "Q" })).is_err());
        assert!(save(dir.path(), &json!({ "other": true })).is_err());
    }
}
