//! What the desktop keeps in the OS credential store: the remembered master password (only
//! when the human turns on background access) and the vault's Secret Key, which stays on this
//! device the way 1Password keeps its Secret Key. The macOS Keychain, or the Secret Service
//! through libsecret's `secret-tool` on Linux. There is no plaintext fallback.

use serde_json::{json, Value};
use std::path::Path;
use vaultos_core::crypto::sha256_hex;
use vaultos_core::SecretString;

pub const PASSWORD: &str = "master-password";
pub const SECRET_KEY: &str = "secret-key";

const DETAIL: &str = "Remembering the password is optional. No plaintext fallback is used.";

#[derive(Debug)]
pub struct Keyring {
    service: String,
}

impl Keyring {
    /// The JavaScript app's service name, so a remembered password carries over: one item
    /// per vault folder.
    pub fn new(data_dir: &Path) -> Keyring {
        let digest = sha256_hex(data_dir.to_string_lossy().as_bytes());
        Keyring {
            service: format!("org.vaultos.preview.{}", &digest[..24]),
        }
    }

    pub fn describe(&self) -> Value {
        imp::describe()
    }

    pub fn secure(&self) -> bool {
        self.describe()["secure"] == json!(true)
    }

    pub fn get(&self, account: &str) -> Option<SecretString> {
        imp::get(&self.service, account).ok().flatten()
    }

    /// Stores and reads back, so a store that silently drops the item is reported.
    pub fn set(&self, account: &str, secret: &SecretString) -> Result<(), String> {
        imp::set(&self.service, account, secret)?;
        match self.get(account) {
            Some(back) if back.expose() == secret.expose() => Ok(()),
            _ => Err(imp::READBACK.into()),
        }
    }

    /// Writes only when the stored value is missing or different.
    pub fn ensure(&self, account: &str, secret: &SecretString) -> Result<(), String> {
        match self.get(account) {
            Some(v) if v.expose() == secret.expose() => Ok(()),
            _ => self.set(account, secret),
        }
    }

    pub fn clear(&self, account: &str) {
        if self.secure() {
            let _ = imp::delete(&self.service, account);
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{json, SecretString, Value, DETAIL};
    use security_framework::base::Error;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    pub const READBACK: &str = "Keychain readback failed";
    const NOT_FOUND: i32 = -25300; // errSecItemNotFound

    pub fn describe() -> Value {
        json!({ "store": "macos-keychain", "secure": true, "detail": DETAIL })
    }

    fn failed(_: Error) -> String {
        "Keychain operation failed; unlock your login Keychain and retry".into()
    }

    pub fn get(service: &str, account: &str) -> Result<Option<SecretString>, String> {
        match get_generic_password(service, account) {
            Ok(bytes) => String::from_utf8(bytes)
                .map(|s| Some(SecretString::new(s)))
                .map_err(|_| "The Keychain item is not text".into()),
            Err(e) if e.code() == NOT_FOUND => Ok(None),
            Err(e) => Err(failed(e)),
        }
    }

    pub fn set(service: &str, account: &str, secret: &SecretString) -> Result<(), String> {
        set_generic_password(service, account, secret.expose().as_bytes()).map_err(failed)
    }

    pub fn delete(service: &str, account: &str) -> Result<(), String> {
        match delete_generic_password(service, account) {
            Err(e) if e.code() != NOT_FOUND => Err(failed(e)),
            _ => Ok(()),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{json, SecretString, Value};
    use std::collections::HashMap;
    use std::io::Write;
    use std::os::unix::fs::FileTypeExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    pub const READBACK: &str = "Secret Service readback failed";
    const FAILED: &str = "Secret Service operation failed; unlock your login keyring and retry";

    fn find(name: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .filter(|d| d.is_absolute())
            .map(|d| d.join(name))
            .find(|f| f.is_file())
    }

    /// systemd user units, cron and SSH sessions can lack DBUS_SESSION_BUS_ADDRESS although
    /// the user's session bus socket exists.
    fn bus_env() -> Option<HashMap<String, String>> {
        let mut env = HashMap::new();
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
            return Some(env);
        }
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or(format!("/run/user/{uid}"));
        let bus = Path::new(&runtime).join("bus");
        let is_socket = std::fs::metadata(&bus)
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false);
        if !Path::new(&runtime).is_absolute() || !is_socket {
            return None;
        }
        env.insert("XDG_RUNTIME_DIR".into(), runtime);
        env.insert(
            "DBUS_SESSION_BUS_ADDRESS".into(),
            format!("unix:path={}", bus.display()),
        );
        Some(env)
    }

    pub fn describe() -> Value {
        match (find("secret-tool"), bus_env()) {
            (None, _) => {
                json!({ "store": "unavailable", "secure": false, "detail": "Remembering the password needs secret-tool (libsecret) and a Secret Service such as GNOME Keyring. No plaintext fallback is used." })
            }
            (Some(_), None) => {
                json!({ "store": "unavailable", "secure": false, "detail": "No D-Bus session bus was found, so the Secret Service is unreachable. No plaintext fallback is used." })
            }
            _ => {
                json!({ "store": "libsecret", "secure": true, "detail": "Remembering the password is optional and uses the Secret Service (libsecret). No plaintext fallback is used." })
            }
        }
    }

    /// secret-tool reads the secret from stdin, so it never appears in process arguments.
    fn run(args: &[&str], input: Option<&str>) -> Result<std::process::Output, String> {
        let tool = find("secret-tool").ok_or(FAILED)?;
        let env = bus_env().ok_or(FAILED)?;
        let mut child = Command::new(tool)
            .args(args)
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| FAILED)?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input.unwrap_or("").as_bytes());
        }
        child.wait_with_output().map_err(|_| FAILED.into())
    }

    pub fn get(service: &str, account: &str) -> Result<Option<SecretString>, String> {
        let out = run(&["lookup", "service", service, "account", account], None)?;
        if out.status.success() {
            let text = String::from_utf8(out.stdout).map_err(|_| FAILED)?;
            return Ok((!text.is_empty()).then(|| SecretString::new(text)));
        }
        // A missing item exits 1 without a message.
        if out.status.code() == Some(1) && out.stderr.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        Err(FAILED.into())
    }

    pub fn set(service: &str, account: &str, secret: &SecretString) -> Result<(), String> {
        let label = "--label=VaultOS master password";
        let out = run(
            &["store", label, "service", service, "account", account],
            Some(secret.expose()),
        )?;
        out.status.success().then_some(()).ok_or(FAILED.into())
    }

    pub fn delete(service: &str, account: &str) -> Result<(), String> {
        let out = run(&["clear", "service", service, "account", account], None)?;
        if out.status.success() || out.status.code() == Some(1) {
            return Ok(());
        }
        Err(FAILED.into())
    }
}
