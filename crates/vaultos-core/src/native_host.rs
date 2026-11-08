//! Registers `vaultos-browser` as the native messaging host for the VaultOS extension in
//! Chromium browsers, for this user only. Each browser reads a small manifest, named after
//! the host, from its own `NativeMessagingHosts` folder; the manifest names the program and
//! the one extension allowed to start it. Nothing here is secret.

use crate::error::{Error, Result};
use crate::fs_safe;
use std::path::{Path, PathBuf};

/// The host's name, in the preview's namespace.
pub const HOST_NAME: &str = "org.vaultos.preview.browser";
/// The extension's ID, fixed by the public key in its manifest.
pub const EXTENSION_ID: &str = "dmimjgolkikglfcphbakbmkaafaadhnb";
/// The origin `vaultos-browser` is given for Safari. Safari's own extension origin is a
/// random UUID, and only the extension packaged with VaultOS's app extension can message
/// it, so the app extension names itself with its bundle identifier.
pub const SAFARI_ORIGIN: &str = "safari-web-extension://org.vaultos.preview.safari/";

/// Chromium browsers and their user data folders, relative to the home folder.
#[cfg(target_os = "macos")]
const BROWSERS: &[(&str, &str)] = &[
    ("Chrome", "Library/Application Support/Google/Chrome"),
    ("Chromium", "Library/Application Support/Chromium"),
    (
        "Brave",
        "Library/Application Support/BraveSoftware/Brave-Browser",
    ),
    ("Edge", "Library/Application Support/Microsoft Edge"),
    ("Arc", "Library/Application Support/Arc/User Data"),
    ("Helium", "Library/Application Support/net.imput.helium"),
    ("Vivaldi", "Library/Application Support/Vivaldi"),
];
#[cfg(not(target_os = "macos"))]
const BROWSERS: &[(&str, &str)] = &[
    ("Chrome", ".config/google-chrome"),
    ("Chromium", ".config/chromium"),
    ("Brave", ".config/BraveSoftware/Brave-Browser"),
    ("Edge", ".config/microsoft-edge"),
    ("Helium", ".config/net.imput.helium"),
    ("Vivaldi", ".config/vivaldi"),
];

/// One browser this user has, and whether the host is registered in it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserHost {
    pub browser: String,
    pub manifest: PathBuf,
    pub installed: bool,
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .ok_or_else(|| Error::invalid("HOME is not set"))
}

fn manifest_in(user_data: &Path) -> PathBuf {
    user_data
        .join("NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"))
}

/// The browsers found in `home` (those whose user data folder exists).
pub fn browsers_in(home: &Path) -> Vec<BrowserHost> {
    BROWSERS
        .iter()
        .map(|(name, dir)| (name, home.join(dir)))
        .filter(|(_, dir)| dir.is_dir())
        .map(|(name, dir)| {
            let manifest = manifest_in(&dir);
            BrowserHost {
                browser: (*name).to_owned(),
                installed: manifest.is_file(),
                manifest,
            }
        })
        .collect()
}

/// The browsers this user has.
pub fn browsers() -> Result<Vec<BrowserHost>> {
    Ok(browsers_in(&home()?))
}

/// The manifest's text for the host program at `program`.
pub fn manifest(program: &Path) -> Result<String> {
    let path = program
        .to_str()
        .filter(|_| program.is_absolute())
        .ok_or_else(|| Error::invalid("the host program's path must be absolute UTF-8"))?;
    let m = serde_json::json!({
        "name": HOST_NAME,
        "description": "VaultOS browser extension helper",
        "path": path,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")],
    });
    serde_json::to_string_pretty(&m).map_err(|_| Error::invalid("cannot encode the manifest"))
}

/// Registers `program` in every browser found in `home` (or only those named in `only`),
/// returning the browsers it was registered in.
pub fn install_in(home: &Path, program: &Path, only: &[String]) -> Result<Vec<BrowserHost>> {
    if !program.is_file() {
        return Err(Error::NotFound(format!(
            "{} is not there",
            program.display()
        )));
    }
    let text = manifest(program)?;
    let mut done = Vec::new();
    for b in browsers_in(home) {
        if !only.is_empty() && !only.iter().any(|o| o.eq_ignore_ascii_case(&b.browser)) {
            continue;
        }
        if let Some(dir) = b.manifest.parent() {
            std::fs::create_dir_all(dir)
                .map_err(Error::io("cannot create the NativeMessagingHosts folder"))?;
        }
        fs_safe::atomic_write(&b.manifest, text.as_bytes())?;
        done.push(BrowserHost {
            installed: true,
            ..b
        });
    }
    Ok(done)
}

/// Registers `program` for this user.
pub fn install(program: &Path, only: &[String]) -> Result<Vec<BrowserHost>> {
    install_in(&home()?, program, only)
}

/// Removes the registration from every browser found in `home`, returning those it was in.
pub fn uninstall_in(home: &Path) -> Result<Vec<BrowserHost>> {
    let mut done = Vec::new();
    for b in browsers_in(home).into_iter().filter(|b| b.installed) {
        std::fs::remove_file(&b.manifest).map_err(Error::io("cannot remove the host manifest"))?;
        done.push(BrowserHost {
            installed: false,
            ..b
        });
    }
    Ok(done)
}

/// Removes the registration for this user.
pub fn uninstall() -> Result<Vec<BrowserHost>> {
    uninstall_in(&home()?)
}

/// The unpacked extension folder shipped with `exe`: `Contents/Resources/extension` in the
/// macOS app (whose programs are in `Contents/MacOS` and `Contents/Helpers`), or `extension`
/// beside the Linux programs.
pub fn extension_dir(exe: &Path) -> Option<PathBuf> {
    let dir = exe.parent()?;
    [dir.join("../Resources/extension"), dir.join("extension")]
        .into_iter()
        .find(|d| d.join("manifest.json").is_file())
        .map(|d| std::fs::canonicalize(&d).unwrap_or(d))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]
    use super::*;

    #[test]
    fn installs_only_in_browsers_present() {
        let home = tempfile::tempdir().unwrap();
        let (chrome, brave) = (BROWSERS[0].1, BROWSERS[2].1);
        std::fs::create_dir_all(home.path().join(chrome)).unwrap();
        std::fs::create_dir_all(home.path().join(brave)).unwrap();
        let program = home.path().join("vaultos-browser");
        std::fs::write(&program, b"").unwrap();

        let found = browsers_in(home.path());
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|b| !b.installed));
        assert!(install_in(home.path(), Path::new("vaultos-browser"), &[]).is_err());

        let done = install_in(home.path(), &program, &["brave".to_owned()]).unwrap();
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].browser, "Brave");
        let m: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&done[0].manifest).unwrap()).unwrap();
        assert_eq!(m["name"], HOST_NAME);
        assert_eq!(m["path"], program.to_str().unwrap());
        assert_eq!(
            m["allowed_origins"],
            serde_json::json!(["chrome-extension://dmimjgolkikglfcphbakbmkaafaadhnb/"])
        );

        assert_eq!(install_in(home.path(), &program, &[]).unwrap().len(), 2);
        assert!(browsers_in(home.path()).iter().all(|b| b.installed));
        assert_eq!(uninstall_in(home.path()).unwrap().len(), 2);
        assert!(browsers_in(home.path()).iter().all(|b| !b.installed));
    }
}
