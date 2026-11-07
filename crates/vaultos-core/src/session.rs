//! `daemon.json`: how clients find the running daemon. It names the socket and holds the
//! session token, so it is private to the user (0600) like the data folder around it.

use crate::error::{Error, Result};
use crate::fs_safe::{atomic_write, read_regular, regular_file};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SESSION_FILE: &str = "daemon.json";
pub const SOCKET_FILE: &str = "vaultosd.sock";
/// `sun_path` holds 104 bytes on macOS and 108 on Linux, terminator included.
pub const MAX_SOCKET_PATH: usize = 100;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub app: String,
    pub socket: PathBuf,
    pub token: String,
    pub pid: u32,
    pub format_version: u64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("socket", &self.socket)
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

pub fn session_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SESSION_FILE)
}

pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The socket's name outside the data folder: one per data folder.
fn fallback_name(data_dir: &Path) -> String {
    let hash = crate::crypto::sha256_hex(data_dir.as_os_str().as_encoded_bytes());
    format!("vaultosd-{}.sock", &hash[..16])
}

/// A short folder private to this user, for when the data folder's path is too long for a
/// socket: `$XDG_RUNTIME_DIR/vaultos`, else `vaultos-UID` in the temporary folder.
fn fallback_dir() -> PathBuf {
    if let Some(run) = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        return run.join("vaultos");
    }
    std::env::temp_dir().join(format!("vaultos-{}", euid()))
}

/// Whether `dir` is a real folder (not a link) owned by this user and closed to others, so
/// nobody else can replace a socket in it.
pub fn private_to_us(dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(dir)
        .is_ok_and(|m| m.is_dir() && m.uid() == euid() && m.mode() & 0o077 == 0)
}

/// Where the daemon listens: `vaultosd.sock` in the data folder, or, when that path is too
/// long for a socket, a per-folder name in a short folder private to this user.
pub fn socket_path(data_dir: &Path) -> Result<PathBuf> {
    let p = data_dir.join(SOCKET_FILE);
    if p.as_os_str().len() <= MAX_SOCKET_PATH {
        return Ok(p);
    }
    let p = fallback_dir().join(fallback_name(data_dir));
    if p.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(Error::invalid(
            "The data folder's path is too long for a socket; use a shorter VAULTOS_DATA_DIR",
        ));
    }
    Ok(p)
}

/// Creates the socket's folder when it is not the data folder, and checks that it is
/// private to this user.
pub fn prepare_socket_dir(socket: &Path, data_dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let Some(dir) = socket.parent().filter(|d| *d != data_dir) else {
        return Ok(());
    };
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::io("cannot create the socket folder")(e)),
    }
    if !private_to_us(dir) {
        return Err(Error::Forbidden(format!(
            "The socket folder {} is not private to this user; remove it or set XDG_RUNTIME_DIR",
            dir.display()
        )));
    }
    Ok(())
}

/// A socket the session file may name: the data folder's own, or this data folder's name in
/// a folder private to this user.
fn trusted_socket(socket: &Path, data_dir: &Path) -> bool {
    if socket == data_dir.join(SOCKET_FILE) {
        return true;
    }
    socket.is_absolute()
        && socket.file_name() == Some(std::ffi::OsStr::new(&fallback_name(data_dir)))
        && socket.parent().is_some_and(private_to_us)
}

fn is_token(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Session {
    pub fn new(socket: PathBuf, token: String) -> Session {
        Session {
            app: crate::paths::APP_DIR.to_owned(),
            socket,
            token,
            pid: std::process::id(),
            format_version: crate::format::VERSION,
        }
    }

    pub fn write(&self, data_dir: &Path) -> Result<()> {
        let bytes = serde_json::to_vec(self).map_err(|e| Error::Format(e.to_string()))?;
        atomic_write(&session_path(data_dir), &bytes)
    }

    /// The session file, if present and well formed. A malformed one is treated as absent.
    pub fn read(data_dir: &Path) -> Option<Session> {
        let file = session_path(data_dir);
        regular_file(&file, true, 4096).ok().flatten()?;
        let s: Session = serde_json::from_slice(&read_regular(&file, 4096).ok()?).ok()?;
        let valid = s.app == crate::paths::APP_DIR
            && is_token(&s.token)
            && s.pid > 0
            && trusted_socket(&s.socket, data_dir);
        valid.then_some(s)
    }

    /// Removes the session file if it is still this one, so a newer daemon's is kept.
    pub fn remove_if_ours(&self, data_dir: &Path) {
        if Session::read(data_dir).is_some_and(|s| s.token == self.token) {
            let _ = std::fs::remove_file(session_path(data_dir));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_strangers() -> Result<()> {
        let dir = tempfile::tempdir().map_err(Error::io("tempdir"))?;
        let s = Session::new(socket_path(dir.path())?, "ab".repeat(32));
        s.write(dir.path())?;
        assert_eq!(Session::read(dir.path()), Some(s.clone()));
        let other = Session::new(PathBuf::from("/elsewhere/vaultosd.sock"), "cd".repeat(32));
        other.write(dir.path())?;
        assert_eq!(
            Session::read(dir.path()),
            None,
            "a socket outside the data folder"
        );
        s.write(dir.path())?;
        Session::new(s.socket.clone(), "ef".repeat(32)).remove_if_ours(dir.path());
        assert!(Session::read(dir.path()).is_some(), "kept: not ours");
        s.remove_if_ours(dir.path());
        assert!(Session::read(dir.path()).is_none());
        Ok(())
    }

    #[test]
    fn a_long_data_folder_gets_a_socket_in_a_private_folder() -> Result<()> {
        let dir = tempfile::tempdir().map_err(Error::io("tempdir"))?;
        let long = dir.path().join("d".repeat(120));
        std::fs::create_dir(&long).map_err(Error::io("mkdir"))?;
        let socket = socket_path(&long)?;
        assert_ne!(socket.parent(), Some(long.as_path()));
        assert!(socket.as_os_str().len() <= MAX_SOCKET_PATH);
        assert_eq!(socket_path(&long)?, socket, "the same path every time");
        prepare_socket_dir(&socket, &long)?;
        let parent = socket.parent().ok_or(Error::Locked)?;
        assert!(private_to_us(parent));

        let s = Session::new(socket.clone(), "ab".repeat(32));
        s.write(&long)?;
        assert_eq!(Session::read(&long), Some(s));
        // Another data folder's socket name in the same folder is not trusted.
        Session::new(parent.join(fallback_name(dir.path())), "cd".repeat(32)).write(&long)?;
        assert_eq!(Session::read(&long), None);
        Ok(())
    }

    #[test]
    fn a_shared_socket_folder_is_refused() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().map_err(Error::io("tempdir"))?;
        let data = dir.path().join("data");
        let shared = dir.path().join("shared");
        std::fs::create_dir_all(&shared).map_err(Error::io("mkdir"))?;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755))
            .map_err(Error::io("chmod"))?;
        let socket = shared.join(fallback_name(&data));
        assert!(prepare_socket_dir(&socket, &data).is_err());
        assert!(!trusted_socket(&socket, &data));
        Ok(())
    }
}
