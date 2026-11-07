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

/// The socket's path, refused when the operating system could not bind it.
pub fn socket_path(data_dir: &Path) -> Result<PathBuf> {
    let p = data_dir.join(SOCKET_FILE);
    if p.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(Error::invalid(
            "The data folder's path is too long for a socket; use a shorter VAULTOS_DATA_DIR",
        ));
    }
    Ok(p)
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
            && s.socket.is_absolute()
            && s.socket.parent() == Some(data_dir);
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
}
