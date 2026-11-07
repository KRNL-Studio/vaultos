//! File rules shared with the JavaScript app: private directories, regular unlinked files
//! only, atomic replacement with fsync, and the same pid lock files (`owner.lock`,
//! `write.lock`) so the two implementations never write a vault at the same time.

use crate::crypto::{hex, random_array};
use crate::error::{Error, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

pub const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;

pub fn private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).map_err(Error::io("cannot create the data directory"))?;
    let meta = fs::symlink_metadata(dir).map_err(Error::io("cannot read the data directory"))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(Error::invalid(
            "The data directory must be a real directory, not a link",
        ));
    }
    #[cfg(unix)]
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(Error::io("cannot make the data directory private"))?;
    Ok(())
}

/// Refuses links, hard-linked files and oversized files, as `fs-safe.js` does.
pub fn regular_file(file: &Path, optional: bool, max: u64) -> Result<Option<fs::Metadata>> {
    let meta = match fs::symlink_metadata(file) {
        Ok(m) => m,
        Err(e) if optional && e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::Io {
                context: "cannot read a vault file",
                source: e,
            })
        }
    };
    #[cfg(unix)]
    let links = meta.nlink();
    #[cfg(not(unix))]
    let links = 1;
    if !meta.is_file() || meta.file_type().is_symlink() || links != 1 {
        return Err(Error::invalid("Expected a regular, unlinked file"));
    }
    if meta.len() > max {
        return Err(Error::invalid("File exceeds the allowed size"));
    }
    Ok(Some(meta))
}

/// One version of a file, known without reading it: device, inode, size, and modification
/// and change times. Every save renames a new file over the vault, so a save by any process
/// changes it; an in-place rewrite changes the change time, which no program can set back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl FileId {
    /// `None` when the file system keeps whole-second times (both nanosecond parts are
    /// zero): two writes within a second could look the same, so callers compare contents.
    #[cfg(unix)]
    pub(crate) fn of(m: &fs::Metadata) -> Option<FileId> {
        if m.mtime_nsec() == 0 && m.ctime_nsec() == 0 {
            return None;
        }
        Some(FileId {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        })
    }

    /// Elsewhere there is no inode, so callers fall back to comparing contents.
    #[cfg(not(unix))]
    pub(crate) fn of(_: &fs::Metadata) -> Option<FileId> {
        None
    }
}

/// The current version of `file`, or `None` if it does not exist.
pub fn file_id(file: &Path) -> Result<Option<FileId>> {
    Ok(regular_file(file, true, MAX_VAULT_BYTES)?.and_then(|m| FileId::of(&m)))
}

/// Reads `file` and identifies the version read, from the same open handle.
pub fn read_with_id(file: &Path, max: u64) -> Result<(Vec<u8>, Option<FileId>)> {
    regular_file(file, false, max)?;
    let f = File::open(file).map_err(Error::io("cannot open a vault file"))?;
    let id = f.metadata().ok().and_then(|m| FileId::of(&m));
    Ok((read_open(f, max)?, id))
}

pub fn read_regular(file: &Path, max: u64) -> Result<Vec<u8>> {
    regular_file(file, false, max)?;
    read_open(
        File::open(file).map_err(Error::io("cannot open a vault file"))?,
        max,
    )
}

fn read_open(f: File, max: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut out)
        .map_err(Error::io("cannot read a vault file"))?;
    if out.len() as u64 > max {
        return Err(Error::invalid("File exceeds the allowed size"));
    }
    Ok(out)
}

/// Writes to a private temporary file beside `file`, fsyncs, renames over it and fsyncs the
/// directory, so a crash leaves either the old or the new file, never a mix.
///
/// Any error before the rename leaves the old file. If only the final directory flush fails,
/// the new file is already in place and the error is [`Error::Unconfirmed`]: the caller must
/// treat the write as done.
pub fn atomic_write(file: &Path, bytes: &[u8]) -> Result<()> {
    regular_file(file, true, u64::MAX)?;
    let dir = file.parent().unwrap_or(Path::new("."));
    let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("vault");
    let tmp = dir.join(format!(".{name}.{}", hex(&random_array::<12>())));
    let result = (|| {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts
            .open(&tmp)
            .map_err(Error::io("cannot create a temporary file"))?;
        f.write_all(bytes)
            .map_err(Error::io("cannot write the vault"))?;
        f.sync_all()
            .map_err(Error::io("cannot flush the vault to disk"))?;
        drop(f);
        regular_file(file, true, u64::MAX)?;
        fs::rename(&tmp, file).map_err(Error::io("cannot replace the vault file"))?;
        sync_dir(dir).map_err(|e| match e {
            Error::Io { source, .. } => Error::Unconfirmed(source),
            other => other,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Flushes a directory, so a file just created or renamed in it survives a power loss. File
/// systems that cannot sync a directory (they report it as unsupported) are accepted; any
/// other failure is an error, because the caller would otherwise report a save that may not
/// last.
pub fn sync_dir(dir: &Path) -> Result<()> {
    let d = File::open(dir).map_err(Error::io("cannot open a directory to flush it"))?;
    match d.sync_all() {
        Ok(()) => Ok(()),
        #[cfg(unix)]
        Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENOTSUP)) => Ok(()),
        Err(e) => Err(Error::Io {
            context: "cannot flush a directory to disk",
            source: e,
        }),
    }
}

/// A held lock: the pid file the JavaScript app understands, and (on Unix) an exclusive
/// `flock` on a companion file that is never deleted. The kernel drops the `flock` when the
/// process exits, so two Rust processes can never both take over a stale pid file.
/// Dropping it removes the pid file if it still names this process, then releases the
/// `flock`.
#[derive(Debug)]
pub struct LockFile {
    path: PathBuf,
    pid: String,
    #[cfg(unix)]
    _guard: File,
}

impl Drop for LockFile {
    fn drop(&mut self) {
        if fs::read_to_string(&self.path).is_ok_and(|s| s == self.pid) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn pid_alive(pid: i32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: kill with signal 0 only checks whether the process exists.
        let r = unsafe { libc::kill(pid, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Takes the exclusive `flock` on `dir/.NAME.flock` without waiting.
#[cfg(unix)]
fn flock_guard(dir: &Path, name: &str) -> Result<File> {
    use std::os::fd::AsRawFd;
    let path = dir.join(format!(".{name}.flock"));
    regular_file(&path, true, 0)?;
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    opts.mode(0o600);
    let f = opts
        .open(&path)
        .map_err(Error::io("cannot open a lock file"))?;
    // SAFETY: flock on a descriptor this function owns; no memory is involved.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Error::Busy
        } else {
            Error::Io {
                context: "cannot take a lock",
                source: e,
            }
        });
    }
    Ok(f)
}

/// Takes over a stale lock as `session.js` does: renames it aside, and removes it only if it
/// still holds `held` (the dead process's pid). A lock created meanwhile by another process
/// is put back and the claim fails, so a takeover never deletes a live lock.
fn take_over(path: &Path, held: &[u8]) -> Result<()> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("lock");
    let aside = path.with_file_name(format!("{name}.stale-{}", hex(&random_array::<6>())));
    match fs::rename(path, &aside) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io("cannot take over a stale lock")(e)),
    }
    let current = fs::read(&aside).ok();
    if current.as_deref() != Some(held) {
        let _ = fs::hard_link(&aside, path);
        let _ = fs::remove_file(&aside);
        return Err(Error::Busy);
    }
    let _ = fs::remove_file(&aside);
    Ok(())
}

/// Claims `dir/name` the way `session.js` does: create-exclusive with our pid, and take over
/// only a lock whose process no longer exists. Rust processes also hold the `flock`, so two
/// of them never race; a JavaScript process racing a takeover finds the lock renamed aside
/// and put back rather than deleted (see `take_over`).
pub fn claim(dir: &Path, name: &str) -> Result<LockFile> {
    #[cfg(unix)]
    let guard = flock_guard(dir, name)?;
    let path = dir.join(name);
    let pid = std::process::id().to_string();
    for _ in 0..2 {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        match opts.open(&path) {
            Ok(mut f) => {
                let lock = LockFile {
                    path,
                    pid,
                    #[cfg(unix)]
                    _guard: guard,
                };
                f.write_all(lock.pid.as_bytes())
                    .map_err(Error::io("cannot write a lock file"))?;
                return Ok(lock);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let held = read_regular(&path, 128)?;
                let other: i32 = std::str::from_utf8(&held)
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .filter(|p| *p > 0)
                    .ok_or_else(|| {
                        Error::invalid("Invalid lock file; inspect it before removing it")
                    })?;
                if pid_alive(other) {
                    return Err(Error::Busy);
                }
                take_over(&path, &held)?;
            }
            Err(e) => {
                return Err(Error::Io {
                    context: "cannot create a lock file",
                    source: e,
                })
            }
        }
    }
    Err(Error::Busy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_and_stays_private() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("vault.enc");
        atomic_write(&f, b"one").unwrap();
        atomic_write(&f, b"two").unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"two");
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_dir(d.path()).unwrap().count(),
            1,
            "no temporary files left"
        );
    }

    #[test]
    fn a_stale_lock_is_taken_over_but_a_live_one_is_put_back() {
        let d = tempfile::tempdir().unwrap();
        let lock = d.path().join("owner.lock");
        // A pid that cannot be running.
        fs::write(&lock, b"2147483646").unwrap();
        let held = claim(d.path(), "owner.lock").unwrap();
        assert_eq!(
            fs::read_to_string(&lock).unwrap(),
            std::process::id().to_string()
        );
        drop(held);
        assert!(!lock.exists());

        // Another process replaced the stale lock between our read and the takeover.
        fs::write(&lock, b"1").unwrap();
        assert!(matches!(take_over(&lock, b"2147483646"), Err(Error::Busy)));
        assert_eq!(fs::read(&lock).unwrap(), b"1", "the live lock is back");
        let aside = fs::read_dir(d.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .is_ok_and(|e| e.file_name().to_string_lossy().contains(".stale-"))
            })
            .count();
        assert_eq!(aside, 0, "nothing left aside");
    }

    #[cfg(unix)]
    #[test]
    fn links_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        fs::write(&real, b"x").unwrap();
        let link = d.path().join("vault.enc");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_regular(&link, 10).is_err());
        assert!(atomic_write(&link, b"y").is_err());
        let hard = d.path().join("hard");
        fs::hard_link(&real, &hard).unwrap();
        assert!(read_regular(&hard, 10).is_err());
    }

    #[test]
    fn locks_exclude_live_holders_and_recover_dead_ones() {
        let d = tempfile::tempdir().unwrap();
        let held = claim(d.path(), "write.lock").unwrap();
        assert!(matches!(claim(d.path(), "write.lock"), Err(Error::Busy)));
        drop(held);
        assert!(!d.path().join("write.lock").exists());
        // A lock left by a process that no longer exists is taken over.
        fs::write(d.path().join("write.lock"), "999999999").unwrap();
        let _again = claim(d.path(), "write.lock").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_stale_pid_file_is_taken_over_by_one_process_only() {
        let d = tempfile::tempdir().unwrap();
        let held = claim(d.path(), "write.lock").unwrap();
        // The pid file disappears (as if its owner died and someone removed it), but the
        // flock still excludes a second Rust claimant.
        fs::write(d.path().join("write.lock"), "999999999").unwrap();
        assert!(matches!(claim(d.path(), "write.lock"), Err(Error::Busy)));
        drop(held);
        assert!(claim(d.path(), "write.lock").is_ok());
    }
}
