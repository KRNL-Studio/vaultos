//! The explicit, one-way upgrade from the JavaScript app's format v3 to v4. Nothing upgrades
//! automatically: the owner asks for it, and the old file is kept as a backup first.
//!
//! The caller must already hold `owner.lock` (as an unlocked session does); the upgrade takes
//! `write.lock` itself. The new file is decoded again with the password and compared with the
//! original before it replaces anything, and it replaces the vault only if the vault did not
//! change in the meantime.

use crate::audit;
use crate::crypto::{sha256_hex, KdfParams};
use crate::error::{Error, Result};
use crate::format::{account_unlock_key, VaultFile};
use crate::fs_safe::{atomic_write, claim, private_dir, read_regular, MAX_VAULT_BYTES};
use crate::history::Payload;
use crate::model::{now_iso, VaultV3, HUMAN};
use crate::secret::SecretString;
use crate::secret_key::SecretKey;
use crate::store::{self, VAULT_FILE};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upgraded {
    /// The untouched v3 file, readable by the earlier app with the earlier password.
    pub backup: PathBuf,
    pub projects: usize,
    pub items: usize,
    pub history: usize,
}

fn write_backup(dir: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let backups = dir.join("backups");
    private_dir(&backups)?;
    let stamp: String = now_iso().chars().filter(char::is_ascii_digit).collect();
    let path = backups.join(format!("vault-v3-{stamp}-{}.enc", &sha256_hex(bytes)[..8]));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(&path)
        .map_err(Error::io("cannot create the upgrade backup"))?;
    f.write_all(bytes)
        .map_err(Error::io("cannot write the upgrade backup"))?;
    f.sync_all()
        .map_err(Error::io("cannot flush the upgrade backup"))?;
    Ok(path)
}

/// The v3 vault as v4 will reproduce it: the reader-version fields are not carried over.
fn comparable(v: &VaultV3) -> VaultV3 {
    let mut v = v.clone();
    v.format_version = None;
    v.min_reader_version = None;
    v
}

/// Checks that `round` (decoded from the new file, without the upgrade's own history entry)
/// holds exactly what `original` held. History may have lost its oldest entries to the size
/// cap, so it must be a suffix of the original's.
fn same(original: &VaultV3, round: &VaultV3) -> Result<()> {
    let differ = || {
        Error::Format("the upgraded vault did not match the original; nothing was changed".into())
    };
    let mut a = comparable(original);
    let mut b = comparable(round);
    let skip = a
        .history
        .len()
        .checked_sub(b.history.len())
        .ok_or_else(differ)?;
    let tail = a.history.split_off(skip);
    let round_history = std::mem::take(&mut b.history);
    a.history.clear();
    let vaults = (serde_json::to_value(&a), serde_json::to_value(&b));
    let histories = (
        serde_json::to_value(&tail),
        serde_json::to_value(&round_history),
    );
    match (vaults, histories) {
        ((Ok(x), Ok(y)), (Ok(h1), Ok(h2))) if x == y && h1 == h2 => Ok(()),
        _ => Err(differ()),
    }
}

/// Moves the v3 activity log to `audit-v3.log` (the v4 chain starts empty) and sets aside a
/// v4 log left by an earlier attempt.
fn rotate_logs(dir: &Path) -> Result<()> {
    let old = dir.join("audit.log");
    if old.exists() {
        let mut to = dir.join("audit-v3.log");
        if to.exists() {
            to = dir.join(format!(
                "audit-v3-{}.log",
                now_iso()
                    .chars()
                    .filter(char::is_ascii_digit)
                    .collect::<String>()
            ));
        }
        std::fs::rename(&old, &to).map_err(Error::io("cannot keep the previous activity log"))?;
    }
    let stale = dir.join(audit::FILE);
    if stale.exists() {
        let to = dir.join(format!(
            "audit-v4.before-upgrade-{}.log",
            now_iso()
                .chars()
                .filter(char::is_ascii_digit)
                .collect::<String>()
        ));
        std::fs::rename(&stale, &to).map_err(Error::io("cannot set aside an earlier audit log"))?;
    }
    Ok(())
}

/// Upgrades the v3 vault in `data_dir` to v4, keeping the same password and optionally
/// adding a Secret Key.
pub fn upgrade(
    data_dir: &Path,
    password: &SecretString,
    secret_key: Option<&SecretKey>,
    params: KdfParams,
) -> Result<Upgraded> {
    params.validate()?;
    let vault = data_dir.join(VAULT_FILE);
    let _write = claim(data_dir, "write.lock")?;
    let bytes = read_regular(&vault, MAX_VAULT_BYTES)?;
    match crate::v3::envelope_version(&bytes)? {
        1 | 2 => {}
        4 => return Err(Error::invalid("This vault already uses format v4")),
        v => return Err(Error::UnsupportedVersion(v)),
    }
    let original = crate::v3::decrypt(&bytes, password.expose())?;

    let (keys, mut state) = store::from_v3(&original, password, secret_key, params)?;
    keys.history_entry(
        &mut state,
        HUMAN,
        "upgrade_v4",
        None,
        None,
        Payload::default(),
        None,
    )?;
    let encoded = store::encode_new(&keys, &mut state)?;
    drop(state);
    drop(keys);

    let file = VaultFile::parse(&encoded)?;
    let auk = account_unlock_key(password, secret_key, &file.kdf, &file.vault_id)?;
    let (k2, s2) = store::decode(&file, auk)?;
    let mut round = store::export_v3(&k2, &s2)?;
    if round.history.pop().map(|e| e.action) != Some("upgrade_v4".into()) {
        return Err(Error::Format(
            "the upgraded vault is missing its upgrade record".into(),
        ));
    }
    same(&original, &round)?;
    drop(round);

    let backup = write_backup(data_dir, &bytes)?;
    if read_regular(&vault, MAX_VAULT_BYTES)? != bytes {
        return Err(Error::Stale);
    }
    atomic_write(&vault, &encoded)?;
    rotate_logs(data_dir)?;
    let detail = format!(
        "from v3; backup {}",
        backup.file_name().and_then(|n| n.to_str()).unwrap_or("")
    );
    audit::append(
        data_dir,
        &k2.vault_id,
        &k2.audit_seed,
        None,
        HUMAN,
        "upgrade_v4",
        &detail,
    )?;

    Ok(Upgraded {
        backup,
        projects: original.projects.len(),
        items: original.projects.iter().map(|p| p.secrets.len()).sum(),
        history: s2.history.len(),
    })
}
