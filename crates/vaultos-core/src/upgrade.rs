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
use crate::fs_safe::{atomic_write, claim, private_dir, read_regular, sync_dir, MAX_VAULT_BYTES};
use crate::history::{self, Payload};
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
    sync_dir(&backups)?;
    sync_dir(dir)?;
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
/// holds exactly what `original` held, except the `drop` oldest history entries, which the
/// size cap removes as the earlier app would at its next save.
fn same(original: &VaultV3, round: &VaultV3, drop: usize) -> Result<()> {
    let differ = || {
        Error::Format("the upgraded vault did not match the original; nothing was changed".into())
    };
    let mut a = comparable(original);
    let mut b = comparable(round);
    if drop > a.history.len() {
        return Err(differ());
    }
    let kept = a.history.split_off(drop);
    let round_history = std::mem::take(&mut b.history);
    a.history.clear();
    let vaults = (serde_json::to_value(&a), serde_json::to_value(&b));
    let histories = (
        serde_json::to_value(&kept),
        serde_json::to_value(&round_history),
    );
    match (vaults, histories) {
        ((Ok(x), Ok(y)), (Ok(h1), Ok(h2))) if x == y && h1 == h2 => Ok(()),
        _ => Err(differ()),
    }
}

/// Sets aside a v4 audit log left by an earlier, unfinished attempt; the new vault's chain
/// starts empty. The v3 `audit.log` stays where it is, with the v3 backup it belongs to.
/// Upgrades the v3 vault in `data_dir` to v4, keeping the same password and optionally
/// adding a Secret Key.
///
/// Everything that can fail happens before the new file replaces the old one: the backup, the
/// first audit entry (whose head the new vault records) and the check that the new file
/// decodes to the original. Replacing the file is the last step, so an error means the v3
/// vault is still in place, except [`Error::Unconfirmed`]: v4 is in place but the system
/// could not confirm it reached the disk.
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
    let mut sizes: Vec<u64> = original.history.iter().map(history::logical_size).collect();
    sizes.push(state.history.last().map_or(0, |e| e.size));
    let expected_drop = history::trim_count(&sizes);

    let backup = write_backup(data_dir, &bytes)?;
    let detail = format!(
        "from v3; backup {}",
        backup.file_name().and_then(|n| n.to_str()).unwrap_or("")
    );
    // A v4 log already here belongs to no vault this upgrade produces.
    let head = audit::restart(
        data_dir,
        &keys.vault_id,
        &keys.audit_seed,
        "before-upgrade",
        "upgrade_v4",
        &detail,
    )?;
    let encoded = store::encode_new(&keys, &mut state, Some(&head))?;
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
    same(&original, &round, expected_drop)?;
    drop(round);

    if read_regular(&vault, MAX_VAULT_BYTES)? != bytes {
        return Err(Error::Stale);
    }
    atomic_write(&vault, &encoded)?;

    Ok(Upgraded {
        backup,
        projects: original.projects.len(),
        items: original.projects.iter().map(|p| p.secrets.len()).sum(),
        history: s2.history.len(),
    })
}
