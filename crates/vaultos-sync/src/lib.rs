//! End-to-end encrypted sync over Git, sync format 2 (vault format 4).
//!
//! Each device encrypts every record and tombstone with age to every trusted device's X25519
//! key, writes it under an opaque name, and signs a manifest of every file's digest with its
//! Ed25519 key. A pull refuses the repository unless every file is signed by a trusted
//! device and no manifest went backwards, then merges three ways against what this device last
//! knew the repository held. Private keys live inside the vault, sealed like everything else.
//! The repository holds ciphertext, opaque names, public keys, counters and timestamps only.
//!
//! The merge rules and refusals are those of the JavaScript preview's `sync.js`; the file
//! format is new. A repository made by that preview (marker version 1) is refused.

mod git;

pub use git::GitRepo;

use age::secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use vaultos_core::canon::{canonical_json, record_hash};
use vaultos_core::crypto::{
    b64, ed25519_public, hex, hkdf, hmac_sha256, random_array, sha256_hex, sign_ed25519, unb64,
    unb64_array, verify_ed25519,
};
use vaultos_core::fs_safe::{atomic_write, read_regular, regular_file, MAX_VAULT_BYTES};
use vaultos_core::model::{now_iso, parse_iso, Record};
use vaultos_core::secret::{Key32, SecretValue};
use vaultos_core::store::{check_record, SyncChanges, SyncRecord, VAULT_FILE};
use vaultos_core::{validate, Store};
use zeroize::Zeroizing;

const APP: &str = "VaultOS-Preview";
const MARKER: &str = "vaultos-sync.json";
const MARKER_VERSION: u64 = 2;
const FORMAT: u64 = 4;
const DIRS: [&str; 6] = [
    "records",
    "tombstones",
    "machines",
    "manifests",
    "peers",
    "revoked",
];
const MAX_SYNC_FILE: u64 = 4 * 1024 * 1024;
const MAX_MANIFEST: u64 = 16 * 1024 * 1024;
const MAX_SMALL: u64 = 64 * 1024;
const MANIFEST_CONTEXT: &[u8] = b"vaultos/v4/sync-manifest\0";
const HEARTBEAT_CONTEXT: &[u8] = b"vaultos/v4/sync-heartbeat\0";
const REVOCATION_CONTEXT: &[u8] = b"vaultos/v4/sync-revocation\0";
/// The local sync index, in the data folder.
pub const INDEX_FILE: &str = "sync-index.json";
/// The names a push is writing, in the data folder, so a push that stopped half way can be
/// told from a tampered repository and finished.
const JOURNAL_FILE: &str = "sync-push.journal";

// A pull that changes the vault first copies vault.enc to backups/<ms>-<id>.enc. The newest
// BACKUPS_KEPT of those, and any younger than BACKUP_DAYS, are kept; other files there are
// never touched.
const BACKUPS_KEPT: usize = 20;
const BACKUP_DAYS: i128 = 30;

// ── Errors ──────────────────────────────────────────────────────────────────────────────

/// A sync failure, with the state autosync and the API report for it.
#[derive(Debug)]
pub struct SyncError {
    pub message: String,
    pub code: &'static str,
    pub status: u16,
    pub conflicts: usize,
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SyncError {}

impl SyncError {
    pub fn new(code: &'static str, message: impl Into<String>) -> SyncError {
        SyncError {
            message: message.into(),
            code,
            status: 409,
            conflicts: 0,
        }
    }

    fn plain(message: impl Into<String>) -> SyncError {
        SyncError {
            status: 400,
            ..SyncError::new("ERROR", message)
        }
    }

    fn refusal(problems: &[String]) -> SyncError {
        SyncError::new(
            "SIGNATURE_INVALID",
            format!("refusing to pull: {}", problems.join("; ")),
        )
    }

    fn locked() -> SyncError {
        SyncError {
            status: 423,
            ..SyncError::new("PAUSED_LOCKED", "Vault is locked")
        }
    }

    fn busy() -> SyncError {
        SyncError::new(
            "VAULT_BUSY",
            "Another process is still saving the vault; the next round syncs its copy",
        )
    }
}

impl From<vaultos_core::Error> for SyncError {
    fn from(e: vaultos_core::Error) -> SyncError {
        use vaultos_core::Error as E;
        match e {
            E::Locked => SyncError::locked(),
            E::Busy | E::Stale => SyncError::busy(),
            other => SyncError {
                status: other.status(),
                ..SyncError::new("ERROR", other.to_string())
            },
        }
    }
}

pub type Result<T> = std::result::Result<T, SyncError>;

// ── Names ───────────────────────────────────────────────────────────────────────────────

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The short code people compare between two devices: the first 64 bits of a device's
/// fingerprint, in four groups.
pub fn code(fingerprint: &str) -> String {
    let head: String = fingerprint.chars().take(16).collect();
    head.to_ascii_uppercase()
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// What a device's fingerprint is taken over: its id, label and two public keys.
fn identity_entry(identity: &Value) -> Value {
    json!({
        "id": str_of(identity, "id"),
        "label": str_of(identity, "label"),
        "signingPublicKey": str_of(identity, "signingPublicKey"),
        "agePublicKey": str_of(identity, "agePublicKey"),
    })
}

fn named(file: &str, len: usize, ext: &str) -> bool {
    file.strip_suffix(ext).is_some_and(|stem| is_hex(stem, len))
}

/// A record's or tombstone's file name: public, the same on every device, and unlinkable to
/// anything but the random ids inside the ciphertext.
pub fn opaque(reference: &str) -> String {
    sha256_hex(reference.as_bytes())
}

/// The files sync writes, by repository path. Anything else in its folders (Finder's
/// .DS_Store, an editor's backup, an interrupted write's temporary file) is not sync's: it is
/// never signed, decrypted, committed or deleted.
fn sync_file(rel: &str) -> bool {
    if rel == "recipients.txt" || rel == MARKER {
        return true;
    }
    let Some((dir, file)) = rel.split_once('/') else {
        return false;
    };
    match dir {
        "records" | "tombstones" => named(file, 64, ".age"),
        "machines" | "manifests" | "peers" | "revoked" => named(file, 16, ".json"),
        _ => false,
    }
}

fn in_sync_dir(rel: &str) -> bool {
    rel.split_once('/').is_some_and(|(d, _)| DIRS.contains(&d))
}

fn stray(rel: &str) -> bool {
    in_sync_dir(rel) && !sync_file(rel)
}

/// Git's own control files. One in the checkout changes what Git commits (a .gitignore can
/// keep out a record that this device's manifest signs) or the bytes it stores.
fn git_control(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    matches!(name, ".gitignore" | ".gitattributes" | ".gitmodules")
}

fn valid_reference(r: &str) -> bool {
    let ok = |id: &str| vaultos_core::format::check_id(id).is_ok();
    match r.split_once(':') {
        Some(("project", pid)) => ok(pid),
        Some((pid, rid)) => ok(pid) && ok(rid),
        None => false,
    }
}

fn ms(s: &str) -> Option<i128> {
    parse_iso(s).map(|t| t.unix_timestamp_nanos() / 1_000_000)
}

/// `Date.parse(x || 0)` in the JavaScript merge: a missing time counts as the epoch.
fn ms_or_epoch(s: &str) -> Option<i128> {
    if s.is_empty() {
        Some(0)
    } else {
        ms(s)
    }
}

fn later(a: Option<i128>, b: Option<i128>) -> bool {
    matches!((a, b), (Some(a), Some(b)) if a > b)
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(500).collect()
}

fn quoted(files: &[String]) -> String {
    files
        .iter()
        .take(3)
        .map(|f| Value::String(f.clone()).to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn read_json(file: &Path, max: u64) -> Result<Value> {
    let bytes = read_regular(file, max)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| SyncError::plain(format!("{} is not valid JSON", file.display())))
}

fn write_json(file: &Path, v: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(v).map_err(|e| SyncError::plain(e.to_string()))?;
    bytes.push(b'\n');
    Ok(atomic_write(file, &bytes)?)
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn private_mkdir(dir: &Path) -> Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
        .map_err(|e| SyncError::plain(format!("cannot create {}: {e}", dir.display())))
}

fn list_dir(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn file_digest(file: &Path) -> Result<String> {
    Ok(sha256_hex(&read_regular(file, MAX_SYNC_FILE)?))
}

fn now_ms() -> i128 {
    time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000
}

// ── Keys and the local index ────────────────────────────────────────────────────────────

/// This device's sync identity and private keys, kept in the vault.
struct Keys {
    machine_id: String,
    label: String,
    age: age::x25519::Identity,
    seed: Key32,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("machine_id", &self.machine_id)
            .finish_non_exhaustive()
    }
}

impl Keys {
    fn generate(label: &str) -> Keys {
        Keys {
            machine_id: hex(&random_array::<8>()),
            label: label.to_owned(),
            age: age::x25519::Identity::generate(),
            seed: Key32::from_bytes(random_array()),
        }
    }

    fn from_value(v: &Value) -> Result<Keys> {
        let bad =
            || SyncError::plain("This vault's sync keys are damaged; restore a trusted backup");
        let machine_id = str_of(v, "machineId");
        if !is_hex(machine_id, 16) || v.get("format").and_then(Value::as_u64) != Some(FORMAT) {
            return Err(bad());
        }
        let age = str_of(v, "ageIdentity")
            .parse::<age::x25519::Identity>()
            .map_err(|_| bad())?;
        let seed =
            Key32::from_bytes(unb64_array(str_of(v, "signingSeed"), "seed").map_err(|_| bad())?);
        Ok(Keys {
            machine_id: machine_id.to_owned(),
            label: str_of(v, "label").to_owned(),
            age,
            seed,
        })
    }

    fn to_value(&self) -> SecretValue {
        SecretValue::new(json!({
            "format": FORMAT,
            "machineId": self.machine_id,
            "label": self.label,
            "ageIdentity": self.age.to_string().expose_secret(),
            "signingSeed": b64(self.seed.expose()),
        }))
    }

    fn age_public(&self) -> String {
        self.age.to_public().to_string()
    }

    fn signing_public(&self) -> String {
        b64(&ed25519_public(&self.seed))
    }

    fn index_key(&self, purpose: &str) -> Key32 {
        hkdf(
            self.seed.expose(),
            self.machine_id.as_bytes(),
            format!("vaultos/v4/sync-index/{purpose}").as_bytes(),
        )
    }

    /// What the index stores for a record's hash: keyed, so the file beside the vault never
    /// holds a plain hash of a secret value that a weak value could be guessed from.
    fn keyed(&self, hash: &str) -> String {
        hex(&hmac_sha256(&self.index_key("hash"), hash.as_bytes()))
    }

    fn sign(&self, context: &[u8], v: &Value) -> String {
        let mut msg = context.to_vec();
        msg.extend_from_slice(canonical_json(v).as_bytes());
        b64(&sign_ed25519(&self.seed, &msg))
    }
}

fn verify_signed(public_b64: &str, context: &[u8], v: &Value, sig_b64: &str) -> bool {
    let Ok(public) = unb64_array::<32>(public_b64, "key") else {
        return false;
    };
    let Ok(sig) = unb64(sig_b64, "signature") else {
        return false;
    };
    let mut msg = context.to_vec();
    msg.extend_from_slice(canonical_json(v).as_bytes());
    verify_ed25519(&public, &msg, &sig)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastPush {
    pub counter: u64,
    pub at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Seen {
    counter: u64,
    hash: String,
    at: String,
}

/// One file as a manifest lists it: its digest and the push (device and counter) that wrote
/// that ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    digest: String,
    by: String,
    counter: u64,
}

impl Entry {
    fn to_json(&self) -> Value {
        json!({ "digest": self.digest, "by": self.by, "counter": self.counter })
    }
}

/// A manifest whose signature verified: its counter, the newest push of every other device
/// it had accepted when it was made, and its files.
#[derive(Debug)]
struct Accepted {
    id: String,
    counter: u64,
    hash: String,
    pushed_at: String,
    seen: BTreeMap<String, u64>,
    files: BTreeMap<String, Entry>,
}

impl Accepted {
    fn parse(id: &str, m: &Value) -> std::result::Result<Accepted, &'static str> {
        let counter = m.get("counter").and_then(Value::as_u64).unwrap_or(0);
        let (Some(files), Some(seen)) = (
            m.get("files").and_then(Value::as_object),
            m.get("seen").and_then(Value::as_object),
        ) else {
            return Err("Unsupported manifest");
        };
        if counter < 1 || m.get("format").and_then(Value::as_u64) != Some(FORMAT) {
            return Err("Unsupported manifest");
        }
        let push = |by: &str, c: Option<u64>| {
            c.filter(|c| *c >= 1 && is_hex(by, 16) && (by != id || *c <= counter))
        };
        let mut a = Accepted {
            id: id.to_owned(),
            counter,
            hash: sha256_hex(canonical_json(m).as_bytes()),
            pushed_at: str_of(m, "pushedAt").to_owned(),
            seen: BTreeMap::new(),
            files: BTreeMap::new(),
        };
        for (device, c) in seen {
            let c = push(device, c.as_u64()).filter(|_| device != id);
            a.seen.insert(device.clone(), c.ok_or("Invalid manifest")?);
        }
        for (name, e) in files {
            let sound = name.split_once('/').is_some_and(|(d, f)| {
                matches!(d, "records" | "tombstones") && named(f, 64, ".age")
            });
            let digest = str_of(e, "digest");
            let by = str_of(e, "by");
            let c = push(by, e.get("counter").and_then(Value::as_u64));
            match c {
                Some(counter) if sound && is_hex(digest, 64) => {
                    a.files.insert(
                        name.clone(),
                        Entry {
                            digest: digest.to_owned(),
                            by: by.to_owned(),
                            counter,
                        },
                    );
                }
                _ => return Err("Invalid manifest"),
            }
        }
        Ok(a)
    }

    /// Whether this manifest's device had accepted `device`'s push `counter` when it made it.
    fn saw(&self, device: &str, counter: u64) -> bool {
        if self.id == device {
            self.counter >= counter
        } else {
            self.seen.get(device).is_some_and(|c| *c >= counter)
        }
    }
}

/// What verification found: its problems, every file's entries that no later push replaced,
/// and each device's newest accepted counter.
#[derive(Debug, Default)]
struct Checked {
    problems: Vec<String>,
    valid: BTreeMap<String, Vec<Entry>>,
    latest: BTreeMap<String, u64>,
    /// Devices removed from sync, with the last push of each that its remover had accepted.
    retired: BTreeMap<String, u64>,
}

/// A device's removal from sync, signed by a device this one trusts.
#[derive(Clone, Debug)]
struct Revocation {
    label: String,
    by: String,
    by_label: String,
    last_counter: u64,
}

/// The names an unfinished push was writing or removing.
#[derive(Serialize, Deserialize)]
struct Journal {
    format: u64,
    names: BTreeSet<String>,
    mac: String,
}

/// What this device last knew the repository held: per record file, the keyed hash of the
/// record it holds; per tombstone file, its deletion time; and per device, the newest manifest
/// seen, so a manifest that goes back is refused.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Index {
    format: u64,
    records: BTreeMap<String, String>,
    tombstones: BTreeMap<String, String>,
    last_push: Option<LastPush>,
    seen_manifests: BTreeMap<String, Seen>,
    recipients_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
}

impl Index {
    fn mac(&self, keys: &Keys) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.mac = None;
        let v = serde_json::to_value(&unsigned).map_err(|e| SyncError::plain(e.to_string()))?;
        Ok(b64(&hmac_sha256(
            &keys.index_key("mac"),
            canonical_json(&v).as_bytes(),
        )))
    }
}

// ── Plans and results ───────────────────────────────────────────────────────────────────

/// A record as another device pushed it.
#[derive(Clone, Debug)]
pub struct Payload {
    pub reference: String,
    pub project_id: String,
    pub project_name: String,
    pub record: Record,
    pub hash: String,
    pub pushed_by: String,
    pub pushed_at: String,
}

#[derive(Clone, Debug)]
struct RemoteTomb {
    deleted_at: String,
    by: String,
}

/// The repository's records and tombstones by reference, and the files that would not decrypt.
type Decoded = (
    BTreeMap<String, Payload>,
    BTreeMap<String, RemoteTomb>,
    Vec<Value>,
);

/// What a pull would change, or changed.
#[derive(Debug, Default)]
pub struct Plan {
    pub added: Vec<Payload>,
    pub updated: Vec<Payload>,
    pub deleted: Vec<String>,
    pub conflicts: Vec<Value>,
    pub unchanged: usize,
    pub unreadable: Vec<Value>,
    pub deleted_projects: Vec<(String, String)>,
}

impl Plan {
    pub fn changes(&self) -> bool {
        !(self.added.is_empty()
            && self.updated.is_empty()
            && self.deleted.is_empty()
            && self.deleted_projects.is_empty())
    }

    /// Counts, as `vaultos sync pull` prints them.
    pub fn summary(&self) -> Value {
        json!({
            "added": self.added.len(),
            "updated": self.updated.len(),
            "deleted": self.deleted.len(),
            "conflicts": self.conflicts,
        })
    }

    /// Names, as `vaultos sync plan` prints them. Never values.
    pub fn detail(&self) -> Value {
        let names = |v: &[Payload]| {
            v.iter()
                .map(|x| json!({ "project": x.project_name, "key": x.record.key }))
                .collect::<Vec<_>>()
        };
        json!({
            "added": names(&self.added),
            "updated": names(&self.updated),
            "deleted": self.deleted,
            "deletedProjects": self.deleted_projects.iter().map(|(id, name)| json!({ "id": id, "name": name })).collect::<Vec<_>>(),
            "conflicts": self.conflicts,
            "unreadable": self.unreadable,
        })
    }
}

/// What a push wrote locally.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Wrote {
    pub written: usize,
    pub unchanged: usize,
    pub removed: usize,
    pub counter: u64,
    pub reencrypted_for_new_recipients: bool,
}

/// A push written and committed locally, ready to deliver.
#[derive(Clone, Debug)]
pub struct Staged {
    pub wrote: Wrote,
    fingerprint: String,
    machine_id: String,
    no_git: bool,
    failed: Option<String>,
    commit: Option<git::Commit>,
}

#[derive(Clone, Debug, Default)]
struct Changes {
    own: Vec<String>,
    stray: Vec<String>,
    unrelated: Vec<String>,
}

/// One remote operation per repository at a time: autosync and a manual sync never overlap
/// in one checkout.
fn repo_lock(repo: &Path) -> &'static Mutex<()> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, &'static Mutex<()>>>> = OnceLock::new();
    let mut map = LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    map.entry(repo.to_owned())
        .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))))
}

/// Where the sync checkout is: `VAULTOS_SYNC_REPO`, or `sync-repository` in the data folder.
/// A relative path would name a different checkout in each process's working directory, so
/// it is refused.
pub fn default_repo(data_dir: &Path) -> Result<PathBuf> {
    match std::env::var_os("VAULTOS_SYNC_REPO").filter(|v| !v.is_empty()) {
        Some(v) if Path::new(&v).is_absolute() => Ok(PathBuf::from(v)),
        Some(_) => Err(SyncError::plain(
            "VAULTOS_SYNC_REPO must be an absolute path",
        )),
        None => Ok(data_dir.join("sync-repository")),
    }
}

// ── The engine ──────────────────────────────────────────────────────────────────────────

/// Sync between this vault and one Git checkout. Local steps take the store; network steps
/// do not, so an owner can serve requests while Git waits on the network.
#[derive(Debug)]
pub struct Sync {
    repo: PathBuf,
    data_dir: PathBuf,
    pub git: GitRepo,
}

impl Sync {
    pub fn new(data_dir: &Path, repo: &Path) -> Sync {
        Sync {
            repo: repo.to_owned(),
            data_dir: data_dir.to_owned(),
            git: GitRepo::new(repo),
        }
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }

    /// Holds this checkout for one remote operation.
    pub fn hold(&self) -> MutexGuard<'static, ()> {
        repo_lock(&self.repo)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.repo.join(name)
    }

    fn rel(&self, rel: &str) -> PathBuf {
        self.repo.join(rel)
    }

    fn index_path(&self) -> PathBuf {
        self.data_dir.join(INDEX_FILE)
    }

    /// Whether this device can sync: a sync checkout under Git, and keys in the vault.
    pub fn configured(&self, store: &Store) -> bool {
        self.dir(MARKER).exists()
            && self.git.is_repo()
            && store.sync_keys().ok().flatten().is_some()
    }

    fn keys(&self, store: &Store) -> Result<Keys> {
        match store.sync_keys()? {
            Some(v) => Keys::from_value(&v.open()),
            None => Err(SyncError::new(
                "NOT_CONFIGURED",
                "Initialize sync on this device first: vaultos sync init <machine-label>",
            )),
        }
    }

    fn read_index(&self, keys: &Keys) -> Result<Index> {
        let path = self.index_path();
        if regular_file(&path, true, MAX_VAULT_BYTES)?.is_none() {
            return Ok(Index {
                format: FORMAT,
                ..Index::default()
            });
        }
        let invalid = || SyncError::plain("Invalid sync index; restore a trusted backup");
        let idx: Index = serde_json::from_slice(&read_regular(&path, MAX_VAULT_BYTES)?)
            .map_err(|_| invalid())?;
        if idx.format != FORMAT || idx.mac.as_deref() != Some(idx.mac(keys)?.as_str()) {
            return Err(invalid());
        }
        Ok(idx)
    }

    fn write_index(&self, keys: &Keys, idx: &mut Index) -> Result<()> {
        idx.format = FORMAT;
        idx.mac = None;
        idx.mac = Some(idx.mac(keys)?);
        write_json(&self.index_path(), idx)
    }

    /// Creates the repository layout in a new, empty checkout, or checks an existing one.
    pub fn ensure_dirs(&self) -> Result<()> {
        let marker = self.dir(MARKER);
        if regular_file(&marker, true, 1024)?.is_none() {
            if list_dir(&self.repo).iter().any(|n| n != ".git") {
                return Err(SyncError::plain("Use a new, empty repository for sync"));
            }
            private_mkdir(&self.repo)?;
            atomic_write(
                &marker,
                canonical_json(&json!({ "app": APP, "version": MARKER_VERSION })).as_bytes(),
            )?;
        }
        let m = read_json(&marker, 1024)?;
        if str_of(&m, "app") != APP {
            return Err(SyncError::plain("Not a VaultOS sync repository"));
        }
        match m.get("version").and_then(Value::as_u64) {
            Some(MARKER_VERSION) => {}
            Some(1) => {
                return Err(SyncError::new(
                    "UNSUPPORTED_REPOSITORY",
                    "This sync repository was made by the VaultOS 0.2 preview (sync format 1), \
                     which this version cannot read or write. Start a new, empty repository and \
                     run `vaultos sync init` on each device; see docs/SYNC.md",
                ))
            }
            _ => {
                return Err(SyncError::new(
                    "UNSUPPORTED_REPOSITORY",
                    "This sync repository needs a newer VaultOS",
                ))
            }
        }
        for d in DIRS {
            let dir = self.dir(d);
            private_mkdir(&dir)?;
            if std::fs::symlink_metadata(&dir).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(SyncError::plain(
                    "Sync directories cannot be symbolic links",
                ));
            }
        }
        Ok(())
    }

    // ── Identity and trust ──────────────────────────────────────────────────────────────

    /// Enrols this device: keys (made once, kept in the vault), its public identity in
    /// `machines/`, its age key in `recipients.txt`, and trust in itself.
    pub fn init(&self, store: &mut Store, label: &str) -> Result<Value> {
        validate::text(label, "machine label", 100, false)?;
        if label.contains(['\r', '\n']) {
            return Err(SyncError::plain("Invalid machine label"));
        }
        self.ensure_dirs()?;
        let mut keys = match store.sync_keys()? {
            Some(v) => Keys::from_value(&v.open())?,
            None => Keys::generate(label),
        };
        let enrolling = store.sync_keys()?.is_none();
        if enrolling || keys.label != label {
            keys.label = label.to_owned();
            store.set_sync_keys(keys.to_value())?;
        }
        // An index already here was not written with these keys: VaultOS 0.2 leaves its own
        // behind, and it would stop every push as invalid. It is kept under another name.
        if enrolling && self.index_path().exists() {
            std::fs::rename(
                self.index_path(),
                self.data_dir.join("sync-index.before-enrolment.json"),
            )
            .map_err(|e| SyncError::plain(format!("cannot set aside the old sync index: {e}")))?;
        }
        let public = keys.age_public();
        let recipients_path = self.dir("recipients.txt");
        let recipients = match regular_file(&recipients_path, true, MAX_SMALL)? {
            Some(_) => {
                String::from_utf8_lossy(&read_regular(&recipients_path, MAX_SMALL)?).into_owned()
            }
            None => String::new(),
        };
        if !recipients.lines().any(|l| l.trim() == public) {
            atomic_write(
                &recipients_path,
                format!("{recipients}# {label}\n{public}\n").as_bytes(),
            )?;
        }
        let identity = json!({
            "id": keys.machine_id,
            "label": label,
            "signingPublicKey": keys.signing_public(),
            "agePublicKey": public,
        });
        let mut machine = identity.clone();
        if let Value::Object(m) = &mut machine {
            m.insert("format".into(), json!(FORMAT));
            m.insert("enrolledAt".into(), json!(now_iso()));
        }
        write_json(
            &self
                .dir("machines")
                .join(format!("{}.json", keys.machine_id)),
            &machine,
        )?;
        self.trust(store, &identity)?;
        Ok(identity)
    }

    /// This device's public identity, to verify and trust on the others.
    pub fn identity(&self, store: &Store) -> Result<Value> {
        let keys = self.keys(store)?;
        let trust = store.sync_trust()?;
        let Some(peer) = trust.get(&keys.machine_id) else {
            return Err(SyncError::plain("Initialize this machine first"));
        };
        let mut out = peer.clone();
        if let Value::Object(m) = &mut out {
            let fingerprint = sha256_hex(canonical_json(peer).as_bytes());
            m.insert("code".into(), json!(code(&fingerprint)));
            m.insert("fingerprint".into(), json!(fingerprint));
        }
        Ok(out)
    }

    /// Sets this device up from a repository address alone: makes the checkout (a clone when
    /// other devices already use the repository) and enrols. `joined` says whether other
    /// devices were found; they are in [`Sync::pending`] until approved here.
    pub fn setup(&self, store: &mut Store, url: &str, label: &str) -> Result<Value> {
        validate::text(label, "machine label", 100, false)?;
        let joined = git::prepare(&self.repo, url).map_err(SyncError::plain)?;
        self.init(store, label)?;
        Ok(json!({ "joined": joined, "identity": self.identity(store)? }))
    }

    /// The devices enrolled in the repository that this vault does not trust yet, each with
    /// the code to compare against the one that device shows for itself.
    pub fn pending(&self, store: &Store) -> Result<Value> {
        let trusted = store.sync_trust()?;
        let mut out = Vec::new();
        for file in list_dir(&self.dir("machines")) {
            if !named(&file, 16, ".json") {
                continue;
            }
            let Ok(machine) = read_json(&self.dir("machines").join(&file), MAX_SMALL) else {
                continue;
            };
            let entry = identity_entry(&machine);
            let id = str_of(&entry, "id");
            if file != format!("{id}.json") || trusted.contains_key(id) {
                continue;
            }
            let label: String = str_of(&entry, "label")
                .chars()
                .filter(|c| !c.is_control())
                .take(100)
                .collect();
            out.push(json!({
                "id": id,
                "label": label,
                "code": code(&sha256_hex(canonical_json(&entry).as_bytes())),
            }));
        }
        Ok(json!({ "pending": out }))
    }

    /// Trusts a pending device once a human has compared its code. The code is checked again
    /// here, against the identity being trusted, so a file swapped in between is refused.
    pub fn approve(&self, store: &mut Store, id: &str, confirmed: &str) -> Result<Value> {
        if !is_hex(id, 16) {
            return Err(SyncError::plain("Invalid device id"));
        }
        let machine = read_json(
            &self.dir("machines").join(format!("{id}.json")),
            MAX_SMALL,
        )
        .map_err(|_| SyncError::plain("That device is not waiting for approval"))?;
        let entry = identity_entry(&machine);
        let plain = |s: &str| {
            s.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_ascii_uppercase()
        };
        let shown = code(&sha256_hex(canonical_json(&entry).as_bytes()));
        if str_of(&entry, "id") != id || plain(&shown) != plain(confirmed) {
            return Err(SyncError::plain(
                "That code is not this device's. Compare it again with the one the other device shows",
            ));
        }
        self.trust(store, &entry)
    }

    /// Trusts a device's identity (from its `machines/` file or `vaultos sync identity`),
    /// after a human compared its fingerprint out of band.
    pub fn trust(&self, store: &mut Store, identity: &Value) -> Result<Value> {
        let invalid = || SyncError::plain("Invalid peer identity");
        let id = str_of(identity, "id");
        let label = str_of(identity, "label");
        let age_key = str_of(identity, "agePublicKey");
        let signing = str_of(identity, "signingPublicKey");
        if !is_hex(id, 16) || age_key.parse::<age::x25519::Recipient>().is_err() {
            return Err(invalid());
        }
        validate::text(label, "machine label", 100, false)?;
        if label.contains(['\r', '\n']) {
            return Err(invalid());
        }
        if unb64_array::<32>(signing, "key").is_err() {
            return Err(SyncError::plain("Expected an Ed25519 signing key"));
        }
        let mut trusted = store.sync_trust()?;
        if let Some(current) = trusted.get(id) {
            if str_of(current, "signingPublicKey") != signing
                || str_of(current, "agePublicKey") != age_key
            {
                return Err(SyncError::plain(
                    "Peer key changed; this machine id is already trusted with other keys",
                ));
            }
        }
        let entry = json!({
            "id": id,
            "label": label,
            "signingPublicKey": signing,
            "agePublicKey": age_key,
        });
        let fingerprint = sha256_hex(canonical_json(&entry).as_bytes());
        if trusted.get(id) != Some(&entry) {
            trusted.insert(id.to_owned(), entry);
            store.set_sync_trust(trusted)?;
        }
        Ok(json!({ "id": id, "fingerprint": fingerprint }))
    }

    // ── Removing a device ───────────────────────────────────────────────────────────────

    /// The removals in `revoked/` that a device in `trusted` signed, by removed device.
    fn revocations(&self, trusted: &Map<String, Value>) -> BTreeMap<String, Revocation> {
        let shown = |s: &str, fallback: &str| {
            let s: String = s.chars().filter(|c| !c.is_control()).take(100).collect();
            if s.is_empty() {
                fallback.to_owned()
            } else {
                s
            }
        };
        let mut out = BTreeMap::new();
        for file in list_dir(&self.dir("revoked")) {
            if !named(&file, 16, ".json") {
                continue;
            }
            let Ok(signed) = read_json(&self.dir("revoked").join(&file), MAX_SMALL) else {
                continue;
            };
            let r = signed.get("revocation").cloned().unwrap_or(Value::Null);
            let id = str_of(&r, "machineId");
            let by = str_of(&r, "revokedBy");
            let Some(signer) = trusted.get(by) else {
                continue;
            };
            if file != format!("{id}.json")
                || id == by
                || r.get("format").and_then(Value::as_u64) != Some(FORMAT)
                || !verify_signed(
                    str_of(signer, "signingPublicKey"),
                    REVOCATION_CONTEXT,
                    &r,
                    str_of(&signed, "signature"),
                )
            {
                continue;
            }
            out.insert(
                id.to_owned(),
                Revocation {
                    label: shown(str_of(&r, "label"), id),
                    by: by.to_owned(),
                    by_label: shown(str_of(signer, "label"), by),
                    last_counter: r.get("lastCounter").and_then(Value::as_u64).unwrap_or(0),
                },
            );
        }
        out
    }

    fn write_revocation(&self, keys: &Keys, id: &str, label: &str, last: u64) -> Result<()> {
        let r = json!({
            "format": FORMAT,
            "machineId": id,
            "label": label,
            "revokedBy": keys.machine_id,
            "revokedAt": now_iso(),
            "lastCounter": last,
        });
        let signed = json!({ "revocation": r, "signature": keys.sign(REVOCATION_CONTEXT, &r) });
        write_json(&self.dir("revoked").join(format!("{id}.json")), &signed)
    }

    /// The devices this vault trusts, and the ones removed from sync.
    pub fn devices(&self, store: &Store) -> Result<Value> {
        let keys = self.keys(store)?;
        let trusted = store.sync_trust()?;
        let devices: Vec<Value> = trusted
            .iter()
            .map(|(id, peer)| {
                json!({
                    "id": id,
                    "label": str_of(peer, "label"),
                    "fingerprint": sha256_hex(canonical_json(peer).as_bytes()),
                    "code": code(&sha256_hex(canonical_json(peer).as_bytes())),
                    "thisDevice": *id == keys.machine_id,
                })
            })
            .collect();
        let removed: Vec<Value> = self
            .revocations(&trusted)
            .iter()
            .map(|(id, r)| {
                json!({
                    "id": id,
                    "label": r.label,
                    "removedOn": r.by_label,
                    "confirmedHere": !trusted.contains_key(id),
                })
            })
            .collect();
        Ok(json!({ "devices": devices, "removed": removed }))
    }

    /// Removes a device from sync: it is trusted no more, it is no longer a recipient, its
    /// manifest, identity and heartbeat leave the repository, and a signed removal tells the
    /// other devices, which each confirm it the same way. The next push encrypts every
    /// record again for the devices that remain. Local only; [`Sync::untrust_remote`] sends it.
    ///
    /// What the removed device could already decrypt, in its own copy or in the repository's
    /// history, it still can: change any secret that matters after removing a lost device.
    pub fn untrust(&self, store: &mut Store, id: &str) -> Result<Value> {
        let keys = self.keys(store)?;
        if !is_hex(id, 16) {
            return Err(SyncError::plain(
                "Expected a device id of 16 hexadecimal characters; list them with: vaultos sync devices",
            ));
        }
        if id == keys.machine_id {
            return Err(SyncError::plain(
                "A device cannot remove itself from sync; remove it from another device",
            ));
        }
        self.ensure_dirs()?;
        let mut trusted = store.sync_trust()?;
        let revoked = self.revocations(&trusted);
        let existing = revoked.get(id).cloned();
        let Some(peer) = trusted.get(id).cloned() else {
            return match existing {
                Some(_) => Ok(json!({ "id": id, "removed": true, "alreadyRemoved": true })),
                None => Err(SyncError::plain(
                    "No trusted device has that id; list them with: vaultos sync devices",
                )),
            };
        };
        let label = str_of(&peer, "label").to_owned();
        let mut idx = self.read_index(&keys)?;
        // The newest push of the device that this one can vouch for: later manifests carry
        // it, so everything that device wrote stays superseded once it is rewritten.
        let in_repository = read_json(
            &self.dir("manifests").join(format!("{id}.json")),
            MAX_MANIFEST,
        )
        .ok()
        .and_then(|signed| {
            let m = signed.get("manifest").cloned().unwrap_or(Value::Null);
            verify_signed(
                str_of(&peer, "signingPublicKey"),
                MANIFEST_CONTEXT,
                &m,
                str_of(&signed, "signature"),
            )
            .then(|| Accepted::parse(id, &m).ok().map(|a| a.counter))
            .flatten()
        })
        .unwrap_or(0);
        let last = in_repository
            .max(idx.seen_manifests.get(id).map_or(0, |s| s.counter))
            .max(existing.as_ref().map_or(0, |r| r.last_counter));
        // The repository first and trust last: stopped half way, the signed removal is there
        // while the device is still trusted, and sync says to run this again.
        let recipients_path = self.dir("recipients.txt");
        if regular_file(&recipients_path, true, MAX_SMALL)?.is_some() {
            let text =
                String::from_utf8_lossy(&read_regular(&recipients_path, MAX_SMALL)?).into_owned();
            let key = str_of(&peer, "agePublicKey");
            let lines: Vec<&str> = text.lines().collect();
            let mut kept: Vec<&str> = Vec::new();
            for (i, line) in lines.iter().enumerate() {
                let comment_of_removed = line.trim_start().starts_with('#')
                    && lines.get(i + 1).is_some_and(|next| next.trim() == key);
                if line.trim() != key && !comment_of_removed {
                    kept.push(line);
                }
            }
            if kept.len() != lines.len() {
                let mut out = kept.join("\n");
                out.push('\n');
                atomic_write(&recipients_path, out.as_bytes())?;
            }
        }
        for dir in ["manifests", "machines", "peers"] {
            let _ = std::fs::remove_file(self.dir(dir).join(format!("{id}.json")));
        }
        if existing.is_none() {
            self.write_revocation(&keys, id, &label, last)?;
        }
        // A removal the departing device signed stops counting once it is not trusted. One
        // this vault had already confirmed is signed again here, so it keeps holding; one it
        // had not (the departing device removing another) is refused by deleting it.
        for (other, r) in &revoked {
            if r.by != id {
                continue;
            }
            if trusted.contains_key(other) || *other == keys.machine_id {
                let _ = std::fs::remove_file(self.dir("revoked").join(format!("{other}.json")));
            } else {
                self.write_revocation(&keys, other, &r.label, r.last_counter)?;
            }
        }
        idx.seen_manifests.remove(id);
        self.write_index(&keys, &mut idx)?;
        trusted.remove(id);
        store.set_sync_trust(trusted)?;
        Ok(json!({
            "id": id,
            "label": label,
            "removed": true,
            "confirmedRemovalFrom": existing.map(|r| r.by_label),
        }))
    }

    /// Removes a device and sends the removal, holding the store throughout (the CLI's way).
    /// It starts from the remote's newest state when that can be reached, and removes the
    /// device here even when it cannot; the next sync round then sends it.
    pub fn untrust_remote(&self, store: &mut Store, id: &str) -> Result<Value> {
        let _held = self.hold();
        let fetch_error = if self.git.is_repo() {
            let _ = self.commit_leftovers(store);
            self.fetch().err().map(|e| e.message)
        } else {
            None
        };
        let mut out = self.untrust(store, id)?;
        let staged = self.stage_push(store, Some(&format!("vault sync: removed device {id}")))?;
        out["push"] = self.deliver(&staged);
        if let Some(e) = fetch_error {
            out["fetchError"] = json!(e);
        }
        Ok(out)
    }

    // ── The push journal ────────────────────────────────────────────────────────────────

    fn journal_path(&self) -> PathBuf {
        self.data_dir.join(JOURNAL_FILE)
    }

    fn journal_mac(keys: &Keys, names: &BTreeSet<String>) -> String {
        b64(&hmac_sha256(
            &keys.index_key("journal"),
            canonical_json(&json!({ "format": FORMAT, "names": names })).as_bytes(),
        ))
    }

    /// The files an unfinished push was writing. A journal that is missing, unreadable or
    /// not this device's names none, and then nothing unsigned is excused.
    fn read_journal(&self, keys: &Keys) -> BTreeSet<String> {
        let path = self.journal_path();
        let Ok(bytes) = read_regular(&path, MAX_MANIFEST) else {
            return BTreeSet::new();
        };
        let Ok(j) = serde_json::from_slice::<Journal>(&bytes) else {
            return BTreeSet::new();
        };
        let sound = j.format == FORMAT
            && j.mac == Self::journal_mac(keys, &j.names)
            && j.names.iter().all(|n| {
                (n.starts_with("records/") || n.starts_with("tombstones/")) && sync_file(n)
            });
        if sound {
            j.names
        } else {
            BTreeSet::new()
        }
    }

    fn write_journal(&self, keys: &Keys, names: &BTreeSet<String>) -> Result<()> {
        write_json(
            &self.journal_path(),
            &Journal {
                format: FORMAT,
                names: names.clone(),
                mac: Self::journal_mac(keys, names),
            },
        )
    }

    fn clear_journal(&self) {
        let _ = std::fs::remove_file(self.journal_path());
    }

    /// Every recipient, all trusted: a recipient someone slipped into `recipients.txt` would
    /// otherwise receive every secret.
    fn recipients(&self, store: &Store) -> Result<Vec<age::x25519::Recipient>> {
        let path = self.dir("recipients.txt");
        if regular_file(&path, true, MAX_SMALL)?.is_none() {
            return Err(SyncError::plain(
                "no recipients.txt. Run: vaultos sync init <machine-label>",
            ));
        }
        let approved: BTreeSet<String> = store
            .sync_trust()?
            .values()
            .map(|v| str_of(v, "agePublicKey").to_owned())
            .collect();
        let text = String::from_utf8_lossy(&read_regular(&path, MAX_SMALL)?).into_owned();
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        let unapproved =
            || SyncError::plain("Unapproved encryption recipient; verify and trust the peer first");
        if lines.is_empty() || lines.iter().any(|l| !approved.contains(*l)) {
            return Err(unapproved());
        }
        lines
            .iter()
            .map(|l| {
                l.parse::<age::x25519::Recipient>()
                    .map_err(|_| unapproved())
            })
            .collect()
    }

    fn encrypt(recipients: &[age::x25519::Recipient], v: &Value) -> Result<Vec<u8>> {
        let plain = Zeroizing::new(canonical_json(v));
        let fail = |e: &dyn std::fmt::Display| SyncError::plain(format!("cannot encrypt: {e}"));
        let enc =
            age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
                .map_err(|e| fail(&e))?;
        let mut out = Vec::new();
        let mut w = enc.wrap_output(&mut out).map_err(|e| fail(&e))?;
        w.write_all(plain.as_bytes()).map_err(|e| fail(&e))?;
        w.finish().map_err(|e| fail(&e))?;
        Ok(out)
    }

    fn decrypt(keys: &Keys, file: &Path) -> std::result::Result<Value, String> {
        let bytes = read_regular(file, MAX_SYNC_FILE).map_err(|e| first_line(&e.to_string()))?;
        let plain = Zeroizing::new(
            age::decrypt(&keys.age, &bytes).map_err(|e| first_line(&e.to_string()))?,
        );
        serde_json::from_slice(&plain).map_err(|_| "not a sync payload".to_owned())
    }

    // ── Verification ────────────────────────────────────────────────────────────────────

    /// Checks every manifest's signature and counter, and that every record and tombstone
    /// file is one a trusted device wrote and no later push replaced or removed. With
    /// `remember`, a clean result records the manifests seen, so none can go back later.
    pub fn verify_manifests(&self, store: &Store, remember: bool) -> Result<Vec<String>> {
        Ok(self.check(store, remember, &BTreeSet::new())?.problems)
    }

    /// `excused` names the files an unfinished push of this device left: the push that
    /// finishes it rewrites or removes each, so they are neither checked nor read.
    fn check(&self, store: &Store, remember: bool, excused: &BTreeSet<String>) -> Result<Checked> {
        let keys = self.keys(store)?;
        let mut idx = self.read_index(&keys)?;
        let trusted = store.sync_trust()?;
        // A removal a trusted device signed stops sync here until a human confirms it on this
        // device too: one device must not be able to end another's trust on its own.
        let revoked = self.revocations(&trusted);
        let notices: Vec<String> = revoked
            .iter()
            .filter_map(|(id, r)| {
                if *id == keys.machine_id {
                    Some(format!(
                        "This device was removed from sync on {}. If you did that, sync has ended for this device and its vault keeps its records. If you did not, that device may be compromised; see docs/SYNC.md",
                        r.by_label
                    ))
                } else if trusted.contains_key(id) {
                    Some(format!(
                        "{} ({id}) was removed from sync on {}. If you did that, confirm it on this device: vaultos sync untrust {id}. If you did not, {} may be compromised; see docs/SYNC.md",
                        r.label, r.by_label, r.by_label
                    ))
                } else {
                    None
                }
            })
            .collect();
        if !notices.is_empty() {
            return Ok(Checked {
                problems: notices,
                ..Checked::default()
            });
        }
        let retired: BTreeMap<String, u64> = revoked
            .iter()
            .map(|(id, r)| (id.clone(), r.last_counter))
            .collect();
        let mut problems: Vec<String> = Vec::new();
        let mut accepted: Vec<Accepted> = Vec::new();
        let mut present = BTreeSet::new();
        // Sync never reads a file under a name it does not write. If only this checkout has
        // one, this account made it and it is ignored. One that arrived in a commit came from
        // a peer or the remote and is refused like any unsigned change, as is every one when
        // Git cannot say.
        let tracked = if self.git.is_repo() {
            self.git
                .tracked_paths(&["records", "tombstones", "manifests"])
                .ok()
        } else {
            None
        };
        let refused = |name: &str| {
            tracked.as_ref().is_none_or(|t| {
                t.iter()
                    .any(|f| f == name || f.strip_prefix(name).is_some_and(|r| r.starts_with('/')))
            })
        };
        let mut problem = |p: String| {
            if !problems.contains(&p) {
                problems.push(p);
            }
        };
        // A committed .gitignore or .gitattributes, wherever it is, changes which files a
        // checkout gets or their bytes, so a peer's or the remote's one is refused too.
        if self.git.is_repo() {
            match self.git.tracked_paths(&["."]) {
                Ok(all) => {
                    let control: Vec<String> = all.into_iter().filter(|f| git_control(f)).collect();
                    if !control.is_empty() {
                        problem(format!(
                            "Git control files in the sync repository change what it commits; remove them with git rm: {}",
                            quoted(&control)
                        ));
                    }
                }
                Err(_) => problem("Cannot list the sync repository's files".into()),
            }
        }
        for file in list_dir(&self.dir("manifests")) {
            if !named(&file, 16, ".json") {
                if refused(&format!("manifests/{file}")) {
                    problem("Invalid manifest filename".into());
                }
                continue;
            }
            let Ok(signed) = read_json(&self.dir("manifests").join(&file), MAX_MANIFEST) else {
                problem("Invalid manifest".into());
                continue;
            };
            let m = signed.get("manifest").cloned().unwrap_or(Value::Null);
            let id = str_of(&m, "machineId").to_owned();
            present.insert(id.clone());
            let Some(peer) = trusted.get(&id).filter(|_| file == format!("{id}.json")) else {
                problem("Untrusted sync machine".into());
                continue;
            };
            if !verify_signed(
                str_of(peer, "signingPublicKey"),
                MANIFEST_CONTEXT,
                &m,
                str_of(&signed, "signature"),
            ) {
                problem("BAD SIGNATURE".into());
                continue;
            }
            let a = match Accepted::parse(&id, &m) {
                Ok(a) => a,
                Err(e) => {
                    problem(e.into());
                    continue;
                }
            };
            if let Some(seen) = idx.seen_manifests.get(&id) {
                if a.counter < seen.counter || (a.counter == seen.counter && seen.hash != a.hash) {
                    problem("ROLLBACK or manifest equivocation".into());
                    continue;
                }
            }
            accepted.push(a);
        }
        for id in idx.seen_manifests.keys() {
            if !present.contains(id) && !retired.contains_key(id) {
                problem("Previously seen manifest is missing".into());
            }
        }
        let latest: BTreeMap<String, u64> =
            accepted.iter().map(|a| (a.id.clone(), a.counter)).collect();
        // Every push a manifest names must be one this checkout still has: a manifest that
        // saw a newer push of a device than that device's manifest here, or names a device
        // whose manifest is gone, means a manifest was rolled back or removed.
        for a in &accepted {
            let pushes = a
                .seen
                .iter()
                .map(|(d, c)| (d, *c))
                .chain(a.files.values().map(|e| (&e.by, e.counter)));
            for (device, counter) in pushes {
                match latest.get(device) {
                    Some(l) if counter <= *l => {}
                    Some(_) => problem("ROLLBACK or manifest equivocation".into()),
                    // A removed device has no manifest; what it pushed stays superseded by
                    // the manifests that saw it.
                    None if retired.contains_key(device) => {}
                    None => problem("A signed manifest is missing".into()),
                }
            }
        }
        // A file's entry is current unless a manifest that saw the push which wrote it lists
        // the file differently or not at all: that later push replaced or removed it. So an
        // older ciphertext put back from history is refused, even though a manifest made
        // before the change still signs it.
        let mut valid: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
        let mut superseded: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
        for a in &accepted {
            for (name, e) in &a.files {
                let replaced = accepted
                    .iter()
                    .any(|b| b.saw(&e.by, e.counter) && b.files.get(name) != Some(e));
                let list = if replaced {
                    &mut superseded
                } else {
                    &mut valid
                }
                .entry(name.clone())
                .or_default();
                if !list.contains(e) {
                    list.push(e.clone());
                }
            }
        }
        let listed = |m: &BTreeMap<String, Vec<Entry>>, rel: &str, h: &str| {
            m.get(rel).is_some_and(|v| v.iter().any(|e| e.digest == h))
        };
        for dir in ["records", "tombstones"] {
            for file in list_dir(&self.dir(dir)) {
                let rel = format!("{dir}/{file}");
                if !sync_file(&rel) {
                    if refused(&rel) {
                        problem(format!(
                            "Unexpected file in the sync repository: {}",
                            Value::String(rel)
                        ));
                    }
                    continue;
                }
                if excused.contains(&rel) {
                    continue;
                }
                match file_digest(&self.rel(&rel)) {
                    Ok(h) if listed(&valid, &rel, &h) => {}
                    Ok(h) if listed(&superseded, &rel, &h) => problem(
                        "ROLLBACK: ciphertext that a later push replaced or removed is back".into(),
                    ),
                    Ok(_) => problem("Unsigned or modified ciphertext".into()),
                    Err(_) => problem("Invalid sync file".into()),
                }
            }
        }
        // A push that removes a file lists it no more, which supersedes its entry; a file
        // with a current entry was never removed by a device, so it must be here.
        for name in valid.keys() {
            if !excused.contains(name) && !self.rel(name).exists() {
                problem("Signed ciphertext is missing".into());
            }
        }
        if problems.is_empty() && remember {
            for a in &accepted {
                idx.seen_manifests.insert(
                    a.id.clone(),
                    Seen {
                        counter: a.counter,
                        hash: a.hash.clone(),
                        at: a.pushed_at.clone(),
                    },
                );
            }
            self.write_index(&keys, &mut idx)?;
        }
        Ok(Checked {
            problems,
            valid,
            latest,
            retired,
        })
    }

    // ── Push ────────────────────────────────────────────────────────────────────────────

    fn sync_files(&self, dir: &str) -> Vec<String> {
        list_dir(&self.dir(dir))
            .into_iter()
            .filter(|f| sync_file(&format!("{dir}/{f}")))
            .collect()
    }

    /// Encrypts every record and tombstone that changed since the last push, removes the
    /// files of records deleted here, and signs a new manifest. Local only.
    pub fn push_local(&self, store: &Store) -> Result<Wrote> {
        self.ensure_dirs()?;
        let keys = self.keys(store)?;
        // What a push that stopped half way was writing: this device's own output, never
        // signed. This push writes each of those again, or removes it.
        let leftover = self.read_journal(&keys);
        let checked = self.check(store, true, &leftover)?;
        if !checked.problems.is_empty() {
            return Err(SyncError::new(
                "SIGNATURE_INVALID",
                checked.problems.join("; "),
            ));
        }
        let mut idx = self.read_index(&keys)?;
        // A counter never goes back, even when the index was restored from an older backup
        // or lost: the manifest already in the repository says where this device got to.
        let counter = idx
            .last_push
            .as_ref()
            .map_or(0, |p| p.counter)
            .max(checked.latest.get(&keys.machine_id).copied().unwrap_or(0))
            + 1;
        let mut fresh = BTreeSet::new();
        let local = store.sync_records()?;
        let recipients = self.recipients(store)?;
        let recipients_hash = Some(file_digest(&self.dir("recipients.txt"))?);
        let changed = idx.recipients_hash.is_some() && idx.recipients_hash != recipients_hash;
        // Taken before a recipient change clears the index, so a record deleted here still
        // has its file removed rather than left encrypted to the old recipients.
        let had: Vec<String> = idx.records.keys().cloned().collect();
        if changed {
            idx.records.clear();
            idx.tombstones.clear();
        }
        let mut wrote = Wrote {
            reencrypted_for_new_recipients: changed,
            ..Wrote::default()
        };
        // Every file this push will write or remove is named in the journal before the
        // first of them changes, and the journal goes once the manifest signs them.
        let tombstones = store.tombstones()?;
        let record_rel = |name: &str| format!("records/{name}.age");
        let tomb_rel = |name: &str| format!("tombstones/{name}.age");
        let record_kept = |idx: &Index, name: &str, keyed: &str| {
            idx.records.get(name).map(String::as_str) == Some(keyed)
                && self.rel(&record_rel(name)).exists()
                && !leftover.contains(&record_rel(name))
        };
        let tomb_kept = |idx: &Index, name: &str, at: &str| {
            idx.tombstones.get(name).map(String::as_str) == Some(at)
                && self.rel(&tomb_rel(name)).exists()
                && !leftover.contains(&tomb_rel(name))
        };
        let names: BTreeSet<String> = local
            .iter()
            .map(|r| opaque(&format!("{}:{}", r.project_id, r.record.id)))
            .collect();
        let tomb_names: BTreeSet<String> =
            tombstones.iter().map(|t| opaque(&t.reference)).collect();
        let stem = |rel: &str, dir: &str| {
            rel.strip_prefix(dir)
                .and_then(|f| f.strip_suffix(".age"))
                .map(str::to_owned)
        };
        let gone: BTreeSet<String> = had
            .into_iter()
            .chain(leftover.iter().filter_map(|rel| stem(rel, "records/")))
            .filter(|n| !names.contains(n))
            .collect();
        let gone_tombs: BTreeSet<String> = leftover
            .iter()
            .filter_map(|rel| stem(rel, "tombstones/"))
            .filter(|n| !tomb_names.contains(n))
            .collect();
        let mut pending = leftover.clone();
        for r in &local {
            let name = opaque(&format!("{}:{}", r.project_id, r.record.id));
            if !record_kept(&idx, &name, &keys.keyed(&r.hash)) {
                pending.insert(record_rel(&name));
            }
        }
        for t in tombstones {
            let name = opaque(&t.reference);
            if !tomb_kept(&idx, &name, &t.deleted_at) {
                pending.insert(tomb_rel(&name));
            }
        }
        pending.extend(gone.iter().map(|n| record_rel(n)));
        pending.extend(gone_tombs.iter().map(|n| tomb_rel(n)));
        if !pending.is_empty() {
            self.write_journal(&keys, &pending)?;
        }
        for r in &local {
            let reference = format!("{}:{}", r.project_id, r.record.id);
            let name = opaque(&reference);
            let file = self.dir("records").join(format!("{name}.age"));
            let keyed = keys.keyed(&r.hash);
            if record_kept(&idx, &name, &keyed) {
                wrote.unchanged += 1;
                continue;
            }
            let payload = json!({
                "format": FORMAT,
                "ref": reference,
                "projectId": r.project_id,
                "projectName": r.project_name,
                "record": r.record,
                "hash": r.hash,
                "pushedBy": keys.machine_id,
                "pushedAt": now_iso(),
            });
            atomic_write(&file, &Self::encrypt(&recipients, &payload)?)?;
            fresh.insert(format!("records/{name}.age"));
            idx.records.insert(name, keyed);
            wrote.written += 1;
        }
        for name in gone {
            let _ = std::fs::remove_file(self.dir("records").join(format!("{name}.age")));
            idx.records.remove(&name);
            wrote.removed += 1;
        }
        for name in gone_tombs {
            let _ = std::fs::remove_file(self.dir("tombstones").join(format!("{name}.age")));
            idx.tombstones.remove(&name);
        }
        for t in tombstones {
            let name = opaque(&t.reference);
            let file = self.dir("tombstones").join(format!("{name}.age"));
            if tomb_kept(&idx, &name, &t.deleted_at) {
                continue;
            }
            let payload = json!({ "format": FORMAT, "ref": t.reference, "deletedAt": t.deleted_at, "by": t.by });
            atomic_write(&file, &Self::encrypt(&recipients, &payload)?)?;
            fresh.insert(format!("tombstones/{name}.age"));
            idx.tombstones.insert(name, t.deleted_at.clone());
        }
        // Each file names the push that wrote it: this one, or the earlier push whose
        // ciphertext it still is.
        let mut files = Map::new();
        for dir in ["records", "tombstones"] {
            for f in self.sync_files(dir) {
                let rel = format!("{dir}/{f}");
                let digest = file_digest(&self.rel(&rel))?;
                let entry = if fresh.contains(&rel) {
                    Entry {
                        digest,
                        by: keys.machine_id.clone(),
                        counter,
                    }
                } else {
                    checked
                        .valid
                        .get(&rel)
                        .and_then(|v| v.iter().find(|e| e.digest == digest))
                        .cloned()
                        .ok_or_else(|| {
                            SyncError::new("SIGNATURE_INVALID", "Unsigned or modified ciphertext")
                        })?
                };
                files.insert(rel, entry.to_json());
            }
        }
        // A removed device's last push stays seen, so what it wrote stays superseded.
        let seen: Map<String, Value> = checked
            .retired
            .iter()
            .filter(|(_, c)| **c >= 1)
            .chain(checked.latest.iter())
            .filter(|(d, _)| **d != keys.machine_id)
            .map(|(d, c)| (d.clone(), json!(c)))
            .collect();
        let pushed_at = now_iso();
        let manifest = json!({
            "format": FORMAT,
            "machineId": keys.machine_id,
            "counter": counter,
            "pushedAt": pushed_at,
            "recordCount": local.len(),
            "seen": seen,
            "files": files,
        });
        let signed =
            json!({ "manifest": manifest, "signature": keys.sign(MANIFEST_CONTEXT, &manifest) });
        write_json(
            &self
                .dir("manifests")
                .join(format!("{}.json", keys.machine_id)),
            &signed,
        )?;
        idx.last_push = Some(LastPush {
            counter,
            at: pushed_at,
        });
        idx.recipients_hash = recipients_hash;
        self.write_index(&keys, &mut idx)?;
        self.clear_journal();
        wrote.counter = counter;
        Ok(wrote)
    }

    /// The checkout's changes that matter to a push, or None if Git cannot say: sync's own
    /// files, which it commits, and changes it refuses to commit beside. A file sync did not
    /// write in one of its folders, and any file only this checkout has, is left alone.
    fn changes(&self) -> Option<Changes> {
        let changed = self.git.changed_paths().ok()?;
        let tracked = self.git.tracked_paths(&["."]).ok()?;
        let alone = |f: &str| !git_control(f) && (in_sync_dir(f) || !tracked.contains(f));
        Some(Changes {
            own: changed.iter().filter(|f| sync_file(f)).cloned().collect(),
            stray: changed.iter().filter(|f| stray(f)).cloned().collect(),
            unrelated: changed
                .iter()
                .filter(|f| !sync_file(f) && !alone(f))
                .cloned()
                .collect(),
        })
    }

    /// Changed paths that a push still has to commit or that stop it.
    fn unsent(&self) -> Option<Vec<String>> {
        self.changes()
            .map(|c| c.own.into_iter().chain(c.unrelated).collect())
    }

    /// Writes a push and commits it: sync's files by name, then this device's signed
    /// heartbeat. Local only; [`Sync::deliver`] sends it.
    pub fn stage_push(&self, store: &Store, message: Option<&str>) -> Result<Staged> {
        let wrote = self.push_local(store)?;
        let keys = self.keys(store)?;
        let mut staged = Staged {
            fingerprint: store.content_fingerprint()?,
            machine_id: keys.machine_id.clone(),
            no_git: !self.git.is_repo(),
            failed: None,
            commit: None,
            wrote,
        };
        if staged.no_git {
            return Ok(staged);
        }
        let msg = message.map_or_else(
            || {
                format!(
                    "vault sync: {} record(s) from {}",
                    staged.wrote.written, keys.machine_id
                )
            },
            str::to_owned,
        );
        let changes = self.changes().ok_or_else(|| {
            SyncError::plain("Cannot list the sync repository's changes; refusing to commit")
        })?;
        if !changes.unrelated.is_empty() {
            return Err(SyncError::plain(format!(
                "Sync repository contains unrelated changes; refusing to commit: {}",
                quoted(&changes.unrelated)
            )));
        }
        // An ignore rule outside the checkout (.git/info/exclude, a global excludes file)
        // hides a file sync wrote from `git status`. Committed without it, this device's
        // manifest would sign a file no peer receives, and every peer would refuse.
        let mut roots: Vec<&str> = DIRS.to_vec();
        roots.extend(["recipients.txt", MARKER]);
        let ignored = self.git.ignored_paths(&roots).map_err(|e| {
            SyncError::plain(format!("cannot list the sync repository's files: {e}"))
        })?;
        let hidden: Vec<String> = ignored.into_iter().filter(|f| sync_file(f)).collect();
        if !hidden.is_empty() {
            return Err(SyncError::plain(format!(
                "Git ignores files sync wrote; refusing to commit: {}",
                quoted(&hidden)
            )));
        }
        // Sync's own files by name, never whole folders. A stray file Git already tracks is
        // taken out of the repository instead; the local copy stays, untracked and ignored.
        let tracked = self.git.tracked_paths(&DIRS).map_err(|e| {
            SyncError::plain(format!("cannot list the sync repository's files: {e}"))
        })?;
        let untrack: Vec<String> = changes
            .stray
            .iter()
            .cloned()
            .chain(tracked)
            .filter(|f| stray(f))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let heartbeat = format!("peers/{}.json", keys.machine_id);
        let own: Vec<String> = changes
            .own
            .into_iter()
            .filter(|f| *f != heartbeat)
            .collect();
        let commit = self.git.commit_paths(&own, &msg, &untrack);
        self.publish_heartbeat(store)?;
        let beat = self.git.commit_paths(
            &[format!("peers/{}.json", keys.machine_id)],
            &format!("heartbeat: {}", keys.machine_id),
            &[],
        );
        // The next round commits whatever a failed commit left (commit_leftovers), so a
        // failed commit is worth retrying rather than a reason to stop.
        staged.failed = if !commit.ok {
            Some(commit.error.clone())
        } else if !beat.ok {
            Some(format!("could not commit the sync receipt: {}", beat.error))
        } else {
            None
        };
        staged.commit = Some(commit);
        Ok(staged)
    }

    fn receipt(&self, fingerprint: Option<&str>, counter: u64, machine_id: &str) -> Value {
        let repo = self.git.is_repo();
        let div = if repo {
            self.git.divergence().ok()
        } else {
            None
        };
        json!({
            "sourceFingerprint": fingerprint,
            "manifestCounter": counter,
            "machineId": machine_id,
            "sourceCommit": if repo { self.git.head() } else { None },
            "remoteCommit": if repo { self.git.remote_head() } else { None },
            "ahead": div.map(|d| d.ahead),
            "behind": div.map(|d| d.behind),
            "uncommitted": if repo { self.unsent().map(|u| u.len()) } else { None },
        })
    }

    /// Sends a staged push: no store needed while Git waits on the network.
    pub fn deliver(&self, staged: &Staged) -> Value {
        let mut out = serde_json::to_value(&staged.wrote).unwrap_or_else(|_| json!({}));
        let receipt = |s: &Sync| {
            s.receipt(
                Some(&staged.fingerprint),
                staged.wrote.counter,
                &staged.machine_id,
            )
        };
        let mut set = |pairs: Vec<(&str, Value)>| {
            if let Value::Object(m) = &mut out {
                for (k, v) in pairs {
                    m.insert(k.into(), v);
                }
            }
        };
        if staged.no_git {
            set(vec![
                ("transport", json!("none")),
                ("delivered", json!(false)),
                (
                    "warning",
                    json!(format!(
                        "{} is not a git repo, so nothing left this machine",
                        self.repo.display()
                    )),
                ),
                ("receipt", receipt(self)),
            ]);
            return out;
        }
        if let Some(e) = &staged.failed {
            set(vec![
                ("transport", json!("commit-failed")),
                ("code", json!("COMMIT_FAILED")),
                ("delivered", json!(false)),
                ("error", json!(e)),
                ("receipt", receipt(self)),
            ]);
            return out;
        }
        let commit = staged.commit.as_ref();
        let committed = commit.is_some_and(|c| c.committed);
        let pushed = self.git.push();
        if !pushed.ok {
            set(vec![
                ("transport", json!("push-failed")),
                ("delivered", json!(false)),
                ("code", json!(pushed.code)),
                ("error", json!(pushed.error)),
                ("committed", json!(committed)),
                ("sourceCommit", json!(commit.and_then(|c| c.sha.clone()))),
                ("receipt", receipt(self)),
            ]);
            return out;
        }
        let head = self.git.head();
        set(vec![
            ("transport", json!("ok")),
            ("delivered", json!(true)),
            ("committed", json!(committed)),
            ("sourceCommit", json!(head)),
            ("remoteCommit", json!(pushed.remote_sha)),
            ("rebased", json!(head != commit.and_then(|c| c.sha.clone()))),
            ("receipt", receipt(self)),
        ]);
        out
    }

    /// Writes, commits and sends a push, holding the store throughout (the CLI's way).
    pub fn push_remote(&self, store: &Store, message: Option<&str>) -> Result<Value> {
        let _held = self.hold();
        let staged = self.stage_push(store, message)?;
        Ok(self.deliver(&staged))
    }

    // ── Pull ────────────────────────────────────────────────────────────────────────────

    /// A round that stops between writing its files and committing them (a failed commit, a
    /// crash) leaves them in the working tree, and Git will not rebase onto a peer's commits
    /// until they are committed. They are this device's own output, so the next round commits
    /// them before it fetches, if they verify and nothing else changed.
    pub fn commit_leftovers(&self, store: &Store) -> Result<()> {
        // A push that stopped between its first file and its manifest left files no manifest
        // signs. Finishing it here, before anything verifies the repository, keeps a crash
        // from reading as tampering.
        if self
            .keys(store)
            .is_ok_and(|keys| !self.read_journal(&keys).is_empty())
        {
            self.push_local(store)?;
        }
        if !self.git.is_repo() {
            return Ok(());
        }
        let Some(changes) = self.changes() else {
            return Ok(());
        };
        if !changes.unrelated.is_empty() || changes.own.is_empty() {
            return Ok(());
        }
        let id = self.keys(store)?.machine_id;
        let trusted = store.sync_trust()?;
        // This device's own output: its manifest, heartbeat and ciphertext, and what removing
        // a device leaves (the recipient list, the signed removal, and the files of a device
        // that is no longer trusted, deleted).
        let own = |f: &str| {
            f == format!("manifests/{id}.json")
                || f == format!("peers/{id}.json")
                || f == "recipients.txt"
                || f.split_once('/').is_some_and(|(d, n)| match d {
                    "records" | "tombstones" => named(n, 64, ".age"),
                    "revoked" => named(n, 16, ".json"),
                    "machines" | "manifests" | "peers" => {
                        named(n, 16, ".json")
                            && !trusted.contains_key(&n[..16])
                            && !self.rel(f).exists()
                    }
                    _ => false,
                })
        };
        if !changes.own.iter().all(|f| own(f)) {
            return Ok(());
        }
        // Checked, not remembered: if this round then halts and a human drops the commit,
        // the older manifest must not read as a rollback.
        let problems = self.verify_manifests(store, false)?;
        if !problems.is_empty() {
            return Err(SyncError::refusal(&problems));
        }
        let c = self.git.commit_paths(
            &changes.own,
            &format!(
                "vault sync: {} file(s) left uncommitted by an earlier round from {id}",
                changes.own.len()
            ),
            &[],
        );
        if !c.ok {
            return Err(SyncError::new(
                "COMMIT_FAILED",
                format!("cannot commit what an earlier round left: {}", c.error),
            ));
        }
        Ok(())
    }

    /// Brings the checkout up to the remote. Network only; returns whether anything arrived.
    pub fn fetch(&self) -> Result<bool> {
        let ff = self.git.pull_ff();
        if !ff.ok {
            return Err(SyncError::new(
                if ff.code.is_empty() {
                    "REMOTE_UNREACHABLE"
                } else {
                    ff.code
                },
                format!("cannot update the sync repo: {}", ff.error),
            ));
        }
        Ok(ff.changed)
    }

    fn decode(&self, keys: &Keys) -> Result<Decoded> {
        let mut remote = BTreeMap::new();
        let mut tombs = BTreeMap::new();
        let mut unreadable = Vec::new();
        for f in self.sync_files("records") {
            let p = match Self::decrypt(keys, &self.dir("records").join(&f)) {
                Ok(p) => p,
                Err(error) => {
                    unreadable.push(json!({ "file": format!("records/{f}"), "error": error }));
                    continue;
                }
            };
            let binding = || SyncError::plain("Invalid record binding");
            let record: Record = p
                .get("record")
                .cloned()
                .and_then(|r| serde_json::from_value(r).ok())
                .ok_or_else(binding)?;
            let reference = str_of(&p, "ref").to_owned();
            let project_id = str_of(&p, "projectId").to_owned();
            if p.get("format").and_then(Value::as_u64) != Some(FORMAT)
                || f != format!("{}.age", opaque(&reference))
                || reference != format!("{project_id}:{}", record.id)
                || record_hash(&record) != str_of(&p, "hash")
            {
                return Err(binding());
            }
            check_record(&record)?;
            remote.insert(
                reference.clone(),
                Payload {
                    reference,
                    project_id,
                    project_name: str_of(&p, "projectName").to_owned(),
                    hash: str_of(&p, "hash").to_owned(),
                    pushed_by: str_of(&p, "pushedBy").to_owned(),
                    pushed_at: str_of(&p, "pushedAt").to_owned(),
                    record,
                },
            );
        }
        for f in self.sync_files("tombstones") {
            let p = match Self::decrypt(keys, &self.dir("tombstones").join(&f)) {
                Ok(p) => p,
                Err(error) => {
                    unreadable.push(json!({ "file": format!("tombstones/{f}"), "error": error }));
                    continue;
                }
            };
            let reference = str_of(&p, "ref").to_owned();
            let by = str_of(&p, "by");
            if p.get("format").and_then(Value::as_u64) != Some(FORMAT)
                || f != format!("{}.age", opaque(&reference))
                || !valid_reference(&reference)
                || ms(str_of(&p, "deletedAt")).is_none()
                || validate::text(by, "tombstone author", 256, true).is_err()
            {
                return Err(SyncError::plain("Invalid tombstone binding"));
            }
            tombs.insert(
                reference,
                RemoteTomb {
                    deleted_at: str_of(&p, "deletedAt").to_owned(),
                    by: by.to_owned(),
                },
            );
        }
        Ok((remote, tombs, unreadable))
    }

    /// The merge against the repository as it is in the checkout. Without `apply`, only the
    /// plan. With it, conflicts stop the merge unless `accept_conflicts`, and the vault is
    /// backed up before anything changes, in one save.
    pub fn pull(&self, store: &mut Store, apply: bool, accept_conflicts: bool) -> Result<Plan> {
        self.ensure_dirs()?;
        let problems = self.verify_manifests(store, true)?;
        if !problems.is_empty() {
            return Err(SyncError::refusal(&problems));
        }
        let keys = self.keys(store)?;
        let (remote, remote_tombs, unreadable) = self.decode(&keys)?;
        let local: BTreeMap<String, SyncRecord> = store
            .sync_records()?
            .into_iter()
            .map(|r| (format!("{}:{}", r.project_id, r.record.id), r))
            .collect();
        let local_tombs: BTreeMap<String, String> = store
            .tombstones()?
            .iter()
            .map(|t| (t.reference.clone(), t.deleted_at.clone()))
            .collect();
        // What this device last knew the repository held, per record: the merge base.
        let base = self.read_index(&keys)?.records;
        let base_is =
            |reference: &str, hash: &str| base.get(&opaque(reference)) == Some(&keys.keyed(hash));
        let mut plan = Plan {
            unreadable,
            ..Plan::default()
        };
        for (reference, rp) in &remote {
            let Some(lo) = local.get(reference) else {
                // A deletion yields only to a later edit. A device that had not seen the
                // deletion can push the old record again (a new recipient, a lost file), with
                // a new push time but the same edit time, and it must stay deleted.
                let edited = ms_or_epoch(&rp.record.updated_at);
                let deleted_here = local_tombs
                    .get(reference)
                    .is_some_and(|d| later(ms(d), edited));
                let deleted_there = remote_tombs
                    .get(reference)
                    .is_some_and(|t| later(ms(&t.deleted_at), edited));
                if !(deleted_here || deleted_there) {
                    plan.added.push(rp.clone());
                }
                continue;
            };
            if lo.hash == rp.hash {
                plan.unchanged += 1;
                continue;
            }
            // Here too a deletion yields to a later edit, on either side.
            if remote_tombs.get(reference).is_some_and(|t| {
                later(ms(&t.deleted_at), ms_or_epoch(&lo.record.updated_at))
                    && later(ms(&t.deleted_at), ms_or_epoch(&rp.record.updated_at))
            }) {
                plan.deleted.push(reference.clone());
                continue;
            }
            let lrev = lo.record.rev.max(1);
            let rrev = rp.record.rev.max(1);
            // Three-way check against the merge base: a record changed on one side only since
            // the last sync is an ordinary update, not a conflict. The revision must agree
            // too, so a damaged index can never let an older copy replace a newer local edit.
            if base_is(reference, &lo.hash) && rrev > lrev {
                plan.updated.push(rp.clone());
                continue;
            }
            if base_is(reference, &rp.hash) && lrev > rrev {
                plan.unchanged += 1;
                continue;
            }
            let lts = ms_or_epoch(&lo.record.updated_at);
            let rts = ms_or_epoch(&rp.record.updated_at);
            // Equal revision and timestamp must break the same way on every device, or each
            // keeps its own version and accepting conflicts never converges. Hash decides.
            let remote_wins = rrev > lrev
                || (rrev == lrev
                    && (later(rts, lts) || (rts.is_some() && rts == lts && rp.hash > lo.hash)));
            plan.conflicts.push(json!({
                "ref": reference,
                "key": lo.record.key,
                "project": lo.project_name,
                "localRev": lrev,
                "remoteRev": rrev,
                "localUpdatedAt": lo.record.updated_at,
                "remoteUpdatedAt": rp.record.updated_at,
                "resolution": if remote_wins { "remote" } else { "local" },
            }));
            if remote_wins {
                plan.updated.push(rp.clone());
            }
        }
        for (reference, t) in &remote_tombs {
            let Some(lo) = local.get(reference) else {
                continue;
            };
            if plan.deleted.contains(reference) {
                continue;
            }
            let edited_there = remote
                .get(reference)
                .is_some_and(|rp| !later(ms(&t.deleted_at), ms_or_epoch(&rp.record.updated_at)));
            if !edited_there && later(ms(&t.deleted_at), ms_or_epoch(&lo.record.updated_at)) {
                plan.deleted.push(reference.clone());
            }
        }
        let project_tombs: Vec<String> = remote_tombs
            .keys()
            .filter_map(|r| r.strip_prefix("project:").map(str::to_owned))
            .collect();
        if apply && !plan.conflicts.is_empty() && !accept_conflicts {
            return Err(SyncError {
                conflicts: plan.conflicts.len(),
                ..SyncError::new(
                    "CONFLICTS_PENDING",
                    "Concurrent edits detected. Back up both vaults and review the conflict plan before accepting its revisions",
                )
            });
        }
        if apply && !plan.unreadable.is_empty() {
            let files: Vec<String> = plan
                .unreadable
                .iter()
                .map(|u| str_of(u, "file").to_owned())
                .collect();
            return Err(SyncError::new(
                "UNREADABLE_RECORDS",
                format!(
                    "{} record file(s) in the sync repo could not be decrypted: {}",
                    files.len(),
                    files.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
        // Projects deleted elsewhere that would be empty here once the merge is done.
        let mut doomed = Vec::new();
        for p in store.list_projects()? {
            if !project_tombs.contains(&p.id) {
                continue;
            }
            let incoming = plan
                .added
                .iter()
                .chain(&plan.updated)
                .any(|x| x.project_id == p.id);
            let live = local
                .keys()
                .filter(|r| r.split_once(':').is_some_and(|(pid, _)| pid == p.id))
                .any(|r| !plan.deleted.contains(r));
            if !incoming && !live {
                doomed.push((p.id.clone(), p.name.clone()));
            }
        }
        if !apply {
            plan.deleted_projects = doomed;
            return Ok(plan);
        }
        if plan.added.is_empty()
            && plan.updated.is_empty()
            && plan.deleted.is_empty()
            && doomed.is_empty()
        {
            self.mark_merged(store, &keys, &remote, &plan)?;
            return Ok(plan);
        }
        self.backup()?;
        let changes = SyncChanges {
            upsert: plan
                .added
                .iter()
                .chain(&plan.updated)
                .map(|p| SyncRecord {
                    project_id: p.project_id.clone(),
                    project_name: p.project_name.clone(),
                    record: p.record.clone(),
                    hash: p.hash.clone(),
                })
                .collect(),
            delete: plan
                .deleted
                .iter()
                .map(|r| {
                    (
                        r.clone(),
                        remote_tombs
                            .get(r)
                            .map_or_else(|| "sync".to_owned(), |t| t.by.clone()),
                    )
                })
                .collect(),
            delete_projects: project_tombs,
        };
        plan.deleted_projects = store.apply_sync(&changes)?;
        self.mark_merged(store, &keys, &remote, &plan)?;
        Ok(plan)
    }

    /// The index tells a push which records the repository already holds. Only records whose
    /// local copy matches the repository are marked: a local edit kept by a conflict
    /// resolution, or a record only this device has, stays unmarked so the next push writes it.
    fn mark_merged(
        &self,
        store: &Store,
        keys: &Keys,
        remote: &BTreeMap<String, Payload>,
        plan: &Plan,
    ) -> Result<()> {
        let mut idx = self.read_index(keys)?;
        let merged: BTreeMap<String, String> = store
            .sync_records()?
            .into_iter()
            .map(|r| (format!("{}:{}", r.project_id, r.record.id), r.hash))
            .collect();
        for (reference, rp) in remote {
            let Some(hash) = merged.get(reference) else {
                continue;
            };
            if *hash == rp.hash {
                idx.records.insert(opaque(reference), keys.keyed(hash));
            } else {
                idx.records.remove(&opaque(reference));
            }
        }
        for reference in merged
            .keys()
            .filter(|r| !remote.contains_key(*r))
            .chain(&plan.deleted)
        {
            idx.records.remove(&opaque(reference));
        }
        self.write_index(keys, &mut idx)
    }

    fn backup(&self) -> Result<()> {
        let dir = self.data_dir.join("backups");
        private_mkdir(&dir)?;
        let bytes = read_regular(&self.data_dir.join(VAULT_FILE), MAX_VAULT_BYTES)?;
        atomic_write(
            &dir.join(format!("{}-{}.enc", now_ms(), hex(&random_array::<8>()))),
            &bytes,
        )?;
        prune_backups(&dir, now_ms());
        Ok(())
    }

    /// Fetches, then merges, holding the store throughout (the CLI's way).
    pub fn pull_remote(&self, store: &mut Store, accept_conflicts: bool) -> Result<Value> {
        let _held = self.hold();
        if !self.git.is_repo() {
            let plan = self.pull(store, true, accept_conflicts)?;
            let mut out = plan.summary();
            out["transport"] = json!("none");
            out["warning"] = json!(format!(
                "{} is not a git repo; merged only what was already local",
                self.repo.display()
            ));
            return Ok(out);
        }
        self.commit_leftovers(store)?;
        let fetched = self.fetch()?;
        let plan = self.reload_and_pull(store, accept_conflicts)?;
        let mut out = plan.summary();
        out["transport"] = json!("ok");
        out["fetched"] = json!(fetched);
        Ok(out)
    }

    /// After a fetch: picks up a save another process made while Git waited, then merges.
    pub fn reload_and_pull(&self, store: &mut Store, accept_conflicts: bool) -> Result<Plan> {
        if !store.is_unlocked() {
            return Err(SyncError::locked());
        }
        match store.reload_if_changed() {
            Ok(_) => {}
            Err(vaultos_core::Error::Busy) => return Err(SyncError::busy()),
            Err(e) => return Err(e.into()),
        }
        self.pull(store, true, accept_conflicts)
    }

    // ── Heartbeats and status ───────────────────────────────────────────────────────────

    /// Writes this device's signed heartbeat: when it last synced and what it holds.
    pub fn publish_heartbeat(&self, store: &Store) -> Result<()> {
        self.ensure_dirs()?;
        let keys = self.keys(store)?;
        let idx = self.read_index(&keys)?;
        let repo = self.git.is_repo();
        let unsent = if repo { self.unsent() } else { None };
        let beat = json!({
            "format": FORMAT,
            "machineId": keys.machine_id,
            "at": now_iso(),
            "records": store.sync_records()?.len(),
            "manifestCounter": idx.last_push.as_ref().map_or(0, |p| p.counter),
            "uncommitted": unsent.map(|u| u.iter().filter(|f| !f.starts_with("peers/")).count()),
            "sourceCommit": if repo { self.git.head() } else { None },
        });
        let signed = json!({ "beat": beat, "signature": keys.sign(HEARTBEAT_CONTEXT, &beat) });
        write_json(
            &self.dir("peers").join(format!("{}.json", keys.machine_id)),
            &signed,
        )
    }

    /// The other devices' heartbeats, verified against their trusted keys.
    pub fn read_peers(&self, store: &Store) -> Result<Vec<Value>> {
        let own = self.keys(store)?.machine_id;
        let trusted = store.sync_trust()?;
        let mut out = Vec::new();
        for f in list_dir(&self.dir("peers")) {
            if !f.ends_with(".json") {
                continue;
            }
            let Ok(signed) = read_json(&self.dir("peers").join(&f), MAX_SMALL) else {
                continue;
            };
            let beat = signed.get("beat").cloned().unwrap_or(Value::Null);
            let id = str_of(&beat, "machineId").to_owned();
            if !is_hex(&id, 16) || id == own {
                continue;
            }
            let mut label = id.clone();
            let mut verified = false;
            if self.dir("machines").join(format!("{id}.json")).exists() {
                let Some(machine) = trusted.get(&id) else {
                    out.push(json!({ "label": id, "verified": false }));
                    continue;
                };
                label = Some(str_of(machine, "label"))
                    .filter(|l| !l.is_empty())
                    .unwrap_or(&id)
                    .to_owned();
                verified = verify_signed(
                    str_of(machine, "signingPublicKey"),
                    HEARTBEAT_CONTEXT,
                    &beat,
                    str_of(&signed, "signature"),
                );
            }
            let age_hours = ms(str_of(&beat, "at"))
                .map(|at| ((now_ms() - at) as f64 / 3_600_000.0 * 10.0).round() / 10.0);
            let mut entry = beat.clone();
            if let Value::Object(m) = &mut entry {
                m.insert("label".into(), json!(label));
                m.insert("verified".into(), json!(verified));
                m.insert("ageHours".into(), json!(age_hours));
            }
            out.push(entry);
        }
        Ok(out)
    }

    pub fn peer_problems(&self, store: &Store) -> Vec<String> {
        const STALE_HOURS: f64 = 48.0;
        let mut problems = Vec::new();
        for p in self.read_peers(store).unwrap_or_default() {
            let label = str_of(&p, "label");
            if p.get("verified") != Some(&json!(true)) {
                problems.push(format!(
                    "{label}: heartbeat signature could not be verified"
                ));
                continue;
            }
            if let Some(n) = p
                .get("uncommitted")
                .and_then(Value::as_u64)
                .filter(|n| *n > 0)
            {
                problems.push(format!(
                    "{label} has {n} record file(s) written but never committed - they have not left that machine"
                ));
            }
            if let Some(h) = p
                .get("ageHours")
                .and_then(Value::as_f64)
                .filter(|h| *h > STALE_HOURS)
            {
                problems.push(format!("{label} has not reported for {}h", h.round()));
            }
        }
        problems
    }

    /// The local view: what a pull would change and how many records a push would send.
    pub fn status(&self, store: &mut Store) -> Result<Value> {
        let keys = self.keys(store)?;
        let local = store.sync_records()?;
        let idx = self.read_index(&keys)?;
        let (plan, error) = match self.pull(store, false, false) {
            Ok(p) => (Some(p), None),
            Err(e) => (None, Some(e.message)),
        };
        let outgoing = plan.as_ref().map(|_| {
            local
                .iter()
                .filter(|r| {
                    idx.records
                        .get(&opaque(&format!("{}:{}", r.project_id, r.record.id)))
                        != Some(&keys.keyed(&r.hash))
                })
                .count()
        });
        Ok(json!({
            "machineId": keys.machine_id,
            "localRecords": local.len(),
            "repoRecords": self.sync_files("records").len(),
            "fingerprint": store.content_fingerprint()?,
            "lastPush": idx.last_push,
            "incoming": plan.as_ref().map(|p| json!({
                "added": p.added.len(),
                "updated": p.updated.len(),
                "deleted": p.deleted.len(),
                "conflicts": p.conflicts.len(),
            })),
            "outgoing": outgoing,
            "conflicts": plan.as_ref().map_or_else(Vec::new, |p| p.conflicts.clone()),
            "unreadable": plan.as_ref().map_or_else(Vec::new, |p| p.unreadable.clone()),
            "error": error,
        }))
    }

    /// The local view plus the remote's: fetches, then names one state for the whole.
    pub fn status_remote(&self, store: &mut Store) -> Result<Value> {
        let _held = self.hold();
        let mut out = self.status(store)?;
        let set = |out: &mut Value, k: &str, v: Value| out[k] = v;
        if !self.git.is_repo() {
            set(&mut out, "state", json!("NO_GIT_REPO"));
            set(&mut out, "remoteReachable", json!(false));
            set(
                &mut out,
                "detail",
                json!(format!(
                    "{} is not a git repo; records go nowhere",
                    self.repo.display()
                )),
            );
            return Ok(out);
        }
        let f = self.git.fetch();
        let unsent = self.unsent();
        let div = if f.ok {
            self.git.divergence().ok()
        } else {
            None
        };
        set(&mut out, "remoteReachable", json!(f.ok));
        set(&mut out, "remote", json!(self.git.remote_name()));
        set(&mut out, "sourceCommit", json!(self.git.head()));
        set(
            &mut out,
            "remoteCommit",
            json!(if f.ok { self.git.remote_head() } else { None }),
        );
        set(&mut out, "ahead", json!(div.map(|d| d.ahead)));
        set(&mut out, "behind", json!(div.map(|d| d.behind)));
        set(
            &mut out,
            "uncommittedFiles",
            json!(unsent.clone().unwrap_or_default()),
        );
        let state = |out: &mut Value, s: &str, detail: Option<String>| {
            out["state"] = json!(s);
            if let Some(d) = detail {
                out["detail"] = json!(d);
            }
        };
        if !f.ok {
            state(&mut out, "REMOTE_UNREACHABLE", Some(f.error));
            return Ok(out);
        }
        if let Some(u) = unsent.filter(|u| !u.is_empty()) {
            state(
                &mut out,
                "LOCAL_SYNC_REPO_DIRTY",
                Some(format!("{} record file(s) written but never committed, so they have not left this machine", u.len())),
            );
            return Ok(out);
        }
        match div {
            Some(d) if d.ahead > 0 && d.behind > 0 => {
                state(&mut out, "GIT_HISTORY_DIVERGED", None);
                return Ok(out);
            }
            Some(d) if d.ahead > 0 => {
                state(&mut out, "UNPUSHED_COMMITS", None);
                return Ok(out);
            }
            Some(d) if d.behind > 0 => {
                state(&mut out, "BEHIND_REMOTE", None);
                return Ok(out);
            }
            _ => {}
        }
        if let Some(e) = out.get("error").and_then(Value::as_str).map(str::to_owned) {
            state(&mut out, "SIGNATURE_INVALID", Some(e));
            return Ok(out);
        }
        let unreadable: Vec<String> = out["unreadable"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|u| str_of(u, "file").to_owned())
            .collect();
        if !unreadable.is_empty() {
            state(
                &mut out,
                "UNREADABLE_RECORDS",
                Some(format!(
                    "{} file(s) in the sync repo will not decrypt: {}",
                    unreadable.len(),
                    unreadable
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            );
            return Ok(out);
        }
        out["peers"] = json!(self.read_peers(store)?);
        let problems = self.peer_problems(store);
        let n = |k: &str| out["incoming"][k].as_u64().unwrap_or(0);
        let drift =
            out["outgoing"].as_u64().unwrap_or(0) + n("added") + n("updated") + n("deleted");
        if drift != 0 {
            state(&mut out, "RECORDS_OUT_OF_SYNC", None);
        } else if !problems.is_empty() {
            state(&mut out, "PEER_STALLED", Some(problems.join("; ")));
        } else {
            state(&mut out, "IN_SYNC", None);
        }
        Ok(out)
    }
}

/// Keeps the newest [`BACKUPS_KEPT`] pull backups and any younger than [`BACKUP_DAYS`].
pub fn prune_backups(dir: &Path, now: i128) {
    let mut found: Vec<(i128, String)> = list_dir(dir)
        .into_iter()
        .filter_map(|name| {
            let (stamp, rest) = name.split_once('-')?;
            let ms: i128 = stamp
                .parse()
                .ok()
                .filter(|_| stamp.bytes().all(|b| b.is_ascii_digit()))?;
            named(rest, 16, ".enc").then_some((ms, name))
        })
        .filter(|(ms, _)| *ms > 0)
        .collect();
    found.sort_by_key(|a| std::cmp::Reverse(a.0));
    for (ms, name) in found.into_iter().skip(BACKUPS_KEPT) {
        if now - ms > BACKUP_DAYS * 86_400_000 {
            let _ = std::fs::remove_file(dir.join(name));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(sync_file(&format!("records/{}.age", "a".repeat(64))));
        assert!(sync_file("manifests/0123456789abcdef.json"));
        assert!(!sync_file("records/.DS_Store"));
        assert!(stray("records/.DS_Store"));
        assert!(!stray("README.md"));
        assert!(git_control("records/.gitignore"));
        assert!(valid_reference("p1:r1") && valid_reference("project:p1"));
        assert!(!valid_reference("p1") && !valid_reference("a:b/c"));
    }

    fn device(root: &Path, name: &str, repo: &Path, label: &str) -> (Store, Sync, Value) {
        let dir = root.join(name);
        let mut store = Store::new(&dir).unwrap_or_else(|e| panic!("{e}"));
        store
            .create(
                &vaultos_core::SecretString::new("synthetic-sync-password"),
                None,
                vaultos_core::KdfParams::FLOOR,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let sync = Sync::new(&dir, repo);
        let identity = sync
            .init(&mut store, label)
            .unwrap_or_else(|e| panic!("{e}"));
        (store, sync, identity)
    }

    fn set(store: &mut Store, key: &str, value: &str) {
        if store.find_project("Example").ok().flatten().is_none() {
            store
                .create_project("Example", "human")
                .unwrap_or_else(|e| panic!("{e}"));
        }
        let f = vaultos_core::Fields {
            key: key.into(),
            value: Some(vaultos_core::SecretString::new(value)),
            ..Default::default()
        };
        store
            .set_item("Example", &f, "human")
            .unwrap_or_else(|e| panic!("{e}"));
    }

    /// The state a push leaves when it stops after writing ciphertext and before signing its
    /// manifest: the new files, the journal that names them, the old manifest and index.
    #[test]
    fn a_push_that_stopped_before_its_manifest_is_finished_and_tampering_is_still_refused() {
        let root = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let repo = root.path().join("repo");
        let (mut a, sa, ia) = device(root.path(), "a", &repo, "Machine A");
        let (mut b, sb, ib) = device(root.path(), "b", &repo, "Machine B");
        sa.trust(&mut a, &ib).unwrap_or_else(|e| panic!("{e}"));
        sb.trust(&mut b, &ia).unwrap_or_else(|e| panic!("{e}"));
        set(&mut a, "KEPT", "kept-synthetic");
        set(&mut a, "EDITED", "first-synthetic");
        set(&mut a, "DELETED", "to-delete-synthetic");
        sa.push_local(&a).unwrap_or_else(|e| panic!("{e}"));
        sb.pull(&mut b, true, false)
            .unwrap_or_else(|e| panic!("{e}"));

        let keys = sa.keys(&a).unwrap_or_else(|e| panic!("{e}"));
        let manifest = sa
            .dir("manifests")
            .join(format!("{}.json", keys.machine_id));
        let before_manifest = std::fs::read(&manifest).unwrap_or_default();
        let before_index = std::fs::read(sa.index_path()).unwrap_or_default();
        let before: BTreeMap<String, String> = sa
            .sync_files("records")
            .into_iter()
            .map(|f| {
                let digest = file_digest(&sa.dir("records").join(&f)).unwrap_or_default();
                (f, digest)
            })
            .collect();

        set(&mut a, "EDITED", "second-synthetic");
        set(&mut a, "ADDED", "added-synthetic");
        sa.push_local(&a).unwrap_or_else(|e| panic!("{e}"));
        let changed: BTreeSet<String> = sa
            .sync_files("records")
            .into_iter()
            .filter(|f| before.get(f) != file_digest(&sa.dir("records").join(f)).ok().as_ref())
            .map(|f| format!("records/{f}"))
            .collect();
        assert_eq!(changed.len(), 2);
        std::fs::write(&manifest, &before_manifest).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(sa.index_path(), &before_index).unwrap_or_else(|e| panic!("{e}"));
        sa.write_journal(&keys, &changed)
            .unwrap_or_else(|e| panic!("{e}"));

        // Nothing but the push that finishes it accepts the unsigned files.
        let problems = sa.verify_manifests(&a, false).unwrap_or_default();
        assert!(
            problems.iter().any(|p| p.contains("Unsigned")),
            "{problems:?}"
        );
        assert!(sb.pull(&mut b, true, false).is_err());

        // A record removed in between has its unsigned file removed, not signed.
        a.delete_item("Example", "ADDED", "human")
            .unwrap_or_else(|e| panic!("{e}"));
        a.purge_item("Example", "ADDED", "human")
            .unwrap_or_else(|e| panic!("{e}"));
        sa.commit_leftovers(&a).unwrap_or_else(|e| panic!("{e}"));
        assert!(!sa.journal_path().exists());
        assert!(sa
            .verify_manifests(&a, false)
            .unwrap_or(vec!["?".into()])
            .is_empty());
        sb.pull(&mut b, true, false)
            .unwrap_or_else(|e| panic!("{e}"));
        let value = b
            .reveal("Example", "EDITED", "human")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(value.value.expose(), "second-synthetic");
        assert!(b.find_item("Example", "ADDED").ok().flatten().is_none());

        // A journal does not excuse a file it does not name, and one that fails its MAC
        // excuses nothing.
        let kept = sa
            .sync_files("records")
            .into_iter()
            .next()
            .unwrap_or_default();
        let named: BTreeSet<String> = [format!("records/{kept}")].into();
        std::fs::write(sa.dir("records").join(&kept), b"tampered")
            .unwrap_or_else(|e| panic!("{e}"));
        let other: BTreeSet<String> = [format!("records/{}.age", "0".repeat(64))].into();
        sa.write_journal(&keys, &other)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(sa.push_local(&a).is_err());
        sa.write_journal(&keys, &named)
            .unwrap_or_else(|e| panic!("{e}"));
        let forged = std::fs::read_to_string(sa.journal_path())
            .unwrap_or_default()
            .replace(&kept, &"1".repeat(64));
        std::fs::write(sa.journal_path(), forged).unwrap_or_else(|e| panic!("{e}"));
        assert!(sa.read_journal(&keys).is_empty());
        assert!(sa.push_local(&a).is_err());
    }

    #[test]
    fn prunes_only_old_backups_beyond_the_newest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let day = 86_400_000i128;
        let now = 100 * day;
        for i in 0..25 {
            let name = format!("{}-{}.enc", now - i * 2 * day, "0".repeat(16));
            std::fs::write(dir.path().join(name), b"x").expect("write");
        }
        std::fs::write(dir.path().join("notes.txt"), b"x").expect("write");
        prune_backups(dir.path(), now);
        let left = list_dir(dir.path());
        // 20 newest kept; of the other 5 (40..48 days old) all are past 30 days.
        assert_eq!(left.len(), 21, "{left:?}");
        assert!(left.contains(&"notes.txt".to_owned()));
    }
}
