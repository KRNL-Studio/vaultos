//! `vaultos`: the human's command line. It creates and
//! upgrades vaults, drives `vaultosd` (start, unlock, lock, stop), and runs recovery and
//! admin commands directly on the vault file while it holds the vault's owner lock. Values
//! are printed only when asked for (`read`, `render`, `otp`, `generate`) and given to a
//! command by `run`; tokens and Secret Keys go to private files.

use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as Process, ExitCode, Stdio};
use std::time::{Duration, Instant};
use vaultos_cli::{emit, read_stdin, say, Fail, Result};
use vaultos_client::Client;
use vaultos_core::agents::Wildcards;
use vaultos_core::fs_safe::{self, LockFile};
use vaultos_core::model::HUMAN;
use vaultos_core::refs::{self, SecretRef};
use vaultos_core::store::VAULT_FILE;
use vaultos_core::{Error, Fields, KdfParams, SecretKey, SecretString, Store};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

const VIA: &str = "admin CLI";
/// The largest value `add` reads, as `vaultos-agent add`.
const MAX_VALUE: usize = 65536;

#[derive(Debug, Parser)]
#[command(
    name = "vaultos",
    version,
    about = "VaultOS for the human: create, unlock and manage the vault, and give secrets to your own commands.",
    after_help = "Set VAULTOS_DATA_DIR to use a non-default data directory. Commands that read or \
change the vault directly need it to themselves: quit the desktop app, or pass --stop-backend \
to stop vaultosd first."
)]
struct Cli {
    /// Read the master password from stdin (rotate-password: the new one on the next line)
    #[arg(long, global = true)]
    password_stdin: bool,
    /// The file holding this vault's Secret Key, when it has one
    #[arg(long, global = true, value_name = "PATH")]
    secret_key_file: Option<PathBuf>,
    /// Stop a running vaultosd before a command that needs the vault to itself
    #[arg(long, global = true)]
    stop_backend: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new vault
    Init {
        /// Also require a new Secret Key, written to this file (mode 0600). Without it the
        /// vault cannot be opened: keep a copy offline.
        #[arg(long, value_name = "PATH")]
        new_secret_key_file: Option<PathBuf>,
    },
    /// Upgrade a v3 vault to v4, keeping the password. A backup of the v3 file is made
    /// first; the earlier app cannot open the upgraded vault.
    Upgrade {
        /// Also require a new Secret Key, written to this file (mode 0600)
        #[arg(long, value_name = "PATH")]
        new_secret_key_file: Option<PathBuf>,
    },
    /// Is vaultosd running and unlocked?
    Status,
    /// Start vaultosd in the background (it starts locked)
    Start,
    /// Unlock the running vaultosd
    Unlock,
    /// Lock the running vaultosd
    Lock,
    /// Stop the running vaultosd
    Stop,
    /// List projects
    Projects,
    /// List a project's key names and metadata
    Keys { project: String },
    /// Store a key, creating its project if needed. The value is read from stdin (after the
    /// password's line with --password-stdin), or at a hidden prompt; never an argument
    Add {
        project: String,
        key: String,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        /// Caught so that a value passed by mistake is refused, never echoed.
        #[arg(hide = true, num_args = 0.., allow_hyphen_values = true)]
        extra: Vec<String>,
    },
    /// Store every KEY=VALUE from an absolute env file, creating the project if needed
    Import { project: String, file: PathBuf },
    /// Write a project's keys into an absolute file, replacing it
    Inject {
        project: String,
        file: PathBuf,
        #[arg(default_value = "dotenv", value_parser = ["dotenv", "json", "shell"])]
        format: String,
    },
    /// Import a 1Password .1pux, Bitwarden .json or CSV export (an absolute path) into a
    /// project, creating it if needed. Attachments and passkeys are not imported
    ImportItems { project: String, file: PathBuf },
    /// Print an item's current one-time code
    Otp { project: String, key: String },
    /// Print the value a reference names: vault://Project/Item, or vault://Project/Item/field
    /// (password, username, email, url, note, otp, or a custom field's label). While the app
    /// owns the vault it asks you to confirm with Touch ID
    Read {
        reference: String,
        /// No newline after the value
        #[arg(short = 'n', long)]
        no_newline: bool,
    },
    /// Fill a template's {{ vault://… }} references, writing it to a new file (mode 0600)
    /// or to stdout
    Render {
        template: PathBuf,
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Run a command with secrets in its environment: a project's values, env files whose
    /// values are vault:// references, and variables set to references. Their values are
    /// masked in its output
    Run {
        /// Give the command this project's values (keys awaiting approval are left out)
        #[arg(long)]
        project: Option<String>,
        /// Only these keys of --project (comma-separated or repeated)
        #[arg(long, requires = "project", value_name = "KEYS")]
        keys: Vec<String>,
        /// A dotenv file whose values may be vault:// references (repeatable)
        #[arg(long, value_name = "PATH")]
        env_file: Vec<PathBuf>,
        /// Pass the command's output through unmasked
        #[arg(long)]
        no_masking: bool,
        /// The command and its arguments, after --
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<std::ffi::OsString>,
    },
    /// Print a new random password, passphrase or PIN. Nothing is stored or opened
    Generate {
        /// Characters in a random password (8-128), or digits in a PIN (4-32)
        #[arg(long)]
        length: Option<usize>,
        /// A passphrase of this many words (3-20) instead
        #[arg(long, conflicts_with = "pin")]
        words: Option<usize>,
        /// A PIN instead
        #[arg(long)]
        pin: bool,
        /// Letters and digits only
        #[arg(long)]
        no_symbols: bool,
    },
    /// Copy the encrypted vault file into an absolute directory
    Backup { directory: PathBuf },
    /// Enrolled agents
    #[command(subcommand)]
    Agents(AgentsCommand),
    /// Agent-added keys waiting for approval before injection
    #[command(subcommand)]
    Pending(PendingCommand),
    /// The approval relay's token
    #[command(subcommand)]
    Approver(ApproverCommand),
    /// Change the master password
    RotatePassword,
    /// Add, replace or remove the vault's Secret Key
    #[command(subcommand)]
    SecretKey(SecretKeyCommand),
    /// End-to-end encrypted sync through a Git checkout (VAULTOS_SYNC_REPO, or
    /// sync-repository in the data directory)
    #[command(subcommand)]
    Sync(SyncCommand),
}

#[derive(Debug, Subcommand)]
enum SyncCommand {
    /// Enrol this device: in a new, empty checkout, or in a clone of an existing sync repository
    Init { label: String },
    /// This device's public identity and fingerprint, to compare and trust on the others
    Identity,
    /// Trust another device's identity file (its machines/<id>.json, or `sync identity`
    /// output) once its fingerprint matches what that device shows
    Trust { file: PathBuf },
    /// Fetch, then report one state for the whole; exits 2 unless IN_SYNC
    Status,
    /// Encrypt, commit and push this device's changes; exits 2 unless delivered
    Push,
    /// Fetch and merge; concurrent edits stop the merge until accepted
    Pull,
    /// What a pull would change, by project and key name (never values)
    Plan,
    /// Fetch and merge, resolving concurrent edits by revision (back up first)
    AcceptConflicts,
    /// Ask the running vaultosd to sync now, the way autosync would (this also clears a
    /// halt); exits 2 unless it succeeded
    Now,
    /// Turn autosync in vaultosd on or off (it is off until turned on)
    Auto {
        #[arg(value_parser = ["on", "off"])]
        state: String,
        /// Seconds between rounds, 30 to 86400 (default 120)
        #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(30..=86_400))]
        interval: Option<u64>,
    },
}

#[derive(Debug, clap::Args)]
struct Access {
    /// Projects to grant (names or ids, comma-separated or repeated)
    #[arg(long, value_name = "A,B")]
    projects: Vec<String>,
    /// Grant every project, including future ones
    #[arg(long)]
    all_projects: bool,
    /// Folders the agent may read and write files in (absolute)
    #[arg(long, value_name = "DIR,DIR")]
    roots: Vec<String>,
    /// Allow files in any folder
    #[arg(long)]
    any_root: bool,
}

#[derive(Debug, Subcommand)]
enum AgentsCommand {
    List,
    /// Enroll an agent (or reissue its token) and write the token to a private file
    #[command(alias = "enrol")]
    Enroll {
        name: String,
        #[arg(long, value_name = "PATH", required = true)]
        token_file: PathBuf,
        /// Scopes, comma-separated (default read,inject)
        #[arg(long, value_name = "A,B")]
        scopes: Option<String>,
        #[command(flatten)]
        access: Access,
    },
    /// Change an agent's scopes or grants
    Grant {
        name: String,
        #[arg(long, value_name = "A,B")]
        scopes: Option<String>,
        #[command(flatten)]
        access: Access,
        /// Remove every project grant
        #[arg(long)]
        no_projects: bool,
        /// Remove every folder grant
        #[arg(long)]
        no_roots: bool,
        /// With the run scope: a command it may run with secrets, a program and optionally
        /// its first arguments ("npm test"). Repeat it; the list replaces the current one
        #[arg(long = "run-command", value_name = "COMMAND")]
        run_commands: Vec<String>,
        /// Remove every allowed command
        #[arg(long, conflicts_with = "run_commands")]
        no_run_commands: bool,
    },
    Revoke {
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum PendingCommand {
    List,
    /// Approve PROJECT KEY, or --all [--project P]
    Approve {
        #[arg(value_name = "PROJECT")]
        project_name: Option<String>,
        key: Option<String>,
        #[arg(long)]
        all: bool,
        /// With --all, only this project
        #[arg(long = "project", value_name = "P", requires = "all")]
        only: Option<String>,
    },
    Deny {
        project: String,
        key: String,
    },
}

#[derive(Debug, Subcommand)]
enum ApproverCommand {
    /// Issue a new relay token and write it to a private file
    Set {
        #[arg(long, value_name = "PATH", required = true)]
        token_file: PathBuf,
    },
    Clear,
    Status,
}

#[derive(Debug, Subcommand)]
enum SecretKeyCommand {
    /// Generate a new Secret Key (replacing any current one) and write it to a private file
    Set {
        #[arg(long, value_name = "PATH", required = true)]
        new_secret_key_file: PathBuf,
    },
    /// Stop requiring a Secret Key
    Remove,
}

struct Ctx {
    data_dir: PathBuf,
    password_stdin: bool,
    secret_key_file: Option<PathBuf>,
    stop_backend: bool,
}

/// A vault this process has to itself, unlocked.
struct Open {
    store: Store,
    password: SecretString,
    secret_key: Option<SecretKey>,
    _owner: LockFile,
}

impl Drop for Open {
    fn drop(&mut self) {
        self.store.lock();
    }
}

fn prompt(label: &str) -> Result<SecretString> {
    rpassword::prompt_password(label)
        .map(SecretString::new)
        .map_err(|_| Fail::new("cannot read the password from the terminal"))
}

fn list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `admin.js` `prepareTokenFile`: an absolute path whose parent is a writable directory
/// (created 0700 if missing) and which, if it exists, is a regular file.
fn prepare_private_file(file: &Path, flag: &str) -> Result<()> {
    if !file.is_absolute() {
        return Err(Fail::usage(format!("{flag} must be an absolute path")));
    }
    let dir = file
        .parent()
        .ok_or_else(|| Fail::usage(format!("{flag} must name a file")))?;
    if !dir.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder
            .create(dir)
            .map_err(|_| Fail::new("cannot create the file's folder"))?;
    }
    if !dir.is_dir() {
        return Err(Fail::new("The file's parent must be a directory"));
    }
    if std::fs::symlink_metadata(file).is_ok_and(|m| !m.is_file()) {
        return Err(Fail::new("The file path must be a regular file"));
    }
    Ok(())
}

fn write_token(file: &Path, token: &SecretString) -> Result<()> {
    let mut line = zeroize::Zeroizing::new(token.expose().as_bytes().to_vec());
    line.push(b'\n');
    fs_safe::atomic_write(file, &line)?;
    Ok(())
}

/// Writes a new Secret Key to a file that must not exist yet, so a key belonging to another
/// vault is never overwritten.
fn write_secret_key(file: &Path, key: &SecretKey) -> Result<()> {
    prepare_private_file(file, "--new-secret-key-file")?;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Fail::new("The Secret Key file already exists; choose a new path")
        } else {
            Fail::new("cannot create the Secret Key file")
        }
    })?;
    let text = key.display();
    let written = f
        .write_all(text.expose().as_bytes())
        .and_then(|()| f.write_all(b"\n"))
        .and_then(|()| f.sync_all());
    if written.is_err() {
        let _ = std::fs::remove_file(file);
        return Err(Fail::new("cannot write the Secret Key file"));
    }
    if let Some(dir) = file.parent() {
        fs_safe::sync_dir(dir)?;
    }
    Ok(())
}

/// Runs `f` with a new Secret Key already safe in `file`; if `f` fails before the vault
/// could need the key, the file is removed again.
fn with_new_secret_key<R>(
    file: Option<&Path>,
    f: impl FnOnce(Option<&SecretKey>) -> std::result::Result<R, Error>,
) -> Result<(R, Option<Value>)> {
    let Some(file) = file else {
        return Ok((f(None)?, None));
    };
    let key = SecretKey::generate();
    write_secret_key(file, &key)?;
    match f(Some(&key)) {
        Ok(r) => Ok((
            r,
            Some(json!({
                "secretKeyFile": file,
                "secretKeyId": key.id(),
                "note": "Keep a copy of the Secret Key offline: the vault cannot be opened without it.",
            })),
        )),
        Err(e) => {
            if !matches!(e, Error::Unconfirmed(_)) {
                let _ = std::fs::remove_file(file);
            }
            Err(e.into())
        }
    }
}

/// Records a change that has already been saved; failing to record it does not undo it.
fn audited(store: &mut Store, action: &str) -> bool {
    store.audit(action, &format!("via {VIA}"), HUMAN).is_ok()
}

fn warnings(audited: bool) -> Vec<&'static str> {
    if audited {
        Vec::new()
    } else {
        vec!["The change was saved, but the audit event could not be written."]
    }
}

fn merge(mut base: Value, extra: Option<Value>) -> Value {
    if let (Some(b), Some(Value::Object(e))) = (base.as_object_mut(), extra) {
        b.extend(e);
    }
    base
}

impl Ctx {
    fn owner_client(&self) -> Client {
        Client::with_token(self.data_dir.clone(), None)
    }

    /// The master password (and, for `count == 2`, the new one).
    fn passwords(&self, count: usize, confirm_new: bool) -> Result<Vec<SecretString>> {
        if self.password_stdin {
            let input = read_stdin(8192, "Password input too long")?;
            let lines: Vec<&str> = input
                .split('\n')
                .map(|l| l.trim_end_matches('\r'))
                .collect();
            if lines.len() < count || lines[..count].iter().any(|l| l.is_empty()) {
                return Err(Fail::new(format!(
                    "Expected {count} password line(s) on stdin"
                )));
            }
            return Ok(lines[..count]
                .iter()
                .map(|l| SecretString::new(*l))
                .collect());
        }
        let mut out = Vec::new();
        if count == 2 || !confirm_new {
            out.push(prompt("Master password: ")?);
        }
        if count == 2 || confirm_new {
            let next = prompt("New master password: ")?;
            if prompt("Confirm new password: ")?.expose() != next.expose() {
                return Err(Fail::new("The new passwords do not match"));
            }
            out.push(next);
        }
        Ok(out)
    }

    /// What `add` reads before opening the vault: with `--password-stdin`, the password's
    /// line and then the value; else a value piped on stdin. `None` for the value means
    /// stdin is a terminal, so it is asked for at a hidden prompt once the vault is open.
    fn add_input(&self) -> Result<(Option<SecretString>, Option<SecretString>)> {
        fn one_line_off(s: &str) -> &str {
            let s = s.strip_suffix('\n').unwrap_or(s);
            s.strip_suffix('\r').unwrap_or(s)
        }
        if self.password_stdin {
            let input = read_stdin(MAX_VALUE + 8192, "Input too long")?;
            let Some((password, rest)) = input.split_once('\n') else {
                return Err(Fail::usage(
                    "Expected the password's line, then the value, on stdin",
                ));
            };
            let password = password.trim_end_matches('\r');
            if password.is_empty() {
                return Err(Fail::usage("Expected the password's line on stdin"));
            }
            return Ok((
                Some(SecretString::new(password)),
                Some(SecretString::new(one_line_off(rest))),
            ));
        }
        if std::io::stdin().is_terminal() {
            return Ok((None, None));
        }
        let input = read_stdin(MAX_VALUE, "Value is too large")?;
        Ok((None, Some(SecretString::new(one_line_off(&input)))))
    }

    /// The vault's Secret Key, from `--secret-key-file` or a prompt, when it has one.
    fn secret_key(&self, store: &Store) -> Result<Option<SecretKey>> {
        if let Some(file) = &self.secret_key_file {
            let bytes = zeroize::Zeroizing::new(fs_safe::read_regular(file, 256)?);
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| Fail::new("The Secret Key file is not text"))?;
            return Ok(Some(SecretKey::parse(text.trim())?));
        }
        // A v3 vault has no Secret Key; unlocking it asks for the upgrade.
        if store.file_version()? < 4 || store.secret_key_id()?.is_none() {
            return Ok(None);
        }
        if self.password_stdin {
            return Err(Fail::usage(
                "This vault uses a Secret Key; pass --secret-key-file PATH",
            ));
        }
        let typed = prompt("Secret Key: ")?;
        Ok(Some(SecretKey::parse(typed.expose().trim())?))
    }

    /// `admin.js` `own`: the owner lock, after stopping vaultosd when asked to.
    fn own(&self) -> Result<LockFile> {
        match fs_safe::claim(&self.data_dir, "owner.lock") {
            Ok(l) => return Ok(l),
            Err(Error::Busy) => {}
            Err(e) => return Err(e.into()),
        }
        if !self.stop_backend {
            return Err(Fail::new(
                "VaultOS is running. Quit the desktop app, or pass --stop-backend to stop vaultosd, then retry",
            ));
        }
        let client = self.owner_client();
        if client.live(Duration::from_millis(1500)).is_some() {
            let _ = client.owner("POST", "/shutdown", None);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match fs_safe::claim(&self.data_dir, "owner.lock") {
                Ok(l) => return Ok(l),
                Err(Error::Busy) => std::thread::sleep(Duration::from_millis(200)),
                Err(e) => return Err(e.into()),
            }
        }
        Err(Fail::new(
            "The running VaultOS owner did not stop; quit the desktop app and retry",
        ))
    }

    fn store(&self) -> Result<Store> {
        let store = Store::new(&self.data_dir)?;
        if !store.exists() {
            return Err(Fail::new("No vault exists in this data directory"));
        }
        Ok(store)
    }

    fn open(&self) -> Result<Open> {
        self.open_with(None)
    }

    /// Opens the vault with `password`, or the one `passwords` reads.
    fn open_with(&self, password: Option<SecretString>) -> Result<Open> {
        let mut store = self.store()?;
        let owner = self.own()?;
        let password = match password {
            Some(p) => p,
            None => self.passwords(1, false)?.remove(0),
        };
        let secret_key = self.secret_key(&store)?;
        store.unlock(&password, secret_key.as_ref())?;
        Ok(Open {
            store,
            password,
            secret_key,
            _owner: owner,
        })
    }

    fn start(&self) -> Result<()> {
        let client = self.owner_client();
        if let Some((s, _)) = client.live(Duration::from_millis(1500)) {
            return emit(&json!({ "running": true, "started": false, "pid": s.pid }));
        }
        let sibling = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.join("vaultosd")))
            .filter(|p| p.is_file());
        // Its messages (no secrets) go to a private log, so a failed start can say why.
        fs_safe::private_dir(&self.data_dir)?;
        let log_path = self.data_dir.join("vaultosd.log");
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let log = opts
            .open(&log_path)
            .map_err(|_| Fail::new("cannot create vaultosd.log"))?;
        let mut cmd = Process::new(sibling.unwrap_or_else(|| PathBuf::from("vaultosd")));
        cmd.arg("--data-dir")
            .arg(&self.data_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log);
        // Its own process group, so ^C here does not stop it.
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd.spawn().map_err(|_| {
            Fail::new("cannot start vaultosd; is it installed next to vaultos or on PATH?")
        })?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Some((s, _)) = client.live(Duration::from_millis(500)) {
                return emit(&json!({ "running": true, "started": true, "pid": s.pid }));
            }
            if let Ok(Some(status)) = child.try_wait() {
                let said = fs_safe::read_regular(&log_path, 64 * 1024)
                    .ok()
                    .and_then(|b| {
                        String::from_utf8_lossy(&b)
                            .lines()
                            .rev()
                            .find(|l| !l.trim().is_empty())
                            .map(str::to_owned)
                    })
                    .unwrap_or_else(|| format!("vaultosd exited ({status})"));
                return Err(Fail::new(said));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(Fail::new(format!(
            "vaultosd did not answer; see {}",
            log_path.display()
        )))
    }

    fn unlock(&self) -> Result<()> {
        let client = self.owner_client();
        let status = client.status();
        if status["running"] != json!(true) {
            return Err(Fail {
                message: "vaultosd is not running. Start it with `vaultos start`".into(),
                code: 3,
            });
        }
        if status["unlocked"] == json!(true) {
            return emit(&json!({ "ok": true, "locked": false }));
        }
        let store = self.store()?;
        let password = self.passwords(1, false)?.remove(0);
        let secret_key = self.secret_key(&store)?;
        let mut body = json!({ "password": password.expose() });
        if let Some(k) = &secret_key {
            body["secretKey"] = json!(k.display().expose());
        }
        let reply = client.owner("POST", "/unlock", Some(&body));
        if let Some(o) = body.as_object_mut() {
            for v in o.values_mut() {
                if let Value::String(s) = v {
                    zeroize::Zeroize::zeroize(s);
                }
            }
        }
        emit(&reply?)
    }

    fn owner_route(&self, route: &str) -> Result<()> {
        emit(&self.owner_client().owner("POST", route, None)?)
    }

    /// Asks vaultosd to stop and waits until it has released the vault.
    fn stop(&self) -> Result<()> {
        let client = self.owner_client();
        client.owner("POST", "/shutdown", None)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if client.live(Duration::from_millis(500)).is_none() {
                return emit(&json!({ "ok": true, "stopped": true }));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(Fail::new("vaultosd did not stop in time"))
    }

    fn status(&self) -> Result<()> {
        let client = self.owner_client();
        let mut status = client.status();
        let store = Store::new(&self.data_dir)?;
        if let Some(o) = status.as_object_mut() {
            // The owner sees autosync's full status, its error and peer problems included.
            if o.get("running") == Some(&json!(true)) {
                if let Ok(full) = client.owner("GET", "/status", None) {
                    if let Some(sync) = full.get("sync") {
                        o.insert("sync".into(), sync.clone());
                    }
                }
            }
            o.insert("dataDir".into(), json!(self.data_dir));
            o.insert("vault".into(), json!(store.exists()));
            if store.exists() {
                let version = store.file_version()?;
                o.insert("fileVersion".into(), json!(version));
                if version >= 4 {
                    o.insert("secretKey".into(), json!(store.secret_key_id()?.is_some()));
                } else {
                    o.insert("needsUpgrade".into(), json!(true));
                }
            }
        }
        emit(&status)
    }

    fn init(&self, new_secret_key_file: Option<&Path>) -> Result<()> {
        let mut store = Store::new(&self.data_dir)?;
        if store.exists() {
            return Err(Fail::new("A vault already exists in this data directory"));
        }
        let _owner = self.own()?;
        let password = self.passwords(1, true)?.remove(0);
        let ((), key) = with_new_secret_key(new_secret_key_file, |k| {
            store.create(&password, k, KdfParams::DEFAULT)
        })?;
        store.lock();
        emit(&merge(
            json!({ "created": true, "dataDir": self.data_dir, "formatVersion": 4 }),
            key,
        ))
    }

    fn upgrade(&self, new_secret_key_file: Option<&Path>) -> Result<()> {
        self.store()?;
        let _owner = self.own()?;
        let password = self.passwords(1, false)?.remove(0);
        let (done, key) = with_new_secret_key(new_secret_key_file, |k| {
            vaultos_core::upgrade::upgrade(&self.data_dir, &password, k, KdfParams::DEFAULT)
        })?;
        emit(&merge(
            json!({
                "upgraded": true,
                "formatVersion": 4,
                "backup": done.backup,
                "projects": done.projects,
                "items": done.items,
                "history": done.history,
                "note": "The earlier app cannot open this vault; the backup is the untouched v3 file.",
            }),
            key,
        ))
    }

    fn backup(&self, target: &Path) -> Result<()> {
        if !target.is_absolute() {
            return Err(Fail::usage("Specify an absolute backup directory"));
        }
        let store = self.store()?;
        let dir = store.data_dir();
        let optional = |name: &str, max: u64| -> Result<Option<(String, Vec<u8>)>> {
            let file = dir.join(name);
            if file.exists() {
                Ok(Some((name.to_owned(), fs_safe::read_regular(&file, max)?)))
            } else {
                Ok(None)
            }
        };
        // Read in this order while sync or agents may still write. The sync index before the
        // vault: an index older than the vault only re-checks records, one newer would make a
        // merge base of a version the copied vault never had. The audit log after it, under
        // its lock, so it holds every entry the copied vault records. Nothing is written
        // until all three are read.
        let index = optional(vaultos_sync::INDEX_FILE, fs_safe::MAX_VAULT_BYTES)?;
        let vault = fs_safe::read_regular(&dir.join(VAULT_FILE), fs_safe::MAX_VAULT_BYTES)?;
        let log = {
            let _lock = vaultos_core::audit::lock(dir)?;
            optional(
                vaultos_core::audit::FILE,
                vaultos_core::audit::MAX_LOG_BYTES,
            )?
        };
        fs_safe::private_dir(target)?;
        fs_safe::atomic_write(&target.join(VAULT_FILE), &vault)?;
        for (name, bytes) in index.into_iter().chain(log) {
            fs_safe::atomic_write(&target.join(name), &bytes)?;
        }
        say("Encrypted vault, audit log and sync index backed up. Restoring needs the password and Secret Key; agent tokens and machine credentials were not copied.")
    }

    fn rotate_password(&self) -> Result<()> {
        let mut store = self.store()?;
        let _owner = self.own()?;
        let pw = self.passwords(2, true)?;
        if pw[0].expose() == pw[1].expose() {
            return Err(Fail::new(
                "The new password must differ from the current one",
            ));
        }
        let secret_key = self.secret_key(&store)?;
        store.unlock(&pw[0], secret_key.as_ref())?;
        let changed = store.change_password(&pw[0], &pw[1], secret_key.as_ref());
        let audited = changed.is_ok() && audited(&mut store, "rotate_master_password");
        store.lock();
        changed?;
        emit(&json!({
            "ok": true,
            "note": "Unlock VaultOS again with the new password.",
            "warnings": warnings(audited),
        }))
    }
}

/// `admin.js` `accessChange`: which grants the flags give, keeping the current ones a flag
/// does not mention.
fn access_change(
    a: &Access,
    no_projects: bool,
    no_roots: bool,
    current: Option<&vaultos_core::agents::Agent>,
) -> Result<(bool, Vec<String>, Vec<String>, Wildcards)> {
    if a.all_projects && (!a.projects.is_empty() || no_projects) {
        return Err(Fail::usage(
            "Use either --all-projects or --projects/--no-projects",
        ));
    }
    if a.any_root && (!a.roots.is_empty() || no_roots) {
        return Err(Fail::usage("Use either --any-root or --roots/--no-roots"));
    }
    let projects_given = a.all_projects || !a.projects.is_empty() || no_projects;
    let roots_given = a.any_root || !a.roots.is_empty() || no_roots;
    let projects = if projects_given {
        list(&a.projects)
    } else {
        current.map(|c| c.projects.clone()).unwrap_or_default()
    };
    let roots = if roots_given {
        list(&a.roots)
    } else {
        current.map(|c| c.roots.clone()).unwrap_or_default()
    };
    let wildcards = Wildcards {
        all_projects: if projects_given {
            a.all_projects
        } else {
            current.is_some_and(|c| c.all_projects)
        },
        any_root: if roots_given {
            a.any_root
        } else {
            current.is_some_and(|c| c.any_root)
        },
    };
    Ok((projects_given || roots_given, projects, roots, wildcards))
}

fn summary(store: &Store, id: &str) -> Result<Value> {
    let s = store
        .list_agents()?
        .into_iter()
        .find(|a| a.id == id)
        .ok_or_else(|| Fail::new("Agent not found"))?;
    serde_json::to_value(s).map_err(|_| Fail::new("The result could not be encoded"))
}

fn agent(store: &Store, name: &str) -> Result<vaultos_core::agents::Agent> {
    store
        .find_agent(name)?
        .ok_or_else(|| Fail::new("Agent not found"))
}

fn agents(ctx: &Ctx, cmd: AgentsCommand) -> Result<()> {
    if let AgentsCommand::Enroll { token_file, .. } = &cmd {
        prepare_private_file(token_file, "--token-file")?;
    }
    let mut open = ctx.open()?;
    let store = &mut open.store;
    match cmd {
        AgentsCommand::List => emit(&store.list_agents()?),
        AgentsCommand::Enroll {
            name,
            token_file,
            scopes,
            access,
        } => {
            let scopes = scopes.map(|s| list(&[s]));
            let existing = store
                .agent_records()?
                .into_iter()
                .find(|a| a.name.to_lowercase() == name.trim().to_lowercase());
            let reissued = existing.is_some();
            let action = if reissued {
                "reissue_agent"
            } else {
                "enrol_agent"
            };
            // The audit entry is written before the save, so no change goes unaudited. The token
            // file only after it: a token the vault never saved would replace a working one.
            let issued = store.batch(|s| {
                let issued = match &existing {
                    None => {
                        let (_, projects, roots, wildcards) =
                            access_change(&access, false, false, None).map_err(to_core)?;
                        s.enrol_agent(&name, scopes.as_deref(), &projects, &roots, wildcards)?
                    }
                    Some(current) => {
                        let (changed, projects, roots, wildcards) =
                            access_change(&access, false, false, Some(current)).map_err(to_core)?;
                        if changed {
                            s.set_agent_access(&current.id, &projects, &roots, wildcards)?;
                        }
                        if let Some(scopes) = &scopes {
                            s.set_agent_scopes(&current.id, scopes)?;
                        }
                        s.reissue_agent(&current.id)?
                    }
                };
                s.audit(action, &format!("{} via {VIA}", issued.name), HUMAN)?;
                Ok(issued)
            })?;
            write_token(&token_file, &issued.token).map_err(unsaved_token)?;
            let mut out = summary(store, &issued.id)?;
            out["tokenFile"] = json!(token_file);
            out["reissued"] = json!(reissued);
            emit(&out)
        }
        AgentsCommand::Grant {
            name,
            scopes,
            access,
            no_projects,
            no_roots,
            run_commands,
            no_run_commands,
        } => {
            let a = agent(store, &name)?;
            let scopes = scopes.map(|s| list(&[s]));
            let (changed, projects, roots, wildcards) =
                access_change(&access, no_projects, no_roots, Some(&a))?;
            let commands = (no_run_commands || !run_commands.is_empty()).then_some(run_commands);
            if !changed && scopes.is_none() && commands.is_none() {
                return Err(Fail::usage(
                    "Specify --scopes, --projects/--all-projects/--no-projects, --roots/--any-root/--no-roots or --run-command/--no-run-commands",
                ));
            }
            store.batch(|s| {
                if changed {
                    s.set_agent_access(&a.id, &projects, &roots, wildcards)?;
                }
                if let Some(scopes) = &scopes {
                    s.set_agent_scopes(&a.id, scopes)?;
                }
                if let Some(commands) = &commands {
                    s.set_agent_run_commands(&a.id, commands)?;
                }
                Ok(())
            })?;
            store.audit("grant_agent", &format!("{} via {VIA}", a.name), HUMAN)?;
            emit(&summary(store, &a.id)?)
        }
        AgentsCommand::Revoke { name } => {
            let a = agent(store, &name)?;
            store.revoke_agent(&a.id)?;
            store.audit("revoke_agent", &format!("{} via {VIA}", a.name), HUMAN)?;
            emit(&summary(store, &a.id)?)
        }
    }
}

/// Carries a usage problem found inside a batch out through the core's error type.
fn to_core(f: Fail) -> Error {
    Error::Invalid(f.message)
}

/// A token the vault saved but that could not be written: the old one no longer works.
fn unsaved_token(f: Fail) -> Fail {
    Fail::new(format!(
        "The new token is in effect but could not be written ({}); the previous token no longer works. Run the command again to issue another.",
        f.message
    ))
}

fn pending(ctx: &Ctx, cmd: PendingCommand) -> Result<()> {
    let usage = "usage: vaultos pending approve PROJECT KEY | --all [--project P]";
    if let PendingCommand::Approve {
        all: false,
        key: None,
        ..
    } = &cmd
    {
        return Err(Fail::usage(usage));
    }
    let mut open = ctx.open()?;
    let store = &mut open.store;
    match cmd {
        PendingCommand::List => emit(&store.pending_approvals()?),
        PendingCommand::Approve {
            all: true, only, ..
        } => emit(&store.approve_all_pending(VIA, only.as_deref())?),
        PendingCommand::Approve {
            project_name: Some(p),
            key: Some(k),
            ..
        } => emit(&store.approve_pending(&p, &k, VIA)?),
        PendingCommand::Approve { .. } => Err(Fail::usage(usage)),
        PendingCommand::Deny { project, key } => emit(&store.deny_pending(&project, &key, VIA)?),
    }
}

fn approver(ctx: &Ctx, cmd: ApproverCommand) -> Result<()> {
    if let ApproverCommand::Set { token_file } = &cmd {
        prepare_private_file(token_file, "--token-file")?;
    }
    let mut open = ctx.open()?;
    let store = &mut open.store;
    match cmd {
        ApproverCommand::Set { token_file } => {
            // Written after the save, so the file never holds a token the vault does not know.
            let token = store.issue_approver_token()?;
            write_token(&token_file, &token).map_err(unsaved_token)?;
            emit(&json!({ "approverConfigured": true, "tokenFile": token_file }))
        }
        ApproverCommand::Clear => {
            emit(&json!({ "approverConfigured": store.set_approver_hash(None)? }))
        }
        ApproverCommand::Status => {
            emit(&json!({ "approverConfigured": store.approver_configured()? }))
        }
    }
}

fn secret_key(ctx: &Ctx, cmd: SecretKeyCommand) -> Result<()> {
    let mut open = ctx.open()?;
    let Open {
        store,
        password,
        secret_key,
        ..
    } = &mut open;
    match cmd {
        SecretKeyCommand::Set {
            new_secret_key_file,
        } => {
            let ((), key) = with_new_secret_key(Some(&new_secret_key_file), |next| {
                store.set_secret_key(password, secret_key.as_ref(), next)
            })?;
            let audited = audited(store, "set_secret_key");
            emit(&merge(
                json!({ "ok": true, "warnings": warnings(audited) }),
                key,
            ))
        }
        SecretKeyCommand::Remove => {
            if secret_key.is_none() {
                return Err(Fail::new("This vault does not use a Secret Key"));
            }
            store.set_secret_key(password, secret_key.as_ref(), None)?;
            let audited = audited(store, "remove_secret_key");
            emit(&json!({ "ok": true, "secretKey": false, "warnings": warnings(audited) }))
        }
    }
}

fn sync(ctx: &Ctx, cmd: SyncCommand) -> Result<()> {
    let exit = |ok: bool| if ok { Ok(()) } else { Err(Fail::quiet(2)) };
    if let SyncCommand::Now = cmd {
        let reply = ctx.owner_client().owner("POST", "/sync", None)?;
        emit(&reply)?;
        return exit(reply["ok"] == json!(true));
    }
    let repo = vaultos_sync::default_repo(&ctx.data_dir)?;
    let mut open = ctx.open()?;
    let store = &mut open.store;
    let engine = vaultos_sync::Sync::new(&ctx.data_dir, &repo);
    match cmd {
        SyncCommand::Init { label } => {
            let identity = engine.init(store, &label)?;
            let _ = store.audit("sync_init", &label, HUMAN);
            emit(&identity)
        }
        SyncCommand::Identity => emit(&engine.identity(store)?),
        SyncCommand::Trust { file } => {
            let bytes = fs_safe::read_regular(&file, 16 * 1024)?;
            let identity: Value = serde_json::from_slice(&bytes)
                .map_err(|_| Fail::new("The identity file is not JSON"))?;
            let trusted = engine.trust(store, &identity)?;
            let detail = format!(
                "{} ({})",
                identity["label"].as_str().unwrap_or_default(),
                trusted["id"].as_str().unwrap_or_default()
            );
            let _ = store.audit("sync_trust", &detail, HUMAN);
            emit(&trusted)
        }
        SyncCommand::Status => {
            let status = engine.status_remote(store)?;
            emit(&status)?;
            exit(status["state"] == json!("IN_SYNC"))
        }
        SyncCommand::Push => {
            let pushed = engine.push_remote(store, None)?;
            emit(&pushed)?;
            exit(pushed["delivered"] == json!(true))
        }
        SyncCommand::Plan => emit(&engine.pull(store, false, false)?.detail()),
        SyncCommand::Pull => emit(&engine.pull_remote(store, false)?),
        SyncCommand::AcceptConflicts => emit(&engine.pull_remote(store, true)?),
        SyncCommand::Auto { state, interval } => {
            let mut auto = store
                .settings()?
                .get("autoSync")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            auto.insert("enabled".into(), json!(state == "on"));
            if let Some(i) = interval {
                auto.insert("intervalSeconds".into(), json!(i));
            }
            let mut patch = serde_json::Map::new();
            patch.insert("autoSync".into(), Value::Object(auto.clone()));
            store.update_settings(patch, HUMAN)?;
            emit(&json!({ "ok": true, "autoSync": auto }))
        }
        SyncCommand::Now => Ok(()),
    }
}

fn run(cli: Cli) -> Result<()> {
    let data_dir = vaultos_core::paths::default_data_dir()?;
    let ctx = Ctx {
        data_dir,
        password_stdin: cli.password_stdin,
        secret_key_file: cli.secret_key_file,
        stop_backend: cli.stop_backend,
    };
    match cli.command {
        Command::Init {
            new_secret_key_file,
        } => ctx.init(new_secret_key_file.as_deref()),
        Command::Upgrade {
            new_secret_key_file,
        } => ctx.upgrade(new_secret_key_file.as_deref()),
        Command::Status => ctx.status(),
        Command::Start => ctx.start(),
        Command::Unlock => ctx.unlock(),
        Command::Lock => ctx.owner_route("/lock"),
        Command::Stop => ctx.stop(),
        Command::Backup { directory } => ctx.backup(&directory),
        Command::RotatePassword => ctx.rotate_password(),
        Command::Projects => emit(&ctx.open()?.store.list_projects()?),
        Command::Keys { project } => emit(&ctx.open()?.store.list_items(&project)?),
        Command::Add {
            project,
            key,
            note,
            provider,
            extra,
        } => {
            if !extra.is_empty() {
                return Err(Fail::usage(
                    "The value is read from stdin or a hidden prompt; never pass it as an argument",
                ));
            }
            let (password, value) = ctx.add_input()?;
            let mut open = ctx.open_with(password)?;
            let value = match value {
                Some(v) => v,
                None => prompt("Value: ")?,
            };
            if value.expose().is_empty() {
                return Err(Fail::usage("No value was received"));
            }
            let fields = Fields {
                key,
                value: Some(value),
                note,
                provider,
                ..Default::default()
            };
            let (created, saved) = open.store.batch(|s| {
                let created = s.find_project(&project)?.is_none();
                if created {
                    s.create_project(&project, HUMAN)?;
                }
                Ok((created, s.set_item(&project, &fields, HUMAN)?))
            })?;
            emit(&json!({ "project": project, "stored": saved.key, "createdProject": created }))
        }
        Command::Import { project, file } => {
            if !file.is_absolute() {
                return Err(Fail::usage("Specify an absolute file path"));
            }
            let mut open = ctx.open()?;
            let pairs = vaultos_core::env::read_env_file(&file)?;
            let (created, keys) = open.store.batch(|s| {
                let created = s.find_project(&project)?.is_none();
                if created {
                    s.create_project(&project, HUMAN)?;
                }
                let mut keys = Vec::new();
                for (key, value) in &pairs {
                    let fields = Fields {
                        key: key.clone(),
                        value: Some(SecretString::new(value.as_str())),
                        ..Default::default()
                    };
                    s.set_item(&project, &fields, HUMAN)?;
                    keys.push(key.clone());
                }
                Ok((created, keys))
            })?;
            let _ = open
                .store
                .audit("import", &format!("{project}: {} keys", keys.len()), HUMAN);
            emit(&json!({ "project": project, "keys": keys, "createdProject": created }))
        }
        Command::Inject {
            project,
            file,
            format,
        } => {
            if !file.is_absolute() {
                return Err(Fail::usage("Specify an absolute file path"));
            }
            let format = vaultos_core::env::Format::parse(&format)?;
            let mut open = ctx.open()?;
            emit(
                &open
                    .store
                    .inject(&project, &file, format, false, None, HUMAN)?,
            )
        }
        Command::ImportItems { project, file } => {
            if !file.is_absolute() {
                return Err(Fail::usage("Specify an absolute file path"));
            }
            let meta = std::fs::metadata(&file).map_err(|e| Fail::new(e.to_string()))?;
            if !meta.is_file() || meta.len() > vaultos_core::import::MAX_IMPORT_BYTES as u64 {
                return Err(Fail::usage("Specify an export file of at most 64 MB"));
            }
            let bytes = zeroize::Zeroizing::new(
                std::fs::read(&file).map_err(|e| Fail::new(e.to_string()))?,
            );
            let name = file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let format = vaultos_core::import::Format::detect(&name, &bytes).ok_or_else(|| {
                Fail::usage("Expected a 1Password .1pux, a Bitwarden .json or a .csv export")
            })?;
            let report = vaultos_core::import::parse(format, &bytes)?;
            let mut open = ctx.open()?;
            emit(&open.store.batch(|s| {
                if s.find_project(&project)?.is_none() {
                    s.create_project(&project, HUMAN)?;
                }
                s.import_items(&project, report, HUMAN)
            })?)
        }
        Command::Otp { project, key } => {
            let open = ctx.open()?;
            let otp = open.store.otp(&project, &key, HUMAN)?;
            say(otp.code.expose())
        }
        Command::Read {
            reference,
            no_newline,
        } => {
            let got = ctx.values(&[SecretRef::parse(&reference)?], None, "read")?;
            let mut out = std::io::stdout().lock();
            let value = got.refs.first().map_or("", |v| v.as_str());
            out.write_all(value.as_bytes())
                .and_then(|()| {
                    if no_newline {
                        Ok(())
                    } else {
                        out.write_all(b"\n")
                    }
                })
                .and_then(|()| out.flush())
                .map_err(|_| Fail::new("cannot write to stdout"))
        }
        Command::Render { template, output } => ctx.render(&template, output.as_deref()),
        Command::Run {
            project,
            keys,
            env_file,
            no_masking,
            command,
        } => ctx.run_command(
            project.as_deref(),
            &list(&keys),
            &env_file,
            no_masking,
            command,
        ),
        Command::Generate {
            length,
            words,
            pin,
            no_symbols,
        } => {
            use vaultos_core::generator::{generate, Recipe};
            let recipe = match (words, pin) {
                (Some(words), _) => Recipe::Passphrase {
                    words,
                    separator: "-".into(),
                    capitalize: false,
                    number: false,
                },
                (None, true) => Recipe::Pin {
                    length: length.unwrap_or(6),
                },
                (None, false) => Recipe::Random {
                    length: length.unwrap_or(24),
                    digits: true,
                    symbols: !no_symbols,
                    avoid_ambiguous: false,
                },
            };
            say(generate(&recipe)?.value.expose())
        }
        Command::Agents(c) => agents(&ctx, c),
        Command::Pending(c) => pending(&ctx, c),
        Command::Approver(c) => approver(&ctx, c),
        Command::SecretKey(c) => secret_key(&ctx, c),
        Command::Sync(c) => sync(&ctx, c),
    }
}

/// What [`Ctx::values`] returns: the references' values in order, and a project's values.
struct Got {
    refs: Vec<Zeroizing<String>>,
    env: Vec<(String, Zeroizing<String>)>,
    held: Vec<String>,
}

const MAX_TEMPLATE: u64 = 1024 * 1024;

impl Ctx {
    /// Values for the human's own commands. While the app or vaultosd owns the vault, it is
    /// asked (it confirms with Touch ID, or this asks for the master password); otherwise the
    /// vault is opened here for the moment it takes.
    fn values(
        &self,
        refs: &[SecretRef],
        env: Option<(&str, Option<&[String]>)>,
        purpose: &str,
    ) -> Result<Got> {
        let client = self.owner_client();
        if client.live(Duration::from_millis(1500)).is_none() {
            let mut open = self.open()?;
            let values = if refs.is_empty() {
                Vec::new()
            } else {
                open.store.resolve_refs(refs, purpose, HUMAN)?
            };
            let (env, held) = match env {
                Some((project, keys)) => {
                    let e = open.store.env_values(project, keys, purpose, HUMAN)?;
                    (e.pairs, e.held_for_approval)
                }
                None => (Vec::new(), Vec::new()),
            };
            return Ok(Got {
                refs: values,
                env,
                held,
            });
        }
        let mut body = json!({
            "refs": refs.iter().map(SecretRef::to_uri).collect::<Vec<_>>(),
            "purpose": purpose,
        });
        if let Some((project, keys)) = env {
            body["env"] = json!({ "project": project });
            if let Some(k) = keys {
                body["env"]["keys"] = json!(k);
            }
        }
        let mut with_password = self.password_stdin;
        let reply = loop {
            if with_password {
                let store = self.store()?;
                let password = self.passwords(1, false)?.remove(0);
                body["password"] = json!(password.expose());
                if let Some(k) = self.secret_key(&store)? {
                    body["secretKey"] = json!(k.display().expose());
                }
            }
            let reply = client.owner("POST", "/human/values", Some(&body));
            for field in ["password", "secretKey"] {
                if let Some(Value::String(s)) = body.get_mut(field) {
                    zeroize::Zeroize::zeroize(s);
                }
            }
            match reply {
                Err(e) if e.status == Some(401) && !with_password => with_password = true,
                other => break other?,
            }
        };
        let text = |v: &Value| Zeroizing::new(v.as_str().unwrap_or_default().to_owned());
        let values = reply["values"]
            .as_array()
            .map(|a| a.iter().map(text).collect())
            .unwrap_or_default();
        let pairs = reply["env"]["values"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|p| {
                        (
                            p["key"].as_str().unwrap_or_default().to_owned(),
                            text(&p["value"]),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let held = reply["env"]["heldForApproval"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Got {
            refs: values,
            env: pairs,
            held,
        })
    }

    fn render(&self, template: &Path, output: Option<&Path>) -> Result<()> {
        let template =
            std::path::absolute(template).map_err(|_| Fail::usage("Invalid template path"))?;
        let bytes = Zeroizing::new(fs_safe::read_regular(&template, MAX_TEMPLATE)?);
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Fail::new("The template is not UTF-8 text"))?;
        let found = refs::placeholders(text)?;
        let wanted: Vec<SecretRef> = found.iter().map(|p| p.reference.clone()).collect();
        let values = if wanted.is_empty() {
            Vec::new()
        } else {
            let name = template
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            self.values(&wanted, None, &format!("render {name}"))?.refs
        };
        let rendered = Zeroizing::new(refs::render(text, &found, &values));
        let Some(output) = output else {
            let mut out = std::io::stdout().lock();
            return out
                .write_all(rendered.as_bytes())
                .and_then(|()| out.flush())
                .map_err(|_| Fail::new("cannot write to stdout"));
        };
        let output = std::path::absolute(output).map_err(|_| Fail::usage("Invalid output path"))?;
        if vaultos_core::agents::resolve_lexically(&output).starts_with(&self.data_dir) {
            return Err(Fail::usage("Cannot write over vault data"));
        }
        if !output.parent().is_some_and(Path::is_dir) {
            return Err(Fail::usage("The output file's folder does not exist"));
        }
        fs_safe::atomic_write(&output, rendered.as_bytes())?;
        emit(&json!({ "output": output, "references": found.len() }))
    }

    /// `vaultos run`: references in env files and in this environment, and a project's
    /// values, given to the command; its exit code becomes this process's.
    fn run_command(
        &self,
        project: Option<&str>,
        keys: &[String],
        env_files: &[PathBuf],
        no_masking: bool,
        command: Vec<std::ffi::OsString>,
    ) -> Result<()> {
        let mut plain = Vec::new();
        let mut named: Vec<(String, SecretRef)> = Vec::new();
        for file in env_files {
            let file =
                std::path::absolute(file).map_err(|_| Fail::usage("Invalid env file path"))?;
            for (k, v) in vaultos_core::env::read_env_file(&file)? {
                if refs::is_ref(&v) {
                    named.push((k, SecretRef::parse(&v)?));
                } else {
                    plain.push((k, v.as_str().to_owned()));
                }
            }
        }
        for (k, v) in std::env::vars_os() {
            let (Some(k), Some(v)) = (k.to_str(), v.to_str()) else {
                continue;
            };
            let set = |n: &String| n == k;
            if refs::is_ref(v)
                && !named.iter().any(|(n, _)| set(n))
                && !plain.iter().any(|(n, _)| set(n))
            {
                named.push((k.to_owned(), SecretRef::parse(v)?));
            }
        }
        if named.is_empty() && project.is_none() {
            return Err(Fail::usage(
                "Nothing to give the command: pass --project or --env-file, or set variables to vault:// references",
            ));
        }
        let program = command
            .first()
            .and_then(|c| Path::new(c).file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let refs: Vec<SecretRef> = named.iter().map(|(_, r)| r.clone()).collect();
        let keys = (!keys.is_empty()).then_some(keys);
        let got = self.values(&refs, project.map(|p| (p, keys)), &format!("run {program}"))?;
        if !got.held.is_empty() {
            eprintln!(
                "vaultos: left out keys awaiting your approval: {}",
                got.held.join(", ")
            );
        }
        let mut env = got.env;
        env.extend(named.into_iter().map(|(k, _)| k).zip(got.refs));
        let program = vaultos_client::run::Program {
            argv: command,
            cwd: None,
            env,
            plain,
        };
        let code = vaultos_client::run::stream(&program, !no_masking)
            .map_err(|e| Fail::new(format!("cannot run the command: {e}")))?;
        match code {
            0 => Ok(()),
            c => Err(Fail::quiet(u8::try_from(c).unwrap_or(1))),
        }
    }
}

fn main() -> ExitCode {
    vaultos_core::hardening::harden_process();
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) => {
            if !f.message.is_empty() {
                eprintln!("vaultos: {}", f.message);
            }
            ExitCode::from(f.code)
        }
    }
}
