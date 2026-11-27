//! What `vaultos` and `vaultos-agent` share: failures with exit codes, JSON output, and
//! bounded reads from stdin into buffers that are zeroed when dropped.

use serde_json::json;
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use vaultos_client::{agent_token_path, Client};
use vaultos_core::agents::{Enrollment, Selection};
use vaultos_core::{fs_safe, SecretString};
use zeroize::Zeroizing;

/// A failure to report: the message goes to stderr and `code` is the exit status.
#[derive(Debug)]
pub struct Fail {
    pub message: String,
    pub code: u8,
}

impl Fail {
    pub fn new(message: impl Into<String>) -> Fail {
        Fail {
            message: message.into(),
            code: 1,
        }
    }

    /// Exit with `code` after printing a result that already says what went wrong.
    pub fn quiet(code: u8) -> Fail {
        Fail {
            message: String::new(),
            code,
        }
    }

    pub fn usage(message: impl Into<String>) -> Fail {
        Fail {
            message: message.into(),
            code: 2,
        }
    }
}

impl From<vaultos_core::Error> for Fail {
    fn from(e: vaultos_core::Error) -> Fail {
        Fail::new(e.to_string())
    }
}

impl From<vaultos_sync::SyncError> for Fail {
    fn from(e: vaultos_sync::SyncError) -> Fail {
        Fail::new(e.message)
    }
}

impl From<vaultos_client::ClientError> for Fail {
    fn from(e: vaultos_client::ClientError) -> Fail {
        Fail {
            code: e.code.exit_code(),
            message: e.message,
        }
    }
}

pub type Result<T> = std::result::Result<T, Fail>;

/// Prints `value` as indented JSON, the way the JavaScript tools did.
pub fn emit(value: &impl serde::Serialize) -> Result<()> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|_| Fail::new("The result could not be encoded"))?;
    say(&text)
}

/// Prints one line on stdout.
pub fn say(text: &str) -> Result<()> {
    writeln!(std::io::stdout().lock(), "{text}").map_err(|_| Fail::new("cannot write to stdout"))
}

/// All of stdin as UTF-8, refusing more than `max` bytes.
pub fn read_stdin(max: usize, too_large: &str) -> Result<Zeroizing<String>> {
    // Sized up front and bounded by `take`, so the buffer never grows and leaves a copy.
    let mut buf = Zeroizing::new(Vec::with_capacity(max + 1));
    std::io::stdin()
        .lock()
        .take(max as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| Fail::new("cannot read stdin"))?;
    if buf.len() > max {
        return Err(Fail::new(too_large));
    }
    let text = std::str::from_utf8(&buf).map_err(|_| Fail::new("stdin is not UTF-8 text"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

#[derive(Debug, clap::Args)]
pub struct Access {
    /// Projects to grant (names or IDs, comma-separated or repeated)
    #[arg(long, value_name = "A,B")]
    pub projects: Vec<String>,
    /// Grant every project, including future ones
    #[arg(long)]
    pub all_projects: bool,
    /// Folders the agent may read and write files in (absolute)
    #[arg(long, value_name = "DIR,DIR")]
    pub roots: Vec<String>,
    /// Allow files in any folder
    #[arg(long)]
    pub any_root: bool,
}

#[derive(Debug, clap::Args)]
pub struct Enroll {
    name: String,
    /// Absolute private token file (default <data dir>/agents/NAME.token)
    #[arg(long, value_name = "PATH")]
    token_file: Option<PathBuf>,
    /// Scopes, comma-separated (new agents default to read,inject)
    #[arg(long, value_name = "A,B")]
    scopes: Option<String>,
    #[command(flatten)]
    access: Access,
}

impl Enroll {
    pub fn prepare(self, data_dir: &Path) -> Result<(Enrollment, PathBuf)> {
        let file = match self.token_file {
            Some(file) => file,
            None => agent_token_path(data_dir, &self.name).map_err(|_| Fail::usage(
                "Use a plain agent name (letters, digits, dot, dash, underscore), or provide an absolute --token-file path",
            ))?,
        };
        let selection = |all, values: &[String], usage| match (all, values.is_empty()) {
            (true, false) => Err(Fail::usage(usage)),
            (true, true) => Ok(Some(Selection::All)),
            (false, true) => Ok(None),
            (false, false) => Ok(Some(Selection::Only(list(values)))),
        };
        let request = Enrollment {
            name: self.name,
            scopes: self.scopes.map(|s| list(&[s])),
            projects: selection(
                self.access.all_projects,
                &self.access.projects,
                "Use either --all-projects or --projects",
            )?,
            roots: selection(
                self.access.any_root,
                &self.access.roots,
                "Use either --any-root or --roots",
            )?,
        };
        prepare_private_file(&file, "--token-file")?;
        fs_safe::regular_file(&file, true, u64::MAX)
            .map_err(|_| Fail::new("The token file must be a regular, unlinked file"))?;
        Ok((request, file))
    }
}

pub fn list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn enroll_live(client: &Client, request: &Enrollment, file: &Path) -> Result<()> {
    let (token, mut summary) = client.request_enrollment(request)?;
    write_token(file, &token).map_err(unsaved_token)?;
    summary["tokenFile"] = json!(file);
    emit(&summary)
}

/// `admin.js` `prepareTokenFile`: an absolute path whose parent is a writable directory
/// (created 0700 if missing) and which, if it exists, is a regular file.
pub fn prepare_private_file(file: &Path, flag: &str) -> Result<()> {
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

pub fn write_token(file: &Path, token: &SecretString) -> Result<()> {
    let mut line = zeroize::Zeroizing::new(token.expose().as_bytes().to_vec());
    line.push(b'\n');
    fs_safe::atomic_write(file, &line)?;
    Ok(())
}

/// A token the vault saved but that could not be written: the old one no longer works.
pub fn unsaved_token(f: Fail) -> Fail {
    Fail::new(format!(
        "The new token is in effect but could not be written ({}); the previous token no longer works. Run the command again to issue another.",
        f.message
    ))
}
