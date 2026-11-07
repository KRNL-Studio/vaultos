//! Talking to `vaultosd`, ported from `agent-client.js`: find the daemon through
//! `daemon.json`, discover this agent's token, and turn the daemon's replies into errors an
//! agent can act on (locked, not running, no token, refused). Used by `vaultos-agent`, the
//! MCP bridge and the human CLI.

pub mod http;

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::{json, Map, Value};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use vaultos_core::session::Session;
use vaultos_core::SecretString;
use zeroize::Zeroizing;

pub mod messages {
    pub const NO_TOKEN: &str = "No agent token is configured. Ask the human to enroll this agent in VaultOS and set VAULTOS_AGENT_TOKEN_FILE (or VAULTOS_AGENT with a per-agent token file).";
    pub const LOCKED: &str = "VaultOS is running but locked. Ask the human to unlock it (`vaultos unlock`); do not retry in a loop.";
    pub const NOT_RUNNING: &str = "VaultOS is not running. Ask the human to start it (`vaultosd`, or the login service) and unlock it (`vaultos unlock`); do not retry in a loop.";
    pub const NO_VAULT: &str = "No VaultOS vault exists in this data directory. Check VAULTOS_DATA_DIR or ask the human to create the vault (`vaultos init`).";
    pub const INTERRUPTED: &str =
        "Connection interrupted. Check the operation result before retrying a write";
}

/// What kind of failure, and the exit code `vaultos-agent` uses for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    Usage,
    NotRunning,
    Locked,
    Token,
    Refused,
    Interrupted,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::Usage => "usage",
            Code::NotRunning => "not_running",
            Code::Locked => "locked",
            Code::Token => "token",
            Code::Refused => "refused",
            Code::Interrupted => "interrupted",
        }
    }

    pub fn exit_code(self) -> u8 {
        match self {
            Code::Usage => 2,
            Code::NotRunning => 3,
            Code::Locked => 4,
            Code::Token => 5,
            Code::Refused | Code::Interrupted => 1,
        }
    }
}

#[derive(Debug)]
pub struct ClientError {
    pub code: Code,
    pub message: String,
    pub status: Option<u16>,
}

impl ClientError {
    pub fn new(code: Code, message: impl Into<String>) -> ClientError {
        ClientError {
            code,
            message: message.into(),
            status: None,
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ClientError {}

type Result<T> = std::result::Result<T, ClientError>;

/// `encodeURIComponent`, for project and key names in paths.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

pub fn enc(s: &str) -> String {
    utf8_percent_encode(s, COMPONENT).to_string()
}

fn token_ok(t: &str) -> bool {
    (16..=512).contains(&t.len()) && t.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Reads a token file: absolute, a regular file with one link, owned by this user, mode
/// 0600 or stricter, holding 16 to 512 printable characters.
pub fn read_token_file(path: &Path) -> Result<SecretString> {
    use std::os::unix::fs::MetadataExt;
    let bad = |m: &str| ClientError::new(Code::Token, m);
    if !path.is_absolute() {
        return Err(bad("The agent token file path must be absolute"));
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(bad("The agent token file does not exist"))
        }
        Err(_) => return Err(bad("The agent token file must be a regular, unlinked file")),
    };
    if !meta.file_type().is_file() || meta.nlink() != 1 || meta.len() > 4096 {
        return Err(bad("The agent token file must be a regular, unlinked file"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(bad("The agent token file must be private (mode 0600)"));
    }
    if meta.uid() != my_uid() {
        return Err(bad(
            "The agent token file must be owned by the current user",
        ));
    }
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|_| bad("The agent token file must be a regular, unlinked file"))?,
    );
    let token = text.trim();
    if !token_ok(token) {
        return Err(bad("The agent token file is empty or malformed"));
    }
    Ok(SecretString::new(token))
}

fn my_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn agent_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.len() <= 100
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// `<data dir>/agents/NAME.token` for `VAULTOS_AGENT=NAME`.
pub fn agent_token_path(data_dir: &Path, name: &str) -> Result<PathBuf> {
    if !agent_name_ok(name) {
        return Err(ClientError::new(
            Code::Token,
            "VAULTOS_AGENT must be a plain agent name (letters, digits, dot, dash, underscore)",
        ));
    }
    Ok(data_dir.join("agents").join(format!("{name}.token")))
}

/// The token from `VAULTOS_AGENT_TOKEN`, `VAULTOS_AGENT_TOKEN_FILE` or `VAULTOS_AGENT`, in
/// that order, and which one supplied it.
pub fn discover_token(
    env: impl Fn(&str) -> Option<String>,
    data_dir: &Path,
) -> Result<Option<(SecretString, &'static str)>> {
    if let Some(t) = env("VAULTOS_AGENT_TOKEN").filter(|t| !t.is_empty()) {
        let t = Zeroizing::new(t);
        if !token_ok(t.trim()) {
            return Err(ClientError::new(
                Code::Token,
                "VAULTOS_AGENT_TOKEN is malformed",
            ));
        }
        return Ok(Some((SecretString::new(t.trim()), "VAULTOS_AGENT_TOKEN")));
    }
    if let Some(f) = env("VAULTOS_AGENT_TOKEN_FILE").filter(|f| !f.is_empty()) {
        return Ok(Some((
            read_token_file(Path::new(&f))?,
            "VAULTOS_AGENT_TOKEN_FILE",
        )));
    }
    if let Some(name) = env("VAULTOS_AGENT").filter(|n| !n.is_empty()) {
        return Ok(Some((
            read_token_file(&agent_token_path(data_dir, &name)?)?,
            "VAULTOS_AGENT",
        )));
    }
    Ok(None)
}

#[derive(Debug)]
pub struct Client {
    data_dir: PathBuf,
    token: Option<SecretString>,
    token_problem: Option<String>,
    /// How long to keep waiting for a daemon whose process is alive but not answering
    /// (busy unlocking).
    busy_wait: Duration,
}

const STATUS_TIMEOUT: Duration = Duration::from_millis(1500);
/// Sync rounds can take up to two minutes.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(130);

impl Client {
    /// A client for `data_dir`, with the agent token found in the environment.
    pub fn from_env(data_dir: PathBuf) -> Client {
        let (token, token_problem) = match discover_token(|k| std::env::var(k).ok(), &data_dir) {
            Ok(Some((t, _))) => (Some(t), None),
            Ok(None) => (None, Some(messages::NO_TOKEN.to_owned())),
            Err(e) => (None, Some(e.message)),
        };
        Client {
            data_dir,
            token,
            token_problem,
            busy_wait: Duration::from_secs(75),
        }
    }

    /// A client with an explicit token (`None` for owner requests only).
    pub fn with_token(data_dir: PathBuf, token: Option<SecretString>) -> Client {
        Client {
            data_dir,
            token,
            token_problem: Some(messages::NO_TOKEN.to_owned()),
            busy_wait: Duration::from_secs(75),
        }
    }

    pub fn with_busy_wait(mut self, wait: Duration) -> Client {
        self.busy_wait = wait;
        self
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The running daemon's session and `/status`, if one answers.
    pub fn live(&self, timeout: Duration) -> Option<(Session, Value)> {
        let session = Session::read(&self.data_dir)?;
        let r = http::request(&session.socket, "GET", "/status", &[], None, timeout).ok()?;
        let status: Value = serde_json::from_slice(&r.body).ok()?;
        (r.status == 200 && status.get("app").and_then(Value::as_str) == Some("VaultOS-Preview"))
            .then_some((session, status))
    }

    fn ensure_up(&self) -> Result<(Session, Value)> {
        if let Some(up) = self.live(STATUS_TIMEOUT) {
            return Ok(up);
        }
        // A daemon unlocking (Argon2id) cannot answer at once. While its process is alive,
        // keep asking instead of reporting it as not running.
        if let Some(s) = Session::read(&self.data_dir) {
            let deadline = Instant::now() + self.busy_wait;
            while Instant::now() < deadline
                && s.pid != std::process::id()
                && vaultos_core::fs_safe::pid_alive(s.pid as i32)
            {
                if let Some(up) = self.live(Duration::from_millis(2500)) {
                    return Ok(up);
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        if !self.data_dir.join(vaultos_core::store::VAULT_FILE).exists() {
            return Err(ClientError::new(Code::NotRunning, messages::NO_VAULT));
        }
        Err(ClientError::new(Code::NotRunning, messages::NOT_RUNNING))
    }

    /// `agent-client.js` `status`: whether the daemon runs and is unlocked, never an error.
    pub fn status(&self) -> Value {
        let (_, st) = match self.ensure_up() {
            Ok(up) => up,
            Err(e) => {
                return json!({
                    "running": false,
                    "unlocked": false,
                    "reason": e.code.as_str(),
                    "message": e.message,
                })
            }
        };
        let unlocked = st.get("locked") == Some(&Value::Bool(false));
        let mut out = Map::new();
        out.insert("running".into(), Value::Bool(true));
        out.insert("unlocked".into(), Value::Bool(unlocked));
        if !unlocked {
            out.insert("reason".into(), json!("locked"));
            out.insert("message".into(), json!(messages::LOCKED));
        }
        for k in ["formatVersion", "deployment"] {
            if let Some(v) = st.get(k) {
                out.insert(k.into(), v.clone());
            }
        }
        if let Some(sync) = st.get("sync") {
            let get = |k: &str| sync.get(k).cloned();
            out.insert(
                "sync".into(),
                json!({
                    "autoSync": get("enabled") == Some(Value::Bool(true)),
                    "state": get("state").unwrap_or(json!("NOT_RUNNING")),
                    "halted": get("halted") == Some(Value::Bool(true)),
                    "lastSyncAt": get("lastSyncAt").unwrap_or(Value::Null),
                    "error": get("error").unwrap_or(Value::Null),
                    "peerStalled": get("peerStalled") == Some(Value::Bool(true)),
                    "peerProblems": get("peerProblems").unwrap_or(json!([])),
                }),
            );
        }
        Value::Object(out)
    }

    /// An agent request: needs this agent's token and an unlocked vault.
    pub fn request(&self, method: &str, route: &str, body: Option<&Value>) -> Result<Value> {
        let token = self.token.as_ref().ok_or_else(|| {
            ClientError::new(
                Code::Token,
                self.token_problem.as_deref().unwrap_or(messages::NO_TOKEN),
            )
        })?;
        let (session, status) = self.ensure_up()?;
        if status.get("locked") != Some(&Value::Bool(false)) {
            return Err(ClientError::new(Code::Locked, messages::LOCKED));
        }
        send(&session, method, route, body, Some(token))
    }

    /// An owner request (unlock, lock, stop, admin): the session token alone. Works on a
    /// locked daemon.
    pub fn owner(&self, method: &str, route: &str, body: Option<&Value>) -> Result<Value> {
        let (session, _) = self.ensure_up()?;
        send(&session, method, route, body, None)
    }
}

fn send(
    session: &Session,
    method: &str,
    route: &str,
    body: Option<&Value>,
    agent: Option<&SecretString>,
) -> Result<Value> {
    let bearer = Zeroizing::new(format!("Bearer {}", session.token));
    let mut headers = vec![("Authorization", bearer.as_str())];
    if let Some(t) = agent {
        headers.push(("x-vault-agent-token", t.expose()));
    }
    let payload = body
        .map(|b| serde_json::to_vec(b).map(Zeroizing::new))
        .transpose()
        .map_err(|_| ClientError::new(Code::Refused, "The request could not be encoded"))?;
    let r = http::request(
        &session.socket,
        method,
        route,
        &headers,
        payload.as_deref().map(Vec::as_slice),
        REQUEST_TIMEOUT,
    )
    .map_err(|_| ClientError::new(Code::Interrupted, messages::INTERRUPTED))?;
    let value: Value = serde_json::from_slice(&r.body).unwrap_or_else(|_| json!({}));
    if r.status == 423 {
        return Err(ClientError {
            code: Code::Locked,
            message: messages::LOCKED.into(),
            status: Some(423),
        });
    }
    if !(200..300).contains(&r.status) {
        let message = value.get("error").and_then(Value::as_str).map_or_else(
            || format!("Vault operation refused (HTTP {})", r.status),
            str::to_owned,
        );
        return Err(ClientError {
            code: Code::Refused,
            message,
            status: Some(r.status),
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_like_encode_uri_component() {
        assert_eq!(enc("My App/1 & 2"), "My%20App%2F1%20%26%202");
        assert_eq!(enc("a-b_c.d!~*'()"), "a-b_c.d!~*'()");
        assert_eq!(enc("é"), "%C3%A9");
    }

    #[test]
    fn discovers_tokens_in_order() {
        let d = std::path::Path::new("/nonexistent-vaultos");
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        let t = discover_token(env(&[("VAULTOS_AGENT_TOKEN", " 0123456789abcdef ")]), d)
            .ok()
            .flatten();
        assert_eq!(
            t.map(|(t, s)| (t.expose().to_owned(), s)),
            Some(("0123456789abcdef".into(), "VAULTOS_AGENT_TOKEN"))
        );
        assert!(discover_token(env(&[("VAULTOS_AGENT_TOKEN", "short")]), d).is_err());
        assert!(discover_token(env(&[("VAULTOS_AGENT", "../x")]), d).is_err());
        assert!(discover_token(env(&[("VAULTOS_AGENT_TOKEN_FILE", "relative")]), d).is_err());
        assert!(matches!(discover_token(env(&[]), d), Ok(None)));
    }
}
