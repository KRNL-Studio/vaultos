//! `POST /human/values`: values for the human's own commands (`vaultos read`, `render` and
//! `run`) while the app or `vaultosd` owns the vault. The session token is not enough, since
//! any process of the user can read it: each request is confirmed with Touch ID by the app,
//! or carries the master password (and Secret Key). Nothing is remembered between requests.

use crate::api::Reply;
use serde_json::{json, Map, Value};
use vaultos_core::model::HUMAN;
use vaultos_core::refs::{SecretRef, MAX_REFS};
use vaultos_core::{Error, SecretKey, SecretString, Store};

/// A parsed request. The password and Secret Key are taken out before the values are read.
pub struct Ask {
    pub refs: Vec<SecretRef>,
    pub env: Option<(String, Option<Vec<String>>)>,
    pub purpose: String,
    pub password: Option<SecretString>,
    pub secret_key: Option<SecretKey>,
}

impl std::fmt::Debug for Ask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ask")
            .field("refs", &self.refs.len())
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

fn bad(msg: &str) -> Reply {
    Reply::error(400, msg)
}

/// Text from the caller shown in a system prompt: one line, at most 120 characters.
fn clean(s: &str) -> String {
    let one: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let t = one.trim();
    if t.chars().count() > 120 {
        format!("{}…", t.chars().take(119).collect::<String>())
    } else {
        t.to_owned()
    }
}

impl Ask {
    pub fn parse(body: &[u8]) -> Result<Ask, Reply> {
        let Ok(Value::Object(mut b)) = serde_json::from_slice::<Value>(body) else {
            return Err(bad("Expected a JSON object"));
        };
        let strings = |v: &Value, what: &str| -> Result<Vec<String>, Reply> {
            v.as_array()
                .and_then(|a| a.iter().map(|x| x.as_str().map(str::to_owned)).collect())
                .ok_or_else(|| bad(&format!("Invalid {what}")))
        };
        let refs = match b.get("refs") {
            None => Vec::new(),
            Some(v) => strings(v, "refs")?,
        };
        if refs.len() > MAX_REFS {
            return Err(bad("Too many references"));
        }
        let refs = refs
            .iter()
            .map(|r| SecretRef::parse(r))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| bad(&e.to_string()))?;
        let env = match b.get("env") {
            None | Some(Value::Null) => None,
            Some(Value::Object(e)) => {
                let project = e
                    .get("project")
                    .and_then(Value::as_str)
                    .filter(|p| !p.trim().is_empty())
                    .ok_or_else(|| bad("Invalid env project"))?
                    .to_owned();
                let keys = e.get("keys").map(|k| strings(k, "env keys")).transpose()?;
                Some((project, keys))
            }
            Some(_) => return Err(bad("Invalid env")),
        };
        if refs.is_empty() && env.is_none() {
            return Err(bad("Nothing was asked for"));
        }
        let purpose = clean(b.get("purpose").and_then(Value::as_str).unwrap_or(""));
        let mut take = |k: &str| -> Option<SecretString> {
            match b.remove(k) {
                Some(Value::String(s)) => Some(SecretString::new(s)),
                _ => None,
            }
        };
        let password = take("password").filter(|p| !p.expose().is_empty());
        let secret_key = take("secretKey")
            .filter(|k| !k.expose().trim().is_empty())
            .map(|k| SecretKey::parse(k.expose().trim()))
            .transpose()
            .map_err(|e| bad(&e.to_string()))?;
        Ok(Ask {
            refs,
            env,
            purpose,
            password,
            secret_key,
        })
    }

    /// The Touch ID sheet's reason, completing "VaultOS is trying to …".
    pub fn reason(&self, who: &Peer) -> String {
        let mut projects: Vec<&str> = self.refs.iter().map(|r| r.project.as_str()).collect();
        if let Some((p, _)) = &self.env {
            projects.push(p);
        }
        projects.sort_unstable();
        projects.dedup();
        let what = match (self.refs.len(), &self.env) {
            (0, Some(_)) => "secrets".to_owned(),
            (1, None) => "1 secret".to_owned(),
            (n, None) => format!("{n} secrets"),
            (n, Some(_)) => format!("{n} secrets and a project's values"),
        };
        let mut r = format!(
            "give {what} from {} to {}",
            clean(&projects.join(", ")),
            who.shown()
        );
        if !self.purpose.is_empty() {
            r.push_str(&format!(" for “{}”", self.purpose));
        }
        r
    }
}

/// The process on the other end of the socket, as the kernel reports it.
#[derive(Clone, Debug, Default)]
pub struct Peer {
    pub pid: Option<i32>,
    pub exe: Option<std::path::PathBuf>,
}

impl Peer {
    pub fn of(pid: Option<i32>) -> Peer {
        Peer {
            pid,
            exe: pid.and_then(exe_of),
        }
    }

    /// For the prompt: the program's full path, so a look-alike name stands out.
    fn shown(&self) -> String {
        let exe = self
            .exe
            .as_ref()
            .map_or_else(|| "a program".to_owned(), |e| e.display().to_string());
        match self.pid {
            Some(pid) => format!("{} (pid {pid})", clean(&exe)),
            None => clean(&exe),
        }
    }

    /// For the audit log: the program's name and pid.
    fn named(&self) -> String {
        let name = self.exe.as_ref().and_then(|e| e.file_name()).map_or_else(
            || "a program".to_owned(),
            |n| n.to_string_lossy().into_owned(),
        );
        match self.pid {
            Some(pid) => format!("{} (pid {pid})", clean(&name)),
            None => clean(&name),
        }
    }
}

#[cfg(target_os = "linux")]
fn exe_of(pid: i32) -> Option<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(target_os = "macos")]
fn exe_of(pid: i32) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0u8; 4096];
    // SAFETY: the buffer is valid for its full length, which is what is passed.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(std::ffi::OsStr::from_bytes(&buf).into())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn exe_of(_pid: i32) -> Option<std::path::PathBuf> {
    None
}

/// Reads what was asked for, as the human, once the request has been confirmed.
pub fn values(store: &mut Store, ask: &Ask, who: &Peer) -> Reply {
    if !store.is_unlocked() {
        return Reply::error(423, "Vault is locked. Unlock the app.");
    }
    if let Err(e) = store.reload_if_changed() {
        if !matches!(e, Error::Busy | Error::Io { .. } | Error::Conflict(_)) {
            store.lock();
        }
        return Reply::error(
            409,
            "The vault changed on disk and could not be reloaded. Unlock the app again.",
        );
    }
    let purpose = if ask.purpose.is_empty() {
        who.named()
    } else {
        format!("{} by {}", ask.purpose, who.named())
    };
    let result = (|| -> Result<Value, Error> {
        let mut body = Map::new();
        if !ask.refs.is_empty() {
            let values = store.resolve_refs(&ask.refs, &purpose, HUMAN)?;
            body.insert(
                "values".into(),
                values.iter().map(|v| json!(v.as_str())).collect(),
            );
        }
        if let Some((project, keys)) = &ask.env {
            let env = store.env_values(project, keys.as_deref(), &purpose, HUMAN)?;
            body.insert(
                "env".into(),
                json!({
                    "project": env.project,
                    "values": env.pairs.iter().map(|(k, v)| json!({ "key": k, "value": v.as_str() })).collect::<Vec<_>>(),
                    "heldForApproval": env.held_for_approval,
                }),
            );
        }
        Ok(Value::Object(body))
    })();
    match result {
        Ok(body) => Reply::ok(body),
        Err(e) => Reply::error(e.status(), e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]
    use super::*;

    #[test]
    fn parses_requests_and_words_the_prompt() {
        let ask = Ask::parse(
            br#"{"refs":["vault://Example App/DB_URL","vault://Other/KEY/password"],"purpose":"run npm\ndev","password":"synthetic"}"#,
        )
        .unwrap();
        assert_eq!(ask.refs.len(), 2);
        assert_eq!(ask.purpose, "run npm dev");
        assert!(ask.password.is_some());
        let who = Peer {
            pid: Some(42),
            exe: Some("/usr/local/bin/vaultos".into()),
        };
        assert_eq!(
            ask.reason(&who),
            "give 2 secrets from Example App, Other to /usr/local/bin/vaultos (pid 42) for “run npm dev”"
        );
        assert_eq!(who.named(), "vaultos (pid 42)");
        let env = Ask::parse(br#"{"env":{"project":"Example App"}}"#).unwrap();
        assert!(env.password.is_none());
        assert_eq!(
            env.reason(&Peer::default()),
            "give secrets from Example App to a program"
        );
        for bad in [
            &br#"{}"#[..],
            br#"{"refs":["op://x/y"]}"#,
            br#"{"refs":"vault://P/I"}"#,
            br#"{"env":{"project":""}}"#,
            br#"[]"#,
        ] {
            assert!(Ask::parse(bad).is_err());
        }
    }
}
