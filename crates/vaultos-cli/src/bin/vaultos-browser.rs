//! `vaultos-browser`: the native messaging host for the VaultOS browser extension. The
//! browser starts it with the extension's origin as its first argument and exchanges
//! length-prefixed JSON messages with it on stdin and stdout. It relays a fixed set of
//! operations to the running owner (the app); the owner checks the pairing key and the
//! origin, and decides what may be filled where. It keeps nothing between messages.
//!
//! Messages: `{id?, op, key?, ...}` with `op` one of `status`, `pair` (`name`, `code`),
//! `whoami`, `logins` (`url`), `fill` (`url`, `projectId`, `itemId`) and `save` (`url`,
//! `username`, `password`, and `projectId` and `itemId` to update that login). Replies:
//! `{id, ok: true, ...}` or
//! `{id, ok: false, code, error}`.

use serde_json::{json, Map, Value};
use std::io::{Read, Write};
use std::process::ExitCode;
use std::time::Duration;
use vaultos_client::{enc, Client};
use zeroize::Zeroizing;

/// The longest message accepted from the browser; requests are small.
const MAX_MESSAGE: usize = 64 * 1024;
/// A pairing, or a passkey that needs Touch ID, waits for the human to confirm in the app.
const PAIR_TIMEOUT: Duration = Duration::from_secs(130);
const TIMEOUT: Duration = Duration::from_secs(20);

fn read_message(input: &mut impl Read) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_ne_bytes(len) as usize;
    if n > MAX_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = Zeroizing::new(vec![0u8; n]);
    input.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn write_message(out: &mut impl Write, v: &Value) -> std::io::Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(v).unwrap_or_default());
    let n = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "reply too large"))?;
    out.write_all(&n.to_ne_bytes())?;
    out.write_all(&bytes)?;
    out.flush()
}

fn field<'a>(m: &'a Map<String, Value>, k: &str) -> &'a str {
    m.get(k).and_then(Value::as_str).unwrap_or("")
}

/// One operation, relayed to the owner.
fn handle(
    client: &Client,
    origin: &str,
    m: &Map<String, Value>,
) -> Result<Value, (String, String)> {
    let key = m
        .get("key")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty());
    let call = |method: &str, route: &str, body: Option<&Value>, timeout: Duration| {
        client
            .browser(method, route, body, origin, key, timeout)
            .map_err(|e| {
                let code = match (e.code.as_str(), e.status) {
                    (_, Some(401)) => "unpaired",
                    (_, Some(409)) => "conflict",
                    (_, Some(412)) => "unverified",
                    (c, _) => c,
                };
                (code.to_owned(), e.message)
            })
    };
    let pick = |names: &[&str]| -> Value {
        Value::Object(
            names
                .iter()
                .filter_map(|n| m.get(*n).map(|v| ((*n).to_owned(), v.clone())))
                .collect(),
        )
    };
    match field(m, "op") {
        "status" => {
            let st = client.status();
            Ok(json!({
                "running": st.get("running").cloned().unwrap_or(json!(false)),
                "unlocked": st.get("unlocked").cloned().unwrap_or(json!(false)),
            }))
        }
        "pair" => call(
            "POST",
            "/browser/pair",
            Some(&pick(&["name", "code"])),
            PAIR_TIMEOUT,
        ),
        "whoami" => call("GET", "/browser/whoami", None, TIMEOUT),
        "logins" => {
            let route = format!("/browser/logins?url={}", enc(field(m, "url")));
            call("GET", &route, None, TIMEOUT)
        }
        "fill" => call(
            "POST",
            "/browser/fill",
            Some(&pick(&["url", "projectId", "itemId"])),
            TIMEOUT,
        ),
        "save" => {
            // The copy of the password sent on is scrubbed as the message itself is.
            let mut body = pick(&["url", "username", "password", "projectId", "itemId"]);
            let r = call("POST", "/browser/save", Some(&body), TIMEOUT);
            vaultos_core::secret::scrub_json(&mut body);
            r
        }
        "passkeys" => call(
            "POST",
            "/browser/passkeys",
            Some(&pick(&["url", "rpId", "allow"])),
            TIMEOUT,
        ),
        "passkeyCreate" => call(
            "POST",
            "/browser/passkey/create",
            Some(&pick(&[
                "url",
                "rpId",
                "user",
                "challenge",
                "algorithms",
                "exclude",
                "userVerification",
            ])),
            // The owner may wait for Touch ID.
            PAIR_TIMEOUT,
        ),
        "passkeyGet" => call(
            "POST",
            "/browser/passkey/get",
            Some(&pick(&[
                "url",
                "rpId",
                "challenge",
                "projectId",
                "itemId",
                "credentialId",
                "userVerification",
            ])),
            PAIR_TIMEOUT,
        ),
        _ => Err(("usage".into(), "Unknown operation".into())),
    }
}

fn reply(id: Option<&Value>, result: Result<Value, (String, String)>) -> Value {
    let mut out = match result {
        Ok(Value::Object(mut o)) => {
            o.insert("ok".into(), json!(true));
            o
        }
        Ok(other) => {
            let mut o = Map::new();
            o.insert("ok".into(), json!(true));
            o.insert("result".into(), other);
            o
        }
        Err((code, error)) => {
            let mut o = Map::new();
            o.insert("ok".into(), json!(false));
            o.insert("code".into(), json!(code));
            o.insert("error".into(), json!(error));
            o
        }
    };
    if let Some(id) = id {
        out.insert("id".into(), id.clone());
    }
    Value::Object(out)
}

fn main() -> ExitCode {
    vaultos_core::hardening::harden_process();
    // Chromium passes the calling extension's origin first (and on some systems more).
    let origin = std::env::args().nth(1).unwrap_or_default();
    if origin == "--version" {
        let line = concat!("vaultos-browser ", env!("CARGO_PKG_VERSION"), "\n");
        return match std::io::stdout().write_all(line.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(255),
        };
    }
    let data_dir = match vaultos_core::paths::default_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("vaultos-browser: {e}");
            return ExitCode::from(2);
        }
    };
    // An owner still unlocking is waited for briefly; the extension asks again.
    let client = Client::with_token(data_dir, None).with_busy_wait(Duration::from_secs(5));
    let (mut input, mut output) = (std::io::stdin().lock(), std::io::stdout().lock());
    loop {
        let msg = match read_message(&mut input) {
            Ok(Some(m)) => m,
            Ok(None) => return ExitCode::SUCCESS,
            Err(_) => return ExitCode::from(1),
        };
        let mut v: Value = serde_json::from_slice(&msg).unwrap_or(Value::Null);
        let mut out = match v.as_object() {
            Some(m) => reply(m.get("id"), handle(&client, &origin, m)),
            None => reply(None, Err(("usage".into(), "Expected a JSON object".into()))),
        };
        vaultos_core::secret::scrub_json(&mut v);
        let sent = write_message(&mut output, &out);
        vaultos_core::secret::scrub_json(&mut out);
        if sent.is_err() {
            return ExitCode::from(1);
        }
    }
}
