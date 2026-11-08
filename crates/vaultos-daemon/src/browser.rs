//! The browser extension's routes, reached through the native messaging host
//! (`vaultos-browser`) with the session token. Agent tokens are refused. Every route but
//! `/browser/pair` needs the key a pairing gave the extension, from the origin it was paired
//! from (`x-vault-browser-key`, `x-vault-browser-origin`). Pairing is confirmed by the human
//! in the app, who compares the code it shows with the one in the extension.
//!
//! - `POST /browser/pair` `{name, code}`: returns `{id, name, key}` once confirmed.
//! - `GET /browser/whoami`: the paired browser.
//! - `GET /browser/logins?url=`: the logins saved for that page's site, without values.
//! - `POST /browser/fill` `{url, projectId, itemId}`: `{username, password, otp}`.
//! - `POST /browser/save` `{url, username, password, projectId?, itemId?}`: saves a login,
//!   `{key, project, updated}`; with ids, a new password for that login only.
//! - `POST /browser/passkeys` `{url, rpId, allow?}`: the passkeys that page may use, without
//!   keys.
//! - `POST /browser/passkey/create` `{url, rpId, user: {id, name}, challenge, algorithms,
//!   exclude?}`: makes and saves a passkey; the credential, client data, attestation object,
//!   authenticator data and public key (base64url).
//! - `POST /browser/passkey/get` `{url, rpId, challenge, projectId, itemId}`: signs in with a
//!   passkey; the credential id, client data, authenticator data, signature and user handle.
//!
//! The extension asks only after the human chose in its own window. `url` is the page's
//! address as the browser reports it; the client data names its origin.

use crate::api::{self, Reply};
use crate::human::{clean, Peer};
use crate::server::{Confirming, Shared};
use serde_json::{json, Map, Value};
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};
use vaultos_core::store::NewPasskeyRequest;
use vaultos_core::webauthn::{self, b64url};
use vaultos_core::{Error, SecretString, Store};

/// After the human declines a pairing, new ones are refused for this long.
const DECLINED_PAUSE: Duration = Duration::from_secs(60);
const CODE_ALPHABET: &str = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// An extension origin as Chromium reports it: `chrome-extension://<32 letters a-p>/`, or the
/// one VaultOS's Safari app extension gives.
pub fn valid_origin(o: &str) -> bool {
    if o == vaultos_core::native_host::SAFARI_ORIGIN {
        return true;
    }
    o.strip_prefix("chrome-extension://")
        .and_then(|r| r.strip_suffix('/'))
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b)))
}

/// `XXXX-XXXX` from letters and digits that are hard to confuse.
fn valid_code(c: &str) -> bool {
    let b = c.as_bytes();
    b.len() == 9
        && b[4] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, x)| i == 4 || CODE_ALPHABET.as_bytes().contains(x))
}

fn body_of(body: &[u8]) -> Result<Map<String, Value>, Reply> {
    if body.is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_slice(body) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(Reply::error(400, "Expected a JSON object")),
    }
}

fn text<'a>(b: &'a Map<String, Value>, k: &str) -> Result<&'a str, Error> {
    b.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| api::invalid(&format!("{k} is required")))
}

/// A list of base64url credential ids (at most 64), or none.
fn credential_ids(b: &Map<String, Value>, k: &str) -> Result<Vec<Vec<u8>>, Error> {
    let Some(list) = b.get(k) else {
        return Ok(Vec::new());
    };
    let list = list
        .as_array()
        .filter(|l| l.len() <= 64)
        .ok_or_else(|| api::invalid(&format!("{k} must be a list of at most 64 ids")))?;
    list.iter()
        .map(|v| {
            let s = v
                .as_str()
                .ok_or_else(|| api::invalid("A credential id must be text"))?;
            webauthn::unb64url(s, "credential id", webauthn::MAX_CREDENTIAL_ID)
        })
        .collect()
}

fn challenge(b: &Map<String, Value>) -> Result<Vec<u8>, Error> {
    webauthn::unb64url(text(b, "challenge")?, "challenge", webauthn::MAX_CHALLENGE)
}

pub(crate) async fn route(
    shared: Arc<Shared>,
    method: String,
    target: String,
    key: Option<String>,
    origin: Option<String>,
    body: Vec<u8>,
    pid: Option<i32>,
) -> Reply {
    let Some(origin) = origin.filter(|o| valid_origin(o)) else {
        return Reply::error(
            400,
            "The extension's origin is missing or not one VaultOS accepts",
        );
    };
    if method == "POST" && target == "/browser/pair" {
        return pair(shared, origin, body, pid).await;
    }
    let Some(key) = key.filter(|k| !k.is_empty()) else {
        return Reply::error(
            401,
            "This browser is not paired with VaultOS. Pair it from the extension.",
        );
    };
    let saving =
        method == "POST" && (target == "/browser/save" || target == "/browser/passkey/create");
    let s = shared.clone();
    let reply = tokio::task::spawn_blocking(move || {
        let mut body = body;
        let r = s.with_store(|store| serve(store, &method, &target, &key, &origin, &body));
        zeroize::Zeroize::zeroize(&mut body);
        r
    })
    .await
    .unwrap_or_else(|_| Reply::error(500, "Internal error"));
    if reply.status == 200 {
        shared.touch();
        if saving {
            shared.autosync.poke();
        }
    }
    reply
}

fn serve(
    store: &mut Store,
    method: &str,
    target: &str,
    key: &str,
    origin: &str,
    body: &[u8],
) -> Reply {
    if let Err(r) = api::ready(store) {
        return r;
    }
    let browser = match store.authenticate_browser(key, origin) {
        Ok(Some(b)) => b,
        Ok(None) => return Reply::error(
            401,
            "This browser's pairing was removed or is not valid. Pair it again from the extension.",
        ),
        Err(e) => return Reply::from_error(&e),
    };
    store.note_browser_seen(&browser.id);
    let b = match body_of(body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let result = (|| -> Result<Value, Error> {
        match (method, path) {
            ("GET", "/browser/whoami") => Ok(json!({ "id": browser.id, "name": browser.name })),
            ("GET", "/browser/logins") => {
                let url = api::query_param(query, "url").unwrap_or_default();
                Ok(json!({ "logins": store.logins_for(&url)? }))
            }
            ("POST", "/browser/fill") => {
                let f = store.fill_login(
                    text(&b, "url")?,
                    text(&b, "projectId")?,
                    text(&b, "itemId")?,
                    &browser,
                )?;
                Ok(json!({
                    "username": f.username,
                    "password": f.password.expose(),
                    "otp": f.otp.as_ref().map(SecretString::expose),
                }))
            }
            ("POST", "/browser/save") => {
                let password = SecretString::new(text(&b, "password")?);
                let id = |k: &str| b.get(k).and_then(Value::as_str).filter(|v| !v.is_empty());
                let target = id("projectId").zip(id("itemId"));
                let (project, saved, updated) = store.save_login(
                    text(&b, "url")?,
                    b.get("username").and_then(Value::as_str).unwrap_or(""),
                    &password,
                    target,
                    &browser,
                )?;
                Ok(json!({ "key": saved.key, "project": project, "updated": updated }))
            }
            ("POST", "/browser/passkeys") => Ok(json!({
                "passkeys": store.passkeys_for(text(&b, "url")?, text(&b, "rpId")?, &credential_ids(&b, "allow")?)?
            })),
            ("POST", "/browser/passkey/create") => {
                let algorithms = b.get("algorithms").and_then(Value::as_array);
                if !algorithms
                    .is_some_and(|a| a.iter().any(|v| v.as_i64() == Some(webauthn::ES256)))
                {
                    return Err(api::invalid("VaultOS makes ES256 passkeys only"));
                }
                let user = b
                    .get("user")
                    .and_then(Value::as_object)
                    .ok_or_else(|| api::invalid("user is required"))?;
                let handle = webauthn::unb64url(
                    text(user, "id")?,
                    "user handle",
                    webauthn::MAX_USER_HANDLE,
                )?;
                let exclude = credential_ids(&b, "exclude")?;
                let challenge = challenge(&b)?;
                let c = store.create_passkey(
                    text(&b, "url")?,
                    &NewPasskeyRequest {
                        rp_id: text(&b, "rpId")?,
                        user_name: user.get("name").and_then(Value::as_str).unwrap_or(""),
                        user_handle: &handle,
                        challenge: &challenge,
                        exclude: &exclude,
                    },
                    &browser,
                )?;
                let r = &c.registration;
                Ok(json!({
                    "credentialId": b64url(&r.credential_id),
                    "clientDataJSON": b64url(r.client_data_json.as_bytes()),
                    "attestationObject": b64url(&r.attestation_object),
                    "authenticatorData": b64url(&r.authenticator_data),
                    "publicKey": b64url(&r.public_key),
                    "project": c.project,
                    "name": c.name,
                }))
            }
            ("POST", "/browser/passkey/get") => {
                let u = store.use_passkey(
                    text(&b, "url")?,
                    text(&b, "rpId")?,
                    text(&b, "projectId")?,
                    text(&b, "itemId")?,
                    &challenge(&b)?,
                    &browser,
                )?;
                Ok(json!({
                    "credentialId": b64url(&u.credential_id),
                    "clientDataJSON": b64url(u.assertion.client_data_json.as_bytes()),
                    "authenticatorData": b64url(&u.assertion.authenticator_data),
                    "signature": b64url(&u.assertion.signature),
                    "userHandle": b64url(&u.user_handle),
                }))
            }
            _ => Err(Error::NotFound("Not found".into())),
        }
    })();
    let mut b = Value::Object(b);
    vaultos_core::secret::scrub_json(&mut b);
    match result {
        Ok(v) => Reply::ok(v),
        Err(e) => Reply::from_error(&e),
    }
}

/// `POST /browser/pair`: shows the extension's code in the app's confirmation and pairs the
/// extension when the human confirms.
async fn pair(shared: Arc<Shared>, origin: String, body: Vec<u8>, pid: Option<i32>) -> Reply {
    let b = match body_of(&body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(code) = b
        .get("code")
        .and_then(Value::as_str)
        .filter(|c| valid_code(c))
    else {
        return Reply::error(400, "code must be the XXXX-XXXX code the extension shows");
    };
    let name = b
        .get("name")
        .and_then(Value::as_str)
        .map(clean)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "Browser".to_owned());
    if !shared.unlocked.load(Ordering::SeqCst) {
        return Reply::error(423, "Vault is locked. Unlock the app.");
    }
    let paused = shared
        .browser_declined
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_some_and(|at| at.elapsed() < DECLINED_PAUSE);
    if paused {
        return Reply::error(
            429,
            "A pairing was just declined; wait a minute before trying again",
        );
    }
    let confirm = shared
        .browser_confirm
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let Some(confirm) = confirm else {
        return Reply::error(503, "Pair browsers while the VaultOS app is open");
    };
    if shared.confirming.swap(true, Ordering::SeqCst) {
        return Reply::error(429, "Another request is waiting for confirmation");
    }
    let _one = Confirming(&shared.confirming);
    let reason = format!(
        "pair the browser extension “{name}” showing the code {code}, for {}. Confirm only if you just chose Pair with VaultOS in the extension loaded from VaultOS and it shows this code",
        Peer::of(pid).shown(),
    );
    let answer = tokio::task::spawn_blocking(move || (confirm.0)(&reason))
        .await
        .ok()
        .flatten();
    if answer != Some(true) {
        *shared
            .browser_declined
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        return Reply::error(403, "The pairing was not confirmed");
    }
    let s = shared.clone();
    tokio::task::spawn_blocking(move || {
        s.with_store(|store| {
            if let Err(r) = api::ready(store) {
                return r;
            }
            match store.pair_browser(&name, &origin) {
                Ok(p) => Reply::ok(json!({ "id": p.id, "name": p.name, "key": p.key.expose() })),
                Err(e) => Reply::from_error(&e),
            }
        })
    })
    .await
    .unwrap_or_else(|_| Reply::error(500, "Internal error"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_origins_and_codes() {
        assert!(valid_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        ));
        assert!(valid_origin(
            "safari-web-extension://org.vaultos.preview.safari/"
        ));
        for bad in [
            "chrome-extension://abcdefghijklmnopabcdefghijklmnoq/",
            "chrome-extension://abc/",
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
            "https://example.com/",
            "safari-web-extension://4F3A2B1C-0000-4000-8000-123456789ABC/",
            "",
        ] {
            assert!(!valid_origin(bad), "{bad}");
        }
        assert!(valid_code("ABCD-2345"));
        for bad in [
            "ABCD2345",
            "abcd-2345",
            "ABC0-2345",
            "ABCD-23456",
            "ABCDE2345",
        ] {
            assert!(!valid_code(bad), "{bad}");
        }
    }
}
