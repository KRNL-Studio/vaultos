//! Passkeys made and used through a paired browser extension: where they are saved, which
//! pages may use them, and that their signatures verify. Synthetic values only.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use std::path::Path;
use vaultos_core::crypto::sha256;
use vaultos_core::error::Error;
use vaultos_core::store::{Browser, NewPasskeyRequest};
use vaultos_core::{Fields, KdfParams, SecretString, Store};

const PW: &str = "synthetic-passkey-password";
const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
const CHALLENGE: &[u8] = b"synthetic-challenge-0123456789ab";

fn store(dir: &Path) -> (Store, Browser) {
    let mut st = Store::new(dir).unwrap();
    st.create(&SecretString::new(PW), None, KdfParams::FLOOR)
        .unwrap();
    st.create_project("Example App", "human").unwrap();
    st.set_item(
        "Example App",
        &Fields {
            key: "Example".into(),
            kind: Some("login".into()),
            username: Some("alice".into()),
            password: Some(SecretString::new("synthetic-pass-1")),
            url: Some("https://example.com/login".into()),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    let p = st.pair_browser("Chrome", ORIGIN).unwrap();
    let b = st
        .authenticate_browser(p.key.expose(), ORIGIN)
        .unwrap()
        .unwrap();
    (st, b)
}

fn request<'a>(user: &'a str, handle: &'a [u8], exclude: &'a [Vec<u8>]) -> NewPasskeyRequest<'a> {
    NewPasskeyRequest {
        rp_id: "example.com",
        user_name: user,
        user_handle: handle,
        challenge: CHALLENGE,
        exclude,
    }
}

/// r and s from WebAuthn's DER signature.
fn from_der(d: &[u8]) -> Signature {
    let mut raw = [0u8; 64];
    let mut at = 2;
    for half in 0..2 {
        let n = d[at + 1] as usize;
        let v = &d[at + 2..at + 2 + n];
        let v = if v.len() == 33 { &v[1..] } else { v };
        raw[half * 32 + 32 - v.len()..half * 32 + 32].copy_from_slice(v);
        at += 2 + n;
    }
    Signature::from_slice(&raw).unwrap()
}

fn verify(public_key: &[u8], auth_data: &[u8], client_data: &str, signature: &[u8]) -> bool {
    let key = VerifyingKey::from_sec1_bytes(&public_key[26..]).unwrap();
    let mut signed = auth_data.to_vec();
    signed.extend_from_slice(&sha256(client_data.as_bytes()));
    key.verify(&signed, &from_der(signature)).is_ok()
}

#[test]
fn makes_a_passkey_in_the_login_and_signs_in_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut st, b) = store(dir.path());
    let page = "https://login.example.com/register";
    let c = st
        .create_passkey(page, &request("alice", b"user-1", &[]), &b)
        .unwrap();
    // The one login for this site and username takes it.
    assert_eq!(
        (c.project.as_str(), c.name.as_str()),
        ("Example App", "Example")
    );
    let client: serde_json::Value = serde_json::from_str(&c.registration.client_data_json).unwrap();
    assert_eq!(client["origin"], "https://login.example.com");
    assert_eq!(client["type"], "webauthn.create");
    let item = st.find_item("Example App", "Example").unwrap().unwrap();
    let ids: Vec<&str> = item.fields.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(
        ids,
        ["passkey-id", "passkey-rp", "passkey-user", "passkey-key"]
    );
    assert!(item.fields.iter().all(|f| f.section == "Passkey"));
    let key_field = &item.fields[3];
    assert!(key_field.is_secret() && key_field.value.is_empty() && key_field.has_value);
    assert_eq!(item.username, "alice");

    // Listed for this relying party, from any page of it; the key never is.
    let found = st
        .passkeys_for("https://example.com/", "example.com", &[])
        .unwrap();
    assert_eq!(found.len(), 1);
    let m = &found[0];
    assert_eq!(m.username, "alice");
    let cred = c.registration.credential_id.clone();
    assert_eq!(m.credential_id, vaultos_core::webauthn::b64url(&cred));
    assert!(!serde_json::to_string(&found)
        .unwrap()
        .contains("passkey-key"));
    assert_eq!(
        st.passkeys_for(
            "https://example.com/",
            "example.com",
            std::slice::from_ref(&cred)
        )
        .unwrap()
        .len(),
        1
    );
    assert!(st
        .passkeys_for("https://example.com/", "example.com", &[b"other".to_vec()])
        .unwrap()
        .is_empty());
    assert!(st
        .passkeys_for("https://login.example.com/", "login.example.com", &[])
        .unwrap()
        .is_empty());

    // The signature verifies with the registered key, after the vault was locked and opened.
    st.lock();
    st.unlock(&SecretString::new(PW), None).unwrap();
    let used = st
        .use_passkey(
            "https://example.com/signin",
            "example.com",
            &m.project_id,
            &m.item_id,
            b"second-synthetic-challenge-0123",
            &b,
        )
        .unwrap();
    assert_eq!(used.credential_id, cred);
    assert_eq!(used.user_handle, b"user-1");
    let a = &used.assertion;
    assert_eq!(&a.authenticator_data[..32], &sha256(b"example.com"));
    assert!(verify(
        &c.registration.public_key,
        &a.authenticator_data,
        &a.client_data_json,
        &a.signature
    ));
    let client: serde_json::Value = serde_json::from_str(&a.client_data_json).unwrap();
    assert_eq!(client["origin"], "https://example.com");

    // The password and other values are kept.
    let revealed = st.reveal("Example App", "Example", "human").unwrap();
    assert_eq!(revealed.password.expose(), "synthetic-pass-1");
    let (_, entries) = st.verify_audit().unwrap();
    let actions: Vec<&str> = entries.iter().map(|e| e.action.as_str()).collect();
    assert!(actions.contains(&"browser-passkey-create") && actions.contains(&"browser-passkey"));
}

#[test]
fn keeps_passkeys_to_their_relying_party() {
    let dir = tempfile::tempdir().unwrap();
    let (mut st, b) = store(dir.path());
    let c = st
        .create_passkey(
            "https://example.com/",
            &request("alice", b"user-1", &[]),
            &b,
        )
        .unwrap();
    let m = st
        .passkeys_for("https://example.com/", "example.com", &[])
        .unwrap()
        .remove(0);
    // Another site, a public suffix, a parent the page is not under, plain HTTP.
    for (page, rp) in [
        ("https://evil.example/", "example.com"),
        ("https://example.com.evil.example/", "example.com"),
        ("https://example.com/", "com"),
        ("https://example.com/", "login.example.com"),
        ("http://example.com/", "example.com"),
    ] {
        assert!(
            st.passkeys_for(page, rp, &[]).is_err(),
            "{page} {rp} listed"
        );
        assert!(
            st.use_passkey(page, rp, &m.project_id, &m.item_id, CHALLENGE, &b)
                .is_err(),
            "{page} {rp} signed"
        );
        assert!(
            st.create_passkey(
                page,
                &NewPasskeyRequest {
                    rp_id: rp,
                    ..request("eve", b"u", &[])
                },
                &b
            )
            .is_err(),
            "{page} {rp} made"
        );
    }
    // A login without a passkey, or one for another relying party, cannot sign.
    let other = st.find_item("Example App", "Example").unwrap().unwrap();
    assert!(matches!(
        st.use_passkey(
            "https://example.org/",
            "example.org",
            &m.project_id,
            &other.id,
            CHALLENGE,
            &b
        ),
        Err(Error::NotFound(_))
    ));
    // The site's list of credentials it already has stops a second passkey.
    let again = st.create_passkey(
        "https://example.com/",
        &request(
            "alice",
            b"user-1",
            &[b"other".to_vec(), c.registration.credential_id],
        ),
        &b,
    );
    assert!(matches!(again, Err(Error::Conflict(_))));
    // Too short a challenge, or no user handle.
    assert!(st
        .use_passkey(
            "https://example.com/",
            "example.com",
            &m.project_id,
            &m.item_id,
            b"short",
            &b
        )
        .is_err());
    assert!(st
        .create_passkey("https://example.com/", &request("carol", b"", &[]), &b)
        .is_err());
}

#[test]
fn saves_a_new_login_when_none_fits() {
    let dir = tempfile::tempdir().unwrap();
    let (mut st, b) = store(dir.path());
    // A username the site has no login for.
    let c = st
        .create_passkey("https://example.com/", &request("bob", b"user-2", &[]), &b)
        .unwrap();
    assert_eq!(
        (c.project.as_str(), c.name.as_str()),
        ("Logins", "example.com")
    );
    let item = st.find_item("Logins", "example.com").unwrap().unwrap();
    assert_eq!(
        (item.username.as_str(), item.url.as_str()),
        ("bob", "https://example.com")
    );
    assert_eq!(item.kind, "login");
    assert!(!item.has_password);
    // Alice's login takes her first passkey; a second one for her goes in a new login.
    st.create_passkey(
        "https://example.com/",
        &request("alice", b"user-1", &[]),
        &b,
    )
    .unwrap();
    let c = st
        .create_passkey(
            "https://example.com/",
            &request("alice", b"user-3", &[]),
            &b,
        )
        .unwrap();
    assert_eq!(
        (c.project.as_str(), c.name.as_str()),
        ("Logins", "example.com (alice)")
    );
    assert_eq!(
        st.passkeys_for("https://example.com/", "example.com", &[])
            .unwrap()
            .len(),
        3
    );
    // Archived and trashed logins' passkeys are not offered.
    st.set_item(
        "Logins",
        &Fields {
            key: "example.com".into(),
            archived: Some(true),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    assert_eq!(
        st.passkeys_for("https://example.com/", "example.com", &[])
            .unwrap()
            .len(),
        2
    );
}
