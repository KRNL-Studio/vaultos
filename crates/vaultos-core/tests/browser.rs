//! Paired browser extensions: pairing keys, which logins a page is offered, filling and
//! saving. Synthetic values only.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::path::Path;
use vaultos_core::error::Error;
use vaultos_core::validate::FieldInput;
use vaultos_core::{Fields, KdfParams, SecretString, Store};

const PW: &str = "synthetic-browser-password";
const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
const OTP: &str =
    "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";

fn s(v: &str) -> Option<SecretString> {
    Some(SecretString::new(v))
}

fn login(st: &mut Store, key: &str, url: &str, user: &str, pass: &str) {
    st.set_item(
        "Example App",
        &Fields {
            key: key.into(),
            kind: Some("login".into()),
            username: Some(user.into()),
            password: s(pass),
            url: Some(url.into()),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
}

fn store(dir: &Path) -> Store {
    let mut st = Store::new(dir).unwrap();
    st.create(&SecretString::new(PW), None, KdfParams::FLOOR)
        .unwrap();
    st.create_project("Example App", "human").unwrap();
    login(
        &mut st,
        "Example",
        "https://example.com/login",
        "alice",
        "synthetic-pass-1",
    );
    login(
        &mut st,
        "Pages",
        "https://alice.github.io",
        "alice",
        "synthetic-pass-2",
    );
    login(
        &mut st,
        "Local",
        "http://localhost:3000",
        "dev",
        "synthetic-pass-3",
    );
    st.set_item(
        "Example App",
        &Fields {
            key: "Example with code".into(),
            kind: Some("login".into()),
            username: Some("bob".into()),
            password: s("synthetic-pass-4"),
            fields: Some(vec![
                FieldInput {
                    label: "Also at".into(),
                    kind: "url".into(),
                    value: s("https://www.example.co.uk"),
                    ..Default::default()
                },
                FieldInput {
                    label: "One-time code".into(),
                    kind: "otp".into(),
                    value: s(OTP),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    // Not logins, or not shown: never offered.
    st.set_item(
        "Example App",
        &Fields {
            key: "EXAMPLE_API_KEY".into(),
            value: s("synthetic-api-value"),
            url: Some("https://example.com".into()),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    login(
        &mut st,
        "Archived",
        "https://example.com",
        "old",
        "synthetic-pass-5",
    );
    st.set_item(
        "Example App",
        &Fields {
            key: "Archived".into(),
            archived: Some(true),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    st
}

fn names(st: &Store, page: &str) -> Vec<String> {
    let mut n: Vec<String> = st
        .logins_for(page)
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    n.sort();
    n
}

#[test]
fn pairs_and_checks_keys_and_origins() {
    let dir = tempfile::tempdir().unwrap();
    let mut st = store(dir.path());
    let p = st.pair_browser("Chrome", ORIGIN).unwrap();
    let b = st
        .authenticate_browser(p.key.expose(), ORIGIN)
        .unwrap()
        .unwrap();
    assert_eq!((b.id.as_str(), b.name.as_str()), (p.id.as_str(), "Chrome"));
    assert!(st
        .authenticate_browser(p.key.expose(), "chrome-extension://other/")
        .unwrap()
        .is_none());
    assert!(st
        .authenticate_browser("synthetic-wrong-key", ORIGIN)
        .unwrap()
        .is_none());
    assert!(st.authenticate_browser("", ORIGIN).unwrap().is_none());

    // Pairings are sealed with the vault and survive a lock; the key is not stored.
    st.lock();
    st.unlock(&SecretString::new(PW), None).unwrap();
    assert!(st
        .authenticate_browser(p.key.expose(), ORIGIN)
        .unwrap()
        .is_some());
    let raw = std::fs::read(dir.path().join("vault.enc")).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains(p.key.expose()));

    st.unpair_browser(&p.id).unwrap();
    assert!(st
        .authenticate_browser(p.key.expose(), ORIGIN)
        .unwrap()
        .is_none());
    assert!(matches!(st.unpair_browser(&p.id), Err(Error::NotFound(_))));
    let (_, entries) = st.verify_audit().unwrap();
    let actions: Vec<&str> = entries.iter().map(|e| e.action.as_str()).collect();
    assert!(actions.contains(&"browser-pair") && actions.contains(&"browser-unpair"));
}

#[test]
fn offers_logins_only_on_their_own_site() {
    let dir = tempfile::tempdir().unwrap();
    let st = store(dir.path());
    assert_eq!(
        names(&st, "https://accounts.example.com/signin"),
        ["Example"]
    );
    assert_eq!(
        names(&st, "https://shop.example.co.uk/"),
        ["Example with code"]
    );
    assert_eq!(names(&st, "https://alice.github.io/blog"), ["Pages"]);
    assert!(names(&st, "https://bob.github.io/").is_empty());
    assert!(names(&st, "https://example.com.evil.example/").is_empty());
    assert_eq!(names(&st, "http://localhost:3000/"), ["Local"]);
    assert!(names(&st, "http://localhost:3001/").is_empty());
    let m = &st.logins_for("https://example.com").unwrap()[0];
    assert_eq!(
        (m.username.as_str(), m.has_password, m.has_otp),
        ("alice", true, false)
    );
    for refused in [
        "http://example.com/login",
        "file:///etc/passwd",
        "not a url",
    ] {
        assert!(st.logins_for(refused).is_err(), "{refused}");
    }
}

#[test]
fn fills_and_saves_logins() {
    let dir = tempfile::tempdir().unwrap();
    let mut st = store(dir.path());
    let p = st.pair_browser("Chrome", ORIGIN).unwrap();
    let b = st
        .authenticate_browser(p.key.expose(), ORIGIN)
        .unwrap()
        .unwrap();
    let m = st
        .logins_for("https://www.example.co.uk/login")
        .unwrap()
        .remove(0);
    let f = st
        .fill_login(
            "https://www.example.co.uk/login",
            &m.project_id,
            &m.item_id,
            &b,
        )
        .unwrap();
    assert_eq!(
        (f.username.as_str(), f.password.expose()),
        ("bob", "synthetic-pass-4")
    );
    let code = f.otp.unwrap();
    assert!(code.expose().len() == 6 && code.expose().bytes().all(|c| c.is_ascii_digit()));
    // The same item, asked for from another site, is refused.
    let err = st
        .fill_login("https://example.org/", &m.project_id, &m.item_id, &b)
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "{err}");
    let (_, entries) = st.verify_audit().unwrap();
    let fill = entries
        .iter()
        .rev()
        .find(|e| e.action == "browser-fill")
        .unwrap();
    assert_eq!(
        fill.detail,
        "Example App/Example with code on www.example.co.uk"
    );
    assert!(fill.actor.starts_with("browser Chrome"), "{}", fill.actor);

    // A new login goes to the Logins project, named after the site.
    let saved = st
        .save_login(
            "https://news.example.net/login?next=/",
            "carol",
            &SecretString::new("synthetic-pass-6"),
            &b,
        )
        .unwrap()
        .1;
    assert_eq!(saved.key, "news.example.net");
    let found = st.logins_for("https://example.net/").unwrap();
    assert_eq!(
        (found[0].project.as_str(), found[0].url.as_str()),
        ("Logins", "https://news.example.net")
    );
    // The same site and username: a new password, not a second item.
    st.save_login(
        "https://news.example.net/",
        "carol",
        &SecretString::new("synthetic-pass-7"),
        &b,
    )
    .unwrap();
    // Another username on the same site gets its own item.
    let other = st
        .save_login(
            "https://news.example.net/",
            "dave",
            &SecretString::new("synthetic-pass-8"),
            &b,
        )
        .unwrap()
        .1;
    assert_eq!(other.key, "news.example.net (dave)");
    let all = st.logins_for("https://example.net/").unwrap();
    assert_eq!(all.len(), 2);
    let carol = all.iter().find(|m| m.username == "carol").unwrap();
    let f = st
        .fill_login(
            "https://example.net/",
            &carol.project_id,
            &carol.item_id,
            &b,
        )
        .unwrap();
    assert_eq!(f.password.expose(), "synthetic-pass-7");
    // A login in another project is updated where it is, keeping its address and code.
    let (project, updated) = st
        .save_login(
            "https://www.example.co.uk/signin",
            "bob",
            &SecretString::new("synthetic-pass-10"),
            &b,
        )
        .unwrap();
    assert_eq!(
        (project.as_str(), updated.key.as_str()),
        ("Example App", "Example with code")
    );
    let bobs: Vec<_> = st
        .logins_for("https://example.co.uk/")
        .unwrap()
        .into_iter()
        .filter(|m| m.username == "bob")
        .collect();
    assert_eq!(bobs.len(), 1);
    assert!(bobs[0].has_otp && bobs[0].url.is_empty());
    assert!(st
        .save_login(
            "http://news.example.net/",
            "carol",
            &SecretString::new("synthetic-pass-9"),
            &b
        )
        .is_err());
    assert!(st
        .save_login(
            "https://news.example.net/",
            "carol",
            &SecretString::new(""),
            &b
        )
        .is_err());
}
