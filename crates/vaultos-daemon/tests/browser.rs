//! The browser extension's routes over the real socket: pairing needs the human's
//! confirmation, the key works only from its own extension, agents cannot use these routes,
//! and pages get only their own site's logins. Synthetic vault, password and values only.

#![allow(clippy::unwrap_used, reason = "test")]

use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vaultos_client::{enc, Client, ClientError};
use vaultos_core::agents::Wildcards;
use vaultos_core::{Fields, KdfParams, SecretString, Store};
use vaultos_daemon::server::{run_embedded, Config, Confirm};

const PW: &str = "synthetic-browser-password";
const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
const OTHER: &str = "chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba/";
const T: Duration = Duration::from_secs(20);

fn status(r: Result<Value, ClientError>) -> Option<u16> {
    r.err().and_then(|e| e.status)
}

#[test]
fn pairs_after_confirmation_and_fills_only_matching_sites() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let mut store = Store::new(&data).unwrap();
    store
        .create(&SecretString::new(PW), None, KdfParams::FLOOR)
        .unwrap();
    store.create_project("Example App", "human").unwrap();
    store
        .set_item(
            "Example App",
            &Fields {
                key: "Example".into(),
                kind: Some("login".into()),
                username: Some("alice".into()),
                password: Some(SecretString::new("synthetic-login-pass")),
                url: Some("https://example.com/login".into()),
                ..Default::default()
            },
            "human",
        )
        .unwrap();
    let issued = store
        .enrol_agent(
            "Test Agent",
            Some(&["read".to_owned(), "reveal".to_owned()]),
            &["Example App".to_owned()],
            &[],
            Wildcards::default(),
        )
        .unwrap();
    store.lock();
    drop(store);

    let (tx, rx) = std::sync::mpsc::channel();
    let cfg = Config {
        data_dir: data.clone(),
        idle_lock: None,
        wait_for_owner: false,
        sync_repo: None,
        confirm: None,
    };
    let owner = std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_embedded(cfg, move |h| tx.send(h).unwrap()))
    });
    let handle = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let host = Client::with_token(data.clone(), None);
    let pair = |code: &str| {
        host.browser(
            "POST",
            "/browser/pair",
            Some(&json!({ "name": "Test Browser", "code": code })),
            ORIGIN,
            None,
            T,
        )
    };

    assert_eq!(status(pair("ABCD-2345")), Some(423), "locked");
    handle
        .with_store(|s| s.unlock(&SecretString::new(PW), None))
        .unwrap();
    assert_eq!(status(pair("ABCD-2345")), Some(503), "no one to confirm");

    // Agents cannot reach these routes, even with an origin.
    let agent = Client::with_token(data.clone(), Some(issued.token.clone()));
    assert_eq!(
        status(agent.request("GET", "/browser/whoami", None)),
        Some(403)
    );
    assert_eq!(
        status(host.browser(
            "GET",
            "/browser/whoami",
            None,
            "https://example.com/",
            Some("k"),
            T
        )),
        Some(400)
    );
    assert_eq!(
        status(host.browser("GET", "/browser/whoami", None, ORIGIN, None, T)),
        Some(401)
    );

    let allow = Arc::new(AtomicBool::new(true));
    let reasons = Arc::new(Mutex::new(Vec::<String>::new()));
    let (a, r) = (allow.clone(), reasons.clone());
    handle.set_browser_confirm(Some(Confirm(Arc::new(move |reason: &str| {
        r.lock().unwrap().push(reason.to_owned());
        Some(a.load(Ordering::SeqCst))
    }))));
    assert_eq!(status(pair("abcd-0000")), Some(400));
    let paired = pair("ABCD-2345").unwrap();
    let key = paired["key"].as_str().unwrap().to_owned();
    assert_eq!(paired["name"], "Test Browser");
    assert!(
        reasons.lock().unwrap()[0].starts_with(
            "pair the browser extension “Test Browser” showing the code ABCD-2345, for "
        ),
        "{:?}",
        reasons.lock().unwrap()
    );

    let call = |method: &str, route: &str, body: Option<Value>| {
        host.browser(method, route, body.as_ref(), ORIGIN, Some(&key), T)
    };
    assert_eq!(
        call("GET", "/browser/whoami", None).unwrap()["name"],
        "Test Browser"
    );
    // The key works only from the extension it was given to.
    assert_eq!(
        status(host.browser("GET", "/browser/whoami", None, OTHER, Some(&key), T)),
        Some(401)
    );
    assert_eq!(
        status(host.browser("GET", "/browser/whoami", None, ORIGIN, Some("wrong-key"), T)),
        Some(401)
    );

    let logins = |url: &str| call("GET", &format!("/browser/logins?url={}", enc(url)), None);
    let found = logins("https://www.example.com/account").unwrap();
    let found = found["logins"].as_array().unwrap().clone();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["username"], "alice");
    assert!(
        found[0].get("password").is_none(),
        "listing never carries passwords"
    );
    assert!(logins("https://example.org/").unwrap()["logins"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        status(logins("http://example.com/")),
        Some(403),
        "not HTTPS"
    );

    let (project_id, item_id) = (found[0]["projectId"].clone(), found[0]["itemId"].clone());
    let fill = |url: &str| {
        call(
            "POST",
            "/browser/fill",
            Some(json!({ "url": url, "projectId": project_id, "itemId": item_id })),
        )
    };
    let filled = fill("https://example.com/login").unwrap();
    assert_eq!(filled["username"], "alice");
    assert_eq!(filled["password"], "synthetic-login-pass");
    assert!(
        fill("https://evil.example.net/").is_err(),
        "another site's page"
    );

    let saved = call(
        "POST",
        "/browser/save",
        Some(json!({ "url": "https://accounts.example.org/signin", "username": "bob", "password": "synthetic-new-pass" })),
    )
    .unwrap();
    assert_eq!(
        (&saved["project"], &saved["updated"]),
        (&json!("Logins"), &json!(false))
    );
    let again = logins("https://example.org/").unwrap();
    assert_eq!(again["logins"][0]["username"], "bob");
    // With the login's ids, that login gets the new password; with another's, nothing does.
    let bob = &again["logins"][0];
    let (project_id, item_id) = (bob["projectId"].clone(), bob["itemId"].clone());
    let updated = call(
        "POST",
        "/browser/save",
        Some(json!({ "url": "https://example.org/", "username": "bob", "password": "synthetic-newer-pass", "projectId": project_id, "itemId": item_id })),
    )
    .unwrap();
    assert_eq!(updated["updated"], true);
    let other = call(
        "POST",
        "/browser/save",
        Some(
            json!({ "url": "https://example.org/", "username": "carol", "password": "synthetic-other-pass", "projectId": project_id, "itemId": item_id }),
        ),
    );
    assert_eq!(status(other), Some(404));

    let audited = handle.with_store(|s| {
        let (_, entries) = s.verify_audit().unwrap();
        ["browser-pair", "browser-fill", "browser-save"]
            .iter()
            .all(|a| entries.iter().any(|e| e.action == *a))
    });
    assert!(audited);

    // Declined: refused, and pairing pauses.
    allow.store(false, Ordering::SeqCst);
    assert_eq!(status(pair("WXYZ-6789")), Some(403));
    assert_eq!(status(pair("WXYZ-6789")), Some(429));

    // Unpaired in the app: the key stops working.
    let id = paired["id"].as_str().unwrap().to_owned();
    handle.with_store(|s| s.unpair_browser(&id)).unwrap();
    assert_eq!(status(call("GET", "/browser/whoami", None)), Some(401));

    handle.shutdown();
    owner.join().unwrap().unwrap();
}
