//! Just-in-time access over the real socket: an agent asks, the human confirms (here a
//! callback), and the grant covers that project and those scopes only, until the vault
//! locks or the human ends it. Synthetic vault, password and values only.

#![allow(clippy::unwrap_used, reason = "test")]

use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vaultos_client::Client;
use vaultos_core::agents::Wildcards;
use vaultos_core::{Fields, KdfParams, SecretString, Store};
use vaultos_daemon::server::{run_embedded, Config, Confirm};

const PW: &str = "synthetic-access-password";

#[test]
fn grants_temporary_access_to_one_project_after_the_human_confirms() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let mut store = Store::new(&data).unwrap();
    store
        .create(&SecretString::new(PW), None, KdfParams::FLOOR)
        .unwrap();
    for (project, key) in [
        ("Example App", "HUMAN_KEY"),
        ("Hidden Project", "HIDDEN_KEY"),
    ] {
        store.create_project(project, "human").unwrap();
        let f = Fields {
            key: key.into(),
            value: Some(SecretString::new("synthetic-access-value")),
            ..Default::default()
        };
        store.set_item(project, &f, "human").unwrap();
    }
    let issued = store
        .enrol_agent(
            "Test Agent",
            Some(&["read".to_owned()]),
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
    handle
        .with_store(|s| s.unlock(&SecretString::new(PW), None))
        .unwrap();
    let agent = Client::with_token(data.clone(), Some(issued.token.clone()));
    let status = |r: Result<Value, vaultos_client::ClientError>| r.err().and_then(|e| e.status);
    let ask = |project: &str, scopes: &[&str]| {
        agent.request(
            "POST",
            "/access/request",
            Some(&json!({ "project": project, "scopes": scopes, "minutes": 5, "reason": "debug the deploy" })),
        )
    };
    let reveal = |project: &str, key: &str| {
        agent.request(
            "POST",
            "/reveal",
            Some(&json!({ "project": project, "key": key })),
        )
    };
    let hidden = "/projects/Hidden%20Project/secrets";

    assert_eq!(status(reveal("Example App", "HUMAN_KEY")), Some(403));
    assert_eq!(status(agent.request("GET", hidden, None)), Some(403));
    assert_eq!(
        status(ask("Hidden Project", &["reveal"])),
        Some(503),
        "no one to confirm"
    );

    let allow = Arc::new(AtomicBool::new(true));
    let reasons = Arc::new(Mutex::new(Vec::<String>::new()));
    let (a, r) = (allow.clone(), reasons.clone());
    handle.set_access_confirm(Some(Confirm(Arc::new(move |reason: &str| {
        r.lock().unwrap().push(reason.to_owned());
        Some(a.load(Ordering::SeqCst))
    }))));
    let bad = agent.request(
        "POST",
        "/access/request",
        Some(&json!({ "project": "Hidden Project", "scopes": ["admin"], "reason": "x" })),
    );
    assert_eq!(status(bad), Some(400));
    let no_reason = agent.request(
        "POST",
        "/access/request",
        Some(&json!({ "project": "Hidden Project", "scopes": ["read"] })),
    );
    assert_eq!(status(no_reason), Some(400));
    assert_eq!(status(ask("No Such Project", &["read"])), Some(403));
    assert!(reasons.lock().unwrap().is_empty(), "nothing to confirm yet");

    let granted = ask("Hidden Project", &["reveal", "read"]).unwrap();
    assert_eq!(granted["granted"], true);
    assert_eq!(granted["scopes"], json!(["read", "reveal"]));
    assert_eq!(
        reasons.lock().unwrap()[0].split(" (").next().unwrap(),
        "give agent “Test Agent” read, reveal access to Hidden Project for 5 minutes, for “debug the deploy”"
    );
    let projects = agent.request("GET", "/projects", None).unwrap();
    assert_eq!(projects.as_array().unwrap().len(), 2);
    assert!(agent.request("GET", hidden, None).is_ok());
    assert_eq!(
        reveal("Hidden Project", "HIDDEN_KEY").unwrap()["value"],
        "synthetic-access-value"
    );
    // The grant's reveal covers its project only.
    assert_eq!(status(reveal("Example App", "HUMAN_KEY")), Some(403));
    let me = agent.request("GET", "/whoami", None).unwrap();
    assert_eq!(me["scopes"], json!(["read"]));
    assert_eq!(me["grants"][0]["project"], "Hidden Project");
    assert_eq!(handle.access_grants().len(), 1);
    let audited = handle.with_store(|s| {
        let (_, entries) = s.verify_audit().unwrap();
        entries.iter().any(|e| {
            e.action == "access-grant"
                && e.detail
                    .contains("read, reveal on Hidden Project for 5 min")
        })
    });
    assert!(audited);

    // Locking ends every grant.
    handle.with_store(|s| {
        s.lock();
        s.unlock(&SecretString::new(PW), None).unwrap();
    });
    assert_eq!(status(agent.request("GET", hidden, None)), Some(403));
    assert!(handle.access_grants().is_empty());

    // The human can end one early.
    assert_eq!(ask("Hidden Project", &["read"]).unwrap()["granted"], true);
    assert!(agent.request("GET", hidden, None).is_ok());
    assert_eq!(handle.end_access(&issued.id, None), 1);
    assert_eq!(status(agent.request("GET", hidden, None)), Some(403));

    // Declined: refused, and the agent cannot ask again at once.
    allow.store(false, Ordering::SeqCst);
    assert_eq!(status(ask("Hidden Project", &["read"])), Some(403));
    assert_eq!(status(ask("Hidden Project", &["read"])), Some(429));
    assert_eq!(reasons.lock().unwrap().len(), 3);

    // Only agents ask.
    let owner_client = Client::with_token(data.clone(), None);
    let by_owner = owner_client.owner(
        "POST",
        "/access/request",
        Some(&json!({ "project": "Hidden Project", "scopes": ["read"], "reason": "x" })),
    );
    assert_eq!(status(by_owner), Some(403));

    handle.shutdown();
    owner.join().unwrap().unwrap();
}
