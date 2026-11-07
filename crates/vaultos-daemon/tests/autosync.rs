//! Autosync in the daemon against a real Git remote: the first round after unlock, a manual
//! round from the owner, what `/status` shows with and without the session token, and a
//! verification failure that halts autosync and is recorded in the audit log.

#![allow(clippy::unwrap_used, reason = "test")]

use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use vaultos_client::Client;
use vaultos_core::session::Session;
use vaultos_core::{Fields, KdfParams, SecretString, Store};
use vaultos_daemon::server::{run, Config};
use vaultos_sync::Sync;

const PW: &str = "synthetic-autosync-password";

fn git(args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn configure(repo: &Path) {
    let r = repo.to_str().unwrap();
    for (k, v) in [
        ("user.name", "Synthetic Test"),
        ("user.email", "test@example.invalid"),
        ("commit.gpgsign", "false"),
    ] {
        git(&["-C", r, "config", k, v]);
    }
}

fn vault(dir: &Path) -> Store {
    let mut s = Store::new(dir).unwrap();
    s.create(&SecretString::new(PW), None, KdfParams::FLOOR)
        .unwrap();
    s
}

fn set(store: &mut Store, key: &str, value: &str) {
    if store.find_project("Example").unwrap().is_none() {
        store.create_project("Example", "human").unwrap();
    }
    let f = Fields {
        key: key.into(),
        value: Some(SecretString::new(value)),
        ..Default::default()
    };
    store.set_item("Example", &f, "human").unwrap();
}

fn public_status(data: &Path) -> Value {
    let session = Session::read(data).unwrap();
    let r = vaultos_client::http::request(
        &session.socket,
        "GET",
        "/status",
        &[],
        None,
        Duration::from_secs(5),
    )
    .unwrap();
    serde_json::from_slice(&r.body).unwrap()
}

#[test]
fn syncs_after_unlock_and_on_request_and_halts_on_a_refusal() {
    let root = tempfile::tempdir().unwrap();
    let remote = root.path().join("remote.git");
    let remote_s = remote.to_str().unwrap();
    git(&[
        "init",
        "--quiet",
        "--bare",
        "--initial-branch=main",
        remote_s,
    ]);
    let repo_a = root.path().join("checkout-a");
    git(&["init", "--quiet", "-b", "main", repo_a.to_str().unwrap()]);
    configure(&repo_a);
    git(&[
        "-C",
        repo_a.to_str().unwrap(),
        "remote",
        "add",
        "origin",
        remote_s,
    ]);

    // Device A, the daemon's vault: sync enrolled, autosync turned on.
    let data_a = root.path().join("a");
    let mut a = vault(&data_a);
    set(&mut a, "FROM_A", "synthetic-a");
    let sync_a = Sync::new(&data_a, &repo_a);
    let ia = sync_a.init(&mut a, "Machine A").unwrap();
    let mut patch = serde_json::Map::new();
    patch.insert(
        "autoSync".into(),
        json!({ "enabled": true, "intervalSeconds": 30 }),
    );
    a.update_settings(patch, "human").unwrap();
    assert_eq!(sync_a.push_remote(&a, None).unwrap()["delivered"], true);

    // Device B, driven directly.
    let repo_b = root.path().join("checkout-b");
    git(&["clone", "--quiet", remote_s, repo_b.to_str().unwrap()]);
    configure(&repo_b);
    let data_b = root.path().join("b");
    let mut b = vault(&data_b);
    let sync_b = Sync::new(&data_b, &repo_b);
    let ib = sync_b.init(&mut b, "Machine B").unwrap();
    sync_b.trust(&mut b, &ia).unwrap();
    sync_a.trust(&mut a, &ib).unwrap();
    assert_eq!(sync_b.push_remote(&b, None).unwrap()["delivered"], true);
    a.lock();
    drop(a);

    let cfg = Config {
        data_dir: data_a.clone(),
        idle_lock: None,
        wait_for_owner: false,
        sync_repo: Some(repo_a.clone()),
    };
    let daemon = std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(run(cfg))
    });
    let owner = Client::with_token(data_a.clone(), None).with_busy_wait(Duration::from_secs(5));
    let deadline = Instant::now() + Duration::from_secs(10);
    while owner.live(Duration::from_millis(500)).is_none() {
        assert!(Instant::now() < deadline, "the daemon did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(public_status(&data_a)["sync"]["state"], "PAUSED_LOCKED");

    // Unlocked, autosync runs its first round on its own.
    owner
        .owner("POST", "/unlock", Some(&json!({ "password": PW })))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let s = owner.owner("GET", "/status", None).unwrap();
        if s["sync"]["state"] == "OK" {
            assert_eq!(s["sync"]["enabled"], true);
            break;
        }
        assert!(Instant::now() < deadline, "no autosync round: {s}");
        std::thread::sleep(Duration::from_millis(200));
    }
    let public = public_status(&data_a)["sync"].clone();
    assert_eq!(public["state"], "OK");
    assert!(
        public.get("error").is_none() && public.get("peerProblems").is_none(),
        "{public}"
    );

    // A change on B arrives with the owner's manual round.
    sync_b.pull_remote(&mut b, false).unwrap();
    set(&mut b, "FROM_B", "synthetic-b");
    assert_eq!(sync_b.push_remote(&b, None).unwrap()["delivered"], true);
    let r = owner.owner("POST", "/sync", None).unwrap();
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["received"]["added"], 1, "{r}");

    // An unsigned file arrives: the round refuses and autosync halts until a human acts.
    let rb = repo_b.to_str().unwrap();
    git(&["-C", rb, "pull", "--quiet", "--rebase", "origin", "main"]);
    std::fs::write(
        repo_b.join(format!("records/{}.age", "0".repeat(64))),
        b"age-encryption.org/v1\n",
    )
    .unwrap();
    git(&["-C", rb, "add", "records"]);
    git(&["-C", rb, "commit", "--quiet", "-m", "unsigned"]);
    git(&["-C", rb, "push", "--quiet", "origin", "HEAD:main"]);
    let r = owner.owner("POST", "/sync", None).unwrap();
    assert_eq!(r["ok"], false, "{r}");
    assert_eq!(r["state"], "SIGNATURE_INVALID", "{r}");
    assert_eq!(r["halted"], true, "{r}");
    assert!(
        r["error"]
            .as_str()
            .unwrap()
            .contains("Unsigned or modified ciphertext"),
        "{r}"
    );

    owner.owner("POST", "/shutdown", None).unwrap();
    daemon.join().unwrap().unwrap();
    let mut a = Store::new(&data_a).unwrap();
    a.unlock(&SecretString::new(PW), None).unwrap();
    let (_, entries) = a.verify_audit().unwrap();
    assert!(entries
        .iter()
        .any(|e| e.action == "sync_halted" && e.actor == "autosync"));
    assert_eq!(
        a.reveal("Example", "FROM_B", "human")
            .unwrap()
            .value
            .expose(),
        "synthetic-b"
    );
}
