//! `POST /run` over the real socket: where the program comes from, which values it gets, and
//! a lock while it runs. Synthetic vault, password and values only.

#![allow(clippy::unwrap_used, reason = "test")]

use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};
use vaultos_client::Client;
use vaultos_core::agents::Wildcards;
use vaultos_core::{Fields, KdfParams, SecretString, Store};
use vaultos_daemon::server::{run_embedded, Config};

const PW: &str = "synthetic-run-password";

#[test]
fn runs_agents_commands_from_trusted_folders_with_maskable_values() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let work = dir.path().join("work");
    // A program named like the allowed one, in a folder the agent can write to.
    let planted = work.join("bin");
    std::fs::create_dir_all(&planted).unwrap();
    let work = std::fs::canonicalize(&work).unwrap();
    let fake = planted.join("sh");
    std::fs::write(&fake, "#!/bin/sh\necho planted\n").unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut store = Store::new(&data).unwrap();
    store
        .create(&SecretString::new(PW), None, KdfParams::FLOOR)
        .unwrap();
    store.create_project("Example App", "human").unwrap();
    for (key, value) in [("LONG_KEY", "synthetic-run-value"), ("SHORT_KEY", "abc")] {
        let f = Fields {
            key: key.into(),
            value: Some(SecretString::new(value)),
            ..Default::default()
        };
        store.set_item("Example App", &f, "human").unwrap();
    }
    let issued = store
        .enrol_agent(
            "Run Agent",
            Some(&["run".to_owned()]),
            &["Example App".to_owned()],
            &[work.to_string_lossy().into_owned()],
            Wildcards::default(),
        )
        .unwrap();
    store
        .set_agent_run_commands(&issued.id, &["sh -c".to_owned(), "/bin/sleep".to_owned()])
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
    let run = |command: Value, path: &str| {
        agent.request_within(
            "POST",
            "/run",
            Some(
                &json!({ "project": "Example App", "command": command, "cwd": work, "path": path }),
            ),
            Duration::from_secs(60),
        )
    };
    let script = r#"printf '%s|%s|%s' "$LONG_KEY" "${SHORT_KEY-unset}" "$PATH""#;
    let path = format!("{}:/bin:/usr/bin", planted.display());

    // The planted program and its folder are passed over; the short value is left out.
    let ran = run(json!(["sh", "-c", script]), &path).unwrap();
    let stdout = ran["stdout"].as_str().unwrap();
    assert!(stdout.starts_with("<concealed by VaultOS>|unset|"), "{ran}");
    assert!(!stdout.contains(planted.to_str().unwrap()), "{stdout}");
    assert_eq!(ran["tooShortToMask"], json!(["SHORT_KEY"]));
    assert_eq!(ran["exitCode"], 0);

    // Nowhere trusted to find it.
    let missing = run(json!(["sh", "-c", "true"]), planted.to_str().unwrap()).unwrap_err();
    assert_eq!(missing.status, Some(400));
    assert!(
        missing.message.contains("was not found"),
        "{}",
        missing.message
    );

    // A lock stops the command, and its reply has no output.
    let started = Instant::now();
    let sleeper = std::thread::scope(|scope| {
        let running = scope.spawn(|| run(json!(["/bin/sleep", "30"]), "/usr/bin:/bin"));
        std::thread::sleep(Duration::from_millis(500));
        handle.with_store(|s| s.lock());
        running.join().unwrap()
    });
    // (The client words every 423 as its own "locked" message.)
    let locked = sleeper.unwrap_err();
    assert_eq!(locked.status, Some(423), "{}", locked.message);
    assert!(started.elapsed() < Duration::from_secs(15));

    handle.shutdown();
    owner.join().unwrap().unwrap();
}
