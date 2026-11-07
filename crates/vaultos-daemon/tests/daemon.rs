//! The daemon end to end, over its real socket: ownership, the session file, unlock and lock,
//! agent authentication and permissions (scopes, project and folder grants, approvals), and
//! shutdown. Synthetic vault, password and values only.

#![allow(clippy::unwrap_used, reason = "test")]

use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use vaultos_client::{Client, Code};
use vaultos_core::agents::Wildcards;
use vaultos_core::session::Session;
use vaultos_core::{Fields, KdfParams, SecretString, Store};
use vaultos_daemon::server::{run, Config};

const PW: &str = "synthetic-daemon-password";

struct Fixture {
    _dir: tempfile::TempDir,
    data: PathBuf,
    work: PathBuf,
    token: SecretString,
    daemon: Option<std::thread::JoinHandle<Result<(), vaultos_core::Error>>>,
}

fn s(v: &str) -> String {
    v.to_owned()
}

fn setup(scopes: &[&str]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let work = std::fs::canonicalize(&work).unwrap();
    let mut store = Store::new(&data).unwrap();
    store
        .create(&SecretString::new(PW), None, KdfParams::FLOOR)
        .unwrap();
    store.create_project("Example App", "human").unwrap();
    store.create_project("Hidden Project", "human").unwrap();
    store
        .set_item(
            "Example App",
            &Fields {
                key: "HUMAN_KEY".into(),
                value: Some(SecretString::new("synthetic-human-value")),
                ..Default::default()
            },
            "human",
        )
        .unwrap();
    let scopes: Vec<String> = scopes.iter().map(|x| s(x)).collect();
    let issued = store
        .enrol_agent(
            "Test Agent",
            Some(&scopes),
            &[s("Example App")],
            &[work.to_string_lossy().into_owned()],
            Wildcards::default(),
        )
        .unwrap();
    store.lock();
    drop(store);
    let cfg = Config {
        data_dir: data.clone(),
        idle_lock: None,
        wait_for_owner: false,
        sync_repo: None,
        confirm: None,
    };
    let daemon = std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(run(cfg))
    });
    let f = Fixture {
        _dir: dir,
        data,
        work,
        token: issued.token,
        daemon: Some(daemon),
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while f.owner().live(Duration::from_millis(500)).is_none() {
        assert!(Instant::now() < deadline, "the daemon did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    f
}

impl Fixture {
    fn agent(&self) -> Client {
        Client::with_token(self.data.clone(), Some(self.token.clone()))
            .with_busy_wait(Duration::from_secs(5))
    }

    fn owner(&self) -> Client {
        Client::with_token(self.data.clone(), None).with_busy_wait(Duration::from_secs(5))
    }

    fn unlock(&self) {
        self.owner()
            .owner("POST", "/unlock", Some(&json!({ "password": PW })))
            .unwrap();
    }

    fn stop(&mut self) {
        let _ = self.owner().owner("POST", "/shutdown", None);
        if let Some(d) = self.daemon.take() {
            d.join().unwrap().unwrap();
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
    }
}

fn refused(r: Result<Value, vaultos_client::ClientError>) -> (Code, Option<u16>, String) {
    let e = r.unwrap_err();
    (e.code, e.status, e.message)
}

#[test]
fn starts_locked_and_unlocks_only_with_the_password() {
    let mut f = setup(&["read"]);
    let session = Session::read(&f.data).unwrap();
    assert!(session.socket.exists());
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(f.data.join("daemon.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let status = f.agent().status();
    assert_eq!(status["running"], true);
    assert_eq!(status["unlocked"], false);
    assert_eq!(
        refused(f.agent().request("GET", "/whoami", None)).0,
        Code::Locked
    );

    // A second daemon cannot take the vault.
    let second = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run(Config {
            data_dir: f.data.clone(),
            idle_lock: None,
            wait_for_owner: false,
            sync_repo: None,
            confirm: None,
        }));
    assert!(second.is_err());

    let started = Instant::now();
    let wrong = f.owner().owner(
        "POST",
        "/unlock",
        Some(&json!({ "password": "synthetic-wrong-password" })),
    );
    assert_eq!(refused(wrong).1, Some(401));
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "failed unlocks are slowed"
    );
    // The owner token alone is not enough for agent routes.
    let raw = vaultos_client::http::request(
        &session.socket,
        "GET",
        "/projects",
        &[("Authorization", &format!("Bearer {}", "0".repeat(64)))],
        None,
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(raw.status, 401);

    f.unlock();
    assert_eq!(f.agent().status()["unlocked"], true);
    let who = f.agent().request("GET", "/whoami", None).unwrap();
    assert_eq!(who["name"], "Test Agent");
    assert_eq!(who["scopes"], json!(["read"]));

    f.owner().owner("POST", "/lock", None).unwrap();
    assert_eq!(
        refused(f.agent().request("GET", "/projects", None)).0,
        Code::Locked
    );

    f.stop();
    assert!(!session.socket.exists(), "the socket is removed");
    assert!(
        Session::read(&f.data).is_none(),
        "the session file is removed"
    );
    assert!(!f.data.join("owner.lock").exists(), "the vault is released");
}

#[test]
fn agents_see_only_what_they_are_granted() {
    let f = setup(&["read", "add", "inject", "delete:own"]);
    f.unlock();
    let a = f.agent();

    let projects = a.request("GET", "/projects", None).unwrap();
    let names: Vec<&str> = projects
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Example App"]);
    let hidden = a.request("GET", "/projects/Hidden%20Project/secrets", None);
    assert_eq!(refused(hidden).2, "Project is not approved for this agent");
    let search = a.request("GET", "/search?q=project", None).unwrap();
    assert_eq!(search, json!([]), "search filters unapproved projects");
    let reveal = a.request(
        "POST",
        "/reveal",
        Some(&json!({"project": "Example App", "key": "HUMAN_KEY"})),
    );
    assert_eq!(
        refused(reveal).2,
        "This agent does not have the reveal scope"
    );

    // A key an agent adds waits for the human before it is injected.
    let saved = a
        .request(
            "POST",
            "/projects/Example%20App/secrets",
            Some(&json!({"key": "AGENT_KEY", "value": "synthetic-agent-value"})),
        )
        .unwrap();
    assert_eq!(saved["injectApproved"], false);
    let pending = a.request("GET", "/pending", None).unwrap();
    assert_eq!(pending[0]["key"], "AGENT_KEY");
    let target = f.work.join("app").join(".env");
    let injected = a
        .request(
            "POST",
            "/inject",
            Some(&json!({"project": "Example App", "target_path": target})),
        )
        .unwrap();
    assert_eq!(injected["count"], 1);
    assert_eq!(injected["heldForApproval"], json!(["AGENT_KEY"]));
    let written = std::fs::read_to_string(&target).unwrap();
    assert_eq!(written, "HUMAN_KEY='synthetic-human-value'\n");

    // Files outside the agent's folders, links and the vault's own folder are refused.
    let outside = a.request(
        "POST",
        "/inject",
        Some(&json!({"project": "Example App", "target_path": "/tmp/vaultos-outside.env"})),
    );
    assert_eq!(
        refused(outside).2,
        "This path is outside the folders approved for this agent"
    );
    std::os::unix::fs::symlink("/tmp", f.work.join("link")).unwrap();
    let linked = a.request(
        "POST",
        "/inject",
        Some(&json!({"project": "Example App", "target_path": f.work.join("link/x.env")})),
    );
    assert_eq!(
        refused(linked).2,
        "Symbolic links are not allowed in file paths"
    );

    // Import from an approved folder.
    let env = f.work.join("import.env");
    std::fs::write(&env, "IMPORTED_A=synthetic-a\nIMPORTED_B=synthetic-b\n").unwrap();
    let imported = a
        .request(
            "POST",
            "/import",
            Some(&json!({"project": "New Project", "env_path": env, "createProject": true})),
        )
        .unwrap();
    assert_eq!(imported["keys"], json!(["IMPORTED_A", "IMPORTED_B"]));
    let projects = a.request("GET", "/projects", None).unwrap();
    assert_eq!(
        projects.as_array().unwrap().len(),
        2,
        "the new project is granted"
    );

    // The agent may delete its own key, not the human's.
    let own = a.request("DELETE", "/projects/Example%20App/secrets/AGENT_KEY", None);
    assert_eq!(own.unwrap()["ok"], true);
    let human = a.request("DELETE", "/projects/Example%20App/secrets/HUMAN_KEY", None);
    assert_eq!(refused(human).1, Some(403));

    // The relay needs its own token; the owner token alone cannot decide.
    let relay = f.owner().owner(
        "POST",
        "/pending/decide",
        Some(&json!({"project": "New Project", "key": "IMPORTED_A", "approve": true})),
    );
    assert_eq!(refused(relay).2, "The approval relay is not configured");
    assert_eq!(refused(a.request("GET", "/nowhere", None)).1, Some(404));
    assert_eq!(
        refused(a.request("POST", "/sync", None)).2,
        "Agents cannot trigger sync"
    );
}

#[test]
fn browser_requests_and_bad_bodies_are_refused() {
    let f = setup(&["read", "add"]);
    f.unlock();
    let session = Session::read(&f.data).unwrap();
    let bearer = format!("Bearer {}", session.token);
    let token = f.token.expose().to_owned();
    let send = |headers: &[(&str, &str)], method: &str, path: &str, body: Option<&[u8]>| {
        vaultos_client::http::request(
            &session.socket,
            method,
            path,
            headers,
            body,
            Duration::from_secs(5),
        )
        .unwrap()
        .status
    };
    let auth = [
        ("Authorization", bearer.as_str()),
        ("x-vault-agent-token", token.as_str()),
    ];
    let mut browser = auth.to_vec();
    browser.push(("Origin", "https://example.invalid"));
    assert_eq!(send(&browser, "GET", "/whoami", None), 403);
    assert_eq!(send(&auth, "POST", "/projects", Some(b"{not json")), 400);
    assert_eq!(
        send(&auth, "POST", "/projects", Some(b"{\"__proto__\":{}}")),
        400
    );
    let big = vec![b' '; 1024 * 1024 + 1];
    assert_eq!(send(&auth, "POST", "/projects", Some(&big)), 413);
    assert_eq!(send(&auth, "GET", "/whoami", None), 200);
}
