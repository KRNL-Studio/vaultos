//! `vaultos` and `vaultos-agent` as a human and an agent would run them: separate
//! processes, passwords on stdin, a real daemon over its socket. Synthetic vaults,
//! passwords and values only; every test uses its own data directory.

#![allow(clippy::unwrap_used, reason = "test")]

use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use vaultos_client::Client;
use vaultos_core::agents::Wildcards;
use vaultos_core::{Fields, KdfParams, SecretString, Store};
use vaultos_daemon::server::{run, Config};

const PW: &str = "synthetic-cli-password";
const VALUE: &str = "synthetic-human-value";

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        assert_eq!(self.code, 0, "{}", self.stderr);
        serde_json::from_str(&self.stdout).unwrap()
    }
}

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    data: PathBuf,
    work: PathBuf,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let data = root.join("data");
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        Env {
            _dir: dir,
            root,
            data,
            work,
        }
    }

    /// A vault with one project and one human key, at the fast KDF floor.
    fn with_vault() -> Env {
        let env = Env::new();
        let mut store = Store::new(&env.data).unwrap();
        store
            .create(&SecretString::new(PW), None, KdfParams::FLOOR)
            .unwrap();
        store.create_project("Example App", "human").unwrap();
        store
            .set_item(
                "Example App",
                &Fields {
                    key: "HUMAN_KEY".into(),
                    value: Some(SecretString::new(VALUE)),
                    ..Default::default()
                },
                "human",
            )
            .unwrap();
        env
    }

    fn run(&self, bin: &str, args: &[&str], stdin: &str, token: Option<&str>) -> Out {
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .current_dir(&self.work)
            .env("VAULTOS_DATA_DIR", &self.data)
            .env_remove("VAULTOS_AGENT_TOKEN")
            .env_remove("VAULTOS_AGENT_TOKEN_FILE")
            .env_remove("VAULTOS_AGENT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(t) = token {
            cmd.env("VAULTOS_AGENT_TOKEN", t);
        }
        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8(out.stdout).unwrap(),
            stderr: String::from_utf8(out.stderr).unwrap(),
        }
    }

    fn human(&self, args: &[&str], stdin: &str) -> Out {
        self.run(env!("CARGO_BIN_EXE_vaultos"), args, stdin, None)
    }

    fn admin(&self, args: &[&str]) -> Out {
        let mut all = vec!["--password-stdin"];
        all.extend_from_slice(args);
        self.human(&all, &format!("{PW}\n"))
    }

    fn agent(&self, args: &[&str], stdin: &str, token: &str) -> Out {
        self.run(
            env!("CARGO_BIN_EXE_vaultos-agent"),
            args,
            stdin,
            Some(token),
        )
    }

    fn path(&self, rel: &str) -> String {
        self.root.join(rel).to_string_lossy().into_owned()
    }
}

fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn actions(data: &Path, password: &str) -> Vec<String> {
    let mut s = Store::new(data).unwrap();
    s.unlock(&SecretString::new(password), None).unwrap();
    let (_, entries) = s.verify_audit().unwrap();
    entries.into_iter().map(|e| e.action).collect()
}

#[test]
fn admin_commands_work_on_a_vault_this_process_owns() {
    let env = Env::with_vault();
    let work = env.work.to_string_lossy().into_owned();
    let token_file = env.path("tokens/cli.token");

    let enrolled = env
        .admin(&[
            "agents",
            "enroll",
            "CLI Agent",
            "--token-file",
            &token_file,
            "--scopes",
            "read,inject,add",
            "--projects",
            "Example App",
            "--roots",
            &work,
        ])
        .json();
    assert_eq!(enrolled["name"], "CLI Agent");
    assert_eq!(enrolled["reissued"], false);
    assert_eq!(enrolled["scopes"], json!(["read", "inject", "add"]));
    assert_eq!(mode(Path::new(&token_file)), 0o600);
    assert_eq!(mode(&env.root.join("tokens")), 0o700);
    let first = std::fs::read_to_string(&token_file).unwrap();
    assert_eq!(first.trim_end().len(), 64);
    assert!(!enrolled.to_string().contains(first.trim_end()));

    let granted = env
        .admin(&["agents", "grant", "cli agent", "--scopes", "read"])
        .json();
    assert_eq!(granted["scopes"], json!(["read"]));
    assert_eq!(granted["roots"], json!([work]), "unmentioned grants stay");
    let reissued = env
        .admin(&["agents", "enroll", "CLI Agent", "--token-file", &token_file])
        .json();
    assert_eq!(reissued["reissued"], true);
    assert_ne!(std::fs::read_to_string(&token_file).unwrap(), first);
    let both = env.admin(&[
        "agents",
        "grant",
        "CLI Agent",
        "--all-projects",
        "--projects",
        "Example App",
    ]);
    assert_eq!(both.code, 2);
    assert!(both.stderr.contains("Use either --all-projects"));
    assert_eq!(env.admin(&["agents", "list"]).json()[0]["revoked"], false);

    assert_eq!(env.admin(&["pending", "list"]).json(), json!([]));
    assert_eq!(env.admin(&["pending", "approve"]).code, 2);
    let relay = env.path("tokens/relay.token");
    assert_eq!(
        env.admin(&["approver", "set", "--token-file", &relay])
            .json()["approverConfigured"],
        true
    );
    assert_eq!(mode(Path::new(&relay)), 0o600);
    assert_eq!(
        env.admin(&["approver", "status"]).json()["approverConfigured"],
        true
    );
    assert_eq!(
        env.admin(&["approver", "clear"]).json()["approverConfigured"],
        false
    );

    let keys = env.admin(&["keys", "Example App"]);
    assert_eq!(keys.json()[0]["key"], "HUMAN_KEY");
    assert!(!keys.stdout.contains(VALUE));
    let target = env.work.join("app.env");
    let injected = env.admin(&["inject", "Example App", target.to_str().unwrap()]);
    assert_eq!(injected.json()["count"], 1);
    assert!(!injected.stdout.contains(VALUE));
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        format!("HUMAN_KEY='{VALUE}'\n")
    );
    assert_eq!(env.admin(&["inject", "Example App", "rel.env"]).code, 2);

    let backup = env.root.join("backup");
    let b = env.human(&["backup", backup.to_str().unwrap()], "");
    assert_eq!(b.code, 0, "{}", b.stderr);
    assert_eq!(
        std::fs::read(backup.join("vault.enc")).unwrap(),
        std::fs::read(env.data.join("vault.enc")).unwrap()
    );

    let wrong = env.human(
        &["--password-stdin", "projects"],
        "synthetic-wrong-password\n",
    );
    assert_eq!(wrong.code, 1);
    assert!(wrong.stderr.contains("password or Secret Key is wrong"));

    let next = "synthetic-cli-password-2";
    let same = env.human(
        &["--password-stdin", "rotate-password"],
        &format!("{PW}\n{PW}\n"),
    );
    assert!(same.stderr.contains("must differ"));
    let rotated = env.human(
        &["--password-stdin", "rotate-password"],
        &format!("{PW}\n{next}\n"),
    );
    assert_eq!(rotated.json()["ok"], true);
    assert_eq!(env.admin(&["projects"]).code, 1, "the old password fails");
    let revoked = env.human(
        &["--password-stdin", "agents", "revoke", "CLI Agent"],
        &format!("{next}\n"),
    );
    assert_eq!(revoked.json()["revoked"], true);

    let log = actions(&env.data, next);
    for a in [
        "enrol_agent",
        "grant_agent",
        "reissue_agent",
        "rotate_master_password",
        "revoke_agent",
    ] {
        assert!(log.iter().any(|x| x == a), "{a} is audited: {log:?}");
    }
}

#[test]
fn the_daemon_serves_the_agent_cli() {
    let env = Env::with_vault();
    let issued = {
        let mut store = Store::new(&env.data).unwrap();
        store.unlock(&SecretString::new(PW), None).unwrap();
        let scopes = ["read", "inject", "add"].map(str::to_owned);
        store
            .enrol_agent(
                "Shell Agent",
                Some(&scopes),
                &["Example App".to_owned()],
                &[env.work.to_string_lossy().into_owned()],
                Wildcards::default(),
            )
            .unwrap()
    };
    let token = issued.token.expose().to_owned();
    let cfg = Config {
        data_dir: env.data.clone(),
        idle_lock: None,
        wait_for_owner: false,
    };
    let daemon = std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(run(cfg))
    });
    let owner = Client::with_token(env.data.clone(), None);
    let deadline = Instant::now() + Duration::from_secs(10);
    while owner.live(Duration::from_millis(500)).is_none() {
        assert!(Instant::now() < deadline, "the daemon did not start");
        std::thread::sleep(Duration::from_millis(50));
    }

    let status = env.human(&["status"], "").json();
    assert_eq!(
        (
            &status["running"],
            &status["unlocked"],
            &status["fileVersion"]
        ),
        (&json!(true), &json!(false), &json!(4))
    );
    let busy = env.admin(&["projects"]);
    assert_eq!(busy.code, 1);
    assert!(busy.stderr.contains("--stop-backend"), "{}", busy.stderr);
    assert_eq!(env.agent(&["whoami"], "", &token).code, 4, "locked");
    assert_eq!(env.admin(&["unlock"]).json()["locked"], false);

    assert_eq!(
        env.agent(&["whoami"], "", &token).json()["name"],
        "Shell Agent"
    );
    let keys = env.agent(&["keys", "Example App"], "", &token);
    assert_eq!(keys.json()[0]["key"], "HUMAN_KEY");
    assert!(!keys.stdout.contains(VALUE));
    let added = env
        .agent(
            &[
                "add",
                "Example App",
                "AGENT_KEY",
                "--note",
                "synthetic note",
            ],
            "synthetic-agent-value\n",
            &token,
        )
        .json();
    assert_eq!(
        added,
        json!({"project": "Example App", "stored": "AGENT_KEY", "owner": issued.reference, "injectApproved": false})
    );
    // A value passed as an argument is refused and never echoed.
    for args in [
        &["add", "Example App", "K2", "synthetic-leaked-value"][..],
        &["add", "Example App", "K2", "--value=synthetic-leaked-value"][..],
    ] {
        let leaked = env.agent(args, "", &token);
        assert_eq!(leaked.code, 2);
        assert!(!leaked.stderr.contains("synthetic-leaked-value"));
        assert!(!leaked.stdout.contains("synthetic-leaked-value"));
    }
    let injected = env
        .agent(&["inject", "Example App", "rel/.env"], "", &token)
        .json();
    assert_eq!(injected["wrote"], 1);
    assert_eq!(injected["heldForApproval"], json!(["AGENT_KEY"]));
    assert_eq!(
        injected["file"],
        json!(env.work.join("rel/.env").to_string_lossy())
    );
    assert_eq!(
        env.agent(&["pending"], "", &token).json()[0]["key"],
        "AGENT_KEY"
    );
    let found = env.agent(&["search", "human"], "", &token).json();
    assert_eq!(found.as_array().unwrap().len(), 1);
    let sync = env.agent(&["sync"], "", &token);
    assert_eq!(sync.code, 1);
    assert!(sync.stderr.contains("Sync is an owner action"));

    assert_eq!(env.human(&["lock"], "").json()["locked"], true);
    // Admin commands can stop the daemon first when asked to.
    let approved = env.admin(&[
        "--stop-backend",
        "pending",
        "approve",
        "Example App",
        "AGENT_KEY",
    ]);
    assert_eq!(approved.json()["key"], "AGENT_KEY");
    daemon.join().unwrap().unwrap();

    let down = env.agent(&["status"], "", &token).json();
    assert_eq!(down["running"], false);
    assert_eq!(env.agent(&["whoami"], "", &token).code, 3);
    let no_token = env.run(env!("CARGO_BIN_EXE_vaultos-agent"), &["whoami"], "", None);
    assert_eq!(no_token.code, 5);
}

#[test]
fn init_secret_keys_and_upgrade() {
    let env = Env::new();
    let kit = env.path("kit/secret-key.txt");
    let created = env
        .human(
            &["--password-stdin", "init", "--new-secret-key-file", &kit],
            &format!("{PW}\n"),
        )
        .json();
    assert_eq!(created["created"], true);
    let key = std::fs::read_to_string(&kit).unwrap();
    assert!(key.starts_with("VK1-"));
    assert_eq!(mode(Path::new(&kit)), 0o600);
    assert!(!created.to_string().contains(key.trim_end()));
    assert!(env.admin(&["init"]).stderr.contains("already exists"));

    let missing = env.admin(&["projects"]);
    assert_eq!(missing.code, 2);
    assert!(missing.stderr.contains("--secret-key-file"));
    assert_eq!(
        env.admin(&["--secret-key-file", &kit, "projects"]).json(),
        json!([])
    );

    let next = env.path("kit/secret-key-2.txt");
    let replaced = env.admin(&[
        "--secret-key-file",
        &kit,
        "secret-key",
        "set",
        "--new-secret-key-file",
        &next,
    ]);
    assert_eq!(replaced.json()["ok"], true);
    assert_eq!(
        env.admin(&["--secret-key-file", &kit, "projects"]).code,
        1,
        "the old Secret Key no longer opens the vault"
    );
    let taken = env.admin(&[
        "--secret-key-file",
        &next,
        "secret-key",
        "set",
        "--new-secret-key-file",
        &kit,
    ]);
    assert!(taken.stderr.contains("already exists"), "{}", taken.stderr);
    assert_eq!(
        env.admin(&["--secret-key-file", &next, "secret-key", "remove"])
            .json()["secretKey"],
        false
    );
    assert_eq!(env.admin(&["projects"]).json(), json!([]));

    // A v3 vault from the JavaScript app.
    let old = Env::new();
    std::fs::create_dir_all(&old.data).unwrap();
    std::fs::write(
        old.data.join("vault.enc"),
        include_str!("../../vaultos-core/tests/fixtures/v3-vault.json").trim_end(),
    )
    .unwrap();
    let fixture = "synthetic-fixture-password\n";
    let before = old.human(&["--password-stdin", "projects"], fixture);
    assert!(
        before.stderr.contains("Upgrade it first"),
        "{}",
        before.stderr
    );
    let upgraded = old.human(&["--password-stdin", "upgrade"], fixture).json();
    assert_eq!(
        (&upgraded["projects"], &upgraded["items"]),
        (&json!(2), &json!(4))
    );
    assert!(Path::new(upgraded["backup"].as_str().unwrap()).is_file());
    let projects = old.human(&["--password-stdin", "projects"], fixture).json();
    assert_eq!(projects.as_array().unwrap().len(), 2);
}
