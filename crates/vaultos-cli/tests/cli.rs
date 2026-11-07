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

    fn run(&self, bin: &str, args: &[&str], stdin: &str, vars: &[(&str, &str)]) -> Out {
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .current_dir(&self.work)
            .env("VAULTOS_DATA_DIR", &self.data)
            .env_remove("VAULTOS_SYNC_REPO")
            .env_remove("VAULTOS_AGENT_TOKEN")
            .env_remove("VAULTOS_AGENT_TOKEN_FILE")
            .env_remove("VAULTOS_AGENT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.envs(vars.iter().copied());
        let mut child = cmd.spawn().unwrap();
        // A command that does not read stdin may have exited already; its result tells.
        let written = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        if let Err(e) = written {
            assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
        }
        let out = child.wait_with_output().unwrap();
        Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8(out.stdout).unwrap(),
            stderr: String::from_utf8(out.stderr).unwrap(),
        }
    }

    fn human(&self, args: &[&str], stdin: &str) -> Out {
        self.run(env!("CARGO_BIN_EXE_vaultos"), args, stdin, &[])
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
            &[("VAULTOS_AGENT_TOKEN", token)],
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
    let commands = env
        .admin(&[
            "agents",
            "grant",
            "cli agent",
            "--run-command",
            "npm  test",
            "--run-command",
            "cargo test",
        ])
        .json();
    assert_eq!(commands["runCommands"], json!(["npm test", "cargo test"]));
    let cleared = env.admin(&["agents", "grant", "cli agent", "--no-run-commands"]);
    assert_eq!(cleared.json()["runCommands"], json!([]));
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
    assert_eq!(
        std::fs::read(backup.join("audit-v4.log")).unwrap(),
        std::fs::read(env.data.join("audit-v4.log")).unwrap()
    );

    // A relative sync checkout would differ by working directory, so it is refused.
    let relative = env.run(
        env!("CARGO_BIN_EXE_vaultos"),
        &["sync", "status"],
        "",
        &[("VAULTOS_SYNC_REPO", "relative/checkout")],
    );
    assert_ne!(relative.code, 0);
    assert!(
        relative.stderr.contains("must be an absolute path"),
        "{}",
        relative.stderr
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
        let scopes = ["read", "inject", "add", "run"].map(str::to_owned);
        let issued = store
            .enrol_agent(
                "Shell Agent",
                Some(&scopes),
                &["Example App".to_owned()],
                &[env.work.to_string_lossy().into_owned()],
                Wildcards::default(),
            )
            .unwrap();
        store
            .set_agent_run_commands(&issued.id, &["/bin/sh -c".to_owned()])
            .unwrap();
        issued
    };
    let token = issued.token.expose().to_owned();
    let cfg = Config {
        data_dir: env.data.clone(),
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
    // The owner's status carries autosync's full fields; an agent's has none of them.
    assert!(
        status["sync"].get("intervalSeconds").is_some(),
        "{}",
        status["sync"]
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
    let agent_status = env.agent(&["status"], "", &token).json();
    assert!(
        agent_status["sync"].get("intervalSeconds").is_none(),
        "{agent_status}"
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
    let ran = env.agent(
        &[
            "run",
            "Example App",
            "--",
            "/bin/sh",
            "-c",
            r#"printf %s "$HUMAN_KEY"; exit 5"#,
        ],
        "",
        &token,
    );
    assert_eq!(
        (ran.code, ran.stdout.as_str()),
        (5, "<concealed by VaultOS>")
    );
    assert!(
        ran.stderr.contains("AGENT_KEY"),
        "held keys are named: {}",
        ran.stderr
    );
    let refused = env.agent(&["run", "Example App", "--", "/bin/echo", "x"], "", &token);
    assert_eq!(refused.code, 1);
    assert!(
        refused.stderr.contains("not one the human allowed"),
        "{}",
        refused.stderr
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
    let no_token = env.run(env!("CARGO_BIN_EXE_vaultos-agent"), &["whoami"], "", &[]);
    assert_eq!(no_token.code, 5);
}

#[test]
fn the_human_adds_and_imports_keys_without_values_in_arguments_or_output() {
    let env = Env::with_vault();
    let added = env.human(
        &[
            "--password-stdin",
            "add",
            "New Project",
            "NEW_KEY",
            "--note",
            "synthetic note",
        ],
        &format!("{PW}\nsynthetic-added-value\n"),
    );
    assert!(!added.stdout.contains("synthetic-added-value"));
    let added = added.json();
    assert_eq!(
        (&added["stored"], &added["createdProject"]),
        (&json!("NEW_KEY"), &json!(true))
    );
    let refused = env.admin(&["add", "Example App", "K", "synthetic-argument-value"]);
    assert_eq!(refused.code, 2);
    assert!(!refused.stderr.contains("synthetic-argument-value"));
    let empty = env.human(
        &["--password-stdin", "add", "Example App", "K"],
        &format!("{PW}\n"),
    );
    assert_eq!(empty.code, 2, "{}", empty.stderr);

    let file = env.work.join("import.env");
    std::fs::write(&file, "A_KEY=synthetic-a\nB_KEY=synthetic-b\n").unwrap();
    let file = file.to_string_lossy().into_owned();
    let imported = env.admin(&["import", "Imported", &file]);
    assert!(!imported.stdout.contains("synthetic-a"));
    let imported = imported.json();
    assert_eq!(imported["keys"], json!(["A_KEY", "B_KEY"]));
    assert_eq!(imported["createdProject"], true);
    assert_eq!(env.admin(&["import", "Imported", "import.env"]).code, 2);

    let mut s = Store::new(&env.data).unwrap();
    s.unlock(&SecretString::new(PW), None).unwrap();
    let mut value = |p: &str, k: &str| s.reveal(p, k, "human").unwrap().value.expose().to_owned();
    assert_eq!(value("New Project", "NEW_KEY"), "synthetic-added-value");
    assert_eq!(value("Imported", "B_KEY"), "synthetic-b");
    drop(s);
    assert!(actions(&env.data, PW).iter().any(|a| a == "import"));
}

#[test]
fn generates_imports_other_managers_and_prints_one_time_codes() {
    let env = Env::with_vault();
    let pin = env.human(&["generate", "--pin", "--length", "8"], "");
    assert_eq!(pin.code, 0, "{}", pin.stderr);
    let pin = pin.stdout.trim();
    assert!(pin.len() == 8 && pin.bytes().all(|b| b.is_ascii_digit()));
    let words = env.human(&["generate", "--words", "4"], "");
    assert_eq!(
        words.stdout.trim().split('-').count(),
        4,
        "{}",
        words.stderr
    );
    assert_eq!(env.human(&["generate", "--length", "4"], "").code, 1);

    let file = env.work.join("export.csv");
    std::fs::write(
        &file,
        "title,username,password,url,otpauth\nSynthetic Site,synthetic-user,synthetic-imported-password,https://example.com,otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP\n",
    )
    .unwrap();
    let file = file.to_string_lossy().into_owned();
    let imported = env.admin(&["import-items", "Imported", &file]);
    assert!(!imported.stdout.contains("synthetic-imported-password"));
    let imported = imported.json();
    assert_eq!(imported["imported"], 1, "{imported}");
    let code = env.admin(&["otp", "Imported", "Synthetic Site"]);
    assert_eq!(code.code, 0, "{}", code.stderr);
    let code = code.stdout.trim();
    assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()));
    assert_eq!(env.admin(&["otp", "Example App", "HUMAN_KEY"]).code, 1);
    assert_eq!(
        env.admin(&["import-items", "Imported", "export.csv"]).code,
        2
    );
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

#[test]
fn sync_commands_enrol_report_and_refuse_without_printing_values() {
    let env = Env::with_vault();
    let id = env.admin(&["sync", "init", "Laptop"]).json();
    assert_eq!(id["label"], "Laptop");
    assert!(id["agePublicKey"].as_str().unwrap().starts_with("age1"));
    let me = env.admin(&["sync", "identity"]).json();
    assert_eq!(me["id"], id["id"]);
    assert_eq!(me["fingerprint"].as_str().unwrap().len(), 64);

    let plan = env.admin(&["sync", "plan"]).json();
    assert_eq!(plan["added"], json!([]));

    // Without Git, a push stays on this machine and says so (exit 2).
    let push = env.admin(&["sync", "push"]);
    assert_eq!(push.code, 2, "{}", push.stderr);
    let pushed: Value = serde_json::from_str(&push.stdout).unwrap();
    assert_eq!(pushed["transport"], "none");
    assert_eq!(pushed["delivered"], false);
    let status = env.admin(&["sync", "status"]);
    assert_eq!(status.code, 2);
    assert!(status.stdout.contains("NO_GIT_REPO"));
    for out in [&push.stdout, &status.stdout] {
        assert!(!out.contains(VALUE) && !out.contains("HUMAN_KEY"));
    }

    let auto = env
        .admin(&["sync", "auto", "on", "--interval", "60"])
        .json();
    assert_eq!(
        auto["autoSync"],
        json!({ "enabled": true, "intervalSeconds": 60 })
    );
    assert_eq!(
        env.admin(&["sync", "auto", "on", "--interval", "5"]).code,
        2
    );

    let bad = env.root.join("peer.json");
    std::fs::write(
        &bad,
        br#"{"id":"0123456789abcdef","label":"Peer","agePublicKey":"age1nope","signingPublicKey":"AA=="}"#,
    )
    .unwrap();
    let trust = env.admin(&["sync", "trust", bad.to_str().unwrap()]);
    assert_eq!(trust.code, 1);
    assert!(
        trust.stderr.contains("Invalid peer identity"),
        "{}",
        trust.stderr
    );

    // `sync now` asks a running daemon; there is none.
    assert_eq!(env.human(&["sync", "now"], "").code, 3);

    let mut store = Store::new(&env.data).unwrap();
    store.unlock(&SecretString::new(PW), None).unwrap();
    let (_, entries) = store.verify_audit().unwrap();
    assert!(entries
        .iter()
        .any(|e| e.action == "sync_init" && e.detail == "Laptop"));
}

#[test]
fn reads_renders_and_runs_with_the_vault_opened_here() {
    let env = Env::with_vault();
    let reference = "vault://Example App/HUMAN_KEY";
    let read = env.admin(&["read", reference]);
    assert_eq!(read.code, 0, "{}", read.stderr);
    assert_eq!(read.stdout, format!("{VALUE}\n"));
    assert_eq!(env.admin(&["read", "-n", reference]).stdout, VALUE);
    let missing = env.admin(&["read", "vault://Example App/NOPE"]);
    assert_eq!(missing.code, 1);
    assert!(
        missing.stderr.contains("was not found"),
        "{}",
        missing.stderr
    );

    std::fs::write(
        env.work.join("app.env.tpl"),
        "KEY={{ vault://Example%20App/HUMAN_KEY }}\nNAME={{ name }}\n",
    )
    .unwrap();
    let rendered = env
        .admin(&["render", "app.env.tpl", "-o", "app.env"])
        .json();
    assert_eq!(rendered["references"], 1);
    let out = env.work.join("app.env");
    assert_eq!(
        env.admin(&["render", "app.env.tpl", "-o", "missing/app.env"])
            .code,
        2
    );
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        format!("KEY={VALUE}\nNAME={{{{ name }}}}\n")
    );
    assert_eq!(mode(&out), 0o600);
    assert!(env.admin(&["render", "app.env.tpl"]).stdout.contains(VALUE));
    // A folder that leads into the data directory through a symlink is refused too.
    std::os::unix::fs::symlink(&env.data, env.work.join("into-data")).unwrap();
    let refused = env.admin(&["render", "app.env.tpl", "-o", "into-data/app.env"]);
    assert_eq!(refused.code, 2, "{}", refused.stderr);
    assert!(!env.data.join("app.env").exists());

    // The command gets the value; its output shows it masked.
    let script = r#"printf '%s|%s' "$HUMAN_KEY" "${#HUMAN_KEY}""#;
    let ran = env.admin(&[
        "run",
        "--project",
        "Example App",
        "--",
        "/bin/sh",
        "-c",
        script,
    ]);
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert_eq!(
        ran.stdout,
        format!("<concealed by VaultOS>|{}", VALUE.len())
    );
    let by_ref = env.run(
        env!("CARGO_BIN_EXE_vaultos"),
        &[
            "--password-stdin",
            "run",
            "--no-masking",
            "--",
            "/bin/sh",
            "-c",
            r#"printf %s "$DB""#,
        ],
        &format!("{PW}\n"),
        &[("DB", reference)],
    );
    assert_eq!(by_ref.stdout, VALUE, "{}", by_ref.stderr);
    std::fs::write(
        env.work.join(".env"),
        format!("DB={reference}\nMODE=development\n"),
    )
    .unwrap();
    let from_file = env.admin(&[
        "run",
        "--env-file",
        ".env",
        "--",
        "/bin/sh",
        "-c",
        r#"printf '%s %s' "$DB" "$MODE"; exit 7"#,
    ]);
    assert_eq!(from_file.code, 7, "{}", from_file.stderr);
    assert_eq!(from_file.stdout, "<concealed by VaultOS> development");
    assert_eq!(env.admin(&["run", "--", "/bin/true"]).code, 2);
}

#[test]
fn asks_the_running_owner_to_confirm() {
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::{Arc, Mutex};
    use vaultos_daemon::server::Confirm;

    let env = Env::with_vault();
    // 0 confirms, 1 declines, 2 has no way to confirm (no Touch ID).
    let answer = Arc::new(AtomicU8::new(0));
    let reasons = Arc::new(Mutex::new(Vec::<String>::new()));
    let (a, r) = (answer.clone(), reasons.clone());
    let cfg = Config {
        data_dir: env.data.clone(),
        idle_lock: None,
        wait_for_owner: false,
        sync_repo: None,
        confirm: Some(Confirm(Arc::new(move |reason: &str| {
            r.lock().unwrap().push(reason.to_owned());
            match a.load(Ordering::SeqCst) {
                0 => Some(true),
                1 => Some(false),
                _ => None,
            }
        }))),
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
    let reference = "vault://Example App/HUMAN_KEY";
    assert_eq!(env.human(&["read", reference], "").code, 4, "locked");
    assert_eq!(env.admin(&["unlock"]).json()["locked"], false);

    let read = env.human(&["read", reference], "");
    assert_eq!(read.stdout, format!("{VALUE}\n"), "{}", read.stderr);
    let reason = reasons.lock().unwrap().last().cloned().unwrap();
    // VaultOS's own programs are undumpable on Linux, so their path cannot be read there.
    let to = if cfg!(target_os = "linux") {
        "to a program (pid "
    } else {
        "to /"
    };
    assert!(
        reason.starts_with(&format!("give 1 secret from Example App {to}")),
        "{reason}"
    );
    assert!(reason.ends_with("for “read”"), "{reason}");
    let ran = env.human(
        &[
            "run",
            "--project",
            "Example App",
            "--",
            "/bin/sh",
            "-c",
            r#"printf %s "$HUMAN_KEY""#,
        ],
        "",
    );
    assert_eq!(ran.stdout, "<concealed by VaultOS>", "{}", ran.stderr);

    answer.store(1, Ordering::SeqCst);
    let declined = env.human(&["read", reference], "");
    assert_eq!(declined.code, 1);
    assert!(
        declined.stderr.contains("not confirmed"),
        "{}",
        declined.stderr
    );
    assert!(declined.stdout.is_empty());

    // Without Touch ID the password confirms; a wrong one is refused.
    answer.store(2, Ordering::SeqCst);
    assert_eq!(env.admin(&["read", "-n", reference]).stdout, VALUE);
    let wrong = env.human(
        &["--password-stdin", "read", reference],
        "synthetic-wrong\n",
    );
    assert_eq!(wrong.code, 1);
    assert!(wrong.stdout.is_empty());
    let before = reasons.lock().unwrap().len();
    assert_eq!(env.admin(&["read", reference]).code, 0);
    assert_eq!(
        reasons.lock().unwrap().len(),
        before,
        "a password needs no sheet"
    );

    assert_eq!(env.human(&["stop"], "").code, 0);
    daemon.join().unwrap().unwrap();
}

#[test]
fn scans_folders_staged_changes_and_history_for_values() {
    let env = Env::with_vault();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args([
                "-c",
                "user.name=Synthetic",
                "-c",
                "user.email=synthetic@example.com",
            ])
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .current_dir(&env.work)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}");
    };
    let none = env.admin(&["scan"]);
    assert_eq!(none.code, 2);
    assert!(none.stderr.contains("--update-index"), "{}", none.stderr);

    std::fs::write(env.work.join("clean.txt"), "nothing to see\n").unwrap();
    let clean = env.admin(&["scan", "--update-index"]);
    assert_eq!(clean.code, 0, "{}", clean.stderr);
    assert_eq!(clean.json()["findings"], json!([]));
    let index = std::fs::read_to_string(env.data.join("leak-index.json")).unwrap();
    assert!(!index.contains(VALUE) && !index.contains("HUMAN_KEY"));
    assert_eq!(mode(&env.data.join("leak-index.json")), 0o600);

    git(&["init", "-q"]);
    std::fs::write(
        env.work.join("app.env"),
        format!("# config\nTOKEN={VALUE}\n"),
    )
    .unwrap();
    // The index works without the vault: no password is given here.
    let found = env.human(&["scan"], "");
    assert_eq!(found.code, 1, "{}", found.stderr);
    let report: Value = serde_json::from_str(&found.stdout).unwrap();
    let f = &report["findings"][0];
    assert!(f["path"].as_str().unwrap().ends_with("app.env"), "{report}");
    assert_eq!((&f["line"], &f["column"]), (&json!(2), &json!(7)));
    assert!(!found.stdout.contains(VALUE));
    let named = env.admin(&["scan", "--names", "app.env"]);
    let named: Value = serde_json::from_str(&named.stdout).unwrap();
    assert_eq!(
        named["findings"][0]["items"],
        json!([{ "project": "Example App", "item": "HUMAN_KEY", "field": "value" }])
    );

    git(&["add", "app.env"]);
    let staged = env.human(&["scan", "--staged"], "");
    assert_eq!(staged.code, 1);
    let staged: Value = serde_json::from_str(&staged.stdout).unwrap();
    assert_eq!(staged["findings"][0]["path"], "app.env");
    git(&["commit", "-qm", "add config"]);
    std::fs::write(env.work.join("app.env"), "# config\nTOKEN=\n").unwrap();
    git(&["commit", "-qam", "remove the value"]);
    assert_eq!(env.human(&["scan", "--staged"], "").code, 0);
    let history = env.human(&["scan", "--history"], "");
    assert_eq!(history.code, 1, "{}", history.stderr);
    let history: Value = serde_json::from_str(&history.stdout).unwrap();
    let f = &history["findings"][0];
    assert_eq!((&f["path"], &f["line"]), (&json!("app.env"), &json!(2)));
    assert_eq!(f["commit"].as_str().unwrap().len(), 40);

    // In the patch, an added line that starts with "++ " reads like a file header.
    std::fs::write(
        env.work.join("notes.md"),
        format!("++ heading\nTOKEN={VALUE}\n"),
    )
    .unwrap();
    git(&["add", "notes.md"]);
    git(&["commit", "-qm", "add notes"]);
    let history = env.human(&["scan", "--history"], "");
    let history: Value = serde_json::from_str(&history.stdout).unwrap();
    assert!(
        history["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["path"] == "notes.md" && f["line"] == 2),
        "{history}"
    );
}
