//! The MCP bridge binary over stdio against a real daemon: the tool list matches
//! `tools.json`, calls reach the daemon as the enrolled agent, and refusals come back as
//! tool errors. Synthetic vault, password and values only.

#![allow(clippy::unwrap_used, reason = "test")]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};
use vaultos_client::Client;
use vaultos_core::agents::Wildcards;
use vaultos_core::{Fields, KdfParams, SecretString, Store};
use vaultos_daemon::server::{run, Config};

const PW: &str = "synthetic-bridge-password";

#[test]
fn the_bridge_reports_its_version_and_refuses_arguments() {
    let bin = env!("CARGO_BIN_EXE_vaultos-mcp");
    let out = Command::new(bin).arg("--version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        format!("vaultos-mcp {}", env!("CARGO_PKG_VERSION"))
    );
    // An argument left over from the 0.2 Node bridge's configuration is an error, not ignored.
    let out = Command::new(bin)
        .arg("/old/vaultos/mcp/server.mjs")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

struct Mcp {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next: u64,
}

impl Mcp {
    fn start(data: &PathBuf, token: &str) -> Mcp {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vaultos-mcp"))
            .env("VAULTOS_DATA_DIR", data)
            .env("VAULTOS_AGENT_TOKEN", token)
            .env_remove("VAULTOS_AGENT_TOKEN_FILE")
            .env_remove("VAULTOS_AGENT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut m = Mcp {
            child,
            stdin,
            stdout,
            next: 1,
        };
        let init = m.rpc(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "bridge-test", "version": "0" },
            }),
        );
        assert_eq!(init["serverInfo"]["name"], "vault-os");
        m.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        m
    }

    fn send(&mut self, v: &Value) {
        let mut line = serde_json::to_vec(v).unwrap();
        line.push(b'\n');
        self.stdin.write_all(&line).unwrap();
        self.stdin.flush().unwrap();
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        loop {
            let mut line = String::new();
            assert!(
                self.stdout.read_line(&mut line).unwrap() > 0,
                "the bridge exited"
            );
            let msg: Value = serde_json::from_str(&line).unwrap();
            if msg["id"] == json!(id) {
                assert!(msg.get("error").is_none(), "{msg}");
                return msg["result"].clone();
            }
        }
    }

    /// Calls a tool; returns whether it was an error and its text.
    fn tool(&mut self, name: &str, args: Value) -> (bool, String) {
        let r = self.rpc("tools/call", json!({ "name": name, "arguments": args }));
        let text = r["content"][0]["text"].as_str().unwrap().to_owned();
        (r["isError"] == json!(true), text)
    }

    fn ok(&mut self, name: &str, args: Value) -> Value {
        let (err, text) = self.tool(name, args);
        assert!(!err, "{name}: {text}");
        serde_json::from_str(&text).unwrap()
    }
}

#[test]
fn the_bridge_speaks_for_the_enrolled_agent() {
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
    let scopes = ["read", "inject", "run"].map(str::to_owned);
    let issued = store
        .enrol_agent(
            "Bridge Agent",
            Some(&scopes),
            &["Example App".to_owned()],
            &[work.to_string_lossy().into_owned()],
            Wildcards::default(),
        )
        .unwrap();
    store
        .set_agent_run_commands(&issued.id, &["/bin/sh  -c".to_owned()])
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
    let owner = Client::with_token(data.clone(), None).with_busy_wait(Duration::from_secs(5));
    let deadline = Instant::now() + Duration::from_secs(10);
    while owner.live(Duration::from_millis(500)).is_none() {
        assert!(Instant::now() < deadline, "the daemon did not start");
        std::thread::sleep(Duration::from_millis(50));
    }

    let mut mcp = Mcp::start(&data, issued.token.expose());

    // The tools, descriptions and schemas in tools.json (those of the 0.2 Node bridge).
    let listed = mcp.rpc("tools/list", json!({}));
    let expected: Value = serde_json::from_str(include_str!("../src/tools.json")).unwrap();
    assert_eq!(listed["tools"], expected);

    let status = mcp.ok("vault_status", json!({}));
    assert_eq!(status["running"], true);
    assert_eq!(status["unlocked"], false);
    assert_eq!(status["bridge"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(status["bridge"]["sha256"].as_str().unwrap().len(), 64);
    let (err, text) = mcp.tool("whoami", json!({}));
    assert!(err);
    assert!(text.starts_with("Error: "), "{text}");

    owner
        .owner("POST", "/unlock", Some(&json!({ "password": PW })))
        .unwrap();
    assert_eq!(mcp.ok("whoami", json!({}))["name"], "Bridge Agent");
    let secrets = mcp.ok("list_secrets", json!({ "project": "Example App" }));
    assert_eq!(secrets[0]["key"], "HUMAN_KEY");
    assert!(
        !secrets.to_string().contains("synthetic-human-value"),
        "listings carry no values"
    );

    let target = work.join(".env");
    let injected = mcp.ok(
        "inject_secrets",
        json!({ "project": "Example App", "target_path": target }),
    );
    assert_eq!(injected["count"], 1);
    assert!(!injected.to_string().contains("synthetic-human-value"));
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "HUMAN_KEY='synthetic-human-value'\n"
    );

    // An allowed command gets the values; the agent sees them masked.
    let ran = mcp.ok(
        "run_with_secrets",
        json!({
            "project": "Example App",
            "command": ["/bin/sh", "-c", r#"printf '%s|%s' "$HUMAN_KEY" "${#HUMAN_KEY}"; exit 4"#],
            "cwd": work,
        }),
    );
    assert_eq!(ran["stdout"], "<concealed by VaultOS>|21", "{ran}");
    assert_eq!(
        (&ran["exitCode"], &ran["timedOut"]),
        (&json!(4), &json!(false))
    );
    assert!(!ran.to_string().contains("synthetic-human-value"));
    // The owner (the daemon in this test process) starts it, not the bridge, and no route
    // hands an agent the values to start it with.
    let parent = mcp.ok(
        "run_with_secrets",
        json!({
            "project": "Example App",
            "command": ["/bin/sh", "-c", r#"printf %s "$PPID""#],
            "cwd": work,
        }),
    );
    assert_eq!(parent["stdout"], std::process::id().to_string());
    let agent = Client::with_token(data.clone(), Some(issued.token.clone()));
    let body =
        json!({ "project": "Example App", "command": ["/bin/sh", "-c", "true"], "cwd": work });
    let gone = agent.request("POST", "/run/env", Some(&body)).unwrap_err();
    assert_eq!(gone.status, Some(404));

    let refusals = [
        (
            "run_with_secrets",
            json!({ "project": "Example App", "command": ["/bin/echo", "x"], "cwd": work }),
            "Error: This command is not one the human allowed this agent to run with secrets",
        ),
        (
            "run_with_secrets",
            json!({ "project": "Example App", "command": ["/bin/sh", "-c", "true"], "cwd": "/" }),
            "Error: This path is outside the folders approved for this agent",
        ),
        (
            "list_secrets",
            json!({ "project": "Hidden Project" }),
            "Error: Project is not approved for this agent",
        ),
        (
            "reveal_secret",
            json!({ "project": "Example App", "key": "HUMAN_KEY" }),
            "Error: This agent does not have the reveal scope",
        ),
        ("list_secrets", json!({}), "Error: project is required"),
        (
            "search",
            json!({ "query": 7 }),
            "Error: query must be a string",
        ),
        ("nope", json!({}), "Error: unknown tool: nope"),
    ];
    for (name, args, message) in refusals {
        assert_eq!(mcp.tool(name, args), (true, message.to_owned()), "{name}");
    }

    // Closing stdin ends the bridge.
    drop(mcp.stdin);
    assert!(mcp.child.wait().unwrap().success());

    let _ = owner.owner("POST", "/shutdown", None);
    daemon.join().unwrap().unwrap();
}
