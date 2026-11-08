//! The browser extension's native messaging host as Chromium runs it: length-prefixed JSON
//! on stdin and stdout, the extension's origin as its argument, relayed to the running
//! owner; `vaultos browser install`, which registers it; and, where VAULTOS_E2E_CHROMIUM
//! names a Chromium, the extension itself in a headless browser. Synthetic values only.

#![allow(clippy::unwrap_used, reason = "test")]

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use vaultos_core::{Fields, KdfParams, SecretString, Store};
use vaultos_daemon::server::{run_embedded, Config, Confirm, Handle};

const PW: &str = "synthetic-browser-password";
const ORIGIN: &str = "chrome-extension://dmimjgolkikglfcphbakbmkaafaadhnb/";

fn send(input: &mut ChildStdin, v: &Value) {
    let bytes = serde_json::to_vec(v).unwrap();
    input
        .write_all(&u32::try_from(bytes.len()).unwrap().to_ne_bytes())
        .unwrap();
    input.write_all(&bytes).unwrap();
    input.flush().unwrap();
}

fn receive(output: &mut ChildStdout) -> Value {
    let mut len = [0u8; 4];
    output.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u32::from_ne_bytes(len) as usize];
    output.read_exact(&mut buf).unwrap();
    serde_json::from_slice(&buf).unwrap()
}

/// An unlocked owner with one login, whose pairing confirmations say yes.
struct Owner {
    _dir: tempfile::TempDir,
    data: PathBuf,
    handle: Handle,
    reasons: Arc<Mutex<Vec<String>>>,
    thread: Option<JoinHandle<()>>,
}

impl Owner {
    fn start(url: &str, password: &str) -> Owner {
        let dir = tempfile::tempdir().unwrap();
        let data = std::fs::canonicalize(dir.path()).unwrap().join("data");
        {
            let mut st = Store::new(&data).unwrap();
            st.create(&SecretString::new(PW), None, KdfParams::FLOOR)
                .unwrap();
            st.create_project("Example App", "human").unwrap();
            let f = Fields {
                key: "Example".into(),
                kind: Some("login".into()),
                username: Some("alice".into()),
                password: Some(SecretString::new(password)),
                url: Some(url.into()),
                ..Default::default()
            };
            st.set_item("Example App", &f, "human").unwrap();
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let cfg = Config {
            data_dir: data.clone(),
            idle_lock: None,
            wait_for_owner: false,
            sync_repo: None,
            confirm: None,
        };
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap()
                .block_on(run_embedded(cfg, move |h| tx.send(h).unwrap()))
                .unwrap();
        });
        let handle = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        handle
            .with_store(|s| s.unlock(&SecretString::new(PW), None))
            .unwrap();
        let reasons = Arc::new(Mutex::new(Vec::new()));
        let r = reasons.clone();
        handle.set_browser_confirm(Some(Confirm(Arc::new(move |reason: &str| {
            r.lock().unwrap().push(reason.to_owned());
            Some(true)
        }))));
        Owner {
            _dir: dir,
            data,
            handle,
            reasons,
            thread: Some(thread),
        }
    }

    fn stop(mut self) {
        self.handle.shutdown();
        self.thread.take().unwrap().join().unwrap();
    }
}

#[test]
fn relays_the_extensions_messages_to_the_owner() {
    let owner = Owner::start("https://example.com", "synthetic-login-pass");
    let data = owner.data.clone();

    let mut host = Command::new(env!("CARGO_BIN_EXE_vaultos-browser"))
        .arg(ORIGIN)
        .env("VAULTOS_DATA_DIR", &data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (mut input, mut output) = (host.stdin.take().unwrap(), host.stdout.take().unwrap());
    let mut ask = |v: Value| {
        send(&mut input, &v);
        receive(&mut output)
    };

    let st = ask(json!({ "id": 1, "op": "status" }));
    assert_eq!(
        st,
        json!({ "id": 1, "ok": true, "running": true, "unlocked": true })
    );
    let who = ask(json!({ "id": 2, "op": "whoami" }));
    assert_eq!(
        (who["ok"].clone(), who["code"].clone()),
        (json!(false), json!("unpaired"))
    );
    assert_eq!(ask(json!({ "op": "nope" }))["code"], "usage");
    assert_eq!(ask(json!([1, 2]))["code"], "usage");

    let paired = ask(json!({ "id": 3, "op": "pair", "name": "Test Browser", "code": "ABCD-2345" }));
    assert_eq!(paired["ok"], true, "{paired}");
    let key = paired["key"].as_str().unwrap().to_owned();
    let found = ask(json!({ "op": "logins", "key": key, "url": "https://example.com/login" }));
    assert_eq!(found["logins"][0]["username"], "alice", "{found}");
    let filled = ask(json!({
        "op": "fill",
        "key": key,
        "url": "https://example.com/login",
        "projectId": found["logins"][0]["projectId"],
        "itemId": found["logins"][0]["itemId"],
    }));
    assert_eq!(filled["password"], "synthetic-login-pass");
    assert_eq!(
        ask(json!({ "op": "whoami", "key": "not-the-key" }))["code"],
        "unpaired"
    );

    // An oversized message ends the host.
    input.write_all(&(1u32 << 20).to_ne_bytes()).unwrap();
    drop(input);
    assert!(!host.wait().unwrap().success());
    owner.stop();
}

#[test]
fn extension_end_to_end() {
    let Some(chromium) = std::env::var_os("VAULTOS_E2E_CHROMIUM") else {
        return;
    };
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let owner = Owner::start(
        &format!("http://localhost:{port}/login"),
        "synthetic-e2e-pass",
    );
    let profile = tempfile::tempdir().unwrap();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let host = std::fs::canonicalize(env!("CARGO_BIN_EXE_vaultos-browser")).unwrap();
    let out = Command::new("node")
        .arg("scripts/test-extension.mjs")
        .current_dir(&repo)
        .env("VAULTOS_E2E_CHROMIUM", &chromium)
        .env("VAULTOS_DATA_DIR", &owner.data)
        .env("VAULTOS_E2E_HOST", &host)
        .env("VAULTOS_E2E_PORT", port.to_string())
        .env("VAULTOS_E2E_PROFILE", profile.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let reasons = owner.reasons.lock().unwrap().clone();
    assert_eq!(reasons.len(), 1);
    assert!(
        reasons[0].starts_with("pair the browser extension “E2E Chromium” showing the code "),
        "{reasons:?}"
    );
    let page = format!("http://localhost:{port}/login");
    let saved = owner.handle.with_store(|s| s.logins_for(&page)).unwrap();
    let users: Vec<&str> = saved.iter().map(|l| l.username.as_str()).collect();
    assert_eq!(users.len(), 2, "{users:?}");
    assert!(users.contains(&"alice") && users.contains(&"bob"));
    let actions: Vec<String> = owner.handle.with_store(|s| {
        let (_, entries) = s.verify_audit().unwrap();
        entries.into_iter().map(|e| e.action).collect()
    });
    for a in [
        "browser-pair",
        "browser-fill",
        "browser-save",
        "browser-passkey-create",
        "browser-passkey",
    ] {
        assert!(actions.iter().any(|x| x == a), "{a} in {actions:?}");
    }
    // The passkey went in Alice's login, the one for this site and username.
    let passkeys = owner
        .handle
        .with_store(|s| s.passkeys_for(&page, "localhost", &[]))
        .unwrap();
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0].username, "alice");
    owner.stop();
}

fn vaultos(home: &Path, args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_vaultos"))
        .args(args)
        .env("HOME", home)
        .env("VAULTOS_DATA_DIR", home.join("data"))
        .output()
        .unwrap();
    let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out.status.code().unwrap_or(-1), v)
}

#[test]
fn registers_the_host_in_the_browsers_found() {
    let home = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home.path()).unwrap();
    let chrome = if cfg!(target_os = "macos") {
        "Library/Application Support/Google/Chrome"
    } else {
        ".config/google-chrome"
    };
    assert_ne!(vaultos(&home, &["browser", "install"]).0, 0, "no browsers");
    std::fs::create_dir_all(home.join(chrome)).unwrap();

    let (code, out) = vaultos(&home, &["browser", "install"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["installed"][0]["browser"], "Chrome");
    let manifest = home
        .join(chrome)
        .join("NativeMessagingHosts/org.vaultos.preview.browser.json");
    let m: Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    let program = std::fs::canonicalize(env!("CARGO_BIN_EXE_vaultos-browser")).unwrap();
    assert_eq!(m["path"], program.to_str().unwrap());
    assert_eq!(m["allowed_origins"], json!([ORIGIN]));

    assert_eq!(
        vaultos(&home, &["browser", "status"]).1["browsers"][0]["installed"],
        true
    );
    assert_eq!(vaultos(&home, &["browser", "uninstall"]).0, 0);
    assert!(!manifest.exists());
}
