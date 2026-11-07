//! The app's SSH agent as ssh, ssh-add and Git use it: keys listed only while unlocked, Git
//! commits signed through `vaultos-ssh-sign` after a confirmation that is then remembered,
//! and refused once the vault has locked and the human declines. Synthetic keys only;
//! skipped where Git or OpenSSH is not installed.

#![allow(clippy::unwrap_used, reason = "test")]

use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vaultos_core::ssh::SshKey;
use vaultos_core::{Fields, KdfParams, SecretString, Store};
use vaultos_daemon::server::{run_embedded, Config, Confirm};

const PW: &str = "synthetic-ssh-password";

fn installed(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn git(work: &Path, data: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(work)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("VAULTOS_DATA_DIR", data)
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .unwrap()
}

#[test]
fn signs_git_commits_through_the_apps_ssh_agent() {
    if !installed("git") || !installed("ssh-keygen") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let (data, work) = (root.join("data"), root.join("work"));
    std::fs::create_dir_all(&work).unwrap();
    let key = SshKey::generate("synthetic");
    {
        let mut st = Store::new(&data).unwrap();
        st.create(&SecretString::new(PW), None, KdfParams::FLOOR)
            .unwrap();
        st.create_project("Example App", "human").unwrap();
        let f = Fields {
            key: "Deploy key".into(),
            value: Some(SecretString::new(key.to_openssh().to_string())),
            kind: Some("ssh_key".into()),
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
    let owner = std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_embedded(cfg, move |h| tx.send(h).unwrap()))
    });
    let handle = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let allow = Arc::new(AtomicBool::new(true));
    let reasons = Arc::new(Mutex::new(Vec::<String>::new()));
    let (a, r) = (allow.clone(), reasons.clone());
    let socket = handle
        .start_ssh_agent(Confirm(Arc::new(move |reason: &str| {
            r.lock().unwrap().push(reason.to_owned());
            Some(a.load(Ordering::SeqCst))
        })))
        .unwrap();
    assert_eq!(socket, data.join("ssh-agent.sock"));
    assert_eq!(handle.ssh_agent_socket(), Some(socket.clone()));

    let keys = |data: &Path| -> Value {
        let out = Command::new(env!("CARGO_BIN_EXE_vaultos"))
            .args(["ssh", "keys"])
            .env("VAULTOS_DATA_DIR", data)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["keys"].clone()
    };
    assert_eq!(keys(&data), serde_json::json!([]), "locked");
    handle
        .with_store(|s| s.unlock(&SecretString::new(PW), None))
        .unwrap();
    let listed = keys(&data);
    let public = key.public_line();
    let public = public.trim_end_matches(" synthetic");
    assert_eq!(listed[0]["publicKey"], public);
    assert_eq!(listed[0]["comment"], "Deploy key (Example App)");
    assert_eq!(listed[0]["fingerprint"], key.fingerprint());
    if installed("ssh-add") {
        let out = Command::new("ssh-add")
            .arg("-L")
            .env("SSH_AUTH_SOCK", &socket)
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).starts_with(public));
    }

    let signers = root.join("allowed_signers");
    std::fs::write(&signers, format!("synthetic@example.com {public}\n")).unwrap();
    let signing_key = format!("key::{public}");
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.name", "Synthetic"],
        vec!["config", "user.email", "synthetic@example.com"],
        vec!["config", "gpg.format", "ssh"],
        vec![
            "config",
            "gpg.ssh.program",
            env!("CARGO_BIN_EXE_vaultos-ssh-sign"),
        ],
        vec![
            "config",
            "gpg.ssh.allowedSignersFile",
            signers.to_str().unwrap(),
        ],
        vec!["config", "user.signingkey", &signing_key],
    ] {
        assert!(git(&work, &data, &args).status.success(), "git {args:?}");
    }
    let commit = |m: &str| {
        git(
            &work,
            &data,
            &["commit", "-q", "--allow-empty", "-S", "-m", m],
        )
    };
    let one = commit("one");
    assert!(
        one.status.success(),
        "{}",
        String::from_utf8_lossy(&one.stderr)
    );
    let verified = git(&work, &data, &["verify-commit", "HEAD"]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    {
        let reasons = reasons.lock().unwrap();
        assert_eq!(reasons.len(), 1);
        assert!(
            reasons[0].starts_with(
                "sign a Git commit or tag with the SSH key “Deploy key” (Example App), for /"
            ),
            "{}",
            reasons[0]
        );
        assert!(
            reasons[0].contains("vaultos-ssh-sign (pid "),
            "{}",
            reasons[0]
        );
    }
    assert!(commit("two").status.success());
    assert_eq!(
        reasons.lock().unwrap().len(),
        1,
        "remembered for this program"
    );

    // Locking ends the approval; declined, nothing is signed.
    handle.with_store(|s| {
        s.lock();
        s.unlock(&SecretString::new(PW), None).unwrap();
    });
    allow.store(false, Ordering::SeqCst);
    let three = commit("three");
    assert!(!three.status.success());
    assert!(
        String::from_utf8_lossy(&three.stderr).contains("VaultOS did not sign"),
        "{}",
        String::from_utf8_lossy(&three.stderr)
    );
    assert_eq!(reasons.lock().unwrap().len(), 2);

    handle.stop_ssh_agent();
    assert!(!socket.exists());
    assert_eq!(handle.ssh_agent_socket(), None);
    handle.shutdown();
    owner.join().unwrap().unwrap();
}
