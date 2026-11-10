//! SSH keys: the agent's identities from `ssh_key` items, signing, and interoperability with
//! OpenSSH's ssh-keygen (skipped where it is not installed). Synthetic keys only.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::process::{Command, Stdio};
use vaultos_core::ssh::{self, SshKey};
use vaultos_core::{Fields, KdfParams, SecretString, Store};

fn ssh_keygen() -> bool {
    Command::new("ssh-keygen")
        .arg("-?")
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

#[test]
fn offers_and_signs_with_ssh_key_items() {
    let dir = tempfile::tempdir().unwrap();
    let mut st = Store::new(dir.path()).unwrap();
    st.create(
        &SecretString::new("synthetic-ssh-password"),
        None,
        KdfParams::FLOOR,
    )
    .unwrap();
    st.create_project("Example App", "human").unwrap();
    let key = SshKey::generate("deploy");
    for (name, value, archived) in [
        ("Deploy key", key.to_openssh().to_string(), false),
        (
            "Old key",
            SshKey::generate("old").to_openssh().to_string(),
            true,
        ),
        ("Not a key", "synthetic".to_owned(), false),
    ] {
        let f = Fields {
            key: name.into(),
            value: Some(SecretString::new(value)),
            kind: Some("ssh_key".into()),
            archived: Some(archived),
            ..Default::default()
        };
        st.set_item("Example App", &f, "human").unwrap();
    }
    let ids = st.ssh_identities().unwrap();
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert_eq!(ids[0].item, "Deploy key");
    assert_eq!(ids[0].blob, key.public_blob());
    assert_eq!(ids[0].fingerprint, key.fingerprint());
    let sig = st
        .ssh_sign(&ids[0].blob, b"data", "/usr/bin/ssh (pid 1)")
        .unwrap();
    assert_eq!(sig, key.sign(b"data"));
    assert!(st.ssh_sign(b"other", b"data", "x").is_err());
    let (_, audit) = st.verify_audit().unwrap();
    assert!(audit
        .iter()
        .any(|e| e.action == "ssh-sign"
            && e.detail == "Example App/Deploy key for /usr/bin/ssh (pid 1)"));
    let before = st.lock_count();
    st.lock();
    st.lock();
    assert_eq!(st.lock_count(), before + 1);
    assert!(st.ssh_identities().is_err());
}

#[test]
fn reads_and_writes_keys_ssh_keygen_understands() {
    if !ssh_keygen() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let theirs = dir.path().join("theirs");
    let made = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "synthetic", "-f"])
        .arg(&theirs)
        .status()
        .unwrap();
    assert!(made.success());
    let key = SshKey::parse(&std::fs::read_to_string(&theirs).unwrap()).unwrap();
    let public = std::fs::read_to_string(theirs.with_extension("pub")).unwrap();
    assert_eq!(key.public_line(), public.trim());

    let ours = SshKey::generate("synthetic@example.com");
    let file = dir.path().join("ours");
    std::fs::write(&file, ours.to_openssh().as_bytes()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let derived = Command::new("ssh-keygen")
        .arg("-y")
        .arg("-f")
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        derived.status.success(),
        "{}",
        String::from_utf8_lossy(&derived.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&derived.stdout).trim(),
        ours.public_line()
    );

    // A Git-style SSHSIG signature that ssh-keygen accepts.
    let message = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n";
    let signed = ssh::sshsig_signed_data("git", message);
    let armored = ssh::sshsig_armor(&ours.public_blob(), "git", &ours.sign(&signed));
    let sig = dir.path().join("message.sig");
    std::fs::write(&sig, armored).unwrap();
    let mut check = Command::new("ssh-keygen")
        .args(["-Y", "check-novalidate", "-n", "git", "-s"])
        .arg(&sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut check.stdin.take().unwrap(), message).unwrap();
    let out = check.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
