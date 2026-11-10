//! Upgrading a vault written by the 0.2 JavaScript app (fixtures in `tests/fixtures`,
//! recorded from it).

#![allow(clippy::unwrap_used, reason = "test helpers")]

use serde_json::Value;
use std::path::Path;
use vaultos_core::error::Error;
use vaultos_core::upgrade::upgrade;
use vaultos_core::{KdfParams, SecretKey, SecretString, Store};

const PW: &str = "synthetic-fixture-password";
const FIXTURE: &str = include_str!("fixtures/v3-vault.json");
const PLAIN: &str = include_str!("fixtures/v3-vault.plain.json");

fn pw() -> SecretString {
    SecretString::new(PW)
}

fn v3_dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("vault.enc"), FIXTURE.trim_end()).unwrap();
    std::fs::write(
        d.path().join("audit.log"),
        "{\"synthetic\":\"v3 activity line\"}\n",
    )
    .unwrap();
    d
}

fn without_reader_versions(mut v: Value) -> Value {
    let o = v.as_object_mut().unwrap();
    o.remove("formatVersion");
    o.remove("minReaderVersion");
    v
}

fn files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        // Lock companions (`.write.lock.flock`) are created once and kept.
        .filter(|n| !n.starts_with('.'))
        .collect();
    v.sort();
    v
}

#[test]
fn a_v3_vault_needs_an_explicit_upgrade() {
    let d = v3_dir();
    let mut s = Store::new(d.path()).unwrap();
    assert!(matches!(s.unlock(&pw(), None), Err(Error::NeedsUpgrade)));
    assert_eq!(s.file_version().unwrap(), 2);
}

#[test]
fn upgrade_keeps_everything_and_a_backup() {
    let d = v3_dir();
    let done = upgrade(d.path(), &pw(), None, KdfParams::FLOOR).unwrap();
    assert_eq!((done.projects, done.items), (2, 4));
    assert_eq!(
        std::fs::read_to_string(&done.backup).unwrap(),
        FIXTURE.trim_end(),
        "the backup is the untouched v3 file"
    );
    assert_eq!(
        std::fs::read_to_string(d.path().join("audit.log")).unwrap(),
        "{\"synthetic\":\"v3 activity line\"}\n",
        "the v3 activity log stays with the v3 backup"
    );

    let mut s = Store::new(d.path()).unwrap();
    s.unlock(&pw(), None).unwrap();
    assert_eq!(s.file_version().unwrap(), 4);
    let mut exported = serde_json::to_value(s.export_v3().unwrap()).unwrap();
    let history = exported["history"].as_array_mut().unwrap();
    assert_eq!(history.pop().unwrap()["action"], "upgrade_v4");
    let expected = without_reader_versions(serde_json::from_str(PLAIN).unwrap());
    assert_eq!(
        without_reader_versions(exported),
        expected,
        "every record, agent, tombstone, setting and history entry survives"
    );

    assert_eq!(
        s.reveal("Example App", "OPENAI_API_KEY", "human")
            .unwrap()
            .value
            .expose(),
        "synthetic-openai-value-2"
    );
    assert_eq!(
        s.reveal("Example App", "LOGIN", "human")
            .unwrap()
            .password
            .expose(),
        "synthetic-login-password"
    );
    let agent_made = s.list_items("Second Project").unwrap().remove(0);
    assert!(agent_made.owner.starts_with("agent:") && !agent_made.inject_approved);

    // Undo still works across the upgrade: the deleted key can be restored.
    let deleted = s
        .list_history(0)
        .unwrap()
        .into_iter()
        .find(|h| h.action == "delete_secret")
        .unwrap();
    s.revert(&deleted.id, "human").unwrap();
    assert_eq!(
        s.reveal("Example App", "TEMPORARY", "human")
            .unwrap()
            .value
            .expose(),
        "synthetic-temporary"
    );

    let (report, entries) = s.verify_audit().unwrap();
    assert!(report.entries >= 1);
    assert_eq!(entries[0].action, "upgrade_v4");
    assert_eq!(
        report.anchored,
        Some(true),
        "the new vault records the upgrade entry"
    );
    assert!(matches!(
        upgrade(d.path(), &pw(), None, KdfParams::FLOOR),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn a_wrong_password_changes_nothing() {
    let d = v3_dir();
    let before = files(d.path());
    assert!(matches!(
        upgrade(
            d.path(),
            &SecretString::new("synthetic-wrong-password"),
            None,
            KdfParams::FLOOR
        ),
        Err(Error::Unlock)
    ));
    assert_eq!(files(d.path()), before, "no backup, no lock left behind");
    assert_eq!(
        std::fs::read_to_string(d.path().join("vault.enc")).unwrap(),
        FIXTURE.trim_end()
    );
}

#[test]
fn upgrade_can_add_a_secret_key() {
    let d = v3_dir();
    let key = SecretKey::generate();
    upgrade(d.path(), &pw(), Some(&key), KdfParams::FLOOR).unwrap();
    let mut s = Store::new(d.path()).unwrap();
    assert!(matches!(
        s.unlock(&pw(), None),
        Err(Error::SecretKeyRequired)
    ));
    s.unlock(&pw(), Some(&key)).unwrap();
    assert_eq!(s.list_projects().unwrap().len(), 2);
}

#[test]
fn upgrade_waits_for_a_writer() {
    let d = v3_dir();
    std::fs::write(d.path().join("write.lock"), std::process::id().to_string()).unwrap();
    assert!(matches!(
        upgrade(d.path(), &pw(), None, KdfParams::FLOOR),
        Err(Error::Busy)
    ));
}
