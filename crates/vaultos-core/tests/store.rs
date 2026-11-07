//! Store behaviour: format v4 on disk, unlock factors, tamper detection, ownership rules,
//! Undo, batches, concurrent writers, password and Secret Key changes, and the audit chain.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use serde_json::Value;
use std::path::Path;
use vaultos_core::error::Error;
use vaultos_core::{Fields, KdfParams, SecretKey, SecretString, Store};

const PW: &str = "synthetic-store-password";
const AGENT: &str = "agent:0123456789abcdef";
const OTHER_AGENT: &str = "agent:fedcba9876543210";

fn pw(s: &str) -> SecretString {
    SecretString::new(s)
}

fn field(key: &str, value: &str) -> Fields {
    Fields {
        key: key.into(),
        value: Some(pw(value)),
        ..Default::default()
    }
}

fn new_store(dir: &Path) -> Store {
    let mut s = Store::new(dir).unwrap();
    s.create(&pw(PW), None, KdfParams::FLOOR).unwrap();
    s.create_project("Example App", "human").unwrap();
    s
}

fn value(s: &mut Store, key: &str) -> String {
    s.reveal("Example App", key, "human")
        .unwrap()
        .value
        .expose()
        .to_owned()
}

fn edit_file(dir: &Path, f: impl FnOnce(&mut Value)) {
    let path = dir.join("vault.enc");
    let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    f(&mut v);
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
}

#[test]
fn creates_v4_and_keeps_values_off_disk_in_plaintext() {
    let d = tempfile::tempdir().unwrap();
    let mut s = new_store(d.path());
    s.set_item(
        "Example App",
        &field("OPENAI_API_KEY", "synthetic-plaintext-marker"),
        "human",
    )
    .unwrap();
    let bytes = std::fs::read(d.path().join("vault.enc")).unwrap();
    let parsed = vaultos_core::format::VaultFile::parse(&bytes).unwrap();
    assert_eq!(
        parsed.to_bytes().unwrap(),
        bytes,
        "the file written in one pass is the ordinary serialisation, so its MAC verifies"
    );
    let text = String::from_utf8(bytes).unwrap();
    for leak in [
        "synthetic-plaintext-marker",
        "OPENAI_API_KEY",
        "Example App",
        PW,
    ] {
        assert!(!text.contains(leak), "{leak} must not appear in the file");
    }
    assert_eq!(s.file_version().unwrap(), 4);

    s.lock();
    assert!(matches!(s.list_projects(), Err(Error::Locked)));
    assert!(matches!(
        s.unlock(&pw("synthetic-wrong-password"), None),
        Err(Error::Unlock)
    ));
    s.unlock(&pw(PW), None).unwrap();
    assert_eq!(
        value(&mut s, "OPENAI_API_KEY"),
        "synthetic-plaintext-marker"
    );
    let items = s.list_items("Example App").unwrap();
    assert_eq!(
        items[0].provider, "openai",
        "the provider is guessed as the JavaScript app does"
    );
    assert!(items[0].has_value && !items[0].has_password);
}

#[test]
fn a_secret_key_is_a_second_factor() {
    let d = tempfile::tempdir().unwrap();
    let key = SecretKey::generate();
    let mut s = Store::new(d.path()).unwrap();
    s.create(&pw(PW), Some(&key), KdfParams::FLOOR).unwrap();
    s.lock();
    assert_eq!(s.secret_key_id().unwrap(), Some(key.id()));
    assert!(matches!(
        s.unlock(&pw(PW), None),
        Err(Error::SecretKeyRequired)
    ));
    let other = SecretKey::generate();
    assert!(matches!(
        s.unlock(&pw(PW), Some(&other)),
        Err(Error::SecretKeyFormat(_))
    ));
    let typed = SecretKey::parse(&key.display().expose().to_lowercase()).unwrap();
    s.unlock(&pw(PW), Some(&typed)).unwrap();

    // Removing it makes the password alone enough again; nothing else is re-encrypted.
    s.set_secret_key(&pw(PW), Some(&key), None).unwrap();
    s.lock();
    assert_eq!(s.secret_key_id().unwrap(), None);
    s.unlock(&pw(PW), None).unwrap();
}

#[test]
fn any_change_to_the_file_is_detected() {
    let d = tempfile::tempdir().unwrap();
    let mut s = new_store(d.path());
    s.set_item("Example App", &field("A", "synthetic-a"), "human")
        .unwrap();
    s.set_item("Example App", &field("B", "synthetic-b"), "human")
        .unwrap();
    s.lock();
    let original = std::fs::read(d.path().join("vault.enc")).unwrap();
    let restore = || std::fs::write(d.path().join("vault.enc"), &original).unwrap();

    // Swapping two items' sealed secrets.
    edit_file(d.path(), |v| {
        let items = v["projects"][0]["items"].as_array_mut().unwrap();
        let a = items[0]["secret"].clone();
        items[0]["secret"] = items[1]["secret"].clone();
        items[1]["secret"] = a;
    });
    assert!(matches!(s.unlock(&pw(PW), None), Err(Error::Integrity)));
    restore();

    // Dropping an item, or rolling its revision back.
    edit_file(d.path(), |v| {
        v["projects"][0]["items"].as_array_mut().unwrap().pop();
    });
    assert!(matches!(s.unlock(&pw(PW), None), Err(Error::Integrity)));
    restore();
    edit_file(d.path(), |v| v["projects"][0]["items"][0]["rev"] = 0.into());
    assert!(matches!(s.unlock(&pw(PW), None), Err(Error::Integrity)));
    restore();

    // Weakening the KDF changes the derived key, so it reads as a wrong password.
    edit_file(d.path(), |v| v["kdf"]["t"] = 3.into());
    assert!(matches!(s.unlock(&pw(PW), None), Err(Error::Unlock)));
    restore();

    // Unknown fields and newer versions are refused, not ignored, inside boxes too.
    edit_file(d.path(), |v| v["extra"] = true.into());
    assert!(s.unlock(&pw(PW), None).is_err());
    restore();
    edit_file(d.path(), |v| {
        v["projects"][0]["items"][0]["secret"]["x"] = 1.into()
    });
    assert!(s.unlock(&pw(PW), None).is_err());
    restore();
    edit_file(d.path(), |v| v["v"] = 5.into());
    assert!(matches!(
        s.unlock(&pw(PW), None),
        Err(Error::TooNew { need: 5, have: 4 })
    ));
    restore();
    s.unlock(&pw(PW), None).unwrap();
}

#[test]
fn agents_change_only_what_they_own_or_were_delegated() {
    let d = tempfile::tempdir().unwrap();
    let mut s = new_store(d.path());
    s.set_item(
        "Example App",
        &field("HUMAN_KEY", "synthetic-human"),
        "human",
    )
    .unwrap();
    assert!(matches!(
        s.set_item("Example App", &field("HUMAN_KEY", "x"), AGENT),
        Err(Error::Forbidden(_))
    ));
    assert!(matches!(
        s.delete_item("Example App", "HUMAN_KEY", AGENT),
        Err(Error::Forbidden(_))
    ));

    let made = s
        .set_item("Example App", &field("AGENT_KEY", "synthetic-agent"), AGENT)
        .unwrap();
    assert_eq!(made.owner, AGENT);
    assert!(
        !made.inject_approved,
        "an agent's new key waits for the human's approval"
    );
    assert_eq!(s.pending_approvals().unwrap().len(), 1);
    assert!(matches!(
        s.set_item("Example App", &field("AGENT_KEY", "x"), OTHER_AGENT),
        Err(Error::Forbidden(_))
    ));
    s.set_item(
        "Example App",
        &field("AGENT_KEY", "synthetic-agent-2"),
        AGENT,
    )
    .unwrap();
    assert!(s.approve_inject("Example App", "AGENT_KEY", true).unwrap());
    assert!(s.pending_approvals().unwrap().is_empty());

    // A bare agent id is accepted as well as an `agent:` reference.
    let bare_id = OTHER_AGENT.trim_start_matches("agent:");
    s.delegate("Example App", "HUMAN_KEY", bare_id, true)
        .unwrap();
    s.set_item(
        "Example App",
        &field("HUMAN_KEY", "synthetic-delegated"),
        OTHER_AGENT,
    )
    .unwrap();
    assert!(
        matches!(
            s.delete_item("Example App", "HUMAN_KEY", OTHER_AGENT),
            Err(Error::Forbidden(_))
        ),
        "delegation allows edits, not deletion"
    );
    s.delegate("Example App", "HUMAN_KEY", OTHER_AGENT, false)
        .unwrap();
    assert!(matches!(
        s.set_item("Example App", &field("HUMAN_KEY", "x"), OTHER_AGENT),
        Err(Error::Forbidden(_))
    ));

    s.adopt("Example App", "AGENT_KEY").unwrap();
    assert!(matches!(
        s.set_item("Example App", &field("AGENT_KEY", "x"), AGENT),
        Err(Error::Forbidden(_))
    ));
    assert!(matches!(
        s.delete_project("Example App", AGENT),
        Err(Error::Forbidden(_))
    ));
    assert!(matches!(
        s.update_settings(serde_json::Map::new(), AGENT),
        Err(Error::Forbidden(_))
    ));
}

#[test]
fn undo_restores_and_refuses_to_overwrite_newer_work() {
    let d = tempfile::tempdir().unwrap();
    let mut s = new_store(d.path());
    s.set_item("Example App", &field("K", "synthetic-one"), "human")
        .unwrap();
    s.set_item("Example App", &field("K", "synthetic-two"), "human")
        .unwrap();
    let update = s.list_history(1).unwrap().remove(0);
    assert_eq!(update.action, "update_secret");
    s.revert(&update.id, "human").unwrap();
    assert_eq!(value(&mut s, "K"), "synthetic-one");
    assert!(
        matches!(s.revert(&update.id, "human"), Err(Error::Conflict(_))),
        "an undone change cannot be undone twice"
    );

    s.set_item("Example App", &field("L", "synthetic-l"), "human")
        .unwrap();
    let create = s.list_history(1).unwrap().remove(0);
    s.set_item("Example App", &field("L", "synthetic-l-newer"), "human")
        .unwrap();
    assert!(matches!(
        s.revert(&create.id, "human"),
        Err(Error::Conflict(_))
    ));

    s.delete_item("Example App", "K", "human").unwrap();
    assert_eq!(
        s.tombstones().unwrap().len(),
        1,
        "a deletion leaves a tombstone for sync"
    );
    let delete = s.list_history(1).unwrap().remove(0);
    s.revert(&delete.id, "human").unwrap();
    assert_eq!(value(&mut s, "K"), "synthetic-one");
    assert!(s.tombstones().unwrap().is_empty(), "restoring removes it");
    assert!(matches!(
        s.revert(&delete.id, AGENT),
        Err(Error::Forbidden(_))
    ));

    s.create_project("Doomed", "human").unwrap();
    s.set_item("Doomed", &field("D", "synthetic-d"), "human")
        .unwrap();
    s.delete_project("Doomed", "human").unwrap();
    let removed = s.list_history(1).unwrap().remove(0);
    s.revert(&removed.id, "human").unwrap();
    assert_eq!(
        s.reveal("Doomed", "D", "human").unwrap().value.expose(),
        "synthetic-d"
    );

    s.lock();
    s.unlock(&pw(PW), None).unwrap();
    assert!(
        s.list_history(0)
            .unwrap()
            .iter()
            .filter(|h| h.reverted)
            .count()
            >= 3,
        "history survives a save"
    );
}

#[test]
fn a_failed_batch_saves_nothing() {
    let d = tempfile::tempdir().unwrap();
    let mut s = new_store(d.path());
    let before = std::fs::read(d.path().join("vault.enc")).unwrap();
    let r: vaultos_core::Result<()> = s.batch(|s| {
        s.set_item("Example App", &field("ONE", "synthetic-1"), "human")?;
        s.set_item("Missing Project", &field("TWO", "synthetic-2"), "human")?;
        Ok(())
    });
    assert!(matches!(r, Err(Error::NotFound(_))));
    assert_eq!(std::fs::read(d.path().join("vault.enc")).unwrap(), before);
    assert!(
        s.list_items("Example App").unwrap().is_empty(),
        "memory matches disk"
    );

    s.batch(|s| {
        for i in 0..5 {
            s.set_item(
                "Example App",
                &field(&format!("K{i}"), "synthetic"),
                "human",
            )?;
        }
        Ok(())
    })
    .unwrap();
    s.lock();
    s.unlock(&pw(PW), None).unwrap();
    assert_eq!(s.list_items("Example App").unwrap().len(), 5);
}

#[test]
fn a_second_writer_is_detected_and_reloaded() {
    let d = tempfile::tempdir().unwrap();
    let mut a = new_store(d.path());
    let mut b = Store::new(d.path()).unwrap();
    b.unlock(&pw(PW), None).unwrap();
    a.set_item("Example App", &field("FROM_A", "synthetic-a"), "human")
        .unwrap();
    assert!(matches!(
        b.set_item("Example App", &field("FROM_B", "synthetic-b"), "human"),
        Err(Error::Stale)
    ));
    assert!(
        b.list_items("Example App").unwrap().is_empty(),
        "the refused change is not kept in memory"
    );
    assert!(b.reload_if_changed().unwrap());
    assert!(!b.reload_if_changed().unwrap());
    b.set_item("Example App", &field("FROM_B", "synthetic-b"), "human")
        .unwrap();
    assert!(a.reload_if_changed().unwrap());
    assert_eq!(a.list_items("Example App").unwrap().len(), 2);

    // A password changed elsewhere needs a new unlock.
    b.change_password(&pw(PW), &pw("synthetic-new-password"), None)
        .unwrap();
    assert!(matches!(a.reload_if_changed(), Err(Error::Unlock)));
}

#[test]
fn password_changes_rewrap_only_the_vault_key() {
    let d = tempfile::tempdir().unwrap();
    let mut s = new_store(d.path());
    s.set_item("Example App", &field("K", "synthetic-k"), "human")
        .unwrap();
    let item_box = |dir: &Path| {
        let v: Value =
            serde_json::from_slice(&std::fs::read(dir.join("vault.enc")).unwrap()).unwrap();
        v["projects"][0]["items"][0]["secret"].clone()
    };
    let sealed = item_box(d.path());
    assert!(matches!(
        s.change_password(
            &pw("synthetic-wrong-password"),
            &pw("synthetic-new-password"),
            None
        ),
        Err(Error::Unlock)
    ));
    assert!(matches!(
        s.change_password(&pw(PW), &pw("short"), None),
        Err(Error::Invalid(_))
    ));
    s.change_password(&pw(PW), &pw("synthetic-new-password"), None)
        .unwrap();
    assert_eq!(item_box(d.path()), sealed, "item boxes are untouched");
    s.lock();
    assert!(matches!(s.unlock(&pw(PW), None), Err(Error::Unlock)));
    s.unlock(&pw("synthetic-new-password"), None).unwrap();
    assert_eq!(value(&mut s, "K"), "synthetic-k");
}

#[test]
fn reveals_are_signed_into_a_chain_the_vault_anchors() {
    let d = tempfile::tempdir().unwrap();
    let mut s = new_store(d.path());
    s.set_item("Example App", &field("K", "synthetic-k"), "human")
        .unwrap();
    value(&mut s, "K");
    s.reveal("Example App", "K", AGENT).unwrap();
    s.set_item("Example App", &field("L", "synthetic-l"), "human")
        .unwrap(); // anchors the head
    let (report, entries) = s.verify_audit().unwrap();
    assert_eq!(report.entries, 2);
    assert_eq!(report.anchored, Some(true));
    assert_eq!(entries[1].actor, AGENT);
    assert_eq!(entries[1].detail, "Example App/K");
    let log = std::fs::read_to_string(d.path().join("audit-v4.log")).unwrap();
    assert!(
        !log.contains("synthetic-k"),
        "the log holds names, never values"
    );

    // Cutting the log short is noticed at the next unlock; the log is set aside, not lost.
    s.lock();
    std::fs::write(
        d.path().join("audit-v4.log"),
        log.lines().next().unwrap().to_owned() + "\n",
    )
    .unwrap();
    s.unlock(&pw(PW), None).unwrap();
    assert!(s.audit_problem().is_some());
    // An ordinary save must not record "no audit head" over the damaged log, or the next
    // unlock would accept the cut-short log; it resets the chain first.
    s.set_item("Example App", &field("M", "synthetic-m"), "human")
        .unwrap();
    assert!(s.audit_problem().is_none());
    s.lock();
    s.unlock(&pw(PW), None).unwrap();
    assert!(s.audit_problem().is_none());
    value(&mut s, "K");
    let set_aside = std::fs::read_dir(d.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("audit-v4.set-aside-")
        })
        .count();
    assert_eq!(set_aside, 1);
    let (report, entries) = s.verify_audit().unwrap();
    assert_eq!(report.entries, 2);
    assert_eq!(entries[0].action, "audit_log_reset");
}

#[test]
fn two_sessions_on_one_damaged_log_reset_it_once() {
    let d = tempfile::tempdir().unwrap();
    let mut a = new_store(d.path());
    a.audit("probe", "one", "human").unwrap();
    a.audit("probe", "two", "human").unwrap();
    a.set_item("Example App", &field("K", "synthetic-k"), "human")
        .unwrap(); // anchors entry 2
    a.lock();
    let log = d.path().join("audit-v4.log");
    let first = std::fs::read_to_string(&log).unwrap();
    std::fs::write(&log, first.lines().next().unwrap().to_owned() + "\n").unwrap();

    a.unlock(&pw(PW), None).unwrap();
    let mut b = Store::new(d.path()).unwrap();
    b.unlock(&pw(PW), None).unwrap();
    assert!(a.audit_problem().is_some() && b.audit_problem().is_some());

    // A resets the chain; B, which saw the same damage, adopts A's new chain instead of
    // setting it aside, and both keep appending to one chain.
    a.audit("probe", "from a", "human").unwrap();
    b.audit("probe", "from b", "human").unwrap();
    b.set_item("Example App", &field("L", "synthetic-l"), "human")
        .unwrap();
    let set_aside = std::fs::read_dir(d.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("audit-v4.set-aside-")
        })
        .count();
    assert_eq!(set_aside, 1);
    let (report, entries) = b.verify_audit().unwrap();
    assert_eq!(report.anchored, Some(true));
    let actions: Vec<&str> = entries.iter().map(|e| e.detail.as_str()).collect();
    assert_eq!(entries[0].action, "audit_log_reset");
    assert_eq!(&actions[1..], ["from a", "from b"]);
}

#[test]
fn moving_a_key_reseals_it_under_the_other_project() {
    let d = tempfile::tempdir().unwrap();
    let mut s = new_store(d.path());
    s.create_project("Other", "human").unwrap();
    s.set_item("Example App", &field("K", "synthetic-k"), "human")
        .unwrap();
    assert!(matches!(
        s.move_item("Example App", "K", "Other", AGENT),
        Err(Error::Forbidden(_))
    ));
    assert!(s.move_item("Example App", "K", "Other", "human").unwrap());
    assert!(s.list_items("Example App").unwrap().is_empty());
    s.set_item("Example App", &field("K", "synthetic-collision"), "human")
        .unwrap();
    assert!(matches!(
        s.move_item("Example App", "K", "Other", "human"),
        Err(Error::Conflict(_))
    ));
    s.lock();
    s.unlock(&pw(PW), None).unwrap();
    assert_eq!(
        s.reveal("Other", "K", "human").unwrap().value.expose(),
        "synthetic-k"
    );
    assert!(
        matches!(s.create_project("other", "human"), Err(Error::Conflict(_))),
        "names are unique ignoring case"
    );
}

#[test]
fn a_failed_password_change_keeps_the_old_password() {
    let d = tempfile::tempdir().unwrap();
    let mut s = new_store(d.path());
    let held = vaultos_core::fs_safe::claim(d.path(), "write.lock").unwrap();
    assert!(matches!(
        s.change_password(&pw(PW), &pw("synthetic-new-password"), None),
        Err(Error::Busy)
    ));
    drop(held);
    s.lock();
    s.unlock(&pw(PW), None).unwrap();
    s.change_password(&pw(PW), &pw("synthetic-new-password"), None)
        .unwrap();
    let history = s.list_history(0).unwrap();
    assert_eq!(history[0].action, "change_password");
    assert_eq!(
        history
            .iter()
            .filter(|h| h.action == "change_password")
            .count(),
        1
    );
}

#[test]
fn two_stores_appending_keep_one_audit_chain() {
    let d = tempfile::tempdir().unwrap();
    let mut a = new_store(d.path());
    a.set_item("Example App", &field("K", "synthetic-k"), "human")
        .unwrap();
    let mut b = Store::new(d.path()).unwrap();
    b.unlock(&pw(PW), None).unwrap();
    value(&mut a, "K");
    value(&mut b, "K"); // b's idea of the head is one entry old
    value(&mut a, "K");
    let mut c = Store::new(d.path()).unwrap();
    c.unlock(&pw(PW), None).unwrap();
    assert!(c.audit_problem().is_none());
    let (report, entries) = c.verify_audit().unwrap();
    assert_eq!(report.entries, 3);
    assert_eq!(
        entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

#[test]
fn metadata_changes_leave_the_secret_box_alone_and_undo() {
    let d = tempfile::tempdir().unwrap();
    let mut s = new_store(d.path());
    s.set_item("Example App", &field("K", "synthetic-k"), AGENT)
        .unwrap();
    let secret_box = |dir: &Path| {
        let v: Value =
            serde_json::from_slice(&std::fs::read(dir.join("vault.enc")).unwrap()).unwrap();
        v["projects"][0]["items"][0]["secret"].clone()
    };
    let sealed = secret_box(d.path());
    s.delegate("Example App", "K", OTHER_AGENT, true).unwrap();
    s.approve_inject("Example App", "K", true).unwrap();
    assert_eq!(secret_box(d.path()), sealed, "the value was not re-sealed");
    let item = s.list_items("Example App").unwrap().remove(0);
    assert!(item.inject_approved && item.editable_by == vec![OTHER_AGENT.to_owned()]);
    assert_eq!(item.rev, 3);

    let approval = s.list_history(1).unwrap().remove(0);
    assert_eq!(approval.action, "update_meta");
    s.revert(&approval.id, "human").unwrap();
    let item = s.list_items("Example App").unwrap().remove(0);
    assert!(!item.inject_approved, "undo restores the earlier metadata");
    assert_eq!(value(&mut s, "K"), "synthetic-k");
}
