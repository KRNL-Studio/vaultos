//! Typed items: custom fields sealed with the value, the Trash, attachments, per-item
//! versions, Watchtower, one-time codes and imports. Synthetic values only.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::path::Path;
use vaultos_core::error::Error;
use vaultos_core::import::{self, Format};
use vaultos_core::validate::FieldInput;
use vaultos_core::{Fields, KdfParams, SecretString, Store};

const PW: &str = "synthetic-items-password";
const AGENT: &str = "agent:0123456789abcdef";
const OTP: &str =
    "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";

fn s(v: &str) -> Option<SecretString> {
    Some(SecretString::new(v))
}

fn new_store(dir: &Path) -> Store {
    let mut st = Store::new(dir).unwrap();
    st.create(&SecretString::new(PW), None, KdfParams::FLOOR)
        .unwrap();
    st.create_project("Example App", "human").unwrap();
    st.create_project("Other", "human").unwrap();
    st
}

fn field(id: &str, label: &str, kind: &str, value: Option<SecretString>) -> FieldInput {
    FieldInput {
        id: id.into(),
        section: String::new(),
        label: label.into(),
        kind: kind.into(),
        value,
    }
}

fn login(st: &mut Store) {
    st.set_item(
        "Example App",
        &Fields {
            key: "Example login".into(),
            kind: Some("login".into()),
            username: Some("alice".into()),
            password: s("synthetic-Strong-Pass-8812!x"),
            tags: Some(vec!["work".into(), " Work ".into(), "dev".into()]),
            fields: Some(vec![
                field("", "Recovery", "concealed", s("synthetic-recovery-marker")),
                field("", "Region", "text", s("eu-west")),
                field("", "One-time code", "otp", s(OTP)),
            ]),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
}

#[test]
fn secret_fields_are_sealed_and_kept_on_save() {
    let d = tempfile::tempdir().unwrap();
    let mut st = new_store(d.path());
    login(&mut st);
    let item = st
        .find_item("Example App", "Example login")
        .unwrap()
        .unwrap();
    assert_eq!(item.kind, "login");
    assert_eq!(
        item.tags,
        ["work", "dev"],
        "tags are trimmed and deduplicated"
    );
    assert!(item.has_otp);
    let recovery = item.fields.iter().find(|f| f.label == "Recovery").unwrap();
    assert!(
        recovery.value.is_empty() && recovery.has_value,
        "metadata has no secret values"
    );
    assert_eq!(item.fields[1].value, "eu-west");
    assert!(!item.secret_changed_at.is_empty());
    let bytes = std::fs::read(d.path().join("vault.enc")).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("synthetic-recovery-marker"));

    // A form that does not reveal secret fields sends them without values; they stay.
    let ids: Vec<String> = item.fields.iter().map(|f| f.id.clone()).collect();
    let changed_at = item.secret_changed_at.clone();
    st.set_item(
        "Example App",
        &Fields {
            key: "Example login".into(),
            fields: Some(vec![
                field(&ids[0], "Recovery code", "concealed", None),
                field(&ids[2], "One-time code", "otp", None),
            ]),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    let item = st
        .find_item("Example App", "Example login")
        .unwrap()
        .unwrap();
    assert_eq!(item.fields.len(), 2);
    assert!(item.fields[0].has_value);
    assert_eq!(item.secret_changed_at, changed_at, "no secret changed");
    let code = st.otp("Example App", "Example login", "human").unwrap();
    assert_eq!(code.code.expose().len(), 6);
    assert!(st.otp("Example App", "Example login", AGENT).is_err());

    // Values survive a lock and unlock.
    st.lock();
    st.unlock(&SecretString::new(PW), None).unwrap();
    assert!(st.otp("Example App", "Example login", "human").is_ok());

    // Bad input is refused.
    for bad in [
        Fields {
            key: "K".into(),
            kind: Some("spaceship".into()),
            ..Default::default()
        },
        Fields {
            key: "K".into(),
            fields: Some(vec![field("", "x", "otp", s("not a code"))]),
            ..Default::default()
        },
        Fields {
            key: "K".into(),
            fields: Some(vec![field("", "x", "date", s("31/12/2026"))]),
            ..Default::default()
        },
        Fields {
            key: "K".into(),
            fields: Some(vec![field("bad id!", "x", "text", s("v"))]),
            ..Default::default()
        },
    ] {
        assert!(st.set_item("Example App", &bad, "human").is_err());
    }
}

#[test]
fn records_from_before_types_are_inferred_and_hash_alike() {
    let d = tempfile::tempdir().unwrap();
    let mut st = new_store(d.path());
    st.set_item(
        "Example App",
        &Fields {
            key: "OPENAI_API_KEY".into(),
            value: s("synthetic-key"),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    st.set_item(
        "Example App",
        &Fields {
            key: "Site".into(),
            username: Some("bob".into()),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    let items = st.list_items("Example App").unwrap();
    assert_eq!(items[0].kind, "api_key");
    assert_eq!(items[1].kind, "login");
    // A record without typed fields serialises without them, so its sync hash is unchanged.
    let rec = st
        .sync_records()
        .unwrap()
        .into_iter()
        .find(|r| r.record.key == "Site")
        .unwrap();
    let json = serde_json::to_value(&rec.record).unwrap();
    for absent in [
        "kind",
        "tags",
        "favorite",
        "archived",
        "trashedAt",
        "fields",
        "attachments",
    ] {
        assert!(json.get(absent).is_none(), "{absent}");
    }
}

#[test]
fn the_trash_hides_items_and_purges_them_with_their_history() {
    let d = tempfile::tempdir().unwrap();
    let mut st = new_store(d.path());
    st.set_item(
        "Example App",
        &Fields {
            key: "AGENT_KEY".into(),
            value: s("synthetic-agent"),
            ..Default::default()
        },
        AGENT,
    )
    .unwrap();
    st.approve_inject("Example App", "AGENT_KEY", true).unwrap();
    st.delete_item("Example App", "AGENT_KEY", AGENT).unwrap();
    assert!(st.list_items("Example App").unwrap().is_empty());
    assert!(st.search("agent").unwrap().is_empty());
    assert!(matches!(
        st.reveal("Example App", "AGENT_KEY", AGENT),
        Err(Error::NotFound(_))
    ));
    assert!(
        st.reveal("Example App", "AGENT_KEY", "human").is_ok(),
        "the human can look in the Trash"
    );
    assert!(matches!(
        st.delete_item("Example App", "AGENT_KEY", AGENT),
        Err(Error::NotFound(_))
    ));
    let target = d
        .path()
        .parent()
        .unwrap()
        .join(format!("items-inject-{}.env", std::process::id()));
    let injected = st
        .inject(
            "Example App",
            &target,
            vaultos_core::env::Format::Dotenv,
            false,
            None,
            "human",
        )
        .unwrap();
    assert_eq!(injected.count, 0, "nothing in the Trash is injected");
    let _ = std::fs::remove_file(&target);

    // An agent cannot overwrite or bring back what is in the Trash; the human's save does.
    let again = Fields {
        key: "AGENT_KEY".into(),
        value: s("synthetic-again"),
        ..Default::default()
    };
    assert!(matches!(
        st.set_item("Example App", &again, AGENT),
        Err(Error::Conflict(_))
    ));
    st.set_item("Example App", &again, "human").unwrap();
    assert!(st.list_trash("human").unwrap().is_empty());
    assert!(st.list_trash(AGENT).is_err(), "the Trash is the human's");
    st.delete_item("Example App", "AGENT_KEY", "human").unwrap();
    assert!(
        st.restore_item("Example App", "AGENT_KEY", AGENT).is_err(),
        "restoring is the human's"
    );
    assert!(st.purge_item("Example App", "AGENT_KEY", AGENT).is_err());
    assert_eq!(
        st.purge_expired_trash("human").unwrap(),
        0,
        "fresh items stay 30 days"
    );
    assert!(st
        .list_history(0)
        .unwrap()
        .iter()
        .any(|e| e.key.as_deref() == Some("AGENT_KEY") && e.action == "update_secret"));

    st.purge_item("Example App", "AGENT_KEY", "human").unwrap();
    assert!(st.list_trash("human").unwrap().is_empty());
    assert_eq!(
        st.tombstones().unwrap().len(),
        1,
        "a purge leaves a tombstone for sync"
    );
    let left: Vec<String> = st
        .list_history(0)
        .unwrap()
        .into_iter()
        .filter(|e| e.key.as_deref() == Some("AGENT_KEY"))
        .map(|e| e.action)
        .collect();
    assert_eq!(
        left,
        ["purge_secret"],
        "earlier versions, with their values, are gone"
    );

    st.set_item(
        "Example App",
        &Fields {
            key: "A".into(),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    st.set_item(
        "Other",
        &Fields {
            key: "B".into(),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    st.delete_item("Example App", "A", "human").unwrap();
    st.delete_item("Other", "B", "human").unwrap();
    assert_eq!(st.list_trash("human").unwrap().len(), 2);
    assert_eq!(st.empty_trash("human").unwrap(), 2);
    assert_eq!(st.empty_trash("human").unwrap(), 0);
}

#[test]
fn agents_never_see_or_change_archived_items_or_secret_fields() {
    let d = tempfile::tempdir().unwrap();
    let mut st = new_store(d.path());
    login(&mut st);
    st.set_item(
        "Example App",
        &Fields {
            key: "AGENT_KEY".into(),
            value: s("synthetic-agent"),
            ..Default::default()
        },
        AGENT,
    )
    .unwrap();
    let count = |st: &Store, actor: &str| st.list_projects_as(actor).unwrap()[0].secret_count;
    assert_eq!(count(&st, AGENT), 2);
    assert_eq!(st.pending_approvals_as(AGENT).unwrap().len(), 1);

    // An agent's reveal and hash leave out concealed and one-time code fields.
    let r = st.reveal("Example App", "Example login", AGENT).unwrap();
    assert!(r.fields.is_empty());
    let hash = |st: &Store| {
        st.fingerprints(AGENT)
            .unwrap()
            .into_iter()
            .find(|f| f.key == "Example login")
            .unwrap()
            .hash
    };
    // The record's hash with secret field values left out, so they cannot be guessed at.
    let mut record = st
        .sync_records()
        .unwrap()
        .into_iter()
        .find(|r| r.record.key == "Example login")
        .unwrap()
        .record;
    assert_ne!(hash(&st), vaultos_core::canon::record_hash(&record));
    for f in record.fields.iter_mut().filter(|f| f.is_secret()) {
        f.value.clear();
    }
    assert_eq!(hash(&st), vaultos_core::canon::record_hash(&record));

    // Archived: gone from the agent's counts, approvals and hashes, and out of its reach.
    st.set_item(
        "Example App",
        &Fields {
            key: "AGENT_KEY".into(),
            archived: Some(true),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    assert_eq!(count(&st, AGENT), 1);
    assert_eq!(count(&st, "human"), 2);
    assert!(st.pending_approvals_as(AGENT).unwrap().is_empty());
    assert!(st
        .fingerprints(AGENT)
        .unwrap()
        .iter()
        .all(|f| f.key != "AGENT_KEY"));
    assert!(matches!(
        st.set_item(
            "Example App",
            &Fields {
                key: "AGENT_KEY".into(),
                value: s("synthetic-overwrite"),
                ..Default::default()
            },
            AGENT,
        ),
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        st.delete_item("Example App", "AGENT_KEY", AGENT),
        Err(Error::NotFound(_))
    ));
    assert_eq!(
        st.reveal("Example App", "AGENT_KEY", "human")
            .unwrap()
            .value
            .expose(),
        "synthetic-agent"
    );
}

#[test]
fn a_purge_forgets_versions_from_before_a_move() {
    let d = tempfile::tempdir().unwrap();
    let mut st = new_store(d.path());
    st.create_project("Third", "human").unwrap();
    for v in ["synthetic-one", "synthetic-two"] {
        st.set_item(
            "Example App",
            &Fields {
                key: "K".into(),
                value: s(v),
                ..Default::default()
            },
            "human",
        )
        .unwrap();
    }
    st.move_item("Example App", "K", "Other", "human").unwrap();
    st.move_item("Other", "K", "Third", "human").unwrap();
    st.delete_item("Third", "K", "human").unwrap();
    st.purge_item("Third", "K", "human").unwrap();
    let left: Vec<String> = st
        .list_history(0)
        .unwrap()
        .into_iter()
        .filter(|e| e.key.as_deref() == Some("K"))
        .map(|e| e.action)
        .collect();
    assert_eq!(left, ["purge_secret"]);
}

#[test]
fn hostile_records_and_inputs_are_refused() {
    use vaultos_core::store::SyncChanges;
    let d = tempfile::tempdir().unwrap();
    let mut st = new_store(d.path());
    login(&mut st);
    let base = st.sync_records().unwrap().remove(0);
    let mut dup = base.clone();
    let first = dup.record.fields[0].clone();
    dup.record.fields.push(first);
    let mut dated = base.clone();
    dated.record.trashed_at = "soon".into();
    for r in [dup, dated] {
        let changes = SyncChanges {
            upsert: vec![r],
            ..Default::default()
        };
        assert!(st.apply_sync(&changes).is_err());
    }

    // A concealed value turned into a one-time code without a new value must be one.
    let item = st
        .find_item("Example App", "Example login")
        .unwrap()
        .unwrap();
    let recovery = item.fields.iter().find(|f| f.label == "Recovery").unwrap();
    // Not Base32 (0, 1, 8 and 9 are not in its alphabet), so not a one-time code key.
    st.set_item(
        "Example App",
        &Fields {
            key: "Example login".into(),
            fields: Some(vec![field(
                &recovery.id,
                "Recovery",
                "concealed",
                s("synthetic-0189"),
            )]),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    let turned = st.set_item(
        "Example App",
        &Fields {
            key: "Example login".into(),
            fields: Some(vec![field(&recovery.id, "Recovery", "otp", None)]),
            ..Default::default()
        },
        "human",
    );
    assert!(turned.is_err());

    assert!(vaultos_core::totp::Totp::parse("ééééééééé:é").is_err());
    let rows = ",\n".repeat(30_000);
    assert!(import::parse(Format::Csv, rows.as_bytes()).is_err());
}

#[test]
fn attachments_are_sealed_files_bound_to_the_vault() {
    let d = tempfile::tempdir().unwrap();
    let mut st = new_store(d.path());
    login(&mut st);
    let contents = b"synthetic attachment contents".repeat(100);
    let a = st
        .add_attachment(
            "Example App",
            "Example login",
            "../keys/recovery.txt",
            &contents,
            "human",
        )
        .unwrap();
    assert_eq!(a.name, "recovery.txt", "only the file name is kept");
    let file = d.path().join("attachments").join(format!("{}.bin", a.id));
    let sealed = std::fs::read(&file).unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains("synthetic attachment"));
    let (name, plain) = st
        .open_attachment("Example App", "Example login", &a.id, "human")
        .unwrap();
    assert_eq!(
        (name.as_str(), plain.expose()),
        ("recovery.txt", contents.as_slice())
    );
    assert!(st
        .add_attachment("Example App", "Example login", "x", b"x", AGENT)
        .is_err());
    assert!(st
        .open_attachment("Example App", "Example login", &a.id, AGENT)
        .is_err());
    let big = vec![0u8; vaultos_core::store::MAX_ATTACHMENT_BYTES + 1];
    assert!(st
        .add_attachment("Example App", "Example login", "big", &big, "human")
        .is_err());

    // A changed file is refused.
    let mut bad = sealed.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    std::fs::write(&file, &bad).unwrap();
    assert!(matches!(
        st.open_attachment("Example App", "Example login", &a.id, "human"),
        Err(Error::Integrity)
    ));
    std::fs::write(&file, &sealed).unwrap();

    // Moving re-seals under the other project's key, as a new file.
    st.move_item("Example App", "Example login", "Other", "human")
        .unwrap();
    assert!(!file.exists());
    let moved = st.find_item("Other", "Example login").unwrap().unwrap();
    let b = &moved.attachments[0];
    assert_ne!(b.id, a.id);
    let (_, plain) = st
        .open_attachment("Other", "Example login", &b.id, "human")
        .unwrap();
    assert_eq!(plain.expose(), contents.as_slice());

    st.remove_attachment("Other", "Example login", &b.id, "human")
        .unwrap();
    let dir = d.path().join("attachments");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);

    let c = st
        .add_attachment("Other", "Example login", "again.txt", b"synthetic", "human")
        .unwrap();
    st.delete_item("Other", "Example login", "human").unwrap();
    assert!(
        dir.join(format!("{}.bin", c.id)).exists(),
        "the Trash keeps attachments"
    );
    st.empty_trash("human").unwrap();
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "purging deletes them"
    );
}

#[test]
fn versions_can_be_listed_and_restored() {
    let d = tempfile::tempdir().unwrap();
    let mut st = new_store(d.path());
    let set = |st: &mut Store, v: &str| {
        st.set_item(
            "Example App",
            &Fields {
                key: "K".into(),
                value: s(v),
                ..Default::default()
            },
            "human",
        )
        .unwrap();
    };
    set(&mut st, "synthetic-one");
    set(&mut st, "synthetic-two");
    set(&mut st, "synthetic-three");
    st.set_item(
        "Example App",
        &Fields {
            key: "UNRELATED".into(),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    let versions = st.item_history("Example App", "K", "human").unwrap();
    assert_eq!(versions.len(), 3);
    assert!(versions.iter().all(|v| v.restorable));
    let first = versions.last().unwrap().entry.id.clone();
    st.restore_version(&first, "human").unwrap();
    let value = |st: &mut Store| {
        st.reveal("Example App", "K", "human")
            .unwrap()
            .value
            .expose()
            .to_owned()
    };
    assert_eq!(value(&mut st), "synthetic-one");
    let restore = st.list_history(1).unwrap().remove(0);
    st.revert(&restore.id, "human").unwrap();
    assert_eq!(value(&mut st), "synthetic-three", "Undo reverses a restore");
    assert!(st.restore_version(&first, AGENT).is_err());
}

#[test]
fn watchtower_reports_weak_reused_and_expired() {
    let d = tempfile::tempdir().unwrap();
    let mut st = new_store(d.path());
    let item = |key: &str, password: &str, expires: &str| Fields {
        key: key.into(),
        password: s(password),
        expires_at: Some(expires.into()),
        ..Default::default()
    };
    st.set_item("Example App", &item("A", "Password123!", ""), "human")
        .unwrap();
    st.set_item("Other", &item("B", "Password123!", ""), "human")
        .unwrap();
    st.set_item(
        "Other",
        &item("C", "u7Gq!2zT#e9Lw$4Np@8K", "2020-01-01"),
        "human",
    )
    .unwrap();
    st.set_item(
        "Other",
        &Fields {
            archived: Some(true),
            ..item("D", "weak", "")
        },
        "human",
    )
    .unwrap();
    let found: Vec<(String, &str)> = st
        .watchtower("human")
        .unwrap()
        .into_iter()
        .map(|f| (f.key, f.problem))
        .collect();
    let has = |k: &str, p: &str| found.iter().any(|(key, problem)| key == k && *problem == p);
    assert!(has("A", "weak") && has("B", "weak"));
    assert!(has("A", "reused") && has("B", "reused"));
    assert!(has("C", "expired") && !has("C", "weak"));
    assert!(
        !found.iter().any(|(k, _)| k == "D"),
        "archived items are left out"
    );
    assert!(st.watchtower(AGENT).is_err());
    let hashes = st.password_sha1s("human").unwrap();
    assert_eq!(hashes.len(), 3);
    assert!(hashes.iter().all(|(_, _, h)| h.len() == 40
        && h.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())));
}

#[test]
fn imports_land_in_one_project_with_unique_keys() {
    let d = tempfile::tempdir().unwrap();
    let mut st = new_store(d.path());
    st.set_item(
        "Example App",
        &Fields {
            key: "Example".into(),
            ..Default::default()
        },
        "human",
    )
    .unwrap();
    let csv = format!(
        "name,url,username,password,totp,note\n\
         Example,https://example.com,alice,synthetic-imported,{OTP},n\n\
         Example,https://example.org,bob,synthetic-imported-2,not-a-secret,\n\
         \"Line\nbreak\",,,,,\n"
    );
    let report = import::parse(Format::Csv, csv.as_bytes()).unwrap();
    let r = st.import_items("Example App", report, "human").unwrap();
    assert_eq!(r.imported, 3);
    assert_eq!(r.renamed, ["Example (2)", "Example (3)"]);
    let items = st.list_items("Example App").unwrap();
    let keys: Vec<&str> = items.iter().map(|i| i.key.as_str()).collect();
    assert_eq!(
        keys,
        ["Example", "Example (2)", "Example (3)", "Line break"]
    );
    assert!(items[1].has_otp);
    assert_eq!(
        items[2].fields[0].kind, "concealed",
        "an unreadable code is kept, concealed"
    );
    assert_eq!(
        st.reveal("Example App", "Example (2)", "human")
            .unwrap()
            .password
            .expose(),
        "synthetic-imported"
    );
    assert!(st
        .import_items("Example App", import::Report::default(), AGENT)
        .is_err());
}
