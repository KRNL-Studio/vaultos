//! Two and three devices syncing through one checkout and through a real Git remote:
//! merges, deletions, conflicts, re-encryption for a new device, and every refusal.

#![allow(clippy::unwrap_used, reason = "test")]

use std::path::{Path, PathBuf};
use std::process::Command;
use vaultos_core::canon::record_hash;
use vaultos_core::store::SyncChanges;
use vaultos_core::{Fields, KdfParams, SecretString, Store};
use vaultos_sync::Sync;

struct Dev {
    store: Store,
    sync: Sync,
}

impl Dev {
    fn new(root: &Path, name: &str, repo: &Path) -> Dev {
        let dir = root.join(name);
        let mut store = Store::new(&dir).unwrap();
        store
            .create(
                &SecretString::new("synthetic-sync-password"),
                None,
                KdfParams::FLOOR,
            )
            .unwrap();
        Dev {
            store,
            sync: Sync::new(&dir, repo),
        }
    }

    fn set(&mut self, project: &str, key: &str, value: &str) {
        if self.store.find_project(project).unwrap().is_none() {
            self.store.create_project(project, "human").unwrap();
        }
        let f = Fields {
            key: key.into(),
            value: Some(SecretString::new(value)),
            ..Default::default()
        };
        self.store.set_item(project, &f, "human").unwrap();
    }

    fn value(&mut self, project: &str, key: &str) -> String {
        self.store
            .reveal(project, key, "human")
            .unwrap()
            .value
            .expose()
            .to_owned()
    }

    fn keys(&self, project: &str) -> Vec<String> {
        self.store
            .list_items(project)
            .unwrap()
            .into_iter()
            .map(|i| i.key)
            .collect()
    }

    fn push(&mut self) -> vaultos_sync::Wrote {
        self.sync.push_local(&self.store).unwrap()
    }

    fn pull(&mut self) -> vaultos_sync::Plan {
        self.sync.pull(&mut self.store, true, false).unwrap()
    }

    fn accept(&mut self) -> vaultos_sync::Plan {
        self.sync.pull(&mut self.store, true, true).unwrap()
    }

    fn identity(&self) -> serde_json::Value {
        self.sync.identity(&self.store).unwrap()
    }

    fn trust(&mut self, other: &serde_json::Value) {
        self.sync.trust(&mut self.store, other).unwrap();
    }

    fn fingerprint(&self) -> String {
        self.store.content_fingerprint().unwrap()
    }

    /// Replaces a record as if it had been edited with this exact revision and time.
    fn force(&mut self, project: &str, key: &str, value: &str, rev: u64, at: &str) {
        let mut r = self
            .store
            .sync_records()
            .unwrap()
            .into_iter()
            .find(|r| r.project_name == project && r.record.key == key)
            .unwrap();
        r.record.value = value.into();
        r.record.rev = rev;
        r.record.updated_at = at.into();
        r.hash = record_hash(&r.record);
        let changes = SyncChanges {
            upsert: vec![r],
            ..Default::default()
        };
        self.store.apply_sync(&changes).unwrap();
    }
}

fn pair() -> (tempfile::TempDir, PathBuf, Dev, Dev) {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    let mut a = Dev::new(root.path(), "a", &repo);
    let mut b = Dev::new(root.path(), "b", &repo);
    let ia = a.sync.init(&mut a.store, "Machine A").unwrap();
    let ib = b.sync.init(&mut b.store, "Machine B").unwrap();
    a.trust(&ib);
    b.trust(&ia);
    (root, repo, a, b)
}

fn every_file(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            every_file(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn contains(dir: &Path, needle: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    every_file(dir, &mut files);
    files
        .into_iter()
        .filter(|f| {
            let bytes = std::fs::read(f).unwrap();
            bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
        })
        .collect()
}

#[test]
fn merges_records_and_deletions_without_disclosing_values_or_their_hashes() {
    let (root, repo, mut a, mut b) = pair();
    a.set("Example", "API_KEY", "synthetic-sync-private");
    a.push();
    b.pull();
    assert_eq!(b.value("Example", "API_KEY"), "synthetic-sync-private");
    b.set("Example", "SECOND", "synthetic-b");
    b.push();
    a.pull();
    assert_eq!(a.value("Example", "SECOND"), "synthetic-b");
    // Moving an item to the Trash is an edit: the other device has it in its Trash too.
    a.store.delete_item("Example", "SECOND", "human").unwrap();
    a.push();
    b.pull();
    assert!(!b.keys("Example").contains(&"SECOND".to_owned()));
    assert_eq!(b.store.list_trash().unwrap().len(), 1);
    a.store.purge_item("Example", "SECOND", "human").unwrap();
    a.push();
    let plan = b.pull();
    assert_eq!(plan.deleted.len(), 1);
    assert!(!b.keys("Example").contains(&"SECOND".to_owned()));
    assert_eq!(a.fingerprint(), b.fingerprint());

    // Neither the repository nor the local index holds a value, a key name or a record hash.
    let hashes: Vec<String> = a
        .store
        .sync_records()
        .unwrap()
        .into_iter()
        .map(|r| r.hash)
        .collect();
    for needle in ["synthetic-sync-private", "API_KEY", "Example"] {
        assert!(
            contains(&repo, needle).is_empty(),
            "{needle} in {:?}",
            contains(&repo, needle)
        );
    }
    for h in &hashes {
        assert!(
            contains(&repo, h).is_empty(),
            "record hash in the repository"
        );
        assert!(
            contains(&root.path().join("a"), h).is_empty(),
            "record hash beside the vault"
        );
    }
    assert!(contains(&root.path().join("a"), "AGE-SECRET-KEY").is_empty());
}

#[test]
fn refuses_recipient_injection_bad_signatures_tampered_files_and_rollback() {
    let (root, repo, mut a, b) = pair();
    a.set("Example", "API_KEY", "synthetic-only");
    a.push();

    let recipients = repo.join("recipients.txt");
    let original = std::fs::read(&recipients).unwrap();
    let stranger = age::x25519::Identity::generate().to_public().to_string();
    std::fs::write(
        &recipients,
        [original.clone(), format!("{stranger}\n").into_bytes()].concat(),
    )
    .unwrap();
    a.set("Example", "API_KEY", "synthetic-changed");
    let e = a.sync.push_local(&a.store).unwrap_err();
    assert!(e.message.contains("Unapproved"), "{e}");
    std::fs::write(&recipients, &original).unwrap();

    let id = a.identity()["id"].as_str().unwrap().to_owned();
    let manifest = repo.join("manifests").join(format!("{id}.json"));
    let signed = std::fs::read(&manifest).unwrap();
    let mut m: serde_json::Value = serde_json::from_slice(&signed).unwrap();
    m["manifest"]["counter"] = (m["manifest"]["counter"].as_u64().unwrap() + 1).into();
    std::fs::write(&manifest, serde_json::to_vec(&m).unwrap()).unwrap();
    let problems = a.sync.verify_manifests(&a.store, false).unwrap();
    assert!(
        problems.contains(&"BAD SIGNATURE".to_owned()),
        "{problems:?}"
    );
    std::fs::write(&manifest, &signed).unwrap();

    let records = repo.join("records");
    let file = std::fs::read_dir(&records)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let bytes = std::fs::read(&file).unwrap();
    std::fs::write(&file, [bytes.clone(), b"bad".to_vec()].concat()).unwrap();
    let problems = a.sync.verify_manifests(&a.store, false).unwrap();
    assert!(
        problems.iter().any(|p| p.contains("ciphertext")),
        "{problems:?}"
    );
    std::fs::write(&file, &bytes).unwrap();

    // A well-named file no manifest signs.
    let unsigned = records.join(format!("{}.age", "0".repeat(64)));
    std::fs::write(&unsigned, b"age-encryption.org/v1").unwrap();
    let problems = a.sync.verify_manifests(&a.store, false).unwrap();
    assert!(
        problems.contains(&"Unsigned or modified ciphertext".to_owned()),
        "{problems:?}"
    );
    std::fs::remove_file(&unsigned).unwrap();

    // A manifest from a device nobody trusts.
    let mut c = Dev::new(root.path(), "c", &repo);
    c.sync.init(&mut c.store, "Machine C").unwrap();
    c.trust(&a.identity());
    c.trust(&b.identity());
    c.push();
    let problems = a.sync.verify_manifests(&a.store, false).unwrap();
    assert!(
        problems.contains(&"Untrusted sync machine".to_owned()),
        "{problems:?}"
    );
    let cid = c.identity()["id"].as_str().unwrap().to_owned();
    std::fs::remove_file(repo.join("manifests").join(format!("{cid}.json"))).unwrap();
    std::fs::write(&recipients, &original).unwrap();

    // Replay: a newer manifest was seen, then the older one comes back.
    a.push();
    assert!(a.sync.verify_manifests(&a.store, true).unwrap().is_empty());
    std::fs::write(&manifest, &signed).unwrap();
    let problems = a.sync.verify_manifests(&a.store, false).unwrap();
    assert!(
        problems.iter().any(|p| p.contains("ROLLBACK")),
        "{problems:?}"
    );
    let e = a.sync.pull(&mut a.store, true, false).unwrap_err();
    assert_eq!(e.code, "SIGNATURE_INVALID");
}

#[test]
fn a_deletion_stays_deleted_when_a_device_that_missed_it_pushes_the_record_again() {
    let (root, repo, mut a, mut b) = pair();
    a.set("Example", "KEY", "synthetic");
    a.force("Example", "KEY", "synthetic", 1, "2026-01-02T03:04:05.678Z");
    a.push();
    b.pull();
    b.push();
    a.store.delete_item("Example", "KEY", "human").unwrap();
    a.store.purge_item("Example", "KEY", "human").unwrap();
    a.push();
    // B has not pulled the deletion. Its record's file is gone, so B writes it again: a new
    // push time, the same edit time.
    assert_eq!(b.push().written, 1);
    let plan = a.pull();
    assert!(plan.added.is_empty(), "{plan:?}");
    assert!(a.keys("Example").is_empty());
    // A device that never had the record sees the deletion too.
    let mut c = Dev::new(root.path(), "c", &repo);
    let ic = c.sync.init(&mut c.store, "Machine C").unwrap();
    c.trust(&a.identity());
    c.trust(&b.identity());
    a.trust(&ic);
    b.trust(&ic);
    a.push();
    assert!(b.push().reencrypted_for_new_recipients);
    assert!(c.pull().added.is_empty());
    let plan = b.pull();
    assert_eq!(plan.deleted.len(), 1, "{plan:?}");
    assert_eq!(a.fingerprint(), b.fingerprint());
}

#[test]
fn an_edit_made_after_a_deletion_is_kept_and_its_file_cannot_be_dropped() {
    let (root, repo, mut a, mut b) = pair();
    let mut c = Dev::new(root.path(), "c", &repo);
    let ic = c.sync.init(&mut c.store, "Machine C").unwrap();
    c.trust(&a.identity());
    c.trust(&b.identity());
    a.trust(&ic);
    b.trust(&ic);
    a.set("Example", "KEY", "synthetic");
    a.force("Example", "KEY", "synthetic", 1, "2026-01-02T03:04:05.678Z");
    a.push();
    b.pull();
    c.pull();
    a.store.delete_item("Example", "KEY", "human").unwrap();
    a.store.purge_item("Example", "KEY", "human").unwrap();
    a.push();
    // B edits the record later than A deleted it, without having pulled the deletion.
    b.force(
        "Example",
        "KEY",
        "edited-after",
        2,
        "2030-01-01T00:00:00.000Z",
    );
    assert_eq!(b.push().written, 1);
    assert_eq!(a.pull().added.len(), 1);
    assert_eq!(a.value("Example", "KEY"), "edited-after");
    // C still has the version from before the deletion: the later edit wins there too.
    assert!(c.pull().deleted.is_empty());
    assert_eq!(c.value("Example", "KEY"), "edited-after");

    // The tombstone of the same name does not excuse a current record file going missing.
    let record = std::fs::read_dir(repo.join("records"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::remove_file(record).unwrap();
    let problems = a.sync.verify_manifests(&a.store, false).unwrap();
    assert!(
        problems.contains(&"Signed ciphertext is missing".to_owned()),
        "{problems:?}"
    );
}

#[test]
fn refuses_ciphertext_a_later_push_replaced_even_when_a_stale_manifest_signs_it() {
    let (root, repo, mut a, mut b) = pair();
    let mut c = Dev::new(root.path(), "c", &repo);
    let ic = c.sync.init(&mut c.store, "Machine C").unwrap();
    c.trust(&a.identity());
    c.trust(&b.identity());
    a.trust(&ic);
    b.trust(&ic);
    a.set("Example", "KEY", "synthetic-old");
    a.push();
    b.pull();
    c.pull();
    c.push();
    let id = |d: &Dev| d.identity()["id"].as_str().unwrap().to_owned();
    let record = std::fs::read_dir(repo.join("records"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let old_record = std::fs::read(&record).unwrap();
    let manifest_a = repo.join("manifests").join(format!("{}.json", id(&a)));
    let old_manifest_a = std::fs::read(&manifest_a).unwrap();

    a.set("Example", "KEY", "synthetic-new");
    a.push();
    let new_record = std::fs::read(&record).unwrap();
    // C's manifest still signs the old ciphertext, but A's newer push replaced it.
    std::fs::write(&record, &old_record).unwrap();
    let problems = b.sync.verify_manifests(&b.store, false).unwrap();
    assert!(
        problems
            .iter()
            .any(|p| p.starts_with("ROLLBACK: ciphertext")),
        "{problems:?}"
    );
    assert_eq!(
        b.sync.pull(&mut b.store, true, false).unwrap_err().code,
        "SIGNATURE_INVALID"
    );
    std::fs::write(&record, &new_record).unwrap();

    // Once C has seen A's newer push, A's older manifest cannot come back with the old
    // file, even to a device that never saw the newer one.
    c.pull();
    c.push();
    std::fs::write(&manifest_a, &old_manifest_a).unwrap();
    std::fs::write(&record, &old_record).unwrap();
    let problems = b.sync.verify_manifests(&b.store, false).unwrap();
    assert!(
        problems.contains(&"ROLLBACK or manifest equivocation".to_owned()),
        "{problems:?}"
    );
}

#[test]
fn the_push_counter_continues_after_the_index_is_lost() {
    let (root, _repo, mut a, mut b) = pair();
    a.set("Example", "KEY", "synthetic");
    a.push();
    a.push();
    assert_eq!(a.push().counter, 3);
    b.pull();
    std::fs::remove_file(root.path().join("a/sync-index.json")).unwrap();
    assert_eq!(a.push().counter, 4);
    assert!(b.pull().conflicts.is_empty());
}

#[test]
fn refuses_concurrent_edits_until_accepted_and_keeps_a_backup() {
    let (root, _repo, mut a, mut b) = pair();
    a.set("Example", "KEY", "base");
    a.push();
    b.pull();
    a.set("Example", "KEY", "left");
    b.set("Example", "KEY", "right");
    b.set("Example", "KEY", "right-again");
    b.push();
    let e = a.sync.pull(&mut a.store, true, false).unwrap_err();
    assert_eq!((e.code, e.conflicts), ("CONFLICTS_PENDING", 1), "{e}");
    assert_eq!(a.value("Example", "KEY"), "left");
    let plan = a.accept();
    assert_eq!(plan.conflicts[0]["resolution"], "remote");
    assert_eq!(a.value("Example", "KEY"), "right-again");
    assert!(
        std::fs::read_dir(root.path().join("a/backups"))
            .unwrap()
            .count()
            > 0
    );
}

#[test]
fn a_one_sided_edit_is_an_update_and_a_kept_local_edit_is_pushed_next() {
    let (_root, _repo, mut a, mut b) = pair();
    a.set("Example", "KEY", "base");
    a.push();
    b.pull();
    a.set("Example", "KEY", "edited-on-a");
    a.push();
    assert!(b.pull().conflicts.is_empty());
    assert_eq!(b.value("Example", "KEY"), "edited-on-a");
    b.set("Example", "FROM_B", "one");
    b.push();
    a.pull();
    b.set("Example", "FROM_B", "two");
    b.push();
    assert!(a.pull().conflicts.is_empty());
    assert_eq!(a.value("Example", "FROM_B"), "two");
    a.set("Example", "KEY", "local-only");
    assert!(a.pull().conflicts.is_empty());
    assert_eq!(a.value("Example", "KEY"), "local-only");

    // A conflict that keeps the local edit leaves it for the next push.
    a.push();
    b.set("Example", "KEY", "edited-on-b");
    b.set("Example", "KEY", "edited-on-b-again");
    b.set("Example", "KEY", "edited-on-b-thrice");
    let plan = b.accept();
    assert_eq!(plan.conflicts[0]["resolution"], "local");
    assert_eq!(b.value("Example", "KEY"), "edited-on-b-thrice");
    assert_eq!(b.sync.status(&mut b.store).unwrap()["outgoing"], 1);
    assert_eq!(b.push().written, 1);
    a.accept();
    assert_eq!(a.value("Example", "KEY"), "edited-on-b-thrice");
    assert_eq!(a.fingerprint(), b.fingerprint());
    assert_eq!(
        b.push().written,
        0,
        "records the repository holds are not rewritten"
    );
}

#[test]
fn ties_resolve_to_the_same_winner_on_both_devices() {
    let (_root, _repo, mut a, mut b) = pair();
    a.set("Example", "KEY", "base");
    a.push();
    b.pull();
    let at = "2026-01-02T03:04:05.678Z";
    a.force("Example", "KEY", "tie-a", 2, at);
    b.force("Example", "KEY", "tie-b", 2, at);
    a.push();
    let plan = b.accept();
    b.push();
    a.accept();
    assert_eq!(plan.conflicts.len(), 1);
    assert_eq!(
        a.fingerprint(),
        b.fingerprint(),
        "both devices keep the same version"
    );
}

#[test]
fn a_new_device_receives_existing_records_re_encrypted() {
    let (root, repo, mut a, mut b) = pair();
    a.set("Example", "K", "existing-synthetic");
    a.push();
    b.pull();
    let mut c = Dev::new(root.path(), "c", &repo);
    let ic = c.sync.init(&mut c.store, "Machine C").unwrap();
    c.trust(&a.identity());
    c.trust(&b.identity());
    a.trust(&ic);
    let wrote = a.push();
    assert!(wrote.reencrypted_for_new_recipients);
    c.pull();
    assert_eq!(c.value("Example", "K"), "existing-synthetic");
}

#[test]
fn project_deletions_propagate_once_the_project_is_empty() {
    let (_root, _repo, mut a, mut b) = pair();
    a.set("Doomed", "K", "synthetic");
    a.push();
    b.pull();
    a.store.delete_item("Doomed", "K", "human").unwrap();
    a.store.purge_item("Doomed", "K", "human").unwrap();
    a.store.delete_project("Doomed", "human").unwrap();
    a.push();
    let plan = b.sync.pull(&mut b.store, false, false).unwrap();
    assert_eq!(plan.deleted.len(), 1);
    assert_eq!(plan.deleted_projects.len(), 1);
    let plan = b.pull();
    assert_eq!(plan.deleted_projects.len(), 1, "{plan:?}");
    assert!(b.store.find_project("Doomed").unwrap().is_none());
}

#[test]
fn refuses_old_and_foreign_repositories_and_a_tampered_index() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        repo.join("vaultos-sync.json"),
        br#"{"app":"VaultOS-Preview","version":1}"#,
    )
    .unwrap();
    let mut a = Dev::new(root.path(), "a", &repo);
    let e = a.sync.init(&mut a.store, "Machine A").unwrap_err();
    assert_eq!(e.code, "UNSUPPORTED_REPOSITORY");
    assert!(e.message.contains("new, empty repository"), "{e}");

    let other = root.path().join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("README.md"), b"not sync").unwrap();
    let mut b = Dev::new(root.path(), "b", &other);
    let e = b.sync.init(&mut b.store, "Machine B").unwrap_err();
    assert!(e.message.contains("new, empty repository"), "{e}");

    let (root, _repo, mut a, _b) = pair();
    a.set("Example", "K", "synthetic");
    a.push();
    let index = root.path().join("a/sync-index.json");
    let mut idx: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
    idx["lastPush"]["counter"] = 99.into();
    std::fs::write(&index, serde_json::to_vec(&idx).unwrap()).unwrap();
    let e = a.sync.pull(&mut a.store, true, false).unwrap_err();
    assert!(e.message.contains("Invalid sync index"), "{e}");
}

// ── Over a real Git remote ──────────────────────────────────────────────────────────────

fn git(args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn configure(repo: &Path) {
    let r = repo.to_str().unwrap();
    for (k, v) in [
        ("user.name", "Synthetic Test"),
        ("user.email", "test@example.invalid"),
        ("commit.gpgsign", "false"),
    ] {
        git(&["-C", r, "config", k, v]);
    }
}

#[test]
fn syncs_two_devices_over_a_git_remote_and_refuses_what_it_did_not_write() {
    let root = tempfile::tempdir().unwrap();
    let remote = root.path().join("remote.git");
    let remote_s = remote.to_str().unwrap();
    git(&[
        "init",
        "--quiet",
        "--bare",
        "--initial-branch=main",
        remote_s,
    ]);
    let repo_a = root.path().join("checkout-a");
    git(&["init", "--quiet", "-b", "main", repo_a.to_str().unwrap()]);
    configure(&repo_a);
    git(&[
        "-C",
        repo_a.to_str().unwrap(),
        "remote",
        "add",
        "origin",
        remote_s,
    ]);

    let mut a = Dev::new(root.path(), "a", &repo_a);
    let ia = a.sync.init(&mut a.store, "Machine A").unwrap();
    a.set("Example", "K", "transport-synthetic");
    let r = a.sync.push_remote(&a.store, None).unwrap();
    assert_eq!(r["delivered"], true, "{r}");
    assert_eq!(r["remoteCommit"], r["sourceCommit"]);

    // A file only this checkout has is left alone: not published, not a reason to stop.
    std::fs::write(repo_a.join("unrelated.txt"), b"must not publish").unwrap();
    std::fs::write(repo_a.join("records/.DS_Store"), b"finder").unwrap();
    let r = a.sync.push_remote(&a.store, None).unwrap();
    assert_eq!(r["delivered"], true, "{r}");
    let published = git(&[
        "--git-dir",
        remote_s,
        "ls-tree",
        "-r",
        "--name-only",
        "HEAD",
    ]);
    assert!(
        !published.contains("unrelated") && !published.contains("DS_Store"),
        "{published}"
    );
    // Given to Git, it is a change sync did not make.
    git(&["-C", repo_a.to_str().unwrap(), "add", "unrelated.txt"]);
    let e = a.sync.push_remote(&a.store, None).unwrap_err();
    assert!(
        e.message
            .contains(r#"unrelated changes; refusing to commit: "unrelated.txt""#),
        "{e}"
    );
    git(&[
        "-C",
        repo_a.to_str().unwrap(),
        "rm",
        "--quiet",
        "--cached",
        "unrelated.txt",
    ]);

    // An ignore rule outside the checkout must not drop a file the manifest signs.
    let exclude = repo_a.join(".git/info/exclude");
    std::fs::write(&exclude, b"tombstones/\n").unwrap();
    a.set("Example", "GONE", "synthetic");
    a.store.delete_item("Example", "GONE", "human").unwrap();
    a.store.purge_item("Example", "GONE", "human").unwrap();
    let e = a.sync.push_remote(&a.store, None).unwrap_err();
    assert!(e.message.contains("Git ignores files sync wrote"), "{e}");
    std::fs::write(&exclude, b"").unwrap();
    // What that push wrote but could not commit goes out with the next round.
    let r = a.sync.pull_remote(&mut a.store, false).unwrap();
    assert_eq!(r["transport"], "ok", "{r}");
    assert_eq!(
        a.sync.push_remote(&a.store, None).unwrap()["delivered"],
        true
    );

    // A second device joins from a clone.
    let repo_b = root.path().join("checkout-b");
    git(&["clone", "--quiet", remote_s, repo_b.to_str().unwrap()]);
    configure(&repo_b);
    let mut b = Dev::new(root.path(), "b", &repo_b);
    let ib = b.sync.init(&mut b.store, "Machine B").unwrap();
    b.trust(&ia);
    a.trust(&ib);
    assert_eq!(
        b.sync.push_remote(&b.store, None).unwrap()["delivered"],
        true
    );
    a.sync.pull_remote(&mut a.store, false).unwrap();
    let r = a.sync.push_remote(&a.store, None).unwrap();
    assert_eq!(r["reencryptedForNewRecipients"], true, "{r}");
    b.sync.pull_remote(&mut b.store, false).unwrap();
    assert_eq!(b.value("Example", "K"), "transport-synthetic");
    b.sync.push_remote(&b.store, None).unwrap();
    a.sync.pull_remote(&mut a.store, false).unwrap();
    a.sync.push_remote(&a.store, None).unwrap();
    b.sync.pull_remote(&mut b.store, false).unwrap();
    let s = b.sync.status_remote(&mut b.store).unwrap();
    assert_eq!(s["state"], "IN_SYNC", "{s}");
    assert_eq!(s["peers"][0]["verified"], true, "{s}");

    // A stray file that arrives in a commit is refused, not ignored.
    let stray = repo_b.join("records/notes.txt");
    std::fs::write(&stray, b"planted").unwrap();
    let rb = repo_b.to_str().unwrap();
    git(&["-C", rb, "add", "-f", "records/notes.txt"]);
    git(&["-C", rb, "commit", "--quiet", "-m", "planted"]);
    git(&["-C", rb, "push", "--quiet", "origin", "HEAD:main"]);
    let e = a.sync.pull_remote(&mut a.store, false).unwrap_err();
    assert!(
        e.message.contains("Unexpected file in the sync repository"),
        "{e}"
    );
}

#[test]
fn refuses_git_rules_that_change_what_it_commits() {
    let root = tempfile::tempdir().unwrap();
    let remote = root.path().join("remote.git");
    let remote_s = remote.to_str().unwrap();
    git(&[
        "init",
        "--quiet",
        "--bare",
        "--initial-branch=main",
        remote_s,
    ]);
    let repo = root.path().join("checkout");
    let r = repo.to_str().unwrap();
    git(&["init", "--quiet", "-b", "main", r]);
    configure(&repo);
    git(&["-C", r, "remote", "add", "origin", remote_s]);
    let mut a = Dev::new(root.path(), "a", &repo);
    a.sync.init(&mut a.store, "Machine A").unwrap();
    a.set("Example", "K", "synthetic");
    assert_eq!(
        a.sync.push_remote(&a.store, None).unwrap()["delivered"],
        true
    );

    // A filter set outside the checkout would commit other bytes than the manifest signs.
    git(&["-C", r, "config", "filter.upper.clean", "tr a-z A-Z"]);
    let attributes = repo.join(".git/info/attributes");
    std::fs::write(&attributes, b"*.json filter=upper\n").unwrap();
    a.set("Example", "K", "synthetic-changed");
    let out = a.sync.push_remote(&a.store, None).unwrap();
    assert_eq!(out["transport"], "commit-failed", "{out}");
    assert!(
        out["error"]
            .as_str()
            .unwrap()
            .contains("Git would change the bytes"),
        "{out}"
    );
    std::fs::write(&attributes, b"").unwrap();
    let out = a.sync.push_remote(&a.store, None).unwrap();
    assert_eq!(out["delivered"], true, "{out}");

    // A control file that arrives in a commit is refused.
    std::fs::write(repo.join(".gitattributes"), b"*.age -text\n").unwrap();
    git(&["-C", r, "add", ".gitattributes"]);
    git(&["-C", r, "commit", "--quiet", "-m", "attributes"]);
    let problems = a.sync.verify_manifests(&a.store, false).unwrap();
    assert!(
        problems
            .iter()
            .any(|p| p.starts_with("Git control files") && p.contains(".gitattributes")),
        "{problems:?}"
    );
}
