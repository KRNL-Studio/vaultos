//! References and program environments: `vault://` resolution, held agent keys, archived
//! and trashed items, and the audit entries. Synthetic values only.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use vaultos_core::refs::{self, SecretRef};
use vaultos_core::validate::FieldInput;
use vaultos_core::{Fields, KdfParams, SecretString, Store};

const PW: &str = "synthetic-run-password";
const AGENT: &str = "agent:0123456789abcdef";
const OTP: &str = "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQ&issuer=Example";

fn s(v: &str) -> Option<SecretString> {
    Some(SecretString::new(v))
}

fn store(dir: &std::path::Path) -> Store {
    let mut st = Store::new(dir).unwrap();
    st.create(&SecretString::new(PW), None, KdfParams::FLOOR)
        .unwrap();
    st.create_project("Example App", "human").unwrap();
    let mut set = |f: Fields, actor: &str| {
        st.set_item("Example App", &f, actor).unwrap();
    };
    set(
        Fields {
            key: "DB_URL".into(),
            value: s("postgres://synthetic-user:synthetic-pass@db.example.test/app"),
            ..Default::default()
        },
        "human",
    );
    set(
        Fields {
            key: "Example login".into(),
            username: Some("alice".into()),
            password: s("synthetic-login-password"),
            fields: Some(vec![
                FieldInput {
                    label: "Recovery".into(),
                    kind: "concealed".into(),
                    value: s("synthetic-recovery-code"),
                    ..Default::default()
                },
                FieldInput {
                    label: "Region".into(),
                    kind: "text".into(),
                    value: s("eu-west"),
                    ..Default::default()
                },
                FieldInput {
                    label: "One-time code".into(),
                    kind: "otp".into(),
                    value: s(OTP),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        },
        "human",
    );
    set(
        Fields {
            key: "AGENT_TOKEN".into(),
            value: s("synthetic-agent-token"),
            ..Default::default()
        },
        AGENT,
    );
    set(
        Fields {
            key: "OLD_KEY".into(),
            value: s("synthetic-archived-value"),
            archived: Some(true),
            ..Default::default()
        },
        "human",
    );
    st
}

fn r(text: &str) -> SecretRef {
    SecretRef::parse(text).unwrap()
}

#[test]
fn resolves_references_by_field() {
    let dir = tempfile::tempdir().unwrap();
    let mut st = store(dir.path());
    let got = st
        .resolve_refs(
            &[
                r("vault://Example%20App/DB_URL"),
                r("vault://Example%20App/Example%20login"),
                r("vault://Example%20App/Example%20login/username"),
                r("vault://Example%20App/Example%20login/recovery"),
                r("vault://Example%20App/Example%20login/Region"),
            ],
            "read",
            "human",
        )
        .unwrap();
    let got: Vec<&str> = got.iter().map(|v| v.as_str()).collect();
    assert_eq!(
        got,
        [
            "postgres://synthetic-user:synthetic-pass@db.example.test/app",
            "synthetic-login-password",
            "alice",
            "synthetic-recovery-code",
            "eu-west",
        ]
    );
    let code = st
        .resolve_refs(
            &[r("vault://Example App/Example login/otp")],
            "read",
            "human",
        )
        .unwrap();
    assert_eq!(code[0].len(), 6);

    // Agents cannot read codes, nor see archived items; nothing missing resolves.
    assert!(st
        .resolve_refs(&[r("vault://Example App/Example login/otp")], "read", AGENT)
        .is_err());
    assert!(st
        .resolve_refs(&[r("vault://Example App/OLD_KEY")], "read", AGENT)
        .is_err());
    assert!(st
        .resolve_refs(&[r("vault://Example App/OLD_KEY")], "read", "human")
        .is_ok());
    for missing in [
        "vault://Nope/DB_URL",
        "vault://Example App/NOPE",
        "vault://Example App/DB_URL/nope",
    ] {
        let err = st.resolve_refs(&[r(missing)], "read", "human").unwrap_err();
        assert!(
            err.to_string().contains("was not found"),
            "{missing}: {err}"
        );
    }

    let (_, entries) = st.verify_audit().unwrap();
    let last = entries
        .iter()
        .rev()
        .find(|e| e.action == "resolve")
        .unwrap();
    assert!(!last.detail.contains("synthetic"), "{}", last.detail);
}

#[test]
fn renders_a_template() {
    let dir = tempfile::tempdir().unwrap();
    let mut st = store(dir.path());
    let t = "DATABASE_URL={{ vault://Example App/DB_URL }}\nUSER={{ vault://Example App/Example login/username }}\n";
    let found = refs::placeholders(t).unwrap();
    let refs: Vec<SecretRef> = found.iter().map(|p| p.reference.clone()).collect();
    let values = st.resolve_refs(&refs, "render", "human").unwrap();
    let values: Vec<&str> = values.iter().map(|v| v.as_str()).collect();
    assert_eq!(
        refs::render(t, &found, &values),
        "DATABASE_URL=postgres://synthetic-user:synthetic-pass@db.example.test/app\nUSER=alice\n"
    );
}

#[test]
fn environment_holds_unapproved_and_archived_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mut st = store(dir.path());
    let env = st.env_values("Example App", None, "npm", "human").unwrap();
    let names: Vec<&str> = env.pairs.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        ["DB_URL"],
        "a login without a value is not given to programs"
    );
    assert_eq!(env.held_for_approval, ["AGENT_TOKEN"]);

    st.approve_inject("Example App", "AGENT_TOKEN", true)
        .unwrap();
    let keys = vec!["AGENT_TOKEN".to_owned()];
    let env = st
        .env_values("Example App", Some(&keys), "npm", "human")
        .unwrap();
    assert_eq!(env.pairs.len(), 1);
    let keys = vec!["OLD_KEY".to_owned()];
    assert!(st
        .env_values("Example App", Some(&keys), "npm", "human")
        .is_err());

    let (_, entries) = st.verify_audit().unwrap();
    let last = entries.iter().rev().find(|e| e.action == "run").unwrap();
    assert_eq!(last.detail, "Example App (1 keys): npm");
}

#[test]
fn allowed_commands_match_word_for_word() {
    let dir = tempfile::tempdir().unwrap();
    let mut st = store(dir.path());
    let scopes = ["read".to_owned(), "run".to_owned()];
    let issued = st
        .enrol_agent(
            "Runner",
            Some(&scopes),
            &[],
            &[],
            vaultos_core::agents::Wildcards::default(),
        )
        .unwrap();
    let given = ["npm test", "  cargo   test ", "npm test"].map(str::to_owned);
    st.set_agent_run_commands(&issued.id, &given).unwrap();
    let a = st.find_agent("Runner").unwrap().unwrap();
    assert_eq!(a.run_commands, ["npm test", "cargo test"]);
    let argv = |s: &str| s.split(' ').map(str::to_owned).collect::<Vec<_>>();
    assert_eq!(a.run_entry(&argv("npm test --watch")), Some("npm test"));
    assert_eq!(a.run_entry(&argv("cargo test")), Some("cargo test"));
    for refused in ["npm install", "npm", "/usr/bin/npm test", "cargo testx"] {
        assert_eq!(a.run_entry(&argv(refused)), None, "{refused}");
    }
    assert!(st
        .set_agent_run_commands(&issued.id, &["a\nb".to_owned()])
        .is_err());
    assert!(st
        .set_agent_run_commands(&issued.id, &[" ".to_owned()])
        .is_err());
    let many: Vec<String> = (0..51).map(|i| format!("tool{i}")).collect();
    assert!(st.set_agent_run_commands(&issued.id, &many).is_err());
}
