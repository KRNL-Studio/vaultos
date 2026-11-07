//! The vault's records, as the JavaScript app (format v3) stores them. Field names match its
//! JSON exactly; anything this build does not know is kept in `extra` and written back.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const HUMAN: &str = "human";

pub fn is_agent(owner: &str) -> bool {
    owner.starts_with("agent:")
}

pub fn agent_ref(agent_id: &str) -> String {
    format!("agent:{agent_id}")
}

pub type Extra = Map<String, Value>;

/// The whole decrypted v3 vault.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultV3 {
    #[serde(default)]
    pub format_version: Option<u64>,
    #[serde(default)]
    pub min_reader_version: Option<u64>,
    pub projects: Vec<ProjectV3>,
    #[serde(default)]
    pub agents: Vec<Value>,
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    #[serde(default)]
    pub history: Vec<HistoryEntryV3>,
    #[serde(default)]
    pub settings: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_trust: Option<Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectV3 {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub secrets: Vec<Record>,
    #[serde(default = "human")]
    pub owner: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: Extra,
}

fn human() -> String {
    HUMAN.to_owned()
}

fn one() -> u64 {
    1
}

fn yes() -> bool {
    true
}

/// One credential, with its value. In memory the v4 store keeps `value` and `password`
/// sealed and decrypts them only to reveal, copy or inject.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub id: String,
    pub key: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub permission: String,
    #[serde(default)]
    pub expires_at: String,
    #[serde(default = "human")]
    pub owner: String,
    #[serde(default = "human")]
    pub created_by: String,
    #[serde(default = "human")]
    pub modified_by: String,
    #[serde(default)]
    pub editable_by: Vec<String>,
    #[serde(default = "yes")]
    pub inject_approved: bool,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default = "one")]
    pub rev: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The part of a record that is not secret: listed, searched and shown without a reveal.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemMeta {
    pub key: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub permission: String,
    #[serde(default)]
    pub expires_at: String,
    pub owner: String,
    pub created_by: String,
    pub modified_by: String,
    #[serde(default)]
    pub editable_by: Vec<String>,
    pub inject_approved: bool,
    pub created_at: String,
    pub updated_at: String,
    /// Whether the sealed part holds a non-empty value or password, so lists can say
    /// "No value" without decrypting it.
    #[serde(default)]
    pub has_value: bool,
    #[serde(default)]
    pub has_password: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The secret part of a record.
#[derive(
    Clone, Default, PartialEq, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop,
)]
pub struct ItemSecret {
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub password: String,
}

impl std::fmt::Debug for ItemSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemSecret(<redacted>)")
    }
}

impl Record {
    pub fn split(&self) -> (ItemMeta, ItemSecret) {
        (
            ItemMeta {
                key: self.key.clone(),
                provider: self.provider.clone(),
                note: self.note.clone(),
                username: self.username.clone(),
                email: self.email.clone(),
                url: self.url.clone(),
                permission: self.permission.clone(),
                expires_at: self.expires_at.clone(),
                owner: self.owner.clone(),
                created_by: self.created_by.clone(),
                modified_by: self.modified_by.clone(),
                editable_by: self.editable_by.clone(),
                inject_approved: self.inject_approved,
                created_at: self.created_at.clone(),
                updated_at: self.updated_at.clone(),
                has_value: !self.value.is_empty(),
                has_password: !self.password.is_empty(),
                extra: self.extra.clone(),
            },
            ItemSecret {
                value: self.value.clone(),
                password: self.password.clone(),
            },
        )
    }

    pub fn join(id: &str, rev: u64, meta: &ItemMeta, secret: &ItemSecret) -> Record {
        Record {
            id: id.to_owned(),
            key: meta.key.clone(),
            value: secret.value.clone(),
            provider: meta.provider.clone(),
            note: meta.note.clone(),
            username: meta.username.clone(),
            email: meta.email.clone(),
            password: secret.password.clone(),
            url: meta.url.clone(),
            permission: meta.permission.clone(),
            expires_at: meta.expires_at.clone(),
            owner: meta.owner.clone(),
            created_by: meta.created_by.clone(),
            modified_by: meta.modified_by.clone(),
            editable_by: meta.editable_by.clone(),
            inject_approved: meta.inject_approved,
            created_at: meta.created_at.clone(),
            updated_at: meta.updated_at.clone(),
            rev,
            extra: meta.extra.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tombstone {
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default)]
    pub deleted_at: String,
    #[serde(default)]
    pub by: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// A v3 history entry: `before` and `after` hold whole records, values included.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntryV3 {
    pub id: String,
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub before: Option<Value>,
    #[serde(default)]
    pub after: Option<Value>,
    #[serde(default, rename = "ref")]
    pub reference: Option<String>,
    #[serde(default)]
    pub reverted: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The current time as the JavaScript app writes it: `2026-11-07T10:13:55.106Z`.
pub fn now_iso() -> String {
    iso(time::OffsetDateTime::now_utc())
}

pub fn iso(t: time::OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

pub fn parse_iso(s: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_match_javascript() {
        let s = now_iso();
        assert_eq!(s.len(), 24, "{s}");
        assert!(s.ends_with('Z'));
        assert!(parse_iso(&s).is_some());
    }

    #[test]
    fn unknown_fields_survive_a_round_trip() {
        let raw = serde_json::json!({
            "id": "a", "key": "K", "value": "synthetic-only", "rev": 2, "futureField": {"x": 1}
        });
        let r: Record = serde_json::from_value(raw).unwrap();
        assert_eq!(r.extra["futureField"]["x"], 1);
        assert_eq!(r.owner, HUMAN);
        assert!(r.inject_approved);
        let (meta, secret) = r.split();
        assert_eq!(Record::join(&r.id, r.rev, &meta, &secret), r);
    }
}
