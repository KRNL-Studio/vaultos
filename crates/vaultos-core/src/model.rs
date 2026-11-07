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

fn is_false(b: &bool) -> bool {
    !*b
}

/// Item types. Records saved before types existed have none; [`ItemMeta::kind`] infers one.
pub const ITEM_KINDS: [&str; 7] = [
    "login",
    "api_key",
    "note",
    "ssh_key",
    "database",
    "server",
    "certificate",
];

/// Custom field types. `concealed` and `otp` values are secret.
pub const FIELD_KINDS: [&str; 6] = ["text", "concealed", "url", "email", "date", "otp"];

/// A custom field. In a [`Record`] it carries its value; in [`ItemMeta`] a secret field's
/// value is empty (it lives in the sealed [`ItemSecret`]) and `has_value` says whether it is set.
#[derive(
    Clone, Default, PartialEq, Eq, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop,
)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub section: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_value: bool,
}

impl Field {
    pub fn is_secret(&self) -> bool {
        matches!(self.kind.as_str(), "concealed" | "otp")
    }
}

impl std::fmt::Debug for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Field")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// A secret custom field's value, sealed with the item's value and password.
#[derive(
    Clone, Default, PartialEq, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop,
)]
pub struct SecretValue {
    pub id: String,
    pub value: String,
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretValue")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// A file attached to an item. Its contents are sealed in a file of their own under the
/// project key; `sha256` is of that sealed file, so the signed vault vouches for it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub added_at: String,
}

/// One credential, with its value. In memory the v4 store keeps `value` and `password`
/// sealed and decrypts them only to reveal, copy or inject.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub favorite: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub archived: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub trashed_at: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    /// When the value, password or a secret field last changed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_changed_at: String,
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub favorite: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub archived: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub trashed_at: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    /// When the value, password or a secret field last changed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_changed_at: String,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<SecretValue>,
}

impl std::fmt::Debug for ItemSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemSecret(<redacted>)")
    }
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("id", &self.id)
            .field("key", &self.key)
            .field("rev", &self.rev)
            .finish_non_exhaustive()
    }
}

/// Decrypted records pass through upgrade, Undo and sync; wipe their secrets when dropped.
impl Drop for Record {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.value.zeroize();
        self.password.zeroize();
    }
}

impl ItemMeta {
    /// Whether `actor` sees this item: nobody sees one in the Trash outside the Trash, and
    /// agents never see archived ones.
    pub fn shown_to(&self, actor: &str) -> bool {
        self.trashed_at.is_empty() && !(self.archived && is_agent(actor))
    }

    /// The item's type; a record saved before types existed is a login if it has a username
    /// or password, otherwise an API key.
    pub fn kind(&self) -> &str {
        if !self.kind.is_empty() {
            &self.kind
        } else if self.has_password || !self.username.is_empty() {
            "login"
        } else {
            "api_key"
        }
    }

    pub fn has_otp(&self) -> bool {
        self.fields.iter().any(|f| f.kind == "otp" && f.has_value)
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
                kind: self.kind.clone(),
                tags: self.tags.clone(),
                favorite: self.favorite,
                archived: self.archived,
                trashed_at: self.trashed_at.clone(),
                fields: self
                    .fields
                    .iter()
                    .map(|f| {
                        let mut m = f.clone();
                        m.has_value = !f.value.is_empty();
                        if f.is_secret() {
                            m.value.clear();
                        }
                        m
                    })
                    .collect(),
                attachments: self.attachments.clone(),
                secret_changed_at: self.secret_changed_at.clone(),
                extra: self.extra.clone(),
            },
            ItemSecret {
                value: self.value.clone(),
                password: self.password.clone(),
                fields: self
                    .fields
                    .iter()
                    .filter(|f| f.is_secret() && !f.value.is_empty())
                    .map(|f| SecretValue {
                        id: f.id.clone(),
                        value: f.value.clone(),
                    })
                    .collect(),
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
            kind: meta.kind.clone(),
            tags: meta.tags.clone(),
            favorite: meta.favorite,
            archived: meta.archived,
            trashed_at: meta.trashed_at.clone(),
            fields: meta
                .fields
                .iter()
                .map(|f| {
                    let mut r = f.clone();
                    r.has_value = false;
                    if f.is_secret() {
                        r.value = secret
                            .fields
                            .iter()
                            .find(|s| s.id == f.id)
                            .map(|s| s.value.clone())
                            .unwrap_or_default();
                    }
                    r
                })
                .collect(),
            attachments: meta.attachments.clone(),
            secret_changed_at: meta.secret_changed_at.clone(),
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
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
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

impl std::fmt::Debug for HistoryEntryV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryEntryV3")
            .field("id", &self.id)
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}

/// The current time as the JavaScript app writes it: `2026-11-07T10:13:55.106Z`.
pub fn now_iso() -> String {
    iso(time::OffsetDateTime::now_utc())
}

/// The time `d` from now, as [`now_iso`] writes it.
pub fn iso_after(d: std::time::Duration) -> String {
    iso(time::OffsetDateTime::now_utc() + d)
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
