//! Input rules, ported from `validation.js`.

use crate::error::{Error, Result};
use crate::model::{parse_iso, FIELD_KINDS, ITEM_KINDS};
use crate::secret::SecretString;

fn has_control(s: &str) -> bool {
    s.chars()
        .any(|c| matches!(c, '\u{0}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' | '\u{7f}'))
}

/// Lengths are counted in UTF-16 code units, as JavaScript's `length` does.
fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

pub fn text(value: &str, name: &str, max: usize, allow_empty: bool) -> Result<()> {
    if js_len(value) > max || (!allow_empty && value.trim().is_empty()) || has_control(value) {
        return Err(Error::invalid(format!("Invalid {name}")));
    }
    Ok(())
}

pub fn password(value: &str) -> Result<()> {
    text(value, "master password", 1024, false)?;
    if js_len(value) < 12 {
        return Err(Error::invalid(
            "Use at least 12 characters for the master password",
        ));
    }
    Ok(())
}

pub fn key_name(key: &str) -> Result<()> {
    text(key, "key name", 256, false)?;
    if ["__proto__", "constructor", "prototype"].contains(&key) || key.contains(['\r', '\n', '\t'])
    {
        return Err(Error::invalid("Invalid key name"));
    }
    Ok(())
}

/// Fields of a record a caller may set. `None` leaves a field unchanged on update.
#[derive(Clone, Default)]
pub struct Fields {
    pub key: String,
    pub value: Option<SecretString>,
    pub password: Option<SecretString>,
    pub note: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub url: Option<String>,
    pub provider: Option<String>,
    pub permission: Option<String>,
    pub expires_at: Option<String>,
    /// One of [`ITEM_KINDS`].
    pub kind: Option<String>,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
    pub archived: Option<bool>,
    /// The item's custom fields, replacing the ones it has.
    pub fields: Option<Vec<FieldInput>>,
}

/// One custom field to save. An empty `id` is a new field. A secret field given without a
/// value keeps the value stored under its id, so a form need not reveal it to save it.
#[derive(Clone, Default)]
pub struct FieldInput {
    pub id: String,
    pub section: String,
    pub label: String,
    pub kind: String,
    pub value: Option<SecretString>,
}

impl std::fmt::Debug for FieldInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldInput")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

pub const MAX_TAGS: usize = 32;
pub const MAX_FIELDS: usize = 64;

/// Trimmed, without empty or repeated (case-insensitively) tags.
pub fn normalize_tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        let t = t.trim();
        if !t.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(t)) {
            out.push(t.to_owned());
        }
    }
    out
}

fn field_input(f: &FieldInput) -> Result<()> {
    if !FIELD_KINDS.contains(&f.kind.as_str()) {
        return Err(Error::invalid("Invalid field type"));
    }
    if !f.id.is_empty()
        && (f.id.len() > 64
            || !f
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    {
        return Err(Error::invalid("Invalid field id"));
    }
    text(&f.label, "field name", 256, true)?;
    text(&f.section, "section name", 256, true)?;
    if let Some(v) = &f.value {
        text(v.expose(), "field value", 65536, true)?;
        let v = v.expose();
        if f.kind == "otp" && !v.is_empty() {
            crate::totp::Totp::parse(v)?;
        }
        if f.kind == "date" && !v.is_empty() && parse_iso(&format!("{v}T00:00:00Z")).is_none() {
            return Err(Error::invalid("Invalid date; use YYYY-MM-DD"));
        }
    }
    Ok(())
}

impl std::fmt::Debug for Fields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fields")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

pub fn fields(f: &Fields) -> Result<()> {
    key_name(&f.key)?;
    for (name, v) in [("value", &f.value), ("password", &f.password)] {
        if let Some(v) = v {
            text(v.expose(), name, 65536, true)?;
        }
    }
    if let Some(v) = &f.note {
        text(v, "note", 65536, true)?;
    }
    let short = [
        ("username", &f.username),
        ("email", &f.email),
        ("url", &f.url),
        ("provider", &f.provider),
        ("permission", &f.permission),
        ("expiresAt", &f.expires_at),
    ];
    for (name, v) in short {
        if let Some(v) = v {
            text(v, name, 2048, true)?;
        }
    }
    if let Some(e) = f.expires_at.as_deref().filter(|e| !e.is_empty()) {
        let date_only = e.len() == 10 && parse_iso(&format!("{e}T00:00:00Z")).is_some();
        if !date_only && parse_iso(e).is_none() {
            return Err(Error::invalid("Invalid expiry date"));
        }
    }
    if let Some(k) = &f.kind {
        if !ITEM_KINDS.contains(&k.as_str()) {
            return Err(Error::invalid("Invalid item type"));
        }
    }
    if let Some(tags) = &f.tags {
        if tags.len() > MAX_TAGS {
            return Err(Error::invalid(format!("Use at most {MAX_TAGS} tags")));
        }
        for t in tags {
            text(t, "tag", 64, true)?;
        }
    }
    if let Some(fields) = &f.fields {
        if fields.len() > MAX_FIELDS {
            return Err(Error::invalid(format!("Use at most {MAX_FIELDS} fields")));
        }
        for x in fields {
            field_input(x)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_match_the_javascript_app() {
        assert!(password("short").is_err());
        assert!(password("long-enough-synthetic").is_ok());
        assert!(key_name("__proto__").is_err());
        assert!(key_name("A\tB").is_err());
        assert!(key_name("  ").is_err());
        assert!(text("ok\u{7}", "x", 10, true).is_err());
        let mut f = Fields {
            key: "K".into(),
            expires_at: Some("2026-12-31".into()),
            ..Default::default()
        };
        assert!(fields(&f).is_ok());
        f.expires_at = Some("not a date".into());
        assert!(fields(&f).is_err());
    }
}
