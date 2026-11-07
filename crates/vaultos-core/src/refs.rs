//! Secret references: `vault://PROJECT/ITEM[/FIELD]`, with each part percent-encoded where
//! it holds `/`, `%` or spaces. They stand in for values in environment variables (`vaultos
//! run`) and in templates as `{{ vault://… }}` (`vaultos render`).

use crate::error::{Error, Result};

pub const SCHEME: &str = "vault://";

/// Most references one call resolves.
pub const MAX_REFS: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRef {
    pub project: String,
    pub item: String,
    /// `value` (the default), `password`, `username`, `email`, `url`, `note`, `otp`, or a
    /// custom field's label or id.
    pub field: String,
}

impl SecretRef {
    pub fn parse(text: &str) -> Result<SecretRef> {
        let bad = || {
            Error::invalid(
                "A reference looks like vault://Project/Item or vault://Project/Item/field",
            )
        };
        let rest = text.trim().strip_prefix(SCHEME).ok_or_else(bad)?;
        if rest.len() > 1024 {
            return Err(bad());
        }
        let parts: Vec<&str> = rest.split('/').collect();
        let decode = |s: &str| -> Result<String> {
            let d = percent_encoding::percent_decode_str(s)
                .decode_utf8()
                .map_err(|_| bad())?
                .into_owned();
            if d.trim().is_empty() || d.chars().any(char::is_control) {
                return Err(bad());
            }
            Ok(d)
        };
        match parts.as_slice() {
            [p, i] => Ok(SecretRef {
                project: decode(p)?,
                item: decode(i)?,
                field: "value".into(),
            }),
            [p, i, f] => Ok(SecretRef {
                project: decode(p)?,
                item: decode(i)?,
                field: decode(f)?,
            }),
            _ => Err(bad()),
        }
    }

    /// The reference as text, encoding what would not survive parsing.
    pub fn to_uri(&self) -> String {
        const PART: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
            .add(b' ')
            .add(b'/')
            .add(b'%')
            .add(b'{')
            .add(b'}');
        let enc = |s: &str| percent_encoding::utf8_percent_encode(s, PART).to_string();
        format!(
            "{SCHEME}{}/{}/{}",
            enc(&self.project),
            enc(&self.item),
            enc(&self.field)
        )
    }
}

/// True when the whole of `value` is a reference.
pub fn is_ref(value: &str) -> bool {
    value.starts_with(SCHEME)
}

/// One `{{ vault://… }}` placeholder in a template: its byte range and reference.
#[derive(Debug, PartialEq, Eq)]
pub struct Placeholder {
    pub start: usize,
    pub end: usize,
    pub reference: SecretRef,
}

/// Finds the placeholders in a template. Braces that do not hold a reference are text.
pub fn placeholders(template: &str) -> Result<Vec<Placeholder>> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(open) = template[from..].find("{{").map(|i| i + from) {
        let Some(close) = template[open + 2..].find("}}").map(|i| i + open + 2) else {
            break;
        };
        let inner = template[open + 2..close].trim();
        if is_ref(inner) {
            out.push(Placeholder {
                start: open,
                end: close + 2,
                reference: SecretRef::parse(inner)?,
            });
            if out.len() > MAX_REFS {
                return Err(Error::invalid(format!(
                    "A template may hold at most {MAX_REFS} references"
                )));
            }
            from = close + 2;
        } else {
            from = open + 2;
        }
    }
    Ok(out)
}

/// The template with each placeholder replaced by its value, in order.
pub fn render(template: &str, found: &[Placeholder], values: &[impl AsRef<str>]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut at = 0;
    for (p, v) in found.iter().zip(values) {
        out.push_str(&template[at..p.start]);
        out.push_str(v.as_ref());
        at = p.end;
    }
    out.push_str(&template[at..]);
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]
    use super::*;

    #[test]
    fn parses_and_prints_references() {
        let r = SecretRef::parse("vault://Example%20App/DB_URL").unwrap();
        assert_eq!(
            (r.project.as_str(), r.item.as_str(), r.field.as_str()),
            ("Example App", "DB_URL", "value")
        );
        let r = SecretRef::parse("vault://P/Client%2FSite/One-time%20code").unwrap();
        assert_eq!(
            (r.item.as_str(), r.field.as_str()),
            ("Client/Site", "One-time code")
        );
        assert_eq!(SecretRef::parse(&r.to_uri()).unwrap(), r);
        for bad in [
            "vault://P",
            "vault://P/I/F/G",
            "vault:///I",
            "vault://P/%0A",
            "op://P/I",
            "vault://P/%FF",
        ] {
            assert!(SecretRef::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn renders_templates() {
        let t = "url={{ vault://P/DB }} user={{vault://P/DB/username}} keep {{ name }} and {{";
        let found = placeholders(t).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[1].reference.field, "username");
        assert_eq!(
            render(t, &found, &["v1", "v2"]),
            "url=v1 user=v2 keep {{ name }} and {{"
        );
        assert!(placeholders("{{ vault://broken }}").is_err());
    }
}
