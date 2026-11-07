//! Reading other password managers' exports into items: 1Password (`.1pux`), Bitwarden's
//! unencrypted JSON, and CSV with a header row (1Password, Bitwarden, Chrome, LastPass and
//! similar column names). Nothing here touches the vault; the store saves what this returns.

use crate::error::{Error, Result};
use crate::secret::SecretString;
use serde_json::Value;
use zeroize::Zeroizing;

/// The largest export read, and the largest `export.data` inflated from a `.1pux`.
pub const MAX_IMPORT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct ImportedField {
    pub section: String,
    pub label: String,
    /// `text`, `concealed`, `url`, `email`, `date` or `otp`.
    pub kind: &'static str,
    pub value: SecretString,
}

#[derive(Debug, Default)]
pub struct Imported {
    pub title: String,
    /// `login`, `api_key`, `note`, `ssh_key`, `database`, `server` or `certificate`.
    pub kind: &'static str,
    pub username: String,
    pub email: String,
    pub url: String,
    pub notes: String,
    pub value: SecretString,
    pub password: SecretString,
    pub fields: Vec<ImportedField>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub archived: bool,
}

#[derive(Debug, Default)]
pub struct Report {
    pub items: Vec<Imported>,
    /// What was left out, for the person importing to read.
    pub skipped: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    OnePux,
    Bitwarden,
    Csv,
}

impl Format {
    /// From the file's name and first bytes.
    pub fn detect(name: &str, bytes: &[u8]) -> Option<Format> {
        let lower = name.to_ascii_lowercase();
        if bytes.starts_with(b"PK\x03\x04") || lower.ends_with(".1pux") {
            return Some(Format::OnePux);
        }
        let start = bytes
            .iter()
            .position(|b| !b" \t\r\n\xef\xbb\xbf".contains(b))
            .map(|i| bytes[i]);
        if start == Some(b'{') || lower.ends_with(".json") {
            return Some(Format::Bitwarden);
        }
        if lower.ends_with(".csv") || lower.ends_with(".txt") {
            return Some(Format::Csv);
        }
        None
    }
}

fn bad(what: &str) -> Error {
    Error::invalid(format!("This file could not be imported: {what}"))
}

pub fn parse(format: Format, bytes: &[u8]) -> Result<Report> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(bad("it is larger than 64 MB"));
    }
    match format {
        Format::OnePux => {
            let data = zip_member(bytes, "export.data", MAX_IMPORT_BYTES)?;
            let json: Value =
                serde_json::from_slice(&data).map_err(|_| bad("export.data is not JSON"))?;
            let mut report = one_pux(&json);
            let files = zip_names(bytes)?
                .iter()
                .filter(|n| n.starts_with("files/") && !n.ends_with('/'))
                .count();
            if files > 0 {
                report.skipped.push(format!(
                    "{files} attached file(s); add them to their items again"
                ));
            }
            Ok(report)
        }
        Format::Bitwarden => {
            let json: Value =
                serde_json::from_slice(strip_bom(bytes)).map_err(|_| bad("it is not JSON"))?;
            bitwarden(&json)
        }
        Format::Csv => {
            let text =
                std::str::from_utf8(strip_bom(bytes)).map_err(|_| bad("it is not UTF-8 text"))?;
            csv_items(&csv(text)?)
        }
    }
}

fn strip_bom(b: &[u8]) -> &[u8] {
    b.strip_prefix(b"\xef\xbb\xbf").unwrap_or(b)
}

// --- ZIP, enough for a 1Password export: stored or deflated members, no ZIP64. ---

struct Zip<'a>(&'a [u8]);

impl Zip<'_> {
    fn u16(&self, at: usize) -> Result<usize> {
        let b = self
            .0
            .get(at..at + 2)
            .ok_or_else(|| bad("the archive is damaged"))?;
        Ok(usize::from(u16::from_le_bytes([b[0], b[1]])))
    }

    fn u32(&self, at: usize) -> Result<usize> {
        let b = self
            .0
            .get(at..at + 4)
            .ok_or_else(|| bad("the archive is damaged"))?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }

    /// Each central directory entry's offset.
    fn entries(&self) -> Result<Vec<usize>> {
        let z = self.0;
        let low = z.len().saturating_sub(22 + 65535);
        let eocd = (low..=z.len().saturating_sub(22))
            .rev()
            .find(|&i| z[i..].starts_with(b"PK\x05\x06"))
            .ok_or_else(|| bad("it is not a ZIP archive"))?;
        let (count, mut at) = (self.u16(eocd + 10)?, self.u32(eocd + 16)?);
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if self.u32(at)? != 0x0201_4b50 {
                return Err(bad("the archive is damaged"));
            }
            out.push(at);
            at += 46 + self.u16(at + 28)? + self.u16(at + 30)? + self.u16(at + 32)?;
        }
        Ok(out)
    }

    fn name(&self, entry: usize) -> Result<&[u8]> {
        let n = self.u16(entry + 28)?;
        self.0
            .get(entry + 46..entry + 46 + n)
            .ok_or_else(|| bad("the archive is damaged"))
    }
}

fn zip_names(zip: &[u8]) -> Result<Vec<String>> {
    let z = Zip(zip);
    z.entries()?
        .into_iter()
        .map(|e| Ok(String::from_utf8_lossy(z.name(e)?).into_owned()))
        .collect()
}

fn zip_member(zip: &[u8], name: &str, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let z = Zip(zip);
    for e in z.entries()? {
        if z.name(e)? != name.as_bytes() {
            continue;
        }
        if z.u16(e + 8)? & 1 != 0 {
            return Err(bad("the archive is encrypted"));
        }
        let (method, size, unpacked) = (z.u16(e + 10)?, z.u32(e + 20)?, z.u32(e + 24)?);
        if unpacked > max {
            return Err(bad("it is too large"));
        }
        let local = z.u32(e + 42)?;
        if z.u32(local)? != 0x0403_4b50 {
            return Err(bad("the archive is damaged"));
        }
        let start = local + 30 + z.u16(local + 26)? + z.u16(local + 28)?;
        let data = zip
            .get(start..start + size)
            .ok_or_else(|| bad("the archive is damaged"))?;
        return match method {
            0 => Ok(Zeroizing::new(data.to_vec())),
            8 => miniz_oxide::inflate::decompress_to_vec_with_limit(data, max)
                .map(Zeroizing::new)
                .map_err(|_| bad("the archive is damaged")),
            _ => Err(bad("the archive uses an unsupported compression")),
        };
    }
    Err(bad(&format!(
        "the archive has no {name}; is it a 1Password export?"
    )))
}

// --- 1Password ---

fn s(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn date(secs: &Value) -> String {
    secs.as_i64()
        .and_then(|t| time::OffsetDateTime::from_unix_timestamp(t).ok())
        .map(|t| format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day()))
        .unwrap_or_default()
}

/// A 1Password field value: `{"concealed": "..."}`, `{"totp": "otpauth://..."}` and so on.
fn op_value(v: &Value) -> Option<(&'static str, String)> {
    let (k, inner) = v.as_object()?.iter().next()?;
    let text = match inner {
        Value::Object(o) => o
            .get("email_address")
            .or_else(|| o.get("privateKey"))
            .map(s)
            .unwrap_or_default(),
        other => s(other),
    };
    let kind = match k.as_str() {
        "concealed" | "creditCardNumber" => "concealed",
        "totp" => "otp",
        "url" => "url",
        "email" => "email",
        "date" | "monthYear" => {
            return Some(("date", if k == "date" { date(inner) } else { text }))
        }
        "sshKey" => "concealed",
        _ => "text",
    };
    Some((kind, text))
}

fn one_pux(json: &Value) -> Report {
    let mut report = Report::default();
    let empty = Vec::new();
    let arr = |v: &Value, k: &str| {
        v.get(k)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    for account in arr(json, "accounts") {
        for vault in arr(&account, "vaults") {
            let vault_name = vault["attrs"]["name"].as_str().unwrap_or("").to_owned();
            for item in arr(&vault, "items") {
                if item["state"].as_str() == Some("trashed") {
                    continue;
                }
                let ov = &item["overview"];
                let d = &item["details"];
                let kind = match item["categoryUuid"].as_str().unwrap_or("") {
                    "001" | "005" | "111" | "109" => "login",
                    "102" => "database",
                    "110" => "server",
                    "112" => "api_key",
                    "114" => "ssh_key",
                    _ => "note",
                };
                let mut it = Imported {
                    title: s(&ov["title"]),
                    kind,
                    url: s(&ov["url"]),
                    notes: s(&d["notesPlain"]),
                    favorite: item["favIndex"].as_i64().unwrap_or(0) > 0,
                    archived: item["state"].as_str() == Some("archived"),
                    tags: ov["tags"]
                        .as_array()
                        .unwrap_or(&empty)
                        .iter()
                        .map(s)
                        .filter(|t| !t.is_empty())
                        .collect(),
                    ..Default::default()
                };
                if !vault_name.is_empty() {
                    it.tags.push(vault_name.clone());
                }
                if it.url.is_empty() {
                    it.url = s(&ov["urls"][0]["url"]);
                }
                for extra in ov["urls"].as_array().unwrap_or(&empty).iter().skip(1) {
                    it.fields
                        .push(field("", &s(&extra["label"]), "url", s(&extra["url"])));
                }
                let pw = s(&d["password"]);
                if !pw.is_empty() {
                    it.password = SecretString::new(pw);
                }
                for f in d["loginFields"].as_array().unwrap_or(&empty) {
                    let value = s(&f["value"]);
                    match f["designation"].as_str() {
                        Some("username") if it.username.is_empty() => it.username = value,
                        Some("password") if it.password.expose().is_empty() => {
                            it.password = SecretString::new(value)
                        }
                        _ if !value.is_empty() => {
                            let concealed = f["fieldType"].as_str() == Some("P");
                            let label = s(&f["name"]);
                            it.fields.push(field(
                                "",
                                &label,
                                if concealed { "concealed" } else { "text" },
                                value,
                            ));
                        }
                        _ => {}
                    }
                }
                for section in d["sections"].as_array().unwrap_or(&empty) {
                    let title = s(&section["title"]);
                    for f in section["fields"].as_array().unwrap_or(&empty) {
                        let Some((fkind, value)) = op_value(&f["value"]) else {
                            continue;
                        };
                        if value.is_empty() {
                            continue;
                        }
                        let id = f["id"].as_str().unwrap_or("");
                        let label = s(&f["title"]);
                        match (kind, id) {
                            ("api_key", "credential") | ("ssh_key", "private_key")
                                if it.value.expose().is_empty() =>
                            {
                                it.value = SecretString::new(value)
                            }
                            ("database" | "server", "username") if it.username.is_empty() => {
                                it.username = value
                            }
                            ("database" | "server" | "api_key", "password")
                                if it.password.expose().is_empty() =>
                            {
                                it.password = SecretString::new(value)
                            }
                            ("server", "url") | ("database" | "api_key", "hostname")
                                if it.url.is_empty() =>
                            {
                                it.url = value
                            }
                            _ => it.fields.push(field(&title, &label, fkind, value)),
                        }
                    }
                }
                report.items.push(it);
            }
        }
    }
    report
}

fn field(section: &str, label: &str, kind: &'static str, value: String) -> ImportedField {
    ImportedField {
        section: section.to_owned(),
        label: if label.is_empty() {
            kind.to_owned()
        } else {
            label.to_owned()
        },
        kind,
        value: SecretString::new(value),
    }
}

// --- Bitwarden ---

fn bitwarden(json: &Value) -> Result<Report> {
    if json["encrypted"].as_bool() == Some(true) {
        return Err(bad(
            "it is an encrypted Bitwarden export; export again as .json (not encrypted)",
        ));
    }
    let items = json["items"]
        .as_array()
        .ok_or_else(|| bad("it has no items; is it a Bitwarden export?"))?;
    let empty = Vec::new();
    let folders: std::collections::HashMap<String, String> = json["folders"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .map(|f| (s(&f["id"]), s(&f["name"])))
        .collect();
    let mut report = Report::default();
    for item in items {
        if !item["deletedDate"].is_null() {
            continue;
        }
        let mut it = Imported {
            title: s(&item["name"]),
            notes: s(&item["notes"]),
            favorite: item["favorite"].as_bool() == Some(true),
            ..Default::default()
        };
        if let Some(folder) = folders.get(&s(&item["folderId"])).filter(|f| !f.is_empty()) {
            it.tags.push(folder.clone());
        }
        match item["type"].as_i64() {
            Some(1) => {
                let l = &item["login"];
                it.kind = "login";
                it.username = s(&l["username"]);
                it.password = SecretString::new(s(&l["password"]));
                let uris = l["uris"].as_array().unwrap_or(&empty);
                it.url = uris.first().map(|u| s(&u["uri"])).unwrap_or_default();
                for u in uris.iter().skip(1) {
                    it.fields.push(field("", "website", "url", s(&u["uri"])));
                }
                let totp = s(&l["totp"]);
                if !totp.is_empty() {
                    it.fields.push(field("", "one-time code", "otp", totp));
                }
            }
            Some(5) => {
                let k = &item["sshKey"];
                it.kind = "ssh_key";
                it.value = SecretString::new(s(&k["privateKey"]));
                for (label, key) in [
                    ("public key", "publicKey"),
                    ("fingerprint", "keyFingerprint"),
                ] {
                    let v = s(&k[key]);
                    if !v.is_empty() {
                        it.fields.push(field("", label, "text", v));
                    }
                }
            }
            Some(t @ (3 | 4)) => {
                it.kind = "note";
                let (section, obj) = if t == 3 {
                    ("Card", &item["card"])
                } else {
                    ("Identity", &item["identity"])
                };
                for (k, v) in obj.as_object().into_iter().flatten() {
                    let v = s(v);
                    if !v.is_empty() {
                        let kind = if matches!(
                            k.as_str(),
                            "number" | "code" | "ssn" | "passportNumber" | "licenseNumber"
                        ) {
                            "concealed"
                        } else {
                            "text"
                        };
                        it.fields.push(field(section, k, kind, v));
                    }
                }
            }
            _ => it.kind = "note",
        }
        for f in item["fields"].as_array().unwrap_or(&empty) {
            let kind = match f["type"].as_i64() {
                Some(1) => "concealed",
                Some(3) => continue,
                _ => "text",
            };
            let v = s(&f["value"]);
            if !v.is_empty() {
                it.fields.push(field("", &s(&f["name"]), kind, v));
            }
        }
        report.items.push(it);
    }
    let attachments = items
        .iter()
        .filter(|i| i["attachments"].as_array().is_some_and(|a| !a.is_empty()))
        .count();
    if attachments > 0 {
        report.skipped.push(format!(
            "attachments on {attachments} item(s); Bitwarden exports do not include them"
        ));
    }
    Ok(report)
}

// --- CSV ---

/// RFC 4180: quoted fields may hold commas, quotes ("") and line breaks.
fn csv(text: &str) -> Result<Vec<Vec<String>>> {
    let (mut rows, mut row, mut cell) = (Vec::new(), Vec::new(), String::new());
    let (mut quoted, mut chars) = (false, text.chars().peekable());
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    cell.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            } else {
                cell.push(c);
            }
            continue;
        }
        match c {
            '"' if cell.is_empty() => quoted = true,
            ',' => row.push(std::mem::take(&mut cell)),
            '\r' => {}
            '\n' => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            c => cell.push(c),
        }
    }
    if quoted {
        return Err(bad("a quoted CSV field is not closed"));
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows.retain(|r: &Vec<String>| r.iter().any(|c| !c.trim().is_empty()));
    Ok(rows)
}

fn csv_items(rows: &[Vec<String>]) -> Result<Report> {
    let (header, body) = rows
        .split_first()
        .ok_or_else(|| bad("the CSV file is empty"))?;
    let names: Vec<String> = header
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let col = |options: &[&str]| {
        options
            .iter()
            .find_map(|o| names.iter().position(|n| n == o))
    };
    let title = col(&["title", "name"]);
    let user = col(&["username", "login_username", "login", "user", "user name"]);
    let pass = col(&["password", "login_password", "pass"]);
    let url = col(&["url", "website", "login_uri", "uri", "web site"]);
    let notes = col(&["notes", "note", "extra", "comments"]);
    let otp = col(&["otpauth", "totp", "login_totp", "otp", "one-time password"]);
    let tags = col(&["tags", "grouping", "folder"]);
    let fav = col(&["favorite", "fav"]);
    let archived = col(&["archived"]);
    if title.is_none() && user.is_none() && pass.is_none() {
        return Err(bad(
            "its first row needs column names such as title, username, password and url",
        ));
    }
    let used: Vec<usize> = [title, user, pass, url, notes, otp, tags, fav, archived]
        .into_iter()
        .flatten()
        .chain(col(&["type", "reprompt", "fields"]))
        .collect();
    let get = |row: &[String], c: Option<usize>| {
        c.and_then(|i| row.get(i))
            .map(|v| v.trim().to_owned())
            .unwrap_or_default()
    };
    let yes = |v: String| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes");
    let mut report = Report::default();
    for row in body {
        let password = get(row, pass);
        let username = get(row, user);
        let mut it = Imported {
            title: get(row, title),
            kind: if password.is_empty() && username.is_empty() {
                "note"
            } else {
                "login"
            },
            username,
            password: SecretString::new(password),
            url: get(row, url),
            notes: get(row, notes),
            favorite: yes(get(row, fav)),
            archived: yes(get(row, archived)),
            tags: get(row, tags)
                .split([',', ';', '/'])
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
                .collect(),
            ..Default::default()
        };
        let code = get(row, otp);
        if !code.is_empty() {
            it.fields.push(field("", "one-time code", "otp", code));
        }
        for (i, v) in row.iter().enumerate() {
            if !used.contains(&i) && !v.trim().is_empty() {
                let label = header.get(i).map_or("field", |h| h.trim());
                it.fields
                    .push(field("", label, "text", v.trim().to_owned()));
            }
        }
        if it.title.is_empty() {
            it.title = if it.url.is_empty() {
                it.username.clone()
            } else {
                it.url.clone()
            };
        }
        report.items.push(it);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn csv_handles_quotes_and_known_columns() {
        let rows = csv("a,\"b,\"\"c\"\"\nd\",e\r\n\r\nf,,\n").unwrap();
        assert_eq!(rows, vec![vec!["a", "b,\"c\"\nd", "e"], vec!["f", "", ""]]);
        assert!(csv("\"open").is_err());
        let r = parse(
            Format::Csv,
            "\u{feff}Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes,Extra\n\
             Example,https://example.com,alice,synthetic-pw,otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ,true,false,\"work,dev\",hi,more\n\
             Note only,,,,,,,,body,\n"
                .as_bytes(),
        )
        .unwrap();
        let a = &r.items[0];
        assert_eq!(
            (
                a.title.as_str(),
                a.kind,
                a.username.as_str(),
                a.password.expose()
            ),
            ("Example", "login", "alice", "synthetic-pw")
        );
        assert!(a.favorite && !a.archived);
        assert_eq!(a.tags, ["work", "dev"]);
        assert_eq!(
            (
                a.fields[0].kind,
                a.fields[1].label.as_str(),
                a.fields[1].value.expose()
            ),
            ("otp", "Extra", "more")
        );
        assert_eq!(
            (r.items[1].kind, r.items[1].notes.as_str()),
            ("note", "body")
        );
        assert!(parse(Format::Csv, b"just,some,columns\n1,2,3\n").is_err());
    }

    #[test]
    fn bitwarden_items_and_refusals() {
        let doc = json!({
            "encrypted": false,
            "folders": [{ "id": "f1", "name": "Work" }],
            "items": [
                { "type": 1, "name": "Example", "folderId": "f1", "favorite": true, "notes": "n",
                  "login": { "username": "alice", "password": "synthetic-pw", "totp": "GEZDGNBVGY3TQOJQ",
                             "uris": [{ "uri": "https://example.com" }, { "uri": "https://example.org" }] },
                  "fields": [{ "name": "PIN", "value": "1234", "type": 1 }, { "name": "linked", "value": null, "type": 3 }],
                  "attachments": [{ "fileName": "a.txt" }] },
                { "type": 5, "name": "Deploy key", "sshKey": { "privateKey": "synthetic-private", "publicKey": "ssh-ed25519 AAAA", "keyFingerprint": "SHA256:x" } },
                { "type": 2, "name": "Gone", "deletedDate": "2026-01-01T00:00:00Z" }
            ]
        });
        let r = parse(Format::Bitwarden, doc.to_string().as_bytes()).unwrap();
        assert_eq!(r.items.len(), 2);
        let a = &r.items[0];
        assert_eq!(
            (a.kind, a.url.as_str(), a.tags[0].as_str()),
            ("login", "https://example.com", "Work")
        );
        let kinds: Vec<_> = a
            .fields
            .iter()
            .map(|f| (f.kind, f.label.as_str()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("url", "website"),
                ("otp", "one-time code"),
                ("concealed", "PIN")
            ]
        );
        assert_eq!(
            (r.items[1].kind, r.items[1].value.expose()),
            ("ssh_key", "synthetic-private")
        );
        assert_eq!(r.skipped.len(), 1);
        assert!(parse(Format::Bitwarden, br#"{"encrypted":true,"items":[]}"#).is_err());
    }

    /// A stored (uncompressed) ZIP with the given members.
    fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
        let (mut out, mut central) = (Vec::new(), Vec::new());
        for (name, data) in members {
            let offset = out.len() as u32;
            let n = name.len() as u16;
            let size = data.len() as u32;
            out.extend_from_slice(b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0\0\0\0\0");
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
            central.extend_from_slice(b"PK\x01\x02\x14\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0");
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&n.to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let (cd_offset, cd_size) = (out.len() as u32, central.len() as u32);
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn one_password_export() {
        let data = json!({ "accounts": [{ "vaults": [{ "attrs": { "name": "Private" }, "items": [
            { "categoryUuid": "001", "favIndex": 1, "state": "active",
              "overview": { "title": "Example", "url": "https://example.com", "tags": ["dev"] },
              "details": { "notesPlain": "n",
                "loginFields": [
                    { "designation": "username", "value": "alice", "fieldType": "T" },
                    { "designation": "password", "value": "synthetic-pw", "fieldType": "P" }],
                "sections": [{ "title": "Security", "fields": [
                    { "title": "one-time password", "id": "TOTP_1", "value": { "totp": "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&issuer=Example" } },
                    { "title": "recovery", "id": "r", "value": { "concealed": "synthetic-recovery" } },
                    { "title": "born", "id": "b", "value": { "date": 0 } }] }] } },
            { "categoryUuid": "112", "state": "archived", "overview": { "title": "Stripe" },
              "details": { "sections": [{ "fields": [
                    { "id": "credential", "title": "credential", "value": { "concealed": "synthetic-api-key" } },
                    { "id": "hostname", "title": "host", "value": { "string": "api.example.com" } }] }] } },
            { "categoryUuid": "003", "state": "trashed", "overview": { "title": "Gone" }, "details": {} }
        ] }] }] });
        let file = zip(&[
            ("export.attributes", b"{}"),
            ("export.data", data.to_string().as_bytes()),
            ("files/abc", b"x"),
        ]);
        assert_eq!(Format::detect("x.1pux", &file), Some(Format::OnePux));
        let r = parse(Format::OnePux, &file).unwrap();
        assert_eq!(r.items.len(), 2);
        let a = &r.items[0];
        assert_eq!(
            (a.kind, a.username.as_str(), a.password.expose()),
            ("login", "alice", "synthetic-pw")
        );
        assert!(a.favorite);
        assert_eq!(a.tags, ["dev", "Private"]);
        let f: Vec<_> = a
            .fields
            .iter()
            .map(|f| (f.section.as_str(), f.kind, f.value.expose()))
            .collect();
        assert_eq!(f[0].1, "otp");
        assert_eq!(f[1], ("Security", "concealed", "synthetic-recovery"));
        assert_eq!(f[2], ("Security", "date", "1970-01-01"));
        let b = &r.items[1];
        assert_eq!(
            (b.kind, b.value.expose(), b.url.as_str()),
            ("api_key", "synthetic-api-key", "api.example.com")
        );
        assert!(b.archived);
        assert_eq!(r.skipped.len(), 1);
        assert!(parse(Format::OnePux, &zip(&[("other", b"{}")])).is_err());
        assert!(parse(Format::OnePux, b"PK\x03\x04 truncated").is_err());
    }
}
