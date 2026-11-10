//! `.env` files. `parse` matches the `dotenv` package's parser, which the JavaScript app uses
//! to import; `write_env` is `env-file.js` `writeEnv`: dotenv, shell or JSON output, merged
//! into an existing file by default and written atomically.

use crate::error::{Error, Result};
use crate::fs_safe::{atomic_write, read_regular, regular_file};
use regex::Regex;
use serde_json::{Map, Value};
use std::path::Path;
use std::sync::OnceLock;
use zeroize::Zeroizing;

pub const MAX_ENV_BYTES: u64 = 1024 * 1024;

/// JavaScript's `\s`, minus the line separators U+2028 and U+2029, which `parse` refuses
/// (JavaScript treats them as line ends; this regex engine does not).
const WS: &str =
    r"[\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{202F}\x{205F}\x{3000}\x{FEFF}]";

fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// `dotenv`'s line pattern, translated: `\w` is ASCII and `.` stops at line ends, as in
/// JavaScript.
fn line_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let src = format!(
            r#"(?m)^{ws}*(?:export{ws}+)?([A-Za-z0-9_.\-]+)(?:{ws}*={ws}*?|:{ws}+?)({ws}*'(?:\\'|[^'])*'|{ws}*"(?:\\"|[^"])*"|{ws}*`(?:\\`|[^`])*`|[^#\r\n]+)?{ws}*(?:#[^\r\n]*)?$"#,
            ws = WS
        );
        Regex::new(&src).unwrap_or_else(|e| unreachable!("the env pattern compiles: {e}"))
    })
}

/// Whether `k` is an array index, which JavaScript objects list first, in numeric order.
fn is_index(k: &str) -> bool {
    !k.is_empty()
        && k.bytes().all(|b| b.is_ascii_digit())
        && (k == "0" || !k.starts_with('0'))
        && k.parse::<u64>().is_ok_and(|n| n < u64::from(u32::MAX))
}

/// Orders keys as a JavaScript object would: array indexes first, ascending, then the rest in
/// insertion order.
fn js_order<T>(entries: Vec<(String, T)>) -> Vec<(String, T)> {
    let (mut idx, rest): (Vec<_>, Vec<_>) = entries.into_iter().partition(|(k, _)| is_index(k));
    idx.sort_by_key(|(k, _)| k.parse::<u64>().unwrap_or(0));
    idx.extend(rest);
    idx
}

fn js_order_value(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let ordered = js_order(m.into_iter().map(|(k, v)| (k, js_order_value(v))).collect());
            Value::Object(ordered.into_iter().collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(js_order_value).collect()),
        other => other,
    }
}

/// Sets `key` like a JavaScript object property: a new key is appended, an existing one
/// keeps its place.
fn set<T>(entries: &mut Vec<(String, T)>, key: String, value: T) {
    match entries.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => entries.push((key, value)),
    }
}

/// Parses `.env` text exactly as `require("dotenv").parse` does.
pub fn parse(src: &str) -> Result<Vec<(String, Zeroizing<String>)>> {
    if src.contains(['\u{2028}', '\u{2029}']) {
        return Err(Error::invalid(
            "The env file contains Unicode line separators (U+2028/U+2029); remove them",
        ));
    }
    let text = Zeroizing::new(src.replace("\r\n", "\n").replace('\r', "\n"));
    let mut out = Vec::new();
    for c in line_pattern().captures_iter(&text) {
        let key = c[1].to_owned();
        let raw = c.get(2).map_or("", |m| m.as_str());
        let trimmed = raw.trim_matches(is_js_space);
        let quote = trimmed.chars().next();
        let mut value = Zeroizing::new(match quote {
            Some(q @ ('\'' | '"' | '`')) if trimmed.len() >= 2 && trimmed.ends_with(q) => {
                trimmed[1..trimmed.len() - 1].to_owned()
            }
            _ => trimmed.to_owned(),
        });
        if quote == Some('"') {
            value = Zeroizing::new(value.replace("\\n", "\n").replace("\\r", "\r"));
        }
        set(&mut out, key, value);
    }
    Ok(js_order(out))
}

/// Reads and parses an env file: a regular, unlinked file of at most 1 MiB.
pub fn read_env_file(path: &Path) -> Result<Vec<(String, Zeroizing<String>)>> {
    let bytes = Zeroizing::new(read_regular(path, MAX_ENV_BYTES)?);
    parse(&String::from_utf8_lossy(&bytes))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Dotenv,
    Shell,
    Json,
}

impl Format {
    pub fn parse(s: &str) -> Result<Format> {
        match s {
            "dotenv" => Ok(Format::Dotenv),
            "shell" => Ok(Format::Shell),
            "json" => Ok(Format::Json),
            _ => Err(Error::invalid("Unsupported export format")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Dotenv => "dotenv",
            Format::Shell => "shell",
            Format::Json => "json",
        }
    }
}

fn is_env_name(k: &str) -> bool {
    let mut b = k.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn lossy() -> Error {
    Error::invalid("Value cannot be represented losslessly as dotenv; use JSON")
}

/// Writes `pairs` to `target` in `format`. With `merge`, keys already in the file are kept
/// (JSON keeps their order; dotenv rewrites the file's formatting and comments). Shell output
/// requires `merge = false` for an existing file.
pub fn write_env(
    target: &Path,
    pairs: &[(String, Zeroizing<String>)],
    format: Format,
    merge: bool,
) -> Result<()> {
    if !target.is_absolute() {
        return Err(Error::invalid("Target must be absolute"));
    }
    let exists = regular_file(target, true, MAX_ENV_BYTES)?.is_some();
    let previous = Zeroizing::new(if merge && exists {
        String::from_utf8_lossy(&Zeroizing::new(read_regular(target, MAX_ENV_BYTES)?)).into_owned()
    } else {
        String::new()
    });
    let result = Zeroizing::new(match format {
        Format::Json => {
            let mut base: Map<String, Value> = if previous.is_empty() {
                Map::new()
            } else {
                match serde_json::from_str::<Value>(&previous) {
                    Ok(Value::Object(m)) => m,
                    Ok(_) => return Err(Error::invalid("Existing JSON must be an object")),
                    Err(_) => return Err(Error::invalid("Invalid JSON")),
                }
            };
            for (k, v) in pairs {
                base.insert(k.clone(), Value::String(v.to_string()));
            }
            let text = serde_json::to_string_pretty(&js_order_value(Value::Object(base)))
                .map_err(|e| Error::invalid(e.to_string()))?;
            text + "\n"
        }
        Format::Dotenv | Format::Shell => {
            if pairs.iter().any(|(k, _)| !is_env_name(k)) {
                return Err(Error::invalid(
                    "Use JSON for keys that are not environment variable names",
                ));
            }
            if format == Format::Shell && !previous.is_empty() {
                return Err(Error::invalid("Shell exports require merge=false"));
            }
            let mut values = if previous.is_empty() {
                Vec::new()
            } else {
                parse(&previous)?
            };
            for (k, v) in pairs {
                set(&mut values, k.clone(), v.clone());
            }
            let values = js_order(values);
            let mut out = String::new();
            for (k, v) in &values {
                if format == Format::Shell {
                    out.push_str(&format!("export {k}='{}'\n", v.replace('\'', "'\\''")));
                    continue;
                }
                let quote = ['\'', '"', '`']
                    .into_iter()
                    .find(|&q| !v.contains(q) && (q != '"' || !v.contains(['\\', '\r', '\n'])))
                    .ok_or_else(lossy)?;
                out.push_str(&format!("{k}={quote}{}{quote}\n", v.as_str()));
            }
            if out.is_empty() {
                out.push('\n');
            }
            if format == Format::Dotenv {
                let parsed = parse(&out)?;
                for (k, v) in &values {
                    if parsed
                        .iter()
                        .find(|(pk, _)| pk == k)
                        .map(|(_, pv)| pv.as_str())
                        != Some(v.as_str())
                    {
                        return Err(lossy());
                    }
                }
            }
            out
        }
    });
    if let Some(dir) = target.parent() {
        create_private_dirs(dir)?;
    }
    atomic_write(target, result.as_bytes())
}

fn create_private_dirs(dir: &Path) -> Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
        .map_err(Error::io("cannot create the target directory"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(src: &str) -> Vec<(String, String)> {
        parse(src)
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect()
    }

    fn kv(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn parses_like_dotenv() {
        assert_eq!(
            p("A=1\nexport B = two # note\nC='x # y'\nD=\"a\\nb\"\nE=`q`\n# c\nF:  g\n"),
            kv(&[
                ("A", "1"),
                ("B", "two"),
                ("C", "x # y"),
                ("D", "a\nb"),
                ("E", "q"),
                ("F", "g")
            ])
        );
        assert_eq!(p("K='multi\nline'"), kv(&[("K", "multi\nline")]));
        assert_eq!(
            p("K=a\r\nL=b\rM=c"),
            kv(&[("K", "a"), ("L", "b"), ("M", "c")])
        );
        assert_eq!(
            p("2=b\n1=a\nZ=z\n1=again"),
            kv(&[("1", "again"), ("2", "b"), ("Z", "z")])
        );
        assert!(parse("K=a\u{2028}b").is_err());
    }

    #[test]
    fn writes_and_merges() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("sub").join(".env");
        let z = |k: &str, v: &str| (k.to_owned(), Zeroizing::new(v.to_owned()));
        write_env(&f, &[z("A", "1"), z("B", "it's")], Format::Dotenv, true).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "A='1'\nB=\"it's\"\n");
        write_env(&f, &[z("C", "x")], Format::Dotenv, true).unwrap();
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            "A='1'\nB=\"it's\"\nC='x'\n"
        );
        assert!(write_env(&f, &[z("C", "x")], Format::Shell, true).is_err());
        assert!(write_env(&f, &[z("a.b", "x")], Format::Dotenv, true).is_err());
        assert!(write_env(&f, &[z("Q", "'\"`")], Format::Dotenv, false).is_err());
        write_env(&f, &[z("S", "it's")], Format::Shell, false).unwrap();
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            "export S='it'\\''s'\n"
        );
        let j = d.path().join("c.json");
        std::fs::write(&j, "{\"z\":1,\"10\":true,\"a\":{\"2\":0,\"b\":1}}").unwrap();
        write_env(&j, &[z("z", "v"), z("new", "n")], Format::Json, true).unwrap();
        assert_eq!(
            std::fs::read_to_string(&j).unwrap(),
            "{\n  \"10\": true,\n  \"z\": \"v\",\n  \"a\": {\n    \"2\": 0,\n    \"b\": 1\n  },\n  \"new\": \"n\"\n}\n"
        );
    }
}
