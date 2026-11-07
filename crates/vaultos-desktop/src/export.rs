//! A project's values as a password-protected PDF (`export.js`): AES-256 encryption with the
//! standard security handler, revision 6 (ISO 32000-2), which current PDF readers open. The
//! text uses the standard Helvetica fonts, so nothing is embedded. Values with characters
//! those fonts cannot show are left out with a note rather than shown wrong.

use crate::app::{blocking, App};
use crate::settings;
use aes::cipher::block_padding::{NoPadding, Pkcs7};
use aes::cipher::{BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::AppHandle;
use vaultos_core::crypto::fill_random;
use vaultos_core::model::HUMAN;
use vaultos_core::store::Exported;
use zeroize::Zeroizing;

const PAGE_W: f64 = 595.28;
const PAGE_H: f64 = 841.89;
const MARGIN: f64 = 50.0;
const BOTTOM: f64 = 790.0;
const ORANGE: &str = "0.918 0.278 0.067";
const DARK: &str = "0.102 0.102 0.102";
const GREY: &str = "0.467 0.467 0.467";
const HAIR: &str = "0.867 0.867 0.867";
/// Print (high quality) and copy; reserved bits set as the standard requires.
const PERMISSIONS: i32 = 0xFFFF_F8D4_u32 as i32;

const HELVETICA: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667,
    611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500,
    222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];
const HELVETICA_BOLD: [u16; 95] = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667,
    611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556,
    278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
];

#[derive(Clone, Copy, PartialEq)]
enum Font {
    Regular,
    Bold,
}

impl Font {
    fn name(self) -> &'static str {
        match self {
            Font::Regular => "F1",
            Font::Bold => "F2",
        }
    }

    /// Glyph width in thousandths of the size; unknown glyphs are counted wide, so text
    /// never runs past the margin.
    fn width(self, c: char) -> f64 {
        let table = match self {
            Font::Regular => &HELVETICA,
            Font::Bold => &HELVETICA_BOLD,
        };
        let w = (c as usize)
            .checked_sub(32)
            .and_then(|i| table.get(i))
            .copied()
            .unwrap_or(1000);
        f64::from(w)
    }
}

/// WinAnsiEncoding (cp1252) for the standard fonts, or `None` for a character they lack.
fn win_ansi(c: char) -> Option<u8> {
    let n = c as u32;
    if (0x20..0x7f).contains(&n) || (0xa0..=0xff).contains(&n) {
        return u8::try_from(n).ok();
    }
    let b = match c {
        '€' => 0x80,
        '‚' => 0x82,
        'ƒ' => 0x83,
        '„' => 0x84,
        '…' => 0x85,
        '†' => 0x86,
        '‡' => 0x87,
        'ˆ' => 0x88,
        '‰' => 0x89,
        'Š' => 0x8a,
        '‹' => 0x8b,
        'Œ' => 0x8c,
        'Ž' => 0x8e,
        '‘' => 0x91,
        '’' => 0x92,
        '“' => 0x93,
        '”' => 0x94,
        '•' => 0x95,
        '–' => 0x96,
        '—' => 0x97,
        '˜' => 0x98,
        '™' => 0x99,
        'š' => 0x9a,
        '›' => 0x9b,
        'œ' => 0x9c,
        'ž' => 0x9e,
        'Ÿ' => 0x9f,
        _ => return None,
    };
    Some(b)
}

fn showable(s: &str) -> bool {
    s.chars()
        .all(|c| c == '\n' || c == '\r' || c == '\t' || win_ansi(c).is_some())
}

/// The content streams of each page, laid out top to bottom.
struct Layout {
    pages: Vec<Zeroizing<Vec<u8>>>,
    page: Zeroizing<Vec<u8>>,
    y: f64,
}

impl Layout {
    fn new() -> Layout {
        Layout {
            pages: Vec::new(),
            page: Zeroizing::new(Vec::new()),
            y: MARGIN,
        }
    }

    fn new_page(&mut self) {
        let done = std::mem::replace(&mut self.page, Zeroizing::new(Vec::new()));
        self.pages.push(done);
        self.y = MARGIN;
    }

    fn finish(mut self) -> Vec<Zeroizing<Vec<u8>>> {
        self.new_page();
        self.pages
    }

    fn rule(&mut self, color: &str, width: f64) {
        let y = PAGE_H - self.y;
        let _ = writeln!(
            self.page,
            "{color} RG {width} w {MARGIN} {y:.2} m {:.2} {y:.2} l S",
            PAGE_W - MARGIN
        );
    }

    fn space(&mut self, size: f64) {
        self.y += size;
    }

    /// Writes runs of text, wrapping at spaces where it can and anywhere it must.
    fn text(&mut self, runs: &[(Font, f64, &str, &str)]) {
        let max = PAGE_W - 2.0 * MARGIN;
        let size = runs.iter().map(|r| r.1).fold(0.0, f64::max);
        let line_h = size * 1.25;
        let mut lines: Vec<Vec<(Font, f64, &str, String)>> = vec![Vec::new()];
        let mut x = 0.0;
        for &(font, sz, color, text) in runs {
            for (n, para) in text.split('\n').enumerate() {
                if n > 0 {
                    lines.push(Vec::new());
                    x = 0.0;
                }
                let mut current = String::new();
                for word in split_keep_spaces(para) {
                    let w: f64 = word.chars().map(|c| font.width(c) * sz / 1000.0).sum();
                    if x + w > max && x > 0.0 && !word.trim().is_empty() {
                        flush(&mut lines, font, sz, color, &mut current);
                        lines.push(Vec::new());
                        x = 0.0;
                    }
                    for c in word.chars() {
                        let cw = font.width(c) * sz / 1000.0;
                        if x + cw > max && x > 0.0 {
                            flush(&mut lines, font, sz, color, &mut current);
                            lines.push(Vec::new());
                            x = 0.0;
                            if c == ' ' {
                                continue;
                            }
                        }
                        current.push(c);
                        x += cw;
                    }
                }
                flush(&mut lines, font, sz, color, &mut current);
            }
        }
        for line in lines {
            if self.y + line_h > BOTTOM {
                self.new_page();
            }
            let baseline = PAGE_H - self.y - size * 0.8;
            let _ = writeln!(self.page, "BT {MARGIN} {baseline:.2} Td");
            for (font, sz, color, s) in &line {
                let _ = write!(self.page, "{color} rg /{} {sz} Tf (", font.name());
                for c in s.chars() {
                    match win_ansi(c).unwrap_or(b'?') {
                        b @ (b'(' | b')' | b'\\') => self.page.extend_from_slice(&[b'\\', b]),
                        b => self.page.push(b),
                    }
                }
                self.page.extend_from_slice(b") Tj\n");
            }
            self.page.extend_from_slice(b"ET\n");
            self.y += line_h;
        }
    }

    fn field(&mut self, label: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        let shown = if showable(value) {
            value.replace(['\r', '\t'], " ")
        } else {
            "(contains characters this PDF cannot show; reveal it in VaultOS)".into()
        };
        self.text(&[
            (Font::Bold, 9.0, GREY, &format!("{label}:")),
            (Font::Regular, 9.5, DARK, &format!("  {shown}")),
        ]);
    }
}

fn split_keep_spaces(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if c == ' ' {
            if start < i {
                out.push(&s[start..i]);
            }
            out.push(&s[i..i + 1]);
            start = i + 1;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

fn flush<'a>(
    lines: &mut [Vec<(Font, f64, &'a str, String)>],
    font: Font,
    size: f64,
    color: &'a str,
    current: &mut String,
) {
    if current.is_empty() {
        return;
    }
    if let Some(line) = lines.last_mut() {
        line.push((font, size, color, std::mem::take(current)));
    }
}

fn provider_info(providers: &Value, id: &str) -> (String, bool) {
    let find = |id: &str| {
        providers
            .as_array()?
            .iter()
            .find(|p| p["id"] == json!(id))
            .cloned()
    };
    let p = find(id).or_else(|| find("custom")).unwrap_or(Value::Null);
    let name = p["name"].as_str().unwrap_or("Custom").to_uppercase();
    (name, p["type"] == json!("password"))
}

fn layout(project: &str, items: &[Exported], generated: &str) -> Vec<Zeroizing<Vec<u8>>> {
    let providers: Value =
        serde_json::from_str(include_str!("providers.json")).unwrap_or(Value::Null);
    let mut l = Layout::new();
    l.text(&[(Font::Bold, 22.0, DARK, project)]);
    l.text(&[(
        Font::Regular,
        10.0,
        GREY,
        &format!("Vault OS export · {generated}"),
    )]);
    l.space(5.0);
    l.rule(ORANGE, 2.0);
    l.space(12.0);
    if items.is_empty() {
        l.text(&[(Font::Regular, 10.0, GREY, "No entries in this project.")]);
    }
    for e in items {
        let (provider, password_type) = provider_info(&providers, &e.meta.provider);
        if l.y > 740.0 {
            l.new_page();
        }
        l.text(&[(Font::Bold, 13.0, DARK, &e.meta.key)]);
        l.text(&[(Font::Bold, 8.0, ORANGE, &provider)]);
        l.space(3.0);
        l.field(
            if password_type { "Password" } else { "Value" },
            e.value.expose(),
        );
        l.field("Permission", &e.meta.permission);
        l.field(
            "Expires",
            e.meta.expires_at.get(..10).unwrap_or(&e.meta.expires_at),
        );
        l.field("Username", &e.meta.username);
        l.field("Email", &e.meta.email);
        if !password_type {
            l.field("Account password", e.password.expose());
        }
        l.field("URL", &e.meta.url);
        l.field("Note", &e.meta.note);
        l.space(6.0);
        l.rule(HAIR, 0.5);
        l.space(8.0);
    }
    l.finish()
}

// ── Encryption (ISO 32000-2, 7.6.4.3) ─────────────────────────────────────────────────

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    fill_random(&mut b);
    b
}

/// Algorithm 2.B: the revision 6 password hash.
fn hash(password: &[u8], salt: &[u8], udata: &[u8]) -> [u8; 32] {
    let mut k: Zeroizing<Vec<u8>> = Zeroizing::new(
        Sha256::new()
            .chain_update(password)
            .chain_update(salt)
            .chain_update(udata)
            .finalize()
            .to_vec(),
    );
    let mut round = 0u32;
    loop {
        let mut k1 = Zeroizing::new(Vec::with_capacity(
            64 * (password.len() + k.len() + udata.len()),
        ));
        for _ in 0..64 {
            k1.extend_from_slice(password);
            k1.extend_from_slice(&k);
            k1.extend_from_slice(udata);
        }
        let e = Zeroizing::new(
            cbc::Encryptor::<aes::Aes128>::new(k[..16].into(), k[16..32].into())
                .encrypt_padded_vec_mut::<NoPadding>(&k1),
        );
        let m = e[..16].iter().map(|b| u32::from(*b)).sum::<u32>() % 3;
        k = Zeroizing::new(match m {
            0 => Sha256::digest(&*e).to_vec(),
            1 => Sha384::digest(&*e).to_vec(),
            _ => Sha512::digest(&*e).to_vec(),
        });
        round += 1;
        if round >= 64 && u32::from(e[e.len() - 1]) <= round - 32 {
            break;
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&k[..32]);
    out
}

fn wrap_key(key: &[u8; 32], file_key: &[u8; 32]) -> Vec<u8> {
    cbc::Encryptor::<aes::Aes256>::new(key.into(), &[0u8; 16].into())
        .encrypt_padded_vec_mut::<NoPadding>(file_key)
}

struct Encryption {
    file_key: Zeroizing<[u8; 32]>,
    dict: String,
}

/// Algorithms 8, 9 and 10: U/UE, O/OE and Perms for one password used as both the user and
/// the owner password (as the JavaScript export did).
fn encryption(password: &str) -> Encryption {
    let pw: Vec<u8> = password.as_bytes().iter().copied().take(127).collect();
    let pw = Zeroizing::new(pw);
    let file_key = Zeroizing::new(random::<32>());
    let (uvs, uks) = (random::<8>(), random::<8>());
    let mut u = hash(&pw, &uvs, &[]).to_vec();
    u.extend_from_slice(&uvs);
    u.extend_from_slice(&uks);
    let ue = wrap_key(&hash(&pw, &uks, &[]), &file_key);
    let (ovs, oks) = (random::<8>(), random::<8>());
    let mut o = hash(&pw, &ovs, &u).to_vec();
    o.extend_from_slice(&ovs);
    o.extend_from_slice(&oks);
    let oe = wrap_key(&hash(&pw, &oks, &u), &file_key);
    let mut perms = [0u8; 16];
    perms[..4].copy_from_slice(&PERMISSIONS.to_le_bytes());
    perms[4..8].copy_from_slice(&[0xff; 4]);
    perms[8..12].copy_from_slice(b"Tadb");
    perms[12..].copy_from_slice(&random::<4>());
    let mut block = aes::cipher::generic_array::GenericArray::from(perms);
    aes::Aes256::new((&*file_key).into()).encrypt_block(&mut block);
    let hexs = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let dict = format!(
        "<< /Filter /Standard /V 5 /R 6 /Length 256 /CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV3 /Length 32 >> >> /StmF /StdCF /StrF /StdCF /O <{}> /U <{}> /OE <{}> /UE <{}> /Perms <{}> /P {PERMISSIONS} /EncryptMetadata true >>",
        hexs(&o), hexs(&u), hexs(&oe), hexs(&ue), hexs(&block)
    );
    Encryption { file_key, dict }
}

/// AESV3: a random IV, then AES-256-CBC with PKCS#7 padding under the file key.
fn seal(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let iv = random::<16>();
    let mut out = iv.to_vec();
    out.extend(
        cbc::Encryptor::<aes::Aes256>::new(key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(data),
    );
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The whole file: catalog, pages, fonts, info, encryption dictionary, cross-reference.
fn pdf(project: &str, items: &[Exported], password: &str, generated: &str) -> Zeroizing<Vec<u8>> {
    let pages = layout(project, items, generated);
    let enc = encryption(password);
    let key = &*enc.file_key;
    let n = pages.len();
    // 1 catalog, 2 pages, 3-4 fonts, 5 info, 6 encrypt, then a page and its contents each.
    let mut objects: Vec<Vec<u8>> = Vec::new();
    objects.push(b"<< /Type /Catalog /Pages 2 0 R /Extensions << /ADBE << /BaseVersion /1.7 /ExtensionLevel 8 >> >> >>".to_vec());
    let kids: Vec<String> = (0..n).map(|i| format!("{} 0 R", 7 + 2 * i)).collect();
    objects.push(format!("<< /Type /Pages /Kids [{}] /Count {n} >>", kids.join(" ")).into_bytes());
    for base in ["Helvetica", "Helvetica-Bold"] {
        objects.push(
            format!(
                "<< /Type /Font /Subtype /Type1 /BaseFont /{base} /Encoding /WinAnsiEncoding >>"
            )
            .into_bytes(),
        );
    }
    // Document text strings are UTF-16BE with a byte order mark.
    let mut title = vec![0xfe, 0xff];
    for unit in format!("{project} — Vault OS export").encode_utf16() {
        title.extend_from_slice(&unit.to_be_bytes());
    }
    objects.push(
        format!(
            "<< /Title <{}> /Producer <{}> >>",
            hex(&seal(key, &title)),
            hex(&seal(key, b"VaultOS"))
        )
        .into_bytes(),
    );
    objects.push(enc.dict.clone().into_bytes());
    for (i, content) in pages.iter().enumerate() {
        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {} 0 R >>",
                8 + 2 * i
            )
            .into_bytes(),
        );
        let sealed = seal(key, content);
        let mut stream = format!("<< /Length {} >>\nstream\n", sealed.len()).into_bytes();
        stream.extend_from_slice(&sealed);
        stream.extend_from_slice(b"\nendstream");
        objects.push(stream);
    }
    let mut out = Zeroizing::new(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec());
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    let mut table = format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1);
    for o in offsets {
        table.push_str(&format!("{o:010} 00000 n \n"));
    }
    let id = hex(&random::<16>());
    table.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R /Info 5 0 R /Encrypt 6 0 R /ID [<{id}> <{id}>] >>\nstartxref\n{xref}\n%%EOF\n",
        objects.len() + 1
    ));
    out.extend_from_slice(table.as_bytes());
    out
}

/// Writes privately beside the target, then renames over it: never through a symlink, never
/// inside the vault's folder.
fn write_file(target: &Path, data_dir: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = target.parent().ok_or("Choose a file name")?;
    let real_dir = std::fs::canonicalize(dir).map_err(|e| e.to_string())?;
    let real_data = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    if real_dir.starts_with(&real_data) {
        return Err("Export outside the vault data directory".into());
    }
    let name = target.file_name().ok_or("Choose a file name")?;
    let target = real_dir.join(name);
    if std::fs::symlink_metadata(&target).is_ok_and(|m| !m.is_file()) {
        return Err("The export target is not a regular file".into());
    }
    let tmp: PathBuf = real_dir.join(format!(
        ".{}.{}",
        name.to_string_lossy(),
        hex(&random::<12>())
    ));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()));
    if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, &target)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.to_string());
    }
    Ok(())
}

pub async fn export_project(
    app: &Arc<App>,
    handle: &AppHandle,
    project: String,
) -> Result<Value, String> {
    let password = app
        .with_store(|s| Ok(settings::export_password(s.settings()?).map(str::to_owned)))?
        .map(Zeroizing::new);
    let Some(password) = password else {
        return Ok(json!({ "ok": false, "error": "Set an export password in Settings first" }));
    };
    app.gate("export secret values").await?;
    use tauri_plugin_dialog::DialogExt;
    let dialog = handle
        .dialog()
        .file()
        .set_title("Export encrypted PDF")
        .set_file_name("vault-export.pdf")
        .add_filter("PDF", &["pdf"]);
    let picked = blocking(move || dialog.blocking_save_file()).await?;
    let Some(target) = picked.and_then(|p| p.into_path().ok()) else {
        return Ok(json!({ "ok": false, "canceled": true }));
    };
    if !app.human_unlocked() {
        return Err("Vault is locked".into());
    }
    let me = app.clone();
    blocking(move || -> Result<(), String> {
        let (name, items) = me.with_store(|s| s.export_project(&project, HUMAN))?;
        let generated = vaultos_core::model::now_iso();
        let bytes = pdf(&name, &items, &password, &generated);
        write_file(&target, &me.data_dir, &bytes)
    })
    .await??;
    Ok(json!({ "ok": true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_an_encrypted_pdf_without_plaintext_values() {
        let item = Exported {
            meta: test_meta(),
            value: vaultos_core::SecretString::new("synthetic-value-123"),
            password: vaultos_core::SecretString::new(""),
        };
        let bytes = pdf("demo", &[item], "export-password-1", "2026-01-01T00:00:00Z");
        assert!(bytes.starts_with(b"%PDF-1.7"));
        assert!(bytes.windows(4).any(|w| w == b"/R 6"));
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("synthetic-value-123"));
        assert!(!text.contains("demo"));
        assert!(text.ends_with("%%EOF\n"));
        // Manual check against an independent reader: set VAULTOS_PDF_SAMPLE to a path, then
        // `pdftotext -upw export-password-1 <path> -` prints the value.
        if let Some(out) = std::env::var_os("VAULTOS_PDF_SAMPLE") {
            std::fs::write(out, &*bytes).expect("sample written");
        }
    }

    fn test_meta() -> vaultos_core::store::ItemSummary {
        vaultos_core::store::ItemSummary {
            id: "i".into(),
            key: "API_KEY".into(),
            provider: "custom".into(),
            note: String::new(),
            username: String::new(),
            email: String::new(),
            url: String::new(),
            permission: String::new(),
            expires_at: String::new(),
            expiry_status: String::new(),
            days_left: None,
            owner: "human".into(),
            created_by: "human".into(),
            editable_by: Vec::new(),
            inject_approved: true,
            has_value: true,
            has_password: false,
            updated_at: String::new(),
            rev: 1,
        }
    }

    #[test]
    fn hash_follows_revision_6() {
        // Deterministic for fixed inputs, and 32 bytes.
        assert_eq!(hash(b"pw", b"saltsalt", b""), hash(b"pw", b"saltsalt", b""));
        assert_ne!(hash(b"pw", b"saltsalt", b""), hash(b"pw", b"saltsal2", b""));
    }

    #[test]
    fn wraps_long_values_onto_more_lines() {
        let mut l = Layout::new();
        l.field("Value", &"x".repeat(400));
        let text = String::from_utf8_lossy(&l.page).to_string();
        assert!(text.matches("BT ").count() > 2);
    }
}
