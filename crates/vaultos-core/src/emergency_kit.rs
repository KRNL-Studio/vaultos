//! The Emergency Kit: one printable A4 page with a vault's Secret Key, as a PDF. It uses the
//! PDF standard fonts, so it embeds no font files, and holds only ASCII text. The page and
//! the buffers that built it are zeroed when dropped.

use crate::secret_key::SecretKey;
use std::fmt::Write as _;
use zeroize::Zeroizing;

const WIDTH: f32 = 595.0;
const HEIGHT: f32 = 842.0;
const MARGIN: f32 = 56.0;

const ADVICE: &[&str] = &[
    "To open this vault on a new device, or after reinstalling VaultOS, you need both your",
    "master password and this Secret Key. Neither one opens the vault alone.",
    "",
    "Print this page, or keep the file somewhere only you can open, offline if you can.",
    "Anyone with this page who also learns your master password can open a copy of the vault.",
    "",
    "Devices where you already entered the Secret Key keep it in their Keychain or keyring.",
    "VaultOS has no recovery service: if you lose this key and every device that has it, the",
    "vault cannot be opened.",
];

/// The kit for `key`, the Secret Key the vault `vault_id` requires, dated `date`.
pub fn pdf(key: &SecretKey, vault_id: &str, date: &str) -> Zeroizing<Vec<u8>> {
    let display = key.display();
    let mut c = Zeroizing::new(String::new());
    let gray = |c: &mut String, g: f32| {
        let _ = writeln!(c, "{g} g");
    };
    let text = |c: &mut String, font: &str, size: f32, y: f32, s: &str| {
        let _ = writeln!(
            c,
            "BT /{font} {size} Tf {MARGIN} {y} Td ({}) Tj ET",
            *escape(s)
        );
    };
    text(&mut c, "F2", 22.0, 778.0, "VaultOS Emergency Kit");
    gray(&mut c, 0.35);
    text(
        &mut c,
        "F1",
        10.5,
        756.0,
        &format!("Created {date} for the vault {vault_id}."),
    );
    text(
        &mut c,
        "F1",
        10.5,
        741.0,
        &format!(
            "Secret Key ID {}: VaultOS names this ID when it asks for the key.",
            key.id()
        ),
    );
    gray(&mut c, 0.0);
    text(&mut c, "F2", 12.0, 704.0, "Secret Key");
    let _ = writeln!(c, "0.6 G 1 w {MARGIN} 644 {} 50 re S", WIDTH - 2.0 * MARGIN);
    let _ = writeln!(
        c,
        "BT /F3 16 Tf {} 664 Td ({}) Tj ET",
        MARGIN + 16.0,
        *escape(display.expose())
    );
    text(&mut c, "F2", 12.0, 606.0, "Master password");
    let _ = writeln!(c, "0.6 G {MARGIN} 570 m {} 570 l S", WIDTH - MARGIN);
    gray(&mut c, 0.35);
    text(
        &mut c,
        "F1",
        9.0,
        556.0,
        "Write it here only if this page will be kept private. VaultOS never stores it.",
    );
    gray(&mut c, 0.0);
    text(&mut c, "F2", 12.0, 512.0, "Keep this page safe");
    let mut y = 492.0;
    for line in ADVICE {
        if !line.is_empty() {
            text(&mut c, "F1", 10.5, y, line);
        }
        y -= if line.is_empty() { 8.0 } else { 15.0 };
    }
    gray(&mut c, 0.35);
    text(
        &mut c,
        "F1",
        8.0,
        48.0,
        "VaultOS Emergency Kit. Keep it private.",
    );

    let objects: [Zeroizing<String>; 8] = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned().into(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned().into(),
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {WIDTH} {HEIGHT}] /Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 6 0 R >> >> /Contents 7 0 R >>"
        )
        .into(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
            .to_owned()
            .into(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
            .to_owned()
            .into(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold >>"
            .to_owned()
            .into(),
        {
            let mut s = Zeroizing::new(String::with_capacity(c.len() + 64));
            let _ = write!(s, "<< /Length {} >>\nstream\n{}endstream", c.len(), *c);
            s
        },
        "<< /Title (VaultOS Emergency Kit) /Producer (VaultOS) >>"
            .to_owned()
            .into(),
    ];
    let mut out = Zeroizing::new(Vec::with_capacity(c.len() + 2048));
    out.extend_from_slice(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body.as_bytes());
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info 8 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// A PDF literal string: backslashes and parentheses escaped, anything but printable ASCII
/// replaced.
fn escape(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(2 * s.len()));
    for ch in s.chars() {
        match ch {
            '\\' | '(' | ')' => {
                out.push('\\');
                out.push(ch);
            }
            ' '..='~' => out.push(ch),
            _ => out.push('?'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]
    use super::*;

    #[test]
    fn writes_a_well_formed_page_with_the_key() {
        let key = SecretKey::generate();
        let pdf = pdf(&key, "0011223344556677", "2026-11-08");
        // One char per byte, so string offsets are file offsets.
        let text: String = pdf
            .iter()
            .map(|&b| if b.is_ascii() { b as char } else { '?' })
            .collect();
        assert!(text.starts_with("%PDF-1.4\n"));
        assert!(text.ends_with("%%EOF\n"));
        assert!(text.contains(&format!("({})", key.display().expose())));
        assert!(text.contains(&key.id()));
        // Every cross-reference entry points at its object, and startxref at the table.
        let start: usize = text
            .rsplit("startxref\n")
            .next()
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(text[start..].starts_with("xref\n0 9\n"));
        let entries: Vec<usize> = text[start..]
            .lines()
            .skip(3)
            .take(8)
            .map(|l| l[..10].parse().unwrap())
            .collect();
        for (i, at) in entries.iter().enumerate() {
            assert!(
                text[*at..].starts_with(&format!("{} 0 obj\n", i + 1)),
                "object {}",
                i + 1
            );
        }
        // The stream's stated length is its length.
        let body = text.split_once(">>\nstream\n").unwrap().1;
        let len: usize = text
            .split("<< /Length ")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(body[len..].starts_with("endstream"));
    }

    #[test]
    fn escapes_pdf_strings() {
        assert_eq!(*escape(r"a(b)c\d"), r"a\(b\)c\\d");
        assert_eq!(*escape("caf\u{e9}"), "caf?");
    }
}
