//! Time-based one-time codes (RFC 6238) from an `otpauth://totp/...` URI or a bare Base32
//! secret, as authenticator apps and sites' QR codes give them.

use crate::error::{Error, Result};
use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: String,
    pub account: String,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

fn invalid(why: &str) -> Error {
    Error::invalid(format!("Invalid one-time code setup: {why}"))
}

/// RFC 4648 Base32, case-insensitive, ignoring spaces, hyphens and padding.
fn base32(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() * 5 / 8));
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars().filter(|c| !matches!(c, ' ' | '-' | '=')) {
        let v = match c.to_ascii_uppercase() {
            u @ 'A'..='Z' => u as u32 - 'A' as u32,
            d @ '2'..='7' => d as u32 - '2' as u32 + 26,
            _ => return None,
        };
        buf = (buf << 5 | v) & 0xfff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

fn percent_decode(s: &str) -> Result<String> {
    percent_encoding::percent_decode_str(&s.replace('+', " "))
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| invalid("the link is not valid UTF-8"))
}

impl Totp {
    /// Parses an `otpauth://totp/` URI or a bare Base32 secret (then SHA-1, 6 digits, 30 s).
    pub fn parse(input: &str) -> Result<Totp> {
        let input = input.trim();
        let mut t = Totp {
            secret: Zeroizing::new(Vec::new()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: String::new(),
            account: String::new(),
        };
        let scheme = input.get(..10);
        let secret = if scheme.is_some_and(|s| s.eq_ignore_ascii_case("otpauth://")) {
            let rest = &input[10..];
            let (kind, rest) = rest.split_once('/').ok_or_else(|| invalid("no label"))?;
            if kind.eq_ignore_ascii_case("hotp") {
                return Err(invalid("counter-based (HOTP) codes are not supported"));
            }
            if !kind.eq_ignore_ascii_case("totp") {
                return Err(invalid("not a one-time code link"));
            }
            let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
            let label = percent_decode(label)?;
            match label.split_once(':') {
                Some((issuer, account)) => {
                    t.issuer = issuer.trim().to_owned();
                    t.account = account.trim().to_owned();
                }
                None => t.account = label.trim().to_owned(),
            }
            let mut secret = None;
            for pair in query.split('&').filter(|p| !p.is_empty()) {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                let v = percent_decode(v)?;
                match k.to_ascii_lowercase().as_str() {
                    "secret" => secret = Some(Zeroizing::new(v)),
                    "issuer" => t.issuer = v.trim().to_owned(),
                    "algorithm" => {
                        t.algorithm = match v.to_ascii_uppercase().as_str() {
                            "SHA1" => Algorithm::Sha1,
                            "SHA256" => Algorithm::Sha256,
                            "SHA512" => Algorithm::Sha512,
                            _ => return Err(invalid("unknown algorithm")),
                        }
                    }
                    "digits" => {
                        t.digits = v
                            .parse()
                            .ok()
                            .filter(|d| (6..=8).contains(d))
                            .ok_or_else(|| invalid("digits must be 6, 7 or 8"))?;
                    }
                    "period" => {
                        t.period = v
                            .parse()
                            .ok()
                            .filter(|p| (1..=600).contains(p))
                            .ok_or_else(|| invalid("the period must be 1 to 600 seconds"))?;
                    }
                    _ => {}
                }
            }
            secret.ok_or_else(|| invalid("the link has no secret"))?
        } else {
            Zeroizing::new(input.to_owned())
        };
        t.secret = base32(&secret).ok_or_else(|| invalid("the secret is not Base32"))?;
        if t.secret.len() < 10 {
            return Err(invalid("the secret is too short"));
        }
        Ok(t)
    }

    /// The code for a Unix time in seconds.
    pub fn code(&self, unix: u64) -> String {
        let counter = (unix / self.period).to_be_bytes();
        let mac = hmac(self.algorithm, &self.secret, &counter);
        let offset = usize::from(mac[mac.len() - 1] & 0x0f);
        let bin = u32::from_be_bytes([
            mac[offset] & 0x7f,
            mac[offset + 1],
            mac[offset + 2],
            mac[offset + 3],
        ]);
        let width = self.digits as usize;
        format!("{:0width$}", bin % 10u32.pow(self.digits))
    }

    /// Seconds until the code for `unix` changes.
    pub fn remaining(&self, unix: u64) -> u64 {
        self.period - unix % self.period
    }

    pub fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

fn hmac(algorithm: Algorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    // HMAC takes a key of any length.
    macro_rules! run {
        ($d:ty) => {{
            let mut m = <Hmac<$d> as Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable!());
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }};
    }
    match algorithm {
        Algorithm::Sha1 => run!(sha1::Sha1),
        Algorithm::Sha256 => run!(sha2::Sha256),
        Algorithm::Sha512 => run!(sha2::Sha512),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc(secret: &[u8], alg: &str) -> Totp {
        let b32 = {
            const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0u32);
            for b in secret {
                buf = buf << 8 | u32::from(*b);
                bits += 8;
                while bits >= 5 {
                    bits -= 5;
                    out.push(A[(buf >> bits & 31) as usize] as char);
                }
            }
            if bits > 0 {
                out.push(A[(buf << (5 - bits) & 31) as usize] as char);
            }
            out
        };
        Totp::parse(&format!(
            "otpauth://totp/Example:alice%40example.com?secret={b32}&algorithm={alg}&digits=8&issuer=Example"
        ))
        .unwrap()
    }

    #[test]
    fn rfc_6238_vectors() {
        let sha1 = rfc(b"12345678901234567890", "SHA1");
        let sha256 = rfc(b"12345678901234567890123456789012", "SHA256");
        let sha512 = rfc(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            "SHA512",
        );
        assert_eq!(sha1.issuer, "Example");
        assert_eq!(sha1.account, "alice@example.com");
        let cases = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, a, b, c) in cases {
            assert_eq!(sha1.code(t), a, "SHA1 at {t}");
            assert_eq!(sha256.code(t), b, "SHA256 at {t}");
            assert_eq!(sha512.code(t), c, "SHA512 at {t}");
        }
        assert_eq!(sha1.remaining(59), 1);
        assert_eq!(sha1.remaining(60), 30);
    }

    #[test]
    fn bare_secrets_and_bad_input() {
        // "12345678901234567890" in Base32, lower case with spaces, as sites print it.
        let t = Totp::parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(t.code(59), "287082");
        assert!(format!("{t:?}").contains("Totp") && !format!("{t:?}").contains("GEZD"));
        for bad in [
            "",
            "not base32!",
            "GEZDGNBV",
            "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=1",
            "otpauth://totp/x?digits=6",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=9",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=0",
        ] {
            assert!(Totp::parse(bad).is_err(), "{bad}");
        }
    }
}
