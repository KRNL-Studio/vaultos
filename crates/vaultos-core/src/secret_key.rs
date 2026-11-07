//! The optional Secret Key: 128 random bits combined with the master password when the vault
//! is unlocked, so a copied vault file cannot be attacked by guessing the password alone.
//!
//! Written as `VK1-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX`: 26 Crockford base32 characters
//! carry the 128 bits, then 4 characters of checksum catch typing mistakes.

use crate::crypto::{hex, sha256};
use crate::error::{Error, Result};
use crate::secret::SecretString;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX: &str = "VK1";
const BODY: usize = 26;
const CHECK: usize = 4;

#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SecretKey([u8; 16]);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey(id {})", self.id())
    }
}

impl SecretKey {
    pub fn generate() -> SecretKey {
        SecretKey(crate::crypto::random_array())
    }

    pub fn from_bytes(bytes: [u8; 16]) -> SecretKey {
        SecretKey(bytes)
    }

    pub fn expose(&self) -> &[u8; 16] {
        &self.0
    }

    /// A short public fingerprint stored in the vault header, so a missing or wrong key can
    /// be named without revealing it. 32 bits of a hash of 128 random bits leaks nothing usable.
    pub fn id(&self) -> String {
        let mut data = b"vaultos/v4/secret-key-id/".to_vec();
        data.extend_from_slice(&self.0);
        hex(&sha256(&data)[..4])
    }

    fn checksum(bytes: &[u8; 16]) -> [u8; CHECK] {
        let mut data = b"vaultos/v4/secret-key-check/".to_vec();
        data.extend_from_slice(bytes);
        let h = sha256(&data);
        // The first 20 bits, as four 5-bit symbols.
        let bits = (u32::from(h[0]) << 12) | (u32::from(h[1]) << 4) | (u32::from(h[2]) >> 4);
        let mut out = [0u8; CHECK];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = ALPHABET[((bits >> (5 * (CHECK - 1 - i))) & 31) as usize];
        }
        out
    }

    /// The form shown to the human and printed in the Emergency Kit.
    pub fn display(&self) -> SecretString {
        let mut v = u128::from_be_bytes(self.0);
        let mut body = [0u8; BODY];
        // 26 symbols hold 130 bits; the top two are always zero.
        for slot in body.iter_mut().rev() {
            *slot = ALPHABET[(v & 31) as usize];
            v >>= 5;
        }
        let mut chars: Vec<u8> = body.to_vec();
        chars.extend_from_slice(&Self::checksum(&self.0));
        let mut out = String::from(PREFIX);
        for group in chars.chunks(6) {
            out.push('-');
            out.push_str(std::str::from_utf8(group).unwrap_or_default());
        }
        chars.zeroize();
        body.zeroize();
        SecretString::new(out)
    }

    /// Accepts any case, spaces or dashes, and Crockford's look-alikes (O for 0, I and L for 1).
    pub fn parse(input: &str) -> Result<SecretKey> {
        let mut symbols: Vec<u8> = Vec::with_capacity(BODY + CHECK + 3);
        for c in input.chars() {
            match c {
                '-' | ' ' => continue,
                _ if c.is_ascii_alphanumeric() => symbols.push(c.to_ascii_uppercase() as u8),
                _ => return Err(Error::SecretKeyFormat("unexpected character")),
            }
        }
        if !symbols.starts_with(PREFIX.as_bytes()) {
            return Err(Error::SecretKeyFormat("it should start with VK1"));
        }
        let rest = &symbols[PREFIX.len()..];
        if rest.len() != BODY + CHECK {
            return Err(Error::SecretKeyFormat(
                "it should have 30 characters after VK1",
            ));
        }
        let value = |c: u8| -> Result<u8> {
            let c = match c {
                b'O' => b'0',
                b'I' | b'L' => b'1',
                other => other,
            };
            ALPHABET
                .iter()
                .position(|&a| a == c)
                .map(|p| p as u8)
                .ok_or(Error::SecretKeyFormat("unexpected character"))
        };
        let mut v: u128 = 0;
        for (i, &c) in rest[..BODY].iter().enumerate() {
            let d = value(c)?;
            // 26 symbols carry 130 bits; the first holds only the top 3 of the 128.
            if i == 0 && d > 7 {
                return Err(Error::SecretKeyFormat("it was mistyped"));
            }
            v = (v << 5) | u128::from(d);
        }
        let bytes = v.to_be_bytes();
        let mut given = [0u8; CHECK];
        for (slot, &c) in given.iter_mut().zip(&rest[BODY..]) {
            *slot = ALPHABET[value(c)? as usize];
        }
        symbols.zeroize();
        if given != Self::checksum(&bytes) {
            return Err(Error::SecretKeyFormat("it was mistyped"));
        }
        Ok(SecretKey(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn display_round_trips_and_is_grouped() {
        let k = SecretKey::generate();
        let shown = k.display();
        assert_eq!(shown.len(), 3 + 5 * 7);
        assert!(shown.expose().starts_with("VK1-"));
        assert_eq!(SecretKey::parse(shown.expose()).unwrap(), k);
    }

    #[test]
    fn typing_mistakes_are_caught() {
        let k = SecretKey::from_bytes([0x5a; 16]);
        let shown = k.display().expose().to_owned();
        let lower = shown.to_lowercase().replace('-', " ");
        assert_eq!(SecretKey::parse(&lower).unwrap(), k);
        let mut chars: Vec<char> = shown.chars().collect();
        let i = 10;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(SecretKey::parse(&typo).is_err());
        assert!(SecretKey::parse("VK1-short").is_err());
        assert!(SecretKey::parse("XX1-AAAAAA-AAAAAA-AAAAAA-AAAAAA-AAAAAA").is_err());
    }

    proptest! {
        #[test]
        fn any_key_round_trips(bytes in any::<[u8; 16]>()) {
            let k = SecretKey::from_bytes(bytes);
            prop_assert_eq!(SecretKey::parse(k.display().expose()).unwrap(), k);
        }

        #[test]
        fn parse_never_panics(s in "\\PC{0,64}") {
            let _ = SecretKey::parse(&s);
        }
    }
}
