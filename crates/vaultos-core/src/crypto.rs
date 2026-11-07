//! The primitives the v4 format uses, all from RustCrypto: Argon2id for the password and
//! HKDF-SHA256 to combine and separate the keys derived from it. Every sealed box uses
//! XChaCha20-Poly1305, whole-file integrity HMAC-SHA256, and the audit chain Ed25519.

use crate::error::{Error, Result};
use crate::secret::{Key32, SecretBytes};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill_random(&mut out);
    out
}

/// 16 random bytes as hex: record, project and history ids.
pub fn random_id() -> String {
    hex(&random_array::<8>())
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&sha256(data))
}

/// Strict standard base64: canonical padding only, so one value has one encoding.
pub fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn unb64(s: &str, what: &str) -> Result<Vec<u8>> {
    let bytes = STANDARD
        .decode(s)
        .map_err(|_| Error::Format(format!("{what} is not base64")))?;
    if STANDARD.encode(&bytes) != s {
        return Err(Error::Format(format!("{what} is not canonical base64")));
    }
    Ok(bytes)
}

pub fn unb64_array<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    let v = unb64(s, what)?;
    v.try_into()
        .map_err(|_| Error::Format(format!("{what} has the wrong length")))
}

/// Argon2id cost. Stored in the vault header so it can be raised without a format change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// About 0.9 s on an Apple M2 (`benches/store.rs`); the lanes are computed one after another.
    pub const DEFAULT: KdfParams = KdfParams {
        m: 256 * 1024,
        t: 3,
        p: 4,
    };

    /// The weakest header any vault may carry: OWASP's minimum for Argon2id (19 MiB, 2 passes).
    /// Tests use it to stay fast; a file asking for less is refused as a downgrade.
    pub const FLOOR: KdfParams = KdfParams {
        m: 19 * 1024,
        t: 2,
        p: 1,
    };

    const MAX_MEMORY_KIB: u32 = 1024 * 1024;
    const MAX_WORK: u64 = 4 * (Self::DEFAULT.m as u64) * (Self::DEFAULT.t as u64);

    pub(crate) fn validate(&self) -> Result<()> {
        // Refuse headers that would make unlock trivially cheap (a downgraded file) or
        // would exhaust memory (a hostile file).
        let floor = Self::FLOOR;
        if self.m < floor.m || self.t < floor.t || self.p < floor.p {
            return Err(Error::Format(
                "key derivation parameters are too weak".into(),
            ));
        }
        // The header is read before anything is authenticated, so cap the work a modified
        // file can demand: at most 1 GiB and four times the default's memory × passes
        // (a few seconds), whatever the split.
        let work = u64::from(self.m) * u64::from(self.t);
        if self.m > Self::MAX_MEMORY_KIB || self.t > 16 || self.p > 16 || work > Self::MAX_WORK {
            return Err(Error::Format(
                "key derivation parameters are too large".into(),
            ));
        }
        Ok(())
    }
}

pub fn argon2id(password: &[u8], salt: &[u8; 16], params: KdfParams) -> Result<Key32> {
    params.validate()?;
    let p = argon2::Params::new(params.m, params.t, params.p, Some(32))
        .map_err(|_| Error::Format("invalid key derivation parameters".into()))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| Error::Format("key derivation failed".into()))?;
    let key = Key32::from_bytes(out);
    out.zeroize();
    Ok(key)
}

pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key32 {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    // 32 bytes is always a valid HKDF-SHA256 output length.
    if hk.expand(info, &mut out).is_err() {
        unreachable!("HKDF-SHA256 accepts 32-byte outputs");
    }
    let key = Key32::from_bytes(out);
    out.zeroize();
    key
}

pub fn hmac_sha256(key: &Key32, data: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(key, &[data])
}

/// The HMAC of the concatenation of `parts`, without building it.
pub fn hmac_sha256_parts(key: &Key32, parts: &[&[u8]]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key.expose()).unwrap_or_else(|_| unreachable!());
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

pub fn hmac_verify(key: &Key32, data: &[u8], tag: &[u8]) -> bool {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key.expose()).unwrap_or_else(|_| unreachable!());
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

/// An XChaCha20-Poly1305 box as raw bytes, for large contents such as attachments: the
/// 24-byte nonce, then the ciphertext and its tag.
pub fn seal_raw(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let nonce: [u8; 24] = random_array();
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .unwrap_or_else(|_| unreachable!("XChaCha20-Poly1305 encryption does not fail"));
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn open_raw(key: &Key32, aad: &[u8], sealed: &[u8]) -> Result<SecretBytes> {
    if sealed.len() < 24 + 16 {
        return Err(Error::Format("sealed contents are too short".into()));
    }
    let (nonce, ct) = sealed.split_at(24);
    XChaCha20Poly1305::new(key.expose().into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(SecretBytes::new)
        .map_err(|_| Error::Integrity)
}

/// One XChaCha20-Poly1305 box: a random 192-bit nonce (safe to pick at random for any number
/// of messages) and ciphertext with its 16-byte tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub n: String,
    pub c: String,
}

impl Sealed {
    pub fn seal(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Sealed {
        let cipher = XChaCha20Poly1305::new(key.expose().into());
        let nonce: [u8; 24] = random_array();
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .unwrap_or_else(|_| unreachable!("XChaCha20-Poly1305 encryption does not fail"));
        Sealed {
            n: b64(&nonce),
            c: b64(&ct),
        }
    }

    pub fn open(&self, key: &Key32, aad: &[u8]) -> Result<SecretBytes> {
        let nonce: [u8; 24] = unb64_array(&self.n, "nonce")?;
        let ct = unb64(&self.c, "ciphertext")?;
        if ct.len() < 16 {
            return Err(Error::Format("ciphertext is too short".into()));
        }
        let cipher = XChaCha20Poly1305::new(key.expose().into());
        cipher
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct, aad })
            .map(SecretBytes::new)
            .map_err(|_| Error::Integrity)
    }

    pub fn seal_key(wrapping: &Key32, aad: &[u8], key: &Key32) -> Sealed {
        Sealed::seal(wrapping, aad, key.expose())
    }

    pub fn open_key(&self, wrapping: &Key32, aad: &[u8]) -> Result<Key32> {
        let bytes = self.open(wrapping, aad)?;
        let arr: [u8; 32] = bytes
            .expose()
            .try_into()
            .map_err(|_| Error::Format("wrapped key has the wrong length".into()))?;
        Ok(Key32::from_bytes(arr))
    }
}

/// Ed25519 signing key held as its 32-byte seed.
pub fn signing_key(seed: &Key32) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(seed.expose())
}

pub fn ed25519_public(seed: &Key32) -> [u8; 32] {
    signing_key(seed).verifying_key().to_bytes()
}

pub fn sign_ed25519(seed: &Key32, msg: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    signing_key(seed).sign(msg).to_bytes()
}

pub fn verify_ed25519(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(public) else {
        return false;
    };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) else {
        return false;
    };
    vk.verify_strict(msg, &sig).is_ok()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_box_binds_its_context() {
        let k = Key32::random();
        let s = Sealed::seal(&k, b"ctx-a", b"synthetic-only");
        assert_eq!(s.open(&k, b"ctx-a").unwrap().expose(), b"synthetic-only");
        assert!(matches!(s.open(&k, b"ctx-b"), Err(Error::Integrity)));
        assert!(matches!(
            s.open(&Key32::random(), b"ctx-a"),
            Err(Error::Integrity)
        ));
    }

    #[test]
    fn base64_must_be_canonical() {
        assert!(unb64("QQ==", "x").is_ok());
        assert!(unb64("QR==", "x").is_err());
        assert!(unb64("QQ", "x").is_err());
    }

    #[test]
    fn weak_kdf_headers_are_refused_outside_tests() {
        assert!(KdfParams { m: 8, t: 1, p: 1 }.validate().is_err());
        assert!(KdfParams {
            m: 8 * 1024 * 1024,
            t: 3,
            p: 4
        }
        .validate()
        .is_err());
        assert!(KdfParams::DEFAULT.validate().is_ok());
        let big = |m: u32, t: u32| KdfParams { m, t, p: 4 }.validate().is_ok();
        assert!(big(1024 * 1024, 3), "1 GiB at 3 passes is allowed");
        assert!(!big(1024 * 1024, 4), "but not more work than that");
        assert!(!big(4 * 1024 * 1024, 2), "nor more than 1 GiB");
        assert!(!big(64 * 1024, 64), "nor many passes");
    }

    #[test]
    fn argon2id_is_deterministic_per_password() {
        let salt = [1u8; 16];
        let a = argon2id(b"synthetic-password", &salt, KdfParams::FLOOR).unwrap();
        let b = argon2id(b"synthetic-password", &salt, KdfParams::FLOOR).unwrap();
        let c = argon2id(b"synthetic-passwore", &salt, KdfParams::FLOOR).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
