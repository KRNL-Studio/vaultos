//! Reads the JavaScript app's vault file: envelope v1 or v2 (scrypt + AES-256-GCM) around
//! the format-v3 JSON. Read-only: v4 never writes this format.

use crate::crypto::{unb64, unb64_array};
use crate::error::{Error, Result};
use crate::model::VaultV3;
use crate::secret::SecretBytes;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::Deserialize;
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    v: u64,
    kdf: String,
    salt: String,
    iv: String,
    tag: String,
    data: String,
}

/// The `v` field of a vault file, without decrypting it.
pub fn envelope_version(bytes: &[u8]) -> Result<u64> {
    #[derive(Deserialize)]
    struct Probe {
        v: u64,
    }
    serde_json::from_slice::<Probe>(bytes)
        .map(|p| p.v)
        .map_err(|_| Error::Format("not a VaultOS vault file".into()))
}

fn scrypt_key(password: &[u8], salt: &[u8], log_n: u8) -> Result<[u8; 32]> {
    let params = scrypt::Params::new(log_n, 8, 1, 32)
        .map_err(|_| Error::Format("invalid scrypt parameters".into()))?;
    let mut out = [0u8; 32];
    scrypt::scrypt(password, salt, &params, &mut out)
        .map_err(|_| Error::Format("scrypt failed".into()))?;
    Ok(out)
}

/// Decrypts and parses a v1/v2 envelope. A wrong password and a modified file are the same
/// error, as they are in the JavaScript app.
pub fn decrypt(bytes: &[u8], password: &str) -> Result<VaultV3> {
    let plain = decrypt_raw(bytes, password)?;
    let raw: serde_json::Value = serde_json::from_slice(plain.expose())
        .map_err(|_| Error::Format("the decrypted vault is not JSON".into()))?;
    let need = ["minReaderVersion", "formatVersion"]
        .iter()
        .filter_map(|k| raw.get(*k).and_then(|v| v.as_u64()))
        .max()
        .unwrap_or(1);
    if need > 3 {
        return Err(Error::TooNew { need, have: 3 });
    }
    serde_json::from_value(raw)
        .map_err(|e| Error::Format(format!("unexpected vault contents: {e}")))
}

pub fn decrypt_raw(bytes: &[u8], password: &str) -> Result<SecretBytes> {
    let env: Envelope = serde_json::from_slice(bytes)
        .map_err(|_| Error::Format("not a v1/v2 vault envelope".into()))?;
    if !(env.v == 1 || env.v == 2) || env.kdf != "scrypt" {
        return Err(Error::UnsupportedVersion(env.v));
    }
    let salt: [u8; 16] = unb64_array(&env.salt, "salt")?;
    let iv: [u8; 12] = unb64_array(&env.iv, "iv")?;
    let tag: [u8; 16] = unb64_array(&env.tag, "tag")?;
    let mut data = unb64(&env.data, "data")?;
    data.extend_from_slice(&tag);
    let log_n = if env.v == 1 { 15 } else { 17 };
    let mut key = scrypt_key(password.as_bytes(), &salt, log_n)?;
    let cipher = Aes256Gcm::new((&key).into());
    key.zeroize();
    let plain = cipher
        .decrypt(Nonce::from_slice(&iv), data.as_slice())
        .map_err(|_| Error::Unlock)?;
    Ok(SecretBytes::new(plain))
}

#[cfg(test)]
pub(crate) mod testing {
    //! Writes v2 envelopes the way `crypto.js` does, for tests only.
    use super::*;
    use crate::crypto::{b64, random_array};

    pub fn encrypt_v2(json: &serde_json::Value, password: &str) -> Vec<u8> {
        let salt: [u8; 16] = random_array();
        let iv: [u8; 12] = random_array();
        let key = scrypt_key(password.as_bytes(), &salt, 17).unwrap();
        let cipher = Aes256Gcm::new((&key).into());
        let mut ct = cipher
            .encrypt(
                Nonce::from_slice(&iv),
                serde_json::to_vec(json).unwrap().as_slice(),
            )
            .unwrap();
        let tag = ct.split_off(ct.len() - 16);
        serde_json::to_vec(&serde_json::json!({
            "v": 2, "kdf": "scrypt", "salt": b64(&salt), "iv": b64(&iv), "tag": b64(&tag), "data": b64(&ct)
        }))
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_password_and_tampering_fail_alike() {
        let vault = serde_json::json!({"formatVersion": 3, "projects": []});
        let bytes = testing::encrypt_v2(&vault, "synthetic-password");
        assert!(decrypt(&bytes, "synthetic-password").is_ok());
        assert!(matches!(
            decrypt(&bytes, "wrong-password-x"),
            Err(Error::Unlock)
        ));
        let mut env: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        env["tag"] = serde_json::json!(crate::crypto::b64(&[0u8; 16]));
        let tampered = serde_json::to_vec(&env).unwrap();
        assert!(matches!(
            decrypt(&tampered, "synthetic-password"),
            Err(Error::Unlock)
        ));
    }

    #[test]
    fn newer_formats_are_refused() {
        let vault = serde_json::json!({"formatVersion": 3, "minReaderVersion": 5, "projects": []});
        let bytes = testing::encrypt_v2(&vault, "synthetic-password");
        assert!(matches!(
            decrypt(&bytes, "synthetic-password"),
            Err(Error::TooNew { need: 5, .. })
        ));
    }
}
