//! Touch ID unlock: the master password sealed (ECIES, P-256, AES-GCM) to a Secure Enclave
//! key that only a Touch ID match on this Mac can use. The key is made with the current
//! fingerprints (adding or removing one invalidates it) and never leaves the enclave; the
//! file holds the enclave's wrapped form of it, which no other Mac can use, and the sealed
//! password. Needs no keychain entitlement, so it works in a Developer ID or unsigned build.

use std::path::Path;
use vaultos_core::SecretString;

pub const FILE: &str = "touch-id-unlock.json";

pub enum Unsealed {
    #[cfg_attr(
        not(target_os = "macos"),
        expect(dead_code, reason = "only the Secure Enclave opens one")
    )]
    Password(SecretString),
    /// Touch ID was not confirmed.
    Canceled,
    /// No sealed password, or one this Mac can no longer open (fingerprints changed).
    Unavailable,
}

pub fn exists(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join(FILE)).is_ok_and(|m| m.is_file())
}

pub fn remove(dir: &Path) {
    if exists(dir) {
        let _ = std::fs::remove_file(dir.join(FILE));
    }
}

#[cfg(target_os = "macos")]
pub use mac::{open, seal};

#[cfg(not(target_os = "macos"))]
pub fn seal(_: &Path, _: &SecretString) -> Result<(), String> {
    Err("Touch ID is not available on this device".into())
}

#[cfg(not(target_os = "macos"))]
pub fn open(_: &Path, _: &str) -> Unsealed {
    Unsealed::Unavailable
}

#[cfg(target_os = "macos")]
mod mac {
    use super::{Unsealed, FILE};
    use core_foundation::base::{CFOptionFlags, CFType, TCFType};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use objc2::rc::Retained;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
    use security_framework_sys::access_control::{
        kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
    };
    use security_framework_sys::item::{
        kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeyType,
        kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
        kSecUseAuthenticationContext,
    };
    use serde_json::{json, Value};
    use std::path::Path;
    use vaultos_core::crypto::{b64, unb64};
    use vaultos_core::fs_safe::{atomic_write, read_regular};
    use vaultos_core::SecretString;
    use zeroize::Zeroizing;

    const ALGORITHM: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
    /// The enclave's wrapped key, in the key's attributes (kSecAttrTokenOID).
    const TOKEN_OBJECT: &str = "toid";

    /// Seals `password` to a new enclave key and replaces the file. Making the key and
    /// sealing need no Touch ID; only opening does.
    pub fn seal(dir: &Path, password: &SecretString) -> Result<(), String> {
        seal_with(
            dir,
            password,
            kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage,
        )
    }

    pub(super) fn seal_with(
        dir: &Path,
        password: &SecretString,
        flags: CFOptionFlags,
    ) -> Result<(), String> {
        let unavailable = |_| "The Secure Enclave is not available".to_owned();
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            flags,
        )
        .map_err(|_| "The Secure Enclave is not available".to_owned())?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_access_control(access);
        let key = SecKey::new(&options).map_err(unavailable)?;
        let wrapped = key
            .attributes()
            .find(CFString::new(TOKEN_OBJECT).as_CFTypeRef())
            // SAFETY: the enclave's token object is a CFData.
            .map(|v| {
                unsafe { CFData::wrap_under_get_rule(*v as _) }
                    .bytes()
                    .to_vec()
            })
            .ok_or("The Secure Enclave key has no wrapped form")?;
        let public = key
            .public_key()
            .ok_or("The Secure Enclave key has no public key")?;
        let sealed = public
            .encrypt_data(ALGORITHM, password.expose().as_bytes())
            .map_err(unavailable)?;
        let doc = json!({ "v": 1, "key": b64(&wrapped), "sealed": b64(&sealed) });
        atomic_write(&dir.join(FILE), doc.to_string().as_bytes()).map_err(|e| e.to_string())
    }

    /// Asks for Touch ID ("VaultOS is trying to `reason`") and opens the sealed password.
    /// Blocks until answered; call it off the main thread.
    pub fn open(dir: &Path, reason: &str) -> Unsealed {
        let Some((wrapped, sealed)) = read(dir) else {
            return Unsealed::Unavailable;
        };
        let Some(context) = crate::platform::mac::evaluated(reason) else {
            return Unsealed::Canceled;
        };
        match decrypt(&wrapped, &sealed, &context) {
            Some(pw) => Unsealed::Password(pw),
            None => Unsealed::Unavailable,
        }
    }

    pub(super) fn read(dir: &Path) -> Option<(Vec<u8>, Vec<u8>)> {
        let bytes = read_regular(&dir.join(FILE), 8192).ok()?;
        let doc: Value = serde_json::from_slice(&bytes).ok()?;
        if doc["v"] != json!(1) {
            return None;
        }
        let field = |k: &str| unb64(doc[k].as_str()?, k).ok();
        Some((field("key")?, field("sealed")?))
    }

    pub(super) fn decrypt(
        wrapped: &[u8],
        sealed: &[u8],
        context: &Retained<objc2_local_authentication::LAContext>,
    ) -> Option<SecretString> {
        // SAFETY: an Objective-C object is a CFType; the dictionary retains it while used.
        let context = unsafe { CFType::wrap_under_get_rule(Retained::as_ptr(context).cast()) };
        // SAFETY: Security framework constants.
        let attributes = unsafe {
            CFDictionary::from_CFType_pairs(&[
                (
                    CFType::wrap_under_get_rule(kSecAttrKeyType.cast()),
                    CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom.cast()),
                ),
                (
                    CFType::wrap_under_get_rule(kSecAttrKeyClass.cast()),
                    CFType::wrap_under_get_rule(kSecAttrKeyClassPrivate.cast()),
                ),
                (
                    CFType::wrap_under_get_rule(kSecAttrTokenID.cast()),
                    CFType::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave.cast()),
                ),
                (
                    CFString::new(TOKEN_OBJECT).as_CFType(),
                    CFData::from_buffer(wrapped).as_CFType(),
                ),
                (
                    CFType::wrap_under_get_rule(kSecUseAuthenticationContext.cast()),
                    context,
                ),
            ])
        };
        let mut error = std::ptr::null_mut();
        // SAFETY: valid dictionary and empty data; the result follows the create rule.
        let key = unsafe {
            security_framework_sys::key::SecKeyCreateWithData(
                CFData::from_buffer(&[]).as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &mut error,
            )
        };
        if key.is_null() {
            if !error.is_null() {
                // SAFETY: an error returned to us under the create rule.
                drop(unsafe { core_foundation::error::CFError::wrap_under_create_rule(error) });
            }
            return None;
        }
        // SAFETY: a new key under the create rule.
        let key = unsafe { SecKey::wrap_under_create_rule(key) };
        let plain = Zeroizing::new(key.decrypt_data(ALGORITHM, sealed).ok()?);
        let text = std::str::from_utf8(&plain).ok()?;
        Some(SecretString::new(text.to_owned()))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]
    use super::mac::{decrypt, read, seal_with};
    use super::{exists, remove};
    use objc2_local_authentication::LAContext;
    use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
    use vaultos_core::SecretString;

    /// The file, the wrapped key and the sealed password round-trip. The key here needs no
    /// Touch ID; the app's own key needs a match, which a test cannot give. Skips where
    /// there is no Secure Enclave (virtual machines).
    #[test]
    fn seals_and_opens_with_the_enclave() {
        let dir = tempfile::tempdir().unwrap();
        let pw = SecretString::new("synthetic-enclave-password".to_owned());
        if seal_with(dir.path(), &pw, kSecAccessControlPrivateKeyUsage).is_err() {
            eprintln!("no Secure Enclave here; skipped");
            return;
        }
        assert!(exists(dir.path()));
        let (wrapped, sealed) = read(dir.path()).unwrap();
        assert!(!sealed.windows(8).any(|w| w == b"enclave-"));
        // SAFETY: a fresh context.
        let context = unsafe { LAContext::new() };
        let open = decrypt(&wrapped, &sealed, &context).unwrap();
        assert_eq!(open.expose(), pw.expose());
        let mut other = wrapped.clone();
        let last = other.len() - 1;
        other[last] ^= 1;
        assert!(decrypt(&other, &sealed, &context).is_none());
        remove(dir.path());
        assert!(!exists(dir.path()));
    }
}
