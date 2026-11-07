//! Secret material in memory: fixed-size keys and byte strings that are zeroed when dropped,
//! never printed by `Debug`, and (where the OS allows) locked out of swap.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit key. Zeroed on drop, redacted in `Debug`, compared in constant time.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key32(Box<[u8; 32]>);

impl Clone for Key32 {
    fn clone(&self) -> Self {
        Key32::from_bytes(*self.0)
    }
}

impl Key32 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut boxed = Box::new(bytes);
        let mut bytes = bytes;
        bytes.zeroize();
        lock_memory(boxed.as_mut_ptr(), 32);
        Key32(boxed)
    }

    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        crate::crypto::fill_random(&mut bytes);
        let key = Key32::from_bytes(bytes);
        bytes.zeroize();
        key
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for Key32 {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&*other.0).into()
    }
}

impl Eq for Key32 {}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key32(<redacted>)")
    }
}

/// Overwrites every string in `v`, a reply or request that may carry values, before it is
/// dropped. Object keys are names, not values, and are kept.
pub fn scrub_json(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(a) => a.iter_mut().for_each(scrub_json),
        serde_json::Value::Object(m) => m.values_mut().for_each(scrub_json),
        _ => {}
    }
}

/// A variable-length secret (a password, a decrypted value). Zeroed on drop.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        SecretString(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        SecretString(s.to_owned())
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        SecretString(s)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(<{} bytes redacted>)", self.0.len())
    }
}

/// Bytes that must not outlive their use: decrypted plaintext buffers.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(v: Vec<u8>) -> Self {
        SecretBytes(v)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.0.len())
    }
}

/// A JSON value that holds key material, such as a device's sync keys: stored as the value
/// itself, redacted in `Debug`, and its strings zeroed when dropped.
#[derive(Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SecretValue(serde_json::Value);

impl SecretValue {
    pub fn new(v: serde_json::Value) -> Self {
        SecretValue(v)
    }

    pub fn expose(&self) -> &serde_json::Value {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        fn wipe(v: &mut serde_json::Value) {
            match v {
                serde_json::Value::String(s) => s.zeroize(),
                serde_json::Value::Array(a) => a.iter_mut().for_each(wipe),
                serde_json::Value::Object(o) => o.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

/// Best effort: keeps the page holding a key out of swap. Failure (an RLIMIT_MEMLOCK
/// limit, an unsupported OS) leaves the key usable; it only loses this protection.
fn lock_memory(ptr: *mut u8, len: usize) {
    #[cfg(unix)]
    // SAFETY: mlock only reads the address range, which is a live allocation of `len` bytes.
    unsafe {
        libc::mlock(ptr.cast(), len);
    }
    #[cfg(not(unix))]
    let _ = (ptr, len);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_secrets() {
        let k = Key32::from_bytes([7u8; 32]);
        let s = SecretString::new("synthetic-only");
        assert!(!format!("{k:?}").contains('7'));
        assert!(!format!("{s:?}").contains("synthetic"));
        let v = SecretValue::new(serde_json::json!({ "seed": "synthetic-seed" }));
        assert!(!format!("{v:?}").contains("synthetic"));
        assert_eq!(
            serde_json::to_string(&v).unwrap_or_default(),
            r#"{"seed":"synthetic-seed"}"#
        );
    }

    #[test]
    fn keys_compare_by_value() {
        assert_eq!(Key32::from_bytes([1; 32]), Key32::from_bytes([1; 32]));
        assert_ne!(Key32::from_bytes([1; 32]), Key32::from_bytes([2; 32]));
    }
}
