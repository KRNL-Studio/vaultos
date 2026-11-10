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

/// A JSON value that holds key material, such as a device's sync keys. It is kept as its
/// JSON text in one buffer that is locked out of swap (where the OS allows) and zeroed when
/// dropped, and is redacted in `Debug`. [`SecretValue::open`] parses it for one use.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretValue(Box<[u8]>);

/// A [`SecretValue`] parsed for one use; its strings are zeroed when it is dropped.
pub struct OpenValue(serde_json::Value);

impl fmt::Debug for OpenValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenValue(<redacted>)")
    }
}

impl std::ops::Deref for OpenValue {
    type Target = serde_json::Value;

    fn deref(&self) -> &serde_json::Value {
        &self.0
    }
}

impl Drop for OpenValue {
    fn drop(&mut self) {
        scrub_json(&mut self.0);
    }
}

impl SecretValue {
    /// Takes the value, zeroing the caller's copy of its strings.
    pub fn new(v: serde_json::Value) -> Self {
        let v = OpenValue(v);
        // Sized first, so the text is written once into memory that is already locked and
        // never passes through a growing buffer.
        struct Count(usize);
        impl std::io::Write for Count {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0 += b.len();
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut n = Count(0);
        if serde_json::to_writer(&mut n, &*v).is_err() {
            return SecretValue::default();
        }
        let mut buf = vec![0u8; n.0].into_boxed_slice();
        lock_memory(buf.as_mut_ptr(), buf.len());
        if serde_json::to_writer(&mut buf[..], &*v).is_err() {
            buf.zeroize();
            return SecretValue::default();
        }
        SecretValue(buf)
    }

    /// The value, for one use. Null if there is none.
    pub fn open(&self) -> OpenValue {
        OpenValue(serde_json::from_slice(&self.0).unwrap_or(serde_json::Value::Null))
    }
}

impl Default for SecretValue {
    fn default() -> Self {
        SecretValue(Box::from(*b"null"))
    }
}

impl Clone for SecretValue {
    fn clone(&self) -> Self {
        let mut buf = vec![0u8; self.0.len()].into_boxed_slice();
        lock_memory(buf.as_mut_ptr(), buf.len());
        buf.copy_from_slice(&self.0);
        SecretValue(buf)
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

impl serde::Serialize for SecretValue {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.open().0, s)
    }
}

impl<'de> serde::Deserialize<'de> for SecretValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(SecretValue::new(
            <serde_json::Value as serde::Deserialize>::deserialize(d)?,
        ))
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
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
    fn a_secret_value_round_trips_and_wipes_what_it_was_given() {
        let v = SecretValue::new(serde_json::json!({ "seed": "synthetic-seed", "n": [1, "two"] }));
        assert_eq!(v.open()["seed"], "synthetic-seed");
        assert_eq!(v.open()["n"][1], "two");
        assert_eq!(v, v.clone());
        assert_ne!(v, SecretValue::default());
        assert!(SecretValue::default().open().is_null());
        let back: SecretValue =
            serde_json::from_str(&serde_json::to_string(&v).unwrap_or_default())
                .unwrap_or_default();
        assert_eq!(back, v);
    }

    #[test]
    fn keys_compare_by_value() {
        assert_eq!(Key32::from_bytes([1; 32]), Key32::from_bytes([1; 32]));
        assert_ne!(Key32::from_bytes([1; 32]), Key32::from_bytes([2; 32]));
    }
}
