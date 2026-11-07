//! Anything accepted as a Secret Key prints back to a form that parses to the same key.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultos_core::SecretKey;

fuzz_target!(|text: &str| {
    if let Ok(key) = SecretKey::parse(text) {
        assert_eq!(SecretKey::parse(key.display().expose()).expect("display parses"), key);
    }
});
