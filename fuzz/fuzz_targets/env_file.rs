//! An env file either fails to parse or gives each key once.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultos_core::env;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(entries) = env::parse(text) {
        let mut keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), entries.len(), "a key appears twice");
    }
});
