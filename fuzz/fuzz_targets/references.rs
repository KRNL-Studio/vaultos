//! A `vault://` reference survives being written and read again, and a template's
//! placeholders are in order and do not overlap.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultos_core::refs::{self, SecretRef};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(r) = SecretRef::parse(text) {
        let again = SecretRef::parse(&r.to_uri()).expect("a written reference parses");
        assert_eq!(again, r);
    }
    if let Ok(found) = refs::placeholders(text) {
        for pair in found.windows(2) {
            assert!(pair[0].end <= pair[1].start, "placeholders overlap");
        }
        let values: Vec<&str> = found.iter().map(|_| "x").collect();
        let _ = refs::render(text, &found, &values);
    }
});
