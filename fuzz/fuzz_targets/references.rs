//! A `vault://` reference survives being written and read again, so does one made from any
//! names VaultOS can store, and a template's placeholders are in order and do not overlap.
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
    // Three names, one per line, of the kind VaultOS stores: at most 256 UTF-16 units each.
    let names: Vec<&str> = text.split('\n').collect();
    if let [project, item, field] = names.as_slice() {
        let storable = |s: &str| {
            !s.trim().is_empty()
                && !s.chars().any(char::is_control)
                && s.encode_utf16().count() <= 256
        };
        if storable(project) && storable(item) && storable(field) {
            let r = SecretRef {
                project: (*project).to_owned(),
                item: (*item).to_owned(),
                field: (*field).to_owned(),
            };
            let again = SecretRef::parse(&r.to_uri()).expect("a reference to stored names parses");
            assert_eq!(again, r);
        }
    }
    if let Ok(found) = refs::placeholders(text) {
        for pair in found.windows(2) {
            assert!(pair[0].end <= pair[1].start, "placeholders overlap");
        }
        let values: Vec<&str> = found.iter().map(|_| "x").collect();
        let _ = refs::render(text, &found, &values);
    }
});
