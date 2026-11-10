//! A web address the extension may fill on matches itself, and its site is a suffix of its
//! host.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultos_core::sites;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(s) = sites::site(text) {
        assert!(s.matches(&s), "an address does not match itself");
        assert!(
            s.host.ends_with(&s.site),
            "the site is not part of the host"
        );
    }
    if let Some(domain) = sites::registrable(&text.to_ascii_lowercase()) {
        assert!(text.to_ascii_lowercase().ends_with(&domain));
    }
});
