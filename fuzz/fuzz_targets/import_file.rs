//! Import files (a 1Password `.1pux` ZIP, Bitwarden JSON, CSV) fail cleanly or parse,
//! however damaged.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultos_core::import::{self, Format};

fuzz_target!(|data: &[u8]| {
    for format in [Format::OnePux, Format::Bitwarden, Format::Csv] {
        let _ = import::parse(format, data);
    }
});
