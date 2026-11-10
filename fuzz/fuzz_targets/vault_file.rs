//! A v4 file either fails to parse or survives a write and re-read unchanged.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultos_core::format::VaultFile;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = VaultFile::parse(data) {
        let bytes = file.to_bytes().expect("a parsed file serialises");
        let again = VaultFile::parse(&bytes).expect("a written file parses");
        assert_eq!(again.to_bytes().expect("serialises"), bytes);
    }
});
