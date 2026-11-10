//! Reading the envelope of a previous-format file never panics. (Decryption itself runs
//! scrypt, too slow to fuzz.)
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vaultos_core::v3::envelope_version(data);
});
