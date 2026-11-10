//! An `otpauth://` URI or Base32 secret either fails to parse or gives codes of its digits.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultos_core::totp::Totp;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(t) = Totp::parse(text) {
        for unix in [0, 1_700_000_000, u64::MAX] {
            let code = t.code(unix);
            assert_eq!(code.len(), t.digits as usize);
            assert!(code.bytes().all(|b| b.is_ascii_digit()));
            assert!(t.remaining(unix) <= t.period);
        }
    }
});
