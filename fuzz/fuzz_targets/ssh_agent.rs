//! SSH agent requests, public key lines and private keys either fail to parse or are read
//! consistently; a key survives being written and read again. Arbitrary bytes almost never
//! make a valid key, so the round trip also starts from a key built from the input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultos_core::ssh;

fuzz_target!(|data: &[u8]| {
    if let Some((seed, comment)) = data.split_first_chunk::<32>() {
        if let Ok(comment) = std::str::from_utf8(comment) {
            let key = ssh::SshKey::from_seed(seed, comment);
            let again = ssh::SshKey::parse(&key.to_openssh()).expect("a written key parses");
            assert_eq!(again.public_blob(), key.public_blob());
            assert_eq!(again.comment, key.comment);
        }
    }
    let _ = ssh::Request::parse(data);
    let _ = ssh::purpose(data);
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = ssh::parse_public_line(text);
    if let Ok(key) = ssh::SshKey::parse(text) {
        let again = ssh::SshKey::parse(&key.to_openssh()).expect("a written key parses");
        assert_eq!(again.public_blob(), key.public_blob());
    }
});
