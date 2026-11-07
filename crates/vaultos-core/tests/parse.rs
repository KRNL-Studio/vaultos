//! The parsers that read untrusted bytes refuse bad input without panicking. The `fuzz/`
//! targets go further on nightly; these run on every CI build.

use proptest::prelude::*;
use vaultos_core::format::VaultFile;

proptest! {
    #[test]
    fn vault_file_parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = VaultFile::parse(&bytes);
        let _ = vaultos_core::v3::envelope_version(&bytes);
    }

    #[test]
    fn json_shaped_input_never_panics(v in 0u64..8, extra in "\\PC{0,64}") {
        let text = format!(r#"{{"v":{v},"vaultId":"{extra}","kdf":{{}},"projects":[{{"id":"{extra}"}}]}}"#);
        let _ = VaultFile::parse(text.as_bytes());
    }
}
