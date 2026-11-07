//! Known-answer vectors for format v4 (`docs/audit/CRYPTO.md`): fixed inputs and the outputs
//! this implementation must keep producing, so an independent implementation can be checked
//! against them and a change to the format cannot pass unnoticed. Synthetic inputs only.

#![allow(clippy::unwrap_used, reason = "test")]

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde_json::{json, Value};
use vaultos_core::crypto::{argon2id, b64, hex, hmac_sha256_parts, Sealed};
use vaultos_core::format::{account_unlock_key, mac_key, KdfHeader};
use vaultos_core::secret::Key32;
use vaultos_core::{KdfParams, SecretKey, SecretString};

const VAULT_ID: &str = "00112233445566778899aabbccddeeff";
const PASSWORD: &str = "synthetic vector password";
const PLAINTEXT: &str = "{\"name\":\"synthetic vault\"}";

/// `n` bytes counting up from `start`.
fn run(start: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| start.wrapping_add(i as u8)).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn format_v4_known_answers() {
    let floor = KdfParams::FLOOR;
    let salt: [u8; 16] = run(0x00, 16).try_into().unwrap();
    let kdf = KdfHeader {
        alg: "argon2id".into(),
        m: floor.m,
        t: floor.t,
        p: floor.p,
        salt: b64(&salt),
    };
    let password = SecretString::new(PASSWORD);
    let pwk = argon2id(PASSWORD.as_bytes(), &salt, floor).unwrap();
    let secret_key = SecretKey::from_bytes(run(0x10, 16).try_into().unwrap());
    let auk = account_unlock_key(&password, None, &kdf, VAULT_ID).unwrap();
    let auk_both = account_unlock_key(&password, Some(&secret_key), &kdf, VAULT_ID).unwrap();
    let vault_key = Key32::from_bytes(run(0x20, 32).try_into().unwrap());
    let file_mac_key = mac_key(&vault_key, VAULT_ID).unwrap();
    let file = br#"{"v":4}"#;
    let file_mac = hmac_sha256_parts(&file_mac_key, &[b"vaultos/v4/file\0", file]);

    // The vault metadata box: XChaCha20-Poly1305 under the vault key, its associated data the
    // purpose and the vault id, NUL-separated.
    let aad = [b"vaultos/v4/meta\0".as_slice(), VAULT_ID.as_bytes()].concat();
    let nonce = run(0x40, 24);
    let ciphertext = XChaCha20Poly1305::new(vault_key.expose().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: PLAINTEXT.as_bytes(),
                aad: &aad,
            },
        )
        .unwrap();

    let actual = json!({
        "inputs": {
            "password": PASSWORD,
            "salt": hex(&salt),
            "kdf": { "alg": "argon2id", "m": floor.m, "t": floor.t, "p": floor.p },
            "vaultId": VAULT_ID,
            "secretKey": hex(secret_key.expose()),
            "vaultKey": hex(vault_key.expose()),
            "fileBytes": std::str::from_utf8(file).unwrap(),
            "boxNonce": hex(&nonce),
            "boxPlaintext": PLAINTEXT,
        },
        "argon2id": hex(pwk.expose()),
        "accountUnlockKey": hex(auk.expose()),
        "accountUnlockKeyWithSecretKey": hex(auk_both.expose()),
        "fileMacKey": hex(file_mac_key.expose()),
        "fileMac": hex(&file_mac),
        "boxAad": hex(&aad),
        "boxCiphertext": hex(&ciphertext),
        "secretKeyDisplay": secret_key.display().expose(),
        "secretKeyId": secret_key.id(),
    });
    let expected: Value = serde_json::from_str(include_str!("fixtures/v4-vectors.json")).unwrap();
    assert_eq!(
        actual,
        expected,
        "{}",
        serde_json::to_string_pretty(&actual).unwrap()
    );

    // The recorded box opens through the store's own code, with the same associated data.
    let sealed = Sealed {
        n: b64(&unhex(expected["inputs"]["boxNonce"].as_str().unwrap())),
        c: b64(&unhex(expected["boxCiphertext"].as_str().unwrap())),
    };
    let opened = sealed.open(&vault_key, &aad).unwrap();
    assert_eq!(opened.expose(), PLAINTEXT.as_bytes());
    assert!(sealed.open(&vault_key, b"vaultos/v4/history").is_err());
    // And the Secret Key reads back from its displayed form.
    let shown = secret_key.display();
    assert_eq!(
        SecretKey::parse(shown.expose()).unwrap().expose(),
        secret_key.expose()
    );
}
