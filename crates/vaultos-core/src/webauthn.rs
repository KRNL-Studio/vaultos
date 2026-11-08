//! The WebAuthn authenticator behind the browser extension's passkeys. A passkey is an ES256
//! (P-256) key that VaultOS makes, keeps in a login item and signs with; it reports "none"
//! attestation and a zero AAGUID, and builds the client data itself from the page's origin
//! as the browser reports it, so a page cannot have it sign for another origin.
//!
//! The authenticator data says the user was present and verified (the vault is unlocked and
//! the human chose in the extension's own window), and that the passkey may be and is backed
//! up (it is in the vault, which syncs). The signature counter is always 0, as for other
//! synced passkeys.

use crate::crypto::{fill_random, sha256};
use crate::error::{Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::json;
use zeroize::Zeroizing;

/// COSE algorithm ES256, the only one VaultOS makes.
pub const ES256: i64 = -7;
/// Credential ids VaultOS makes are 16 random bytes; ones it is asked about may be longer.
const CREDENTIAL_ID_LEN: usize = 16;
pub const MAX_CREDENTIAL_ID: usize = 1023;
/// The longest challenge and user handle accepted (the spec caps the user handle at 64).
pub const MAX_CHALLENGE: usize = 1024;
pub const MAX_USER_HANDLE: usize = 64;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
const AAGUID: [u8; 16] = [0; 16];

pub fn b64url(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Unpadded base64url, as WebAuthn's JSON forms use, at most `max` bytes decoded.
pub fn unb64url(s: &str, what: &str, max: usize) -> Result<Vec<u8>> {
    if s.len() > max.div_ceil(3) * 4 {
        return Err(Error::invalid(format!("{what} is too long")));
    }
    let b = URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| Error::invalid(format!("{what} is not base64url")))?;
    if b.len() > max {
        return Err(Error::invalid(format!("{what} is too long")));
    }
    Ok(b)
}

/// A new passkey: its credential id and private key (the P-256 scalar, base64url).
pub struct NewPasskey {
    pub credential_id: Vec<u8>,
    pub private_key: Zeroizing<String>,
}

impl std::fmt::Debug for NewPasskey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewPasskey(<redacted>)")
    }
}

pub fn new_passkey() -> NewPasskey {
    let mut credential_id = vec![0u8; CREDENTIAL_ID_LEN];
    fill_random(&mut credential_id);
    loop {
        let mut scalar = Zeroizing::new([0u8; 32]);
        fill_random(scalar.as_mut());
        // Fails only for zero or a value past the group order: about 2^-32 of the time.
        if SigningKey::from_slice(scalar.as_ref()).is_ok() {
            return NewPasskey {
                credential_id,
                private_key: Zeroizing::new(b64url(scalar.as_ref())),
            };
        }
    }
}

fn signing_key(private_key: &str) -> Result<SigningKey> {
    let raw = Zeroizing::new(unb64url(private_key, "passkey key", 32)?);
    SigningKey::from_slice(&raw).map_err(|_| Error::invalid("This passkey's key is damaged"))
}

// The few CBOR items a COSE key and an attestation object need (RFC 8949, CTAP2 canonical).
fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend([m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes());
        }
        _ => {
            out.push(m | 26);
            out.extend((n as u32).to_be_bytes());
        }
    }
}

fn int(out: &mut Vec<u8>, i: i64) {
    if i >= 0 {
        head(out, 0, i.unsigned_abs());
    } else {
        head(out, 1, (-1 - i).unsigned_abs());
    }
}

fn bytes(out: &mut Vec<u8>, b: &[u8]) {
    head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

fn text(out: &mut Vec<u8>, s: &str) {
    head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// The uncompressed point's coordinates.
fn coordinates(key: &SigningKey) -> ([u8; 32], [u8; 32]) {
    let point = key.verifying_key().to_encoded_point(false);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    if let (Some(px), Some(py)) = (point.x(), point.y()) {
        x.copy_from_slice(px);
        y.copy_from_slice(py);
    }
    (x, y)
}

/// The public key as a COSE_Key: `{1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}`.
fn cose_key(key: &SigningKey) -> Vec<u8> {
    let (x, y) = coordinates(key);
    let mut out = Vec::with_capacity(77);
    head(&mut out, 5, 5);
    for (k, v) in [(1, 2), (3, ES256), (-1, 1)] {
        int(&mut out, k);
        int(&mut out, v);
    }
    int(&mut out, -2);
    bytes(&mut out, &x);
    int(&mut out, -3);
    bytes(&mut out, &y);
    out
}

/// The public key as a DER SubjectPublicKeyInfo, which `getPublicKey()` returns.
fn spki(key: &SigningKey) -> Vec<u8> {
    // SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING 04 || x || y }
    const PREFIX: [u8; 27] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    let (x, y) = coordinates(key);
    let mut out = PREFIX.to_vec();
    out.extend_from_slice(&x);
    out.extend_from_slice(&y);
    out
}

fn auth_data(rp_id: &str, attested: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut out = sha256(rp_id.as_bytes()).to_vec();
    let at = if attested.is_some() { FLAG_AT } else { 0 };
    out.push(FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | at);
    out.extend([0, 0, 0, 0]);
    if let Some((credential_id, cose)) = attested {
        out.extend_from_slice(&AAGUID);
        out.extend((credential_id.len() as u16).to_be_bytes());
        out.extend_from_slice(credential_id);
        out.extend_from_slice(cose);
    }
    out
}

/// The client data, as a browser serializes it.
fn client_data(kind: &str, challenge: &[u8], origin: &str) -> String {
    json!({
        "type": kind,
        "challenge": b64url(challenge),
        "origin": origin,
        "crossOrigin": false,
    })
    .to_string()
}

/// ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`, the form WebAuthn's ES256 signatures take.
fn der(sig: &Signature) -> Vec<u8> {
    let bytes = sig.to_bytes();
    let integer = |v: &[u8]| {
        let v = &v[v.iter().position(|b| *b != 0).unwrap_or(v.len() - 1)..];
        let mut out = vec![0x02];
        if v[0] & 0x80 != 0 {
            out.push(v.len() as u8 + 1);
            out.push(0);
        } else {
            out.push(v.len() as u8);
        }
        out.extend_from_slice(v);
        out
    };
    let (r, s) = (integer(&bytes[..32]), integer(&bytes[32..]));
    let mut out = vec![0x30, (r.len() + s.len()) as u8];
    out.extend(r);
    out.extend(s);
    out
}

/// What `navigator.credentials.create` resolves with, in its parts.
#[derive(Debug)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub client_data_json: String,
    pub attestation_object: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Registers the passkey with the site: its public key in "none" attestation.
pub fn register(
    rp_id: &str,
    origin: &str,
    challenge: &[u8],
    credential_id: &[u8],
    private_key: &str,
) -> Result<Registration> {
    let key = signing_key(private_key)?;
    let authenticator_data = auth_data(rp_id, Some((credential_id, &cose_key(&key))));
    let mut attestation_object = Vec::with_capacity(authenticator_data.len() + 32);
    head(&mut attestation_object, 5, 3);
    text(&mut attestation_object, "fmt");
    text(&mut attestation_object, "none");
    text(&mut attestation_object, "attStmt");
    head(&mut attestation_object, 5, 0);
    text(&mut attestation_object, "authData");
    bytes(&mut attestation_object, &authenticator_data);
    Ok(Registration {
        credential_id: credential_id.to_vec(),
        client_data_json: client_data("webauthn.create", challenge, origin),
        attestation_object,
        authenticator_data,
        public_key: spki(&key),
    })
}

/// What `navigator.credentials.get` resolves with, in its parts.
#[derive(Debug)]
pub struct Assertion {
    pub client_data_json: String,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Signs in with the passkey: an ES256 signature over the authenticator data and the hash of
/// the client data.
pub fn assert(rp_id: &str, origin: &str, challenge: &[u8], private_key: &str) -> Result<Assertion> {
    let key = signing_key(private_key)?;
    let authenticator_data = auth_data(rp_id, None);
    let client_data_json = client_data("webauthn.get", challenge, origin);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&sha256(client_data_json.as_bytes()));
    let sig: Signature = key.sign(&signed);
    Ok(Assertion {
        client_data_json,
        authenticator_data,
        signature: der(&sig),
    })
}

/// Whether a page at `host` may use passkeys for `rp_id`: the host itself, or a parent
/// domain of it that is not a public suffix (WebAuthn's "registrable domain suffix"). Never
/// an IP address, which WebAuthn does not allow.
pub fn rp_id_fits(rp_id: &str, host: &str) -> bool {
    if rp_id.is_empty()
        || rp_id.len() > 253
        || rp_id != rp_id.to_ascii_lowercase()
        || rp_id.contains([':', '[', ']'])
        || rp_id.parse::<std::net::Ipv4Addr>().is_ok()
    {
        return false;
    }
    if rp_id == host {
        return true;
    }
    host.strip_suffix(rp_id)
        .is_some_and(|rest| rest.ends_with('.'))
        && crate::sites::registrable(host)
            .is_some_and(|site| rp_id == site || rp_id.ends_with(&format!(".{site}")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;

    /// r and s from a DER signature, for p256 (which reads only their fixed-size form here).
    fn undo_der(d: &[u8]) -> Signature {
        assert_eq!((d[0], d[1] as usize), (0x30, d.len() - 2));
        let mut raw = [0u8; 64];
        let mut at = 2;
        for half in 0..2 {
            assert_eq!(d[at], 0x02);
            let n = d[at + 1] as usize;
            let v = &d[at + 2..at + 2 + n];
            let v = if v.len() == 33 { &v[1..] } else { v };
            raw[half * 32 + 32 - v.len()..half * 32 + 32].copy_from_slice(v);
            at += 2 + n;
        }
        assert_eq!(at, d.len());
        Signature::from_slice(&raw).unwrap()
    }

    #[test]
    fn registers_and_signs_as_webauthn_expects() {
        let pk = new_passkey();
        let challenge = b"synthetic-challenge-0123456789ab";
        let reg = register(
            "example.com",
            "https://login.example.com",
            challenge,
            &pk.credential_id,
            &pk.private_key,
        )
        .unwrap();
        let client: serde_json::Value = serde_json::from_str(&reg.client_data_json).unwrap();
        assert_eq!(client["type"], "webauthn.create");
        assert_eq!(client["origin"], "https://login.example.com");
        assert_eq!(
            unb64url(client["challenge"].as_str().unwrap(), "c", 64).unwrap(),
            challenge
        );
        let ad = &reg.authenticator_data;
        assert_eq!(&ad[..32], &sha256(b"example.com"));
        assert_eq!(ad[32], 0x5d);
        assert_eq!(&ad[33..37], &[0, 0, 0, 0]);
        assert_eq!(&ad[37..53], &AAGUID);
        assert_eq!(&ad[53..55], &[0, 16]);
        assert_eq!(&ad[55..71], pk.credential_id.as_slice());
        let cose = &ad[71..];
        assert_eq!(cose.len(), 77);
        assert_eq!(
            &cose[..10],
            &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
        );
        // fmt "none", attStmt {}, then the same authenticator data.
        assert_eq!(&reg.attestation_object[..1], &[0xa3]);
        assert!(reg.attestation_object.ends_with(ad));

        assert_eq!(reg.public_key.len(), 91);
        let public = VerifyingKey::from_sec1_bytes(&reg.public_key[26..]).unwrap();
        assert_eq!(
            &public.to_encoded_point(false).as_bytes()[1..33],
            &cose[10..42]
        );

        let a = assert(
            "example.com",
            "https://login.example.com",
            b"second-challenge",
            &pk.private_key,
        )
        .unwrap();
        assert_eq!(a.authenticator_data.len(), 37);
        assert_eq!(a.authenticator_data[32], 0x1d);
        let mut signed = a.authenticator_data.clone();
        signed.extend_from_slice(&sha256(a.client_data_json.as_bytes()));
        let sig = undo_der(&a.signature);
        assert!(public.verify(&signed, &sig).is_ok());
        assert!(a
            .client_data_json
            .starts_with(r#"{"type":"webauthn.get","challenge":"#));
    }

    #[test]
    fn encodes_der_integers_minimally() {
        let mut raw = [0u8; 64];
        raw[31] = 1;
        raw[32] = 0x80;
        raw[63] = 2;
        let sig = Signature::from_slice(&raw).unwrap();
        let d = der(&sig);
        assert_eq!(&d[..5], &[0x30, 0x26, 0x02, 0x01, 0x01]);
        assert_eq!(&d[5..8], &[0x02, 0x21, 0x00]);
        assert_eq!(undo_der(&d), sig);
    }

    #[test]
    fn relying_party_ids_fit_the_page() {
        assert!(rp_id_fits("example.com", "example.com"));
        assert!(rp_id_fits("example.com", "login.example.com"));
        assert!(rp_id_fits("login.example.com", "login.example.com"));
        assert!(!rp_id_fits("login.example.com", "example.com"));
        assert!(!rp_id_fits("com", "example.com"));
        assert!(!rp_id_fits("co.uk", "shop.example.co.uk"));
        assert!(!rp_id_fits("github.io", "alice.github.io"));
        assert!(!rp_id_fits("ample.com", "example.com"));
        assert!(!rp_id_fits("other.com", "example.com"));
        assert!(!rp_id_fits("Example.com", "example.com"));
        assert!(!rp_id_fits("", "example.com"));
        assert!(rp_id_fits("localhost", "localhost"));
        assert!(!rp_id_fits("127.0.0.1", "127.0.0.1"));
        assert!(!rp_id_fits("[::1]", "[::1]"));
    }

    #[test]
    fn decodes_bounded_base64url() {
        assert_eq!(unb64url("AQID", "x", 3).unwrap(), [1, 2, 3]);
        assert!(unb64url("AQIDBA", "x", 3).is_err());
        assert!(unb64url("+/==", "x", 3).is_err());
    }
}
