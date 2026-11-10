//! SSH keys: Ed25519 keys in OpenSSH's private key format, the SSH agent protocol's messages
//! (draft-miller-ssh-agent) and SSHSIG signatures (OpenSSH's PROTOCOL.sshsig), which Git uses
//! to sign commits with SSH keys. Keys protected by a passphrase are not read: the vault
//! already encrypts them.

use crate::crypto::{b64, sha256};
use crate::error::{Error, Result};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

pub const ED25519: &str = "ssh-ed25519";
const MAGIC: &[u8] = b"openssh-key-v1\0";
// Split so secret scanners do not read the armor lines themselves as a key.
const PEM_BEGIN: &str = concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----");
const PEM_END: &str = concat!("-----END OPENSSH ", "PRIVATE KEY-----");
const SIG_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const SIG_END: &str = "-----END SSH SIGNATURE-----";
const SSHSIG: &[u8] = b"SSHSIG";

pub const FAILURE: u8 = 5;
pub const REQUEST_IDENTITIES: u8 = 11;
pub const IDENTITIES_ANSWER: u8 = 12;
pub const SIGN_REQUEST: u8 = 13;
pub const SIGN_RESPONSE: u8 = 14;
/// The longest agent message read: requests to sign are small.
pub const MAX_MESSAGE: usize = 256 * 1024;

/// An Ed25519 key pair. The private half is zeroed when dropped.
pub struct SshKey {
    key: SigningKey,
    pub comment: String,
}

impl std::fmt::Debug for SshKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshKey")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl SshKey {
    pub fn generate(comment: &str) -> SshKey {
        let seed = Zeroizing::new(crate::crypto::random_array::<32>());
        SshKey::from_seed(&seed, comment)
    }

    /// The key pair for a 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32], comment: &str) -> SshKey {
        SshKey {
            key: SigningKey::from_bytes(seed),
            comment: comment.to_owned(),
        }
    }

    /// Reads an unencrypted OpenSSH private key (PEM armored, as `ssh-keygen` writes it).
    pub fn parse(pem: &str) -> Result<SshKey> {
        let bad = || Error::invalid("This is not an OpenSSH private key");
        let body = pem
            .trim()
            .strip_prefix(PEM_BEGIN)
            .and_then(|b| b.strip_suffix(PEM_END))
            .ok_or_else(bad)?;
        let mut text = Zeroizing::new(String::with_capacity(body.len()));
        text.extend(body.chars().filter(|c| !c.is_whitespace()));
        let bytes = Zeroizing::new(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text.as_bytes())
                .map_err(|_| bad())?,
        );
        let mut r = Reader(bytes.strip_prefix(MAGIC).ok_or_else(bad)?);
        let (cipher, kdf) = (r.string()?, r.string()?);
        r.string()?;
        if cipher != b"none" || kdf != b"none" {
            return Err(Error::invalid(
                "This SSH key has a passphrase. Remove it first (ssh-keygen -p -N \"\" -f KEY on a copy); the vault encrypts the key",
            ));
        }
        if r.u32()? != 1 {
            return Err(Error::invalid("Only files with one SSH key can be read"));
        }
        r.string()?;
        let mut p = Reader(r.string()?);
        if p.u32()? != p.u32()? {
            return Err(bad());
        }
        if p.string()? != ED25519.as_bytes() {
            return Err(Error::invalid(
                "Only Ed25519 SSH keys can be used by the VaultOS SSH agent",
            ));
        }
        let public = p.string()?;
        let private = p.string()?;
        let comment = String::from_utf8_lossy(p.string()?).into_owned();
        if public.len() != 32 || private.len() != 64 || private[32..] != *public {
            return Err(bad());
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&private[..32]);
        let key = SigningKey::from_bytes(&seed);
        if key.verifying_key().as_bytes() != public {
            return Err(Error::invalid("This SSH key's halves do not match"));
        }
        Ok(SshKey { key, comment })
    }

    /// The key in OpenSSH's format, as `ssh-keygen -t ed25519` writes it.
    pub fn to_openssh(&self) -> Zeroizing<String> {
        let public = self.key.verifying_key().to_bytes();
        let mut private = Zeroizing::new(Vec::new());
        let check = u32::from_ne_bytes(crate::crypto::random_array::<4>());
        put_u32(&mut private, check);
        put_u32(&mut private, check);
        put_string(&mut private, ED25519.as_bytes());
        put_string(&mut private, &public);
        let mut pair = Zeroizing::new(self.key.to_bytes().to_vec());
        pair.extend_from_slice(&public);
        put_string(&mut private, &pair);
        put_string(&mut private, self.comment.as_bytes());
        for pad in 1..=7u8 {
            if private.len() % 8 == 0 {
                break;
            }
            private.push(pad);
        }
        let mut out = Zeroizing::new(MAGIC.to_vec());
        for s in [&b"none"[..], b"none", b""] {
            put_string(&mut out, s);
        }
        put_u32(&mut out, 1);
        put_string(&mut out, &self.public_blob());
        put_string(&mut out, &private);
        Zeroizing::new(armor(PEM_BEGIN, &out, PEM_END))
    }

    /// The public key in the wire format: `string "ssh-ed25519", string key`.
    pub fn public_blob(&self) -> Vec<u8> {
        public_blob(self.key.verifying_key().as_bytes())
    }

    /// `ssh-ed25519 AAAA… comment`, for `authorized_keys` and Git's `user.signingkey`.
    pub fn public_line(&self) -> String {
        let line = format!("{ED25519} {}", b64(&self.public_blob()));
        match self.comment.trim() {
            "" => line,
            c => format!("{line} {c}"),
        }
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_blob())
    }

    /// An SSH signature blob: `string "ssh-ed25519", string signature`.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(83);
        put_string(&mut out, ED25519.as_bytes());
        put_string(&mut out, &self.key.sign(data).to_bytes());
        out
    }
}

fn public_blob(key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(51);
    put_string(&mut out, ED25519.as_bytes());
    put_string(&mut out, key);
    out
}

/// `SHA256:…`, as `ssh-keygen -l` and `ssh-add -l` show it.
pub fn fingerprint(blob: &[u8]) -> String {
    use base64::Engine;
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha256(blob))
    )
}

/// The key blob of a public key line (`ssh-ed25519 AAAA… comment`, with Git's optional
/// `key::` prefix).
pub fn parse_public_line(line: &str) -> Option<Vec<u8>> {
    let line = line.trim();
    let line = line.strip_prefix("key::").unwrap_or(line);
    let mut words = line.split_whitespace();
    let kind = words.next()?;
    let blob = crate::crypto::unb64(words.next()?, "public key").ok()?;
    let mut r = Reader(&blob);
    (r.string().ok()? == kind.as_bytes()).then_some(())?;
    Some(blob)
}

fn armor(begin: &str, bytes: &[u8], end: &str) -> String {
    let text = Zeroizing::new(b64(bytes));
    let mut out = String::with_capacity(text.len() + text.len() / 70 + begin.len() + end.len() + 4);
    out.push_str(begin);
    out.push('\n');
    for chunk in text.as_bytes().chunks(70) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(end);
    out.push('\n');
    out
}

pub fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_be_bytes());
}

pub fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    put_u32(out, u32::try_from(s.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(s);
}

/// Reads SSH wire types from a buffer.
#[derive(Debug)]
pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn u8(&mut self) -> Result<u8> {
        let (&b, rest) = self.0.split_first().ok_or_else(short)?;
        self.0 = rest;
        Ok(b)
    }

    pub fn u32(&mut self) -> Result<u32> {
        let (n, rest) = self.0.split_first_chunk::<4>().ok_or_else(short)?;
        self.0 = rest;
        Ok(u32::from_be_bytes(*n))
    }

    pub fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > self.0.len() {
            return Err(short());
        }
        let (s, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(s)
    }
}

fn short() -> Error {
    Error::invalid("The SSH data is cut short")
}

/// An agent request the VaultOS agent answers; anything else gets `SSH_AGENT_FAILURE`.
#[derive(Debug, PartialEq, Eq)]
pub enum Request<'a> {
    List,
    Sign { key: &'a [u8], data: &'a [u8] },
    Other(u8),
}

impl<'a> Request<'a> {
    pub fn parse(message: &'a [u8]) -> Result<Request<'a>> {
        let mut r = Reader(message);
        Ok(match r.u8()? {
            REQUEST_IDENTITIES => Request::List,
            SIGN_REQUEST => {
                let key = r.string()?;
                let data = r.string()?;
                Request::Sign { key, data }
            }
            other => Request::Other(other),
        })
    }
}

/// `SSH_AGENT_IDENTITIES_ANSWER` for (key blob, comment) pairs.
pub fn identities_answer(keys: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut out = vec![IDENTITIES_ANSWER];
    put_u32(&mut out, u32::try_from(keys.len()).unwrap_or(0));
    for (blob, comment) in keys {
        put_string(&mut out, blob);
        put_string(&mut out, comment.as_bytes());
    }
    out
}

pub fn sign_response(signature: &[u8]) -> Vec<u8> {
    let mut out = vec![SIGN_RESPONSE];
    put_string(&mut out, signature);
    out
}

/// What data to be signed is for, to word the confirmation: an SSHSIG namespace (`git`,
/// `file`) or the user an SSH login is for.
#[derive(Debug, PartialEq, Eq)]
pub enum Purpose {
    Namespace(String),
    Login(String),
    Unknown,
}

pub fn purpose(data: &[u8]) -> Purpose {
    let text = |b: &[u8]| {
        String::from_utf8_lossy(b)
            .chars()
            .take(64)
            .collect::<String>()
    };
    if let Some(rest) = data.strip_prefix(SSHSIG) {
        return Reader(rest)
            .string()
            .map_or(Purpose::Unknown, |ns| Purpose::Namespace(text(ns)));
    }
    // SSH_MSG_USERAUTH_REQUEST: string session id, byte 50, string user, ...
    let mut r = Reader(data);
    match (r.string(), r.u8(), r.string()) {
        (Ok(_), Ok(50), Ok(user)) => Purpose::Login(text(user)),
        _ => Purpose::Unknown,
    }
}

/// What an SSHSIG signature signs: the namespace and the SHA-512 of the message.
pub fn sshsig_signed_data(namespace: &str, message: &[u8]) -> Vec<u8> {
    let mut out = SSHSIG.to_vec();
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, b"sha512");
    put_string(&mut out, &Sha512::digest(message));
    out
}

/// The armored signature `ssh-keygen -Y sign` writes.
pub fn sshsig_armor(public_blob: &[u8], namespace: &str, signature: &[u8]) -> String {
    let mut out = SSHSIG.to_vec();
    put_u32(&mut out, 1);
    put_string(&mut out, public_blob);
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, b"sha512");
    put_string(&mut out, signature);
    armor(SIG_BEGIN, &out, SIG_END)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_openssh_keys() {
        let key = SshKey::generate("synthetic@example.com");
        let pem = key.to_openssh();
        assert!(pem.starts_with(PEM_BEGIN) && pem.ends_with("-----\n"));
        assert!(pem.lines().all(|l| l.len() <= 70 || l.starts_with("-----")));
        let back = SshKey::parse(&pem).unwrap();
        assert_eq!(back.public_blob(), key.public_blob());
        assert_eq!(back.comment, "synthetic@example.com");
        assert_eq!(
            parse_public_line(&key.public_line()),
            Some(key.public_blob())
        );
        assert_eq!(
            parse_public_line(&format!("key::{}", key.public_line())),
            Some(key.public_blob())
        );
        assert!(key.fingerprint().starts_with("SHA256:") && !key.fingerprint().ends_with('='));
        assert!(SshKey::parse("not a key").is_err());
        assert!(!format!("{key:?}").contains(&b64(&key.key.to_bytes())));
    }

    #[test]
    fn parses_agent_requests_and_purposes() {
        let mut sign = vec![SIGN_REQUEST];
        put_string(&mut sign, b"blob");
        put_string(&mut sign, b"data");
        put_u32(&mut sign, 0);
        assert_eq!(
            Request::parse(&sign).unwrap(),
            Request::Sign {
                key: b"blob",
                data: b"data"
            }
        );
        assert_eq!(
            Request::parse(&[REQUEST_IDENTITIES]).unwrap(),
            Request::List
        );
        assert_eq!(Request::parse(&[27]).unwrap(), Request::Other(27));
        assert!(Request::parse(&[SIGN_REQUEST, 0, 0, 1]).is_err());
        assert_eq!(
            purpose(&sshsig_signed_data("git", b"tree")),
            Purpose::Namespace("git".into())
        );
        let mut login = Vec::new();
        put_string(&mut login, b"session");
        login.push(50);
        put_string(&mut login, b"git");
        assert_eq!(purpose(&login), Purpose::Login("git".into()));
        assert_eq!(purpose(b""), Purpose::Unknown);
    }
}
