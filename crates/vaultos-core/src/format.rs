//! Vault format v4 on disk.
//!
//! ```text
//! master password ──Argon2id(salt, m,t,p)──► password key ─┐
//!                       optional Secret Key (128 bits) ────┴─HKDF─► Account Unlock Key (AUK)
//! AUK ──unwraps──► Vault Key (VK, random)
//! VK  ──unwraps──► one Project Key per project (random)
//! VK  ──seals────► vault metadata (settings, agents, tombstones, audit key) and history
//! PK  ──seals────► the project's name and, per item, its metadata and its secret separately
//! HKDF(VK) ──────► MAC key: HMAC-SHA256 over the whole file, so no box can be dropped,
//!                  swapped or rolled back on its own
//! ```
//!
//! Every box is XChaCha20-Poly1305 with a random nonce and associated data naming the vault,
//! the box's purpose and the ids it belongs to. Changing the password re-wraps only the
//! Vault Key. Item secrets stay sealed in memory until something reveals them.

use crate::crypto::{
    argon2id, b64, hex, hkdf, hmac_sha256_parts, hmac_verify, random_array, unb64, unb64_array,
    KdfParams, Sealed,
};
use crate::error::{Error, Result};
use crate::model::{Extra, ItemMeta, Tombstone};
use crate::secret::{Key32, SecretString};
use crate::secret_key::SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const VERSION: u64 = 4;

const MAC_LABEL: &[u8] = b"vaultos/v4/file\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfHeader {
    pub alg: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String,
}

impl KdfHeader {
    pub fn new(params: KdfParams) -> KdfHeader {
        KdfHeader {
            alg: "argon2id".into(),
            m: params.m,
            t: params.t,
            p: params.p,
            salt: b64(&random_array::<16>()),
        }
    }

    pub fn params(&self) -> Result<KdfParams> {
        if self.alg != "argon2id" {
            return Err(Error::Format(format!(
                "unsupported key derivation {}",
                self.alg
            )));
        }
        let p = KdfParams {
            m: self.m,
            t: self.t,
            p: self.p,
        };
        p.validate()?;
        Ok(p)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretKeyHeader {
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ItemFile {
    pub id: String,
    pub rev: u64,
    pub meta: Sealed,
    pub secret: Sealed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProjectFile {
    pub id: String,
    pub key: Sealed,
    pub meta: Sealed,
    pub items: Vec<ItemFile>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VaultFile {
    pub v: u64,
    pub vault_id: String,
    pub kdf: KdfHeader,
    pub secret_key: Option<SecretKeyHeader>,
    pub vault_key: Sealed,
    /// The audit chain's Ed25519 public key, so the log can be checked without unlocking.
    pub audit_key: String,
    /// The audit chain's signing seed, sealed under the Vault Key.
    pub audit_seed: Sealed,
    pub meta: Sealed,
    pub projects: Vec<ProjectFile>,
    pub history: Sealed,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

/// Decrypted vault-wide metadata.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMeta {
    #[serde(default)]
    pub settings: Map<String, Value>,
    #[serde(default)]
    pub agents: Vec<Value>,
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_trust: Option<Value>,
    /// This machine's sync identity and private keys (`vaultos-sync`), sealed with the rest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_keys: Option<crate::secret::SecretValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_head: Option<AuditHead>,
    pub created_at: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditHead {
    pub seq: u64,
    pub hash: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectMeta {
    pub name: String,
    pub owner: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The audit signing seed travels in its own box so metadata reads never touch it.
#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct AuditSeed {
    seed: String,
}

/// Associated data: purpose and ids, NUL-separated. Ids are hex, so they cannot contain NUL.
pub(crate) fn aad(purpose: &str, ids: &[&str]) -> Vec<u8> {
    let mut out = format!("vaultos/v4/{purpose}").into_bytes();
    for id in ids {
        out.push(0);
        out.extend_from_slice(id.as_bytes());
    }
    out
}

fn vault_id_bytes(vault_id: &str) -> Result<[u8; 16]> {
    if vault_id.len() != 32
        || !vault_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::Format("invalid vault id".into()));
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&vault_id[2 * i..2 * i + 2], 16)
            .map_err(|_| Error::Format("invalid vault id".into()))?;
    }
    Ok(out)
}

pub fn check_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::Format("invalid record id".into()));
    }
    Ok(())
}

/// Derives the Account Unlock Key. With a Secret Key, both factors are needed: the HKDF input
/// is the Argon2id output followed by the 128-bit key, under a distinct label.
pub fn account_unlock_key(
    password: &SecretString,
    secret_key: Option<&SecretKey>,
    kdf: &KdfHeader,
    vault_id: &str,
) -> Result<Key32> {
    let salt: [u8; 16] = unb64_array(&kdf.salt, "salt")?;
    let pwk = argon2id(password.expose().as_bytes(), &salt, kdf.params()?)?;
    let vid = vault_id_bytes(vault_id)?;
    Ok(match secret_key {
        Some(sk) => {
            let mut ikm = zeroize::Zeroizing::new(Vec::with_capacity(48));
            ikm.extend_from_slice(pwk.expose());
            ikm.extend_from_slice(sk.expose());
            hkdf(&ikm, &vid, b"vaultos/v4/auk/password+secret-key")
        }
        None => hkdf(pwk.expose(), &vid, b"vaultos/v4/auk/password"),
    })
}

pub fn mac_key(vk: &Key32, vault_id: &str) -> Result<Key32> {
    Ok(hkdf(
        vk.expose(),
        &vault_id_bytes(vault_id)?,
        b"vaultos/v4/file-mac",
    ))
}

impl VaultFile {
    /// The file's JSON without `mac`, which the MAC covers after a label.
    fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.mac = None;
        unsigned.to_bytes()
    }

    pub fn sign(&mut self, mac_key: &Key32) -> Result<()> {
        self.signed_bytes(mac_key).map(|_| ())
    }

    /// Signs the file and returns its bytes, serialising it once: `mac` is the last field, so
    /// the signed form is the unsigned JSON with `,"mac":"…"` before its closing brace.
    pub fn signed_bytes(&mut self, mac_key: &Key32) -> Result<Vec<u8>> {
        self.mac = None;
        let mut bytes = self.to_bytes()?;
        let mac = b64(&hmac_sha256_parts(mac_key, &[MAC_LABEL, &bytes]));
        if bytes.pop() != Some(b'}') {
            return Err(Error::Format("unexpected serialisation".into()));
        }
        bytes.extend_from_slice(format!(",\"mac\":\"{mac}\"}}").as_bytes());
        self.mac = Some(mac);
        Ok(bytes)
    }

    pub fn verify(&self, mac_key: &Key32) -> Result<()> {
        let tag = unb64(self.mac.as_deref().ok_or(Error::Integrity)?, "mac")?;
        let mut input = MAC_LABEL.to_vec();
        input.extend(self.unsigned_bytes()?);
        if !hmac_verify(mac_key, &input, &tag) {
            return Err(Error::Integrity);
        }
        Ok(())
    }

    pub fn parse(bytes: &[u8]) -> Result<VaultFile> {
        let v = crate::v3::envelope_version(bytes)?;
        if v > VERSION {
            return Err(Error::TooNew {
                need: v,
                have: VERSION,
            });
        }
        if v != VERSION {
            return Err(Error::UnsupportedVersion(v));
        }
        let f: VaultFile =
            serde_json::from_slice(bytes).map_err(|e| Error::Format(format!("{e}")))?;
        vault_id_bytes(&f.vault_id)?;
        for p in &f.projects {
            check_id(&p.id)?;
            for i in &p.items {
                check_id(&i.id)?;
            }
        }
        Ok(f)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| Error::Format(e.to_string()))
    }
}

pub(crate) fn seal_json<T: Serialize>(key: &Key32, aad: &[u8], value: &T) -> Result<Sealed> {
    let bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(value).map_err(|e| Error::Format(e.to_string()))?,
    );
    Ok(Sealed::seal(key, aad, &bytes))
}

pub(crate) fn open_json<T: for<'de> Deserialize<'de>>(
    sealed: &Sealed,
    key: &Key32,
    aad: &[u8],
) -> Result<T> {
    let plain = sealed.open(key, aad)?;
    serde_json::from_slice(plain.expose())
        .map_err(|e| Error::Format(format!("sealed contents: {e}")))
}

pub(crate) fn seal_audit_seed(vk: &Key32, vault_id: &str, seed: &Key32) -> Result<Sealed> {
    seal_json(
        vk,
        &aad("audit-seed", &[vault_id]),
        &AuditSeed {
            seed: b64(seed.expose()),
        },
    )
}

pub(crate) fn open_audit_seed(sealed: &Sealed, vk: &Key32, vault_id: &str) -> Result<Key32> {
    let s: AuditSeed = open_json(sealed, vk, &aad("audit-seed", &[vault_id]))?;
    Ok(Key32::from_bytes(unb64_array(&s.seed, "audit seed")?))
}

pub fn new_vault_id() -> String {
    hex(&random_array::<16>())
}

/// Item metadata plus the sealed secret, as kept in memory while unlocked.
#[derive(Clone, Debug)]
pub struct Item {
    pub id: String,
    pub rev: u64,
    pub meta: ItemMeta,
    pub secret: Sealed,
    pub(crate) sealed_meta: Option<Sealed>,
}
