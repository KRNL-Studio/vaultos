# Cryptography in format v4

This is the cryptographic part of VaultOS's on-disk and sync formats, precise enough to
reimplement. [`v4-vectors.json`](../../crates/vaultos-core/tests/fixtures/v4-vectors.json) gives
known answers for Argon2id, both Account Unlock Keys, the file MAC key with an HMAC over sample
bytes, one sealed box with its associated data, and the Secret Key's encoding;
`crates/vaultos-core/tests/vectors.rs` checks them on every CI run. They do not cover the file's
canonical form, the audit or sync signatures, or the sync index keys. They were reproduced
independently (Python's standard library for HKDF, HMAC
and the Secret Key encoding; OpenSSL's Argon2id and ChaCha20-Poly1305, with HChaCha20 in
Python, for the rest). The code is in `crates/vaultos-core/src/crypto.rs` and `format.rs`
unless named.

## Primitives

| Use | Primitive | Crate |
| --- | --- | --- |
| Password hashing | Argon2id v1.3, 32-byte output | `argon2` |
| Key derivation | HKDF-SHA256, 32-byte output | `hkdf`, `sha2` |
| Encryption | XChaCha20-Poly1305 (192-bit random nonce, 128-bit tag) | `chacha20poly1305` |
| File and index MACs | HMAC-SHA256 | `hmac` |
| Audit and sync signatures | Ed25519 (from a 32-byte seed) | `ed25519-dalek` |
| Sync encryption | age (X25519 recipients) | `age` |
| Randomness | the operating system's CSPRNG | `getrandom` (via `rand_core`) |

Comparisons of secrets (MACs, token hashes) are constant time. Key material is held in types
that zero their memory when dropped (`Key32`, `SecretString`, `SecretBytes`).

## Identifiers

The vault id is 16 random bytes written as 32 lowercase hex digits; derivations use the 16
bytes. Project, item, history and attachment ids are 1 to 64 characters of `[A-Za-z0-9_-]`
(random ones are hex), so they never contain NUL.

## Key hierarchy

```text
password ──Argon2id(salt, m, t, p)──▶ PWK (32 bytes)
                                        │
             no Secret Key:  AUK = HKDF(ikm = PWK,       salt = vault id, info = "vaultos/v4/auk/password")
             with Secret Key: AUK = HKDF(ikm = PWK ‖ SK,  salt = vault id, info = "vaultos/v4/auk/password+secret-key")

AUK ──unwraps──▶ VK (vault key, 32 random bytes)
VK  ──unwraps──▶ PK (one 32-byte random key per project)
VK  ──HKDF(ikm = VK, salt = vault id, info = "vaultos/v4/file-mac")──▶ file MAC key
```

- **Argon2id** parameters and the 16-byte random salt are in the file's `kdf` header
  (`{"alg":"argon2id","m":KiB,"t":passes,"p":lanes,"salt":base64}`). New vaults use m = 256 MiB,
  t = 3, p = 4. A header below m = 19 MiB, t = 2, p = 1 (OWASP's minimum) is refused as a
  downgrade, and one above 1 GiB, 16 passes, 16 lanes or four times the default's m × t is
  refused before any work, since the header is read before anything is authenticated.
- **Secret Key** (optional): 16 random bytes, kept out of the vault. Written as `VK1-` and 30
  symbols of Crockford's Base32 alphabet (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`) in groups of six:
  26 symbols encode the 128-bit value big-endian (the top two bits are zero), then 4 symbols
  are the first 20 bits of SHA-256(`"vaultos/v4/secret-key-check/"` ‖ SK). Parsing accepts any
  case, spaces and dashes, and O for 0 and I or L for 1. The header's `secretKey.id` is the
  first 4 bytes of SHA-256(`"vaultos/v4/secret-key-id/"` ‖ SK) in hex, so a missing or wrong
  key can be named.
- Changing the password (or adding or removing the Secret Key) rewraps VK under a new AUK with
  a new salt; the data keys stay. There is no key escrow or recovery path: without the
  password (and the Secret Key, when used) the vault cannot be opened.

## Boxes

Every encrypted value is a box: `{"n": base64(24-byte nonce), "c": base64(ciphertext ‖ tag)}`
(attachments, which can be large, use the raw form `nonce ‖ ciphertext ‖ tag` in their own
file). Nonces are random; at 192 bits that is safe for any practical number of messages under
one key. The associated data names what the box is and where it belongs:

```text
"vaultos/v4/" ‖ purpose ‖ ( 0x00 ‖ id )*
```

| Box | Key | Purpose and ids |
| --- | --- | --- |
| `vaultKey` (VK, wrapped) | AUK | `vault-key`, vault id |
| Vault metadata (`meta`) | VK | `meta`, vault id |
| History list, history entry | VK | `history`, vault id; `history-entry`, vault id, entry id |
| Audit signing seed | VK | `audit-seed`, vault id |
| A project's key | VK | `project-key`, vault id, project id |
| Project metadata | PK | `project`, vault id, project id |
| Item metadata | PK | `item-meta`, vault id, project id, item id |
| Item secret (value, password, OTP, secret fields) | PK | `item-secret`, vault id, project id, item id |
| Attachment | PK | `attachment`, vault id, project id, item id, attachment id |

So a box copied to another item, project, purpose or vault fails to open. A box's plaintext is
compact JSON, except an attachment's, which is the file's bytes.
Item secrets stay sealed while the vault is unlocked and are opened only when used.

## File MAC

`vault.enc` is JSON with `"v":4` first and `"mac"` last. It is parsed into fixed structures
that refuse unknown fields at every level, boxes included. The MAC is HMAC-SHA256(file MAC key,
`"vaultos/v4/file"` ‖ 0x00 ‖ C), base64, where C is the parsed file written again without `mac`:
compact JSON (no whitespace, `serde_json` escaping) with fields in this order:

```text
v, vaultId, kdf {alg, m, t, p, salt}, secretKey ({id} or null), vaultKey, auditKey, auditSeed,
meta, projects [{id, key, meta, items [{id, rev, meta, secret}]}], history
```

Each box is `{"n", "c"}`. VaultOS writes C followed by `,"mac":"…"` before the closing brace.
Because the MAC covers C rather than the bytes read, the same values with other whitespace or
field order still verify. It is verified after VK is unwrapped and before anything else is
read, so a file with its boxes or entries reordered, removed or replaced by older ones (from
the same vault) is refused, and one with fields added does not parse. Replacing the whole file with an older copy is not detected (see
[SECURITY.md](../../SECURITY.md)). A file whose `v` is not 4 is refused before parsing (a newer one with a message to
update VaultOS).

## Audit log

`audit-v4.log` is one JSON entry per line: `seq`, `at`, `actor`, `action`, `detail` (control
characters replaced, at most 1024 characters), `prev` (hex SHA-256 of the previous line; 64 zeros
for the first) and `sig`: Ed25519 over `"vaultos/v4/audit"` ‖ 0x00 ‖ vault id ‖ 0x00 ‖ the
entry's JSON without `sig`. The 32-byte signing seed is random and sealed in the vault
(`auditSeed`); its public key is in the file in the clear (`auditKey`), so the log can be
checked without unlocking. The vault metadata keeps the last entry's sequence and hash, so truncating the log or
rewriting it without the seed is detected when the vault is unlocked. Entries hold no values.

## Tokens and local keys

| What | Form | Stored as |
| --- | --- | --- |
| Session token (owner socket) | 32 random bytes, hex | `daemon.json` (0600) in the data directory, where the socket is too unless that path is too long for one |
| Agent token | 32 random bytes, hex | SHA-256 hex in the sealed vault metadata |
| Browser pairing key | 32 random bytes, hex | SHA-256 hex in the sealed vault metadata, with the extension's origin |
| Leak index key | 32 random bytes | `leak-index.json` (0600), beside 16-byte HMAC-SHA256 tags |
| SSH keys | Unencrypted OpenSSH Ed25519 private key (PEM) | inside an item's sealed secret |

Token hashes are unsalted because tokens are 256-bit random values; a guess is no easier
against the hash. The leak index key sits beside its tags, so anyone who can read that file
can test guesses for indexed values offline (see [SECURITY.md](../../SECURITY.md)).

## Sync format 2

Each device keeps an age X25519 identity and an Ed25519 seed in the sealed vault metadata, and
pins the other devices' public keys there. Every record and tombstone in the Git remote is
age-encrypted to all trusted devices' recipients; the plaintext is canonical JSON. Machine files
(each device's id, label and public keys), `recipients.txt`, manifests and heartbeats are in the
clear; machine files are trusted only after their fingerprints are compared out of band.
Each push signs a manifest (Ed25519 over `"vaultos/v4/sync-manifest"` ‖ 0x00 ‖ canonical JSON
naming every file and its hash) and a heartbeat (`"vaultos/v4/sync-heartbeat"` ‖ 0x00 ‖ …), and
a pull verifies them against the pins before applying anything. Manifests sign ciphertext
digests, so the remote learns no hash of a value; an older ciphertext restored from Git
history is refused (`ROLLBACK`) once a manifest has seen the push that replaced it. The
remote's host can withhold pushes, but not forge or alter one. The local `sync-index.json` keys
record hashes with HMAC-SHA256 under HKDF(seed, machine id, `"vaultos/v4/sync-index/hash"`), so
it holds no plain hash of a value. The code is in `crates/vaultos-sync/src/lib.rs`; see
[the sync guide](../SYNC.md).

## Format v3 (read once, to upgrade)

`v3.rs` reads the 0.2 format only for the explicit upgrade; v4 never writes it. The upgrade
backs up the v3 file, creates new keys (salt, VK, project keys, audit seed) and checks that the
new file decodes to the same records before replacing anything.
