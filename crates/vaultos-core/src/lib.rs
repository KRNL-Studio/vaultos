//! VaultOS core: the v4 vault format, its cryptography and the store.
//!
//! Format v4 derives an Account Unlock Key from the master password with Argon2id (and, when
//! the vault uses one, a 128-bit Secret Key mixed in with HKDF). That key unwraps a random
//! Vault Key, which unwraps one key per project. Item metadata and item secrets are sealed
//! separately with XChaCha20-Poly1305, so listing and searching never decrypt a value. The
//! whole file carries an HMAC, and activity goes to a signed, hash-chained audit log whose
//! newest entry the vault records at every save. See `docs/ARCHITECTURE.md` and `SECURITY.md`.
//!
//! Format v3 (the JavaScript app's scrypt + AES-256-GCM vault) can be read for the explicit
//! [`upgrade`](upgrade::upgrade); a v3 vault is never written.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod agents;
pub mod approvals;
pub mod audit;
pub mod canon;
pub mod crypto;
pub mod env;
pub mod error;
pub mod format;
pub mod fs_safe;
pub mod hardening;
pub mod history;
pub mod model;
pub mod paths;
pub mod providers;
pub mod secret;
pub mod secret_key;
pub mod session;
pub mod store;
pub mod upgrade;
pub mod v3;
pub mod validate;

pub use crypto::KdfParams;
pub use error::{Error, Result};
pub use secret::SecretString;
pub use secret_key::SecretKey;
pub use store::Store;
pub use validate::Fields;
