//! The VaultOS daemon (`vaultosd`): one process owns the vault and serves the agent API,
//! ported from `api.js`, over a Unix socket in the private data folder.
//!
//! `api` routes requests and enforces agent permissions; `server` is the transport, the
//! session file and the background guard. See `docs/AGENTS.md`.

pub mod api;
pub mod server;
