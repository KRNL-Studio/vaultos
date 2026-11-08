# Security review package

A starting point for an independent review of VaultOS 0.3. VaultOS has not had one yet. Read
[SECURITY.md](../../SECURITY.md) first for what it protects and its known limitations, then
[the architecture](../ARCHITECTURE.md) for the components.

## What is here

- [CRYPTO.md](CRYPTO.md): format v4, the key hierarchy, every box and its associated data, the
  file MAC, the audit chain, tokens and sync format 2, with known-answer vectors in
  [`v4-vectors.json`](../../crates/vaultos-core/tests/fixtures/v4-vectors.json) that CI checks
  (`cargo test -p vaultos-core --test vectors`).
- The trust boundaries below, and where the code that enforces each one lives.

## Trust boundaries

| Boundary | Enforced by | Code |
| --- | --- | --- |
| The vault file at rest | Argon2id, XChaCha20-Poly1305, the file MAC | `vaultos-core/src/crypto.rs`, `format.rs`, `store.rs` |
| One owner process at a time | `owner.lock` and `write.lock` pid files with `flock`, change detection before every save | `vaultos-core/src/store.rs`, `fs_safe.rs`, `session.rs` |
| Other local users | 0700 data folder, 0600 files, socket peer uid check | `vaultos-core/src/session.rs`, `fs_safe.rs`, `vaultos-daemon/src/server.rs` |
| Agents (MCP bridge, `vaultos-agent`) | Agent tokens, scopes, approved projects and folders, run commands, just-in-time grants, all checked in the owner | `vaultos-daemon/src/api.rs`, `access.rs`, `vaultos-core/src/agents.rs`, `approvals.rs` |
| Programs run with values (run scope) | The owner starts them: clean environment, filtered `PATH`, masked output, process group kill, stop on lock | `vaultos-daemon/src/server.rs`, `api.rs`, `vaultos-client/src/run.rs`, `vaultos-core/src/mask.rs` |
| The human's confirmations | Touch ID or the app's dialog, worded from the request; password fallback | `vaultos-daemon/src/human.rs`, `vaultos-desktop/src/app.rs` |
| The desktop pages | Tauri v2 capabilities; every privileged command re-checked in Rust | `vaultos-desktop/src/commands.rs`, `app.rs`, `tauri.conf.json`, `capabilities/` |
| Web pages and the browser extension | Native messaging host for one extension ID, pairing keys, site matching on the browser-reported origin, trusted clicks | `extension/`, `vaultos-cli/src/bin/vaultos-browser.rs`, `vaultos-daemon/src/browser.rs`, `vaultos-core/src/sites.rs` |
| Safari | The app extension's sandbox (it reads only the session file and connects only to the owner's socket) and its fixed origin | `safari/`, `scripts/package-mac.mjs`, `vaultos-core/src/native_host.rs` |
| Passkeys | Relying party IDs against the browser-reported host, client data built by the owner, the human's choice in the extension's window | `extension/passkeys.js`, `passkey.js`, `background.js`, `vaultos-core/src/webauthn.rs`, `store/passkeys.rs` |
| SSH clients | The owner's agent socket, per-key approval, signing only | `vaultos-daemon/src/ssh_agent.rs`, `vaultos-core/src/ssh.rs`, `vaultos-cli/src/bin/vaultos-ssh-sign.rs` |
| The sync remote | age encryption to pinned devices, signed manifests and heartbeats, rollback checks | `vaultos-sync/src/lib.rs`, `vaultos-core/src/store/sync.rs` |
| Imported files | Size limits and a minimal ZIP reader; parsed into a preview without touching the vault | `vaultos-core/src/import.rs` |

## Suggested focus

1. Format v4 and the store's save path: AAD binding, the MAC's coverage, the downgrade and
   resource limits on the unauthenticated header, and the lock and change-detection logic.
2. Authorization in the owner: each route in `api.rs`, `browser.rs` and `human.rs`, and that
   nothing an agent sends can widen its scopes, projects or folders.
3. The run scope: what a program started with values can learn or leave behind, and the
   masker (`mask.rs`, fuzzed by `mask_stream`).
4. The browser extension's page boundary: what a hostile page or another extension can see or
   trigger.
5. Sync merge and rollback handling against a hostile remote.

## Building and testing

`CONTRIBUTING.md` has the commands. In short: `cargo test --workspace --locked`, `npm run check`,
`npm run test:desktop` (macOS, interactive), `sh scripts/fuzz.sh SECONDS` for the ten fuzz
targets, and `cargo deny check` for advisories, licences and sources. Release archives carry a
CycloneDX inventory of the Rust crates and, from the release workflow, signed build provenance.
Test only against new data directories (`VAULTOS_DATA_DIR`) and synthetic values.

## Out of scope today

Unsigned and unnotarized builds (see the release notes), passkeys in Safari, and a compromised
account on the same computer: anything running as the user can read the session token and
act as the owner (see SECURITY.md).
