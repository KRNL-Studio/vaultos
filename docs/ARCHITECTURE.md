# Architecture

```text
Human → sandboxed renderer → narrow preload IPC → main process / Store
                                                     ↑
Coding client → MCP stdio bridge → authenticated localhost API
                                                     ↓
             encrypted vault + optional Keychain helper / Secret Service
                                                     ↓
                         optional age ciphertext + signed Git sync
```

`store.js` owns encrypted persistence, record ownership, mutation history and audit events. `model.js` defines format versions and syncable fields. `crypto.js` implements the versioned AES-GCM/scrypt envelope and signing primitives using Node's crypto library; the store passes it a per-unlock key cache so writes reuse the vault's salt and derived key with a fresh nonce. `fs-safe.js` and `env-file.js` centralize bounded path and serialization rules.

`main.js` is the desktop authority boundary: it gates all privileged IPC on the exact window/frame and human unlock state. `preload.js` exposes named operations only. The renderer receives metadata for lists and raw values only for explicit reveal/edit. Lock removes the API session, releases process ownership, drops the store state and replaces the rendered view.

`api.js` authorizes each agent request independently; `approvals.js` holds pending-key decisions and the optional approval-relay secret check. Session identity is distinct from agent identity. `agents.js` validates enrollment, scopes and canonical folder/project grants. `agent-client.js` discovers the agent token, finds or starts the owner and maps lock/availability errors; both `mcp/server.mjs` and the `agent-cli.cjs` shell client use it. `mcp/server.mjs` holds the integration token and forwards tool requests; injection does not return secret values. `set_secret` and `reveal_secret` necessarily carry values through the bridge when permitted.

`session.js` coordinates one owner process and validates runtime session discovery. `keyring.js` stores an explicitly remembered password through the native macOS Keychain helper or, on Linux, libsecret's `secret-tool`, both over stdin and in the preview's service namespace; it has no plaintext fallback. `backend.cjs` is an optional separate owner that can start only with that remembered password. With `--service` it is long-running: it waits while another process owns the vault (without holding `owner.lock`), retries unlock with backoff, takes over when the owner exits, returns to waiting after a `/shutdown` handover, restores a removed `session.json`, and reloads `vault.enc` when another writer replaced it. Nothing installs it automatically: `scripts/install-service-macos.sh` installs a per-user LaunchAgent (`org.vaultos.preview.backend`) and `scripts/install-linux.sh --enable-service` an opt-in systemd user unit. The CLI (`cli.cjs`, with human admin commands in `admin.js`) requires a hidden password prompt and claims ownership for decrypted operations, except `sync now`, which asks the running owner to sync.

`main.js` applies the vault's `lockPolicy`: screen lock, sleep and idle either fully lock (`hard`, default) or lock only the window while the process keeps owning and serving (`soft`). Manual Lock is always full. Optional Touch ID (`human-auth.js`, off by default) is also enforced in `main.js`: Touch ID unlock reads the remembered password through `keyring.js` and runs the normal unlock checks, and human-only IPC handlers call a gate that requires a recent Touch ID or master-password confirmation when `touchId.humanActions` is on. Every lock resets it.

`store.js` checks the disk hash before each write and refuses stale writes. Owners call `reloadIfChanged()` between operations (API requests, desktop IPC, the service guard, autosync rounds); it reloads under the write lock and refuses if unsaved in-memory changes exist. Mutations persist or roll back synchronously, so a reload never discards a completed local write.

`sync.js` separates local merging from remote transport. `autosync.js` runs pull-then-push rounds inside the owning process, debounced after local writes and on an interval, and halts on any conflict or verification failure. `git.js` uses argument arrays, disabled hooks, known staged paths and remote receipts. Fetch and push run asynchronously, so the owner keeps serving the window and API while a remote is slow (local Git commands stay synchronous); `Sync` runs one remote operation per checkout at a time, and the local merge and age encryption still run synchronously. Fetches and pushes over SSH share one multiplexed connection unless the user configured SSH for Git. A pull reuses plaintext it already decrypted from byte-identical ciphertext, so only new or changed sync files run `age`. `Store.batch()` defers saves inside a bulk change (an .env import, Approve all, an agent creating a project) to one encrypted write. Trust pins live inside the encrypted vault; age/signing machine keys and the replay index live in the private data directory. The sync format is specific to this preview and is not a public interoperability standard.

## Rust core (format v4)

`crates/vaultos-core` is the Rust implementation of vault format v4, the base for moving the app to Rust. The desktop app, CLI, backend and MCP bridge do not use it yet; they still read and write format v3 through `store.js`.

```text
master password ─Argon2id─┐
Secret Key (optional) ────┴─HKDF─▶ Account Unlock Key ─unwraps─▶ Vault Key
                                                                  ├─▶ per-project keys ─▶ item metadata, item secrets
                                                                  ├─▶ vault metadata, history, audit signing seed
                                                                  └─HKDF─▶ file MAC key
```

`format.rs` defines the file and key derivation; every box is XChaCha20-Poly1305 with associated data naming its purpose and the vault, project and item ids, so a box moved elsewhere in the file fails to open. `store.rs` follows `store.js`: projects, items, ownership, delegation, injection approval, history with Undo, tombstones and settings. While unlocked it holds decrypted metadata, and item secrets stay sealed until `reveal`. Each change is applied to a copy of the state and kept only once the file is saved; saving takes `write.lock`, refuses a file that changed since it was read (device, inode, size, modification and change times, or the contents where the file system keeps whole-second times), and replaces the file atomically, flushing the file and its directory. Lock files are the pid files `session.js` uses, so the two implementations exclude each other. Rust processes also hold a `flock` on a companion file (`.write.lock.flock`, `.owner.lock.flock`), which the kernel releases when a process dies, so two of them can never both take over a stale pid file. Both implementations take over a stale pid file by renaming it aside and deleting it only if it still names the dead process; a lock created in the meantime is put back. Only three processes taking over the same stale lock at the same instant could still both succeed. The JavaScript app cannot open a v4 vault, so after the upgrade it never writes one. Delegating, adopting and approving change item metadata only (history action `update_meta`), without opening the sealed secret. `audit.rs` writes the signed, hash-chained `audit-v4.log`. `upgrade.rs` is the explicit v3-to-v4 upgrade, and `v3.rs` reads format v3 only for it. `canon.rs` and `providers.rs` match `model.js` and `providers.js`, with tests that compare against them (`tests/fixtures/record-hash.txt`, `test/rust-providers.test.js`). `tests/fixtures/v3-vault.json` is a vault written by `store.js` with synthetic values (`scripts/make-rust-fixtures.mjs`); the upgrade tests read it.

See [SECURITY.md](../SECURITY.md) for trust boundaries and limitations. Test files map to persistence/export, HTTP authorization, MCP transport, desktop behavior and encrypted sync rather than trying to establish security through UI tests alone.
