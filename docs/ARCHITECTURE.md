# Architecture

VaultOS is a Rust workspace. Every program uses `crates/vaultos-core` and vault format v4.

```text
Human → window / Quick Access (renderer/, system web view)
            │ two Tauri commands, checked per window and page
            ▼
        VaultOS (vaultos-desktop) ─┐            ┌─▶ vault.enc (v4), audit-v4.log
                                   │ owns,      │
Human → vaultos (CLI) ─────────────┤ one at a   ├─▶ vaultos-core
                                   │ time       │
        VaultOS --service ─────────┤            └─▶ vaultos-sync ─▶ age + signed Git sync
        vaultosd ──────────────────┘
            ▲  HTTP over a Unix socket (daemon.json token, same-user peers only)
            │
Coding client → vaultos-mcp      Shell agent → vaultos-agent
```

| Crate | Role |
| --- | --- |
| `vaultos-core` | Format v4, the store, the audit chain, the v3 upgrade, file safety, process hardening |
| `vaultos-daemon` (`vaultosd`) | The owner's server. `server.rs` serves HTTP/1.1 (hyper, tokio) on `vaultosd.sock`, accepts only peers with this user's id, and requires the session token from `daemon.json` on every route but `/status`. `api.rs` authorizes each agent request independently for scopes, project and folder grants and approvals. A guard loop restores `daemon.json`, reloads `vault.enc` when another writer replaced it and applies the idle lock. `autosync.rs` runs sync rounds, holding the store only for their local steps. `run_embedded` lets the desktop and service mode run the same server in-process |
| `vaultos-client` | Finds the owner through `daemon.json` and a trusted socket path, discovers the agent token and maps errors to exit codes. It never starts an owner |
| `vaultos-mcp` | The stdio MCP bridge (rmcp) with the tool names and schemas in `tools.json`. It keeps no vault state; each tool call is one owner request |
| `vaultos-cli` (`vaultos`, `vaultos-agent`) | The human CLI, which opens the vault itself for admin and sync commands and talks to the owner for `start`, `unlock`, `lock`, `stop`, `status` and `sync now`; and the agent shell client |
| `vaultos-sync` | Sync format 2: `lib.rs` encrypts, signs, verifies and merges; `git.rs` runs Git with argument arrays, disabled hooks and known paths only |
| `vaultos-desktop` (`VaultOS`) | The Tauri v2 app (below) |

## Desktop

`main.rs` builds the Tauri app; `commands.rs` holds the two commands the pages call, `vault` for the main window and `quick` for Quick Access. `from_page` accepts a call only from its own window label at its own page (`index.html` or `quick.html` on the app's origin), so Quick Access cannot reach settings, agents or sync, and every non-public call needs the human's unlock and resets the idle timer. `renderer/tauri-bridge.js` gives the pages the `window.vault` / `window.quick` objects they use, over those commands. The pages never receive a value unless the human reveals or edits it; copies go through `platform.rs`, which on macOS writes concealed, transient, current-host-only pasteboard data and clears it only if unchanged.

`app.rs` keeps the state and lock rules. Unlocking claims `owner.lock` by starting the daemon's server in-process (`run_embedded`), so enrolled agents are served while the window is unlocked; the window's own calls reach the store through the server's handle, never the socket. Every lock bumps a generation, so an unlock still waiting (for its turn, for Touch ID, for another process to hand over the vault) cannot finish after a later Lock. A full Lock stops the server, clears the window, Quick Access and the clipboard, and, for Lock and the hard lock policy's screen lock, sleep and idle, writes the `locked` block and removes the remembered password. Closing the window locks without the block. A soft lock only locks the window. Human-only actions pass `gate`, which requires a recent Touch ID or master-password confirmation when `touchId.humanActions` is on.

`ui.rs` owns the windows, the menu bar item, the application menu, the Quick Access shortcut, notifications and the watch loop (every 2 seconds: idle, screen lock, a gap in its own clock after sleep, and a server that stopped underneath). `platform.rs` adds the macOS will-sleep and session-resign observers, Touch ID through LocalAuthentication, and logind's `LockedHint` on Linux. `keyring.rs` stores the remembered password and the Secret Key in the macOS Keychain (Security framework) or the Secret Service (`secret-tool`), in the preview's namespace, with no plaintext fallback. `prefs.rs` validates the plaintext `desktop-prefs.json`, `login.rs` writes the opt-in LaunchAgent or XDG autostart entry, `search.rs` ranks metadata without values, `export.rs` writes the encrypted PDF export, and `settings.rs` validates the vault's encrypted settings.

`service.rs` is `VaultOS --service`: the same program without Tauri, for the LaunchAgent or systemd unit. It waits while another process holds `owner.lock` or the `locked` block exists, reads the remembered password in a blocking task, runs the embedded server and unlocks it, and returns to waiting when the window asks it to stop (standing back 10 seconds so the window can claim the vault) or when the vault locks underneath it. Conditions a restart cannot fix exit 0.

## Vault format v4

```text
master password ─Argon2id─┐
Secret Key (optional) ────┴─HKDF─▶ Account Unlock Key ─unwraps─▶ Vault Key
                                                                  ├─▶ per-project keys ─▶ item metadata, item secrets
                                                                  ├─▶ vault metadata, history, audit signing seed
                                                                  └─HKDF─▶ file MAC key
```

`format.rs` defines the file and key derivation; every box is XChaCha20-Poly1305 with associated data naming its purpose and the vault, project and item ids, so a box moved elsewhere in the file fails to open. `store.rs` holds projects, items, ownership, delegation, injection approval, history with Undo, tombstones and settings. While unlocked it holds decrypted metadata, and item secrets stay sealed until `reveal`. Each change is applied to a copy of the state and kept only once the file is saved; saving takes `write.lock`, refuses a file that changed since it was read (device, inode, size, modification and change times, or the contents where the file system keeps whole-second times), and replaces the file atomically, flushing the file and its directory. Lock files are pid files that VaultOS 0.2 also understood, and Rust processes also hold a `flock` on a companion file (`.write.lock.flock`, `.owner.lock.flock`), which the kernel releases when a process dies, so two of them can never both take over a stale pid file. A stale pid file is taken over by renaming it aside and deleting it only if it still names the dead process; a lock created in the meantime is put back with a hard link, which never replaces a file (if that fails, it is left beside the lock as `*.stale-*` and the claim fails). Delegating, adopting and approving change item metadata only (history action `update_meta`), without opening the sealed secret. `audit.rs` writes the signed, hash-chained `audit-v4.log`. `upgrade.rs` is the explicit v3-to-v4 upgrade, and `v3.rs` reads format v3 only for it; `tests/fixtures/v3-vault.json` is a vault written by VaultOS 0.2 with synthetic values, which the upgrade tests read. `canon.rs` keeps 0.2's record hash (`tests/fixtures/record-hash.txt`).

Sync format 2 keeps the device's age and Ed25519 keys in `VaultMeta.sync_keys`, inside the encrypted vault, and its trust pins beside them. The local index is keyed and authenticated with keys derived from the signing key, so it holds no plain record hashes. `Store::apply_sync` writes every change of one pull in a single save. See [the sync guide](SYNC.md).

See [SECURITY.md](../SECURITY.md) for trust boundaries and limitations. Tests cover persistence and the upgrade (`vaultos-core`), socket authorization and the agent API (`vaultos-daemon`), the MCP transport (`vaultos-mcp`), the CLIs, encrypted sync, and the desktop flow and service mode (`npm run test:desktop`), rather than trying to establish security through UI tests alone.
