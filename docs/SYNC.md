# Optional encrypted Git sync

Sync is for your own trusted devices. Each enrolled device can decrypt all records in its sync group. Start with disposable vaults, use a **new private Git repository** that holds nothing else, and keep sync off until you configure it. No Git credentials are stored in the vault or published by the project; configure transport through your normal Git tools.

There are two sync formats, and they cannot share a repository:

- **Sync format 2** is used by the Rust tools (`vaultos`, `vaultosd`) with a format v4 vault. It is described first.
- **Sync format 1** is used by the desktop app and the JavaScript CLI (`node cli.cjs`) with a format v3 vault, until the desktop moves to the Rust core. See [the desktop app's sync](#desktop-app-sync-format-1).

Each refuses the other's repository: the Rust tools stop with `UNSUPPORTED_REPOSITORY` on a format 1 repository, and the desktop says a newer VaultOS made a format 2 one. Nothing converts a repository. To move to format 2, upgrade every device's vault (`vaultos upgrade`), then start a **new, empty** sync repository and enrol each device again.

## Sync format 2 (vaultos and vaultosd)

The checkout is `sync-repository` inside the data directory, or the absolute path in `VAULTOS_SYNC_REPO`. Set it the same way for `vaultos` and `vaultosd`; `vaultos start` passes its environment on. No `age` binary is needed. Every `vaultos sync` command except `now` opens the vault itself and asks for the master password, so stop a running `vaultosd` first or add `--stop-backend`.

### What it stores

A device's keys are made by `vaultos sync init` and kept **inside the encrypted vault**: an X25519 age key that receives records, and an Ed25519 key that signs. Nothing about sync is kept in a plaintext key file, so a stolen data directory without the password (and Secret Key, if set) does not open the sync repository. The repository holds:

| Path | Contents |
| --- | --- |
| `vaultos-sync.json` | `{"app":"VaultOS-Preview","version":2}` |
| `recipients.txt` | The age public key of every device |
| `machines/<id>.json` | Each device's public identity: id, label, signing and age public keys |
| `records/<hash>.age`, `tombstones/<hash>.age` | One age file per record or deletion, encrypted to every recipient; the name is a SHA-256 of the record's id |
| `manifests/<id>.json` | Each device's Ed25519-signed list of the ciphertext files it published, with a counter |
| `peers/<id>.json` | Each device's signed heartbeat |

Manifests sign ciphertext digests, not plaintext. Unlike format 1, they carry no per-record content hash or fingerprint, so the repository cannot be used to guess low-entropy values. Signatures are domain-separated (`vaultos/v4/sync-manifest`, `vaultos/v4/sync-heartbeat`), so a manifest signature cannot be replayed as a heartbeat or as anything the vault signs.

The local index (`sync-index.json` in the data directory) remembers what was last synced, each peer's latest counter and the recipient list. Its record hashes are keyed with a key derived from this device's signing key, and the whole file carries an HMAC under another, so it reveals nothing to someone who copies it, and a modified index stops sync with `Invalid sync index; restore a trusted backup`.

### First device

Create a dedicated empty checkout with `git init -b main /absolute/new/sync-repository`, set a repository-local Git author you want recorded, and add the private remote with `git remote add origin <your-private-remote>`. Do not use a URL with an embedded access token.

```sh
export VAULTOS_SYNC_REPO=/absolute/new/sync-repository
vaultos --stop-backend sync init 'Device A'
vaultos sync push
```

`init` prints this device's public identity. Labels are visible to anyone who can read the repository; choose a generic one. `push` exits 2 unless `delivered` is `true`; delivery means the remote accepted the commit, not that another device has pulled it.

### Add another device

1. On device B, create its own vault (`vaultos init`); never copy another device's vault or keys. Clone the sync repository and point `VAULTOS_SYNC_REPO` at the clone.
2. Run `vaultos sync init 'Device B'`. It adds B's identity to `machines/` and its key to `recipients.txt`.
3. On each device, run `vaultos sync identity` and compare the two `fingerprint` values through a channel you trust, such as reading them aloud side by side. A file fetched from the same Git remote does not authenticate itself.
4. Give each device the other's identity: B's `machines/<id>.json` (after A fetches it) or the JSON `sync identity` printed, saved to a file. Run `vaultos sync trust /absolute/peer-identity.json` and check that the fingerprint it prints is the one you compared. Both devices must trust each other.
5. B runs `vaultos sync push`, so its enrolment reaches the remote. A runs `vaultos sync pull`, then `vaultos sync push`: the recipient list changed, so A re-encrypts every record and tombstone it holds for B and reports `reencryptedForNewRecipients: true`. B can then `vaultos sync pull`.

A recipient in `recipients.txt` that this device has not trusted stops every push (`Unapproved encryption recipient`), so nobody can add themselves by committing a key. Trusting a device id that is already trusted with different keys is refused.

### Routine use

| Command | What it does |
| --- | --- |
| `vaultos sync status` | Fetches and reports one state for the whole group; exits 2 unless `IN_SYNC` |
| `vaultos sync push` | Encrypts changed records, signs the manifest, commits only sync's own files, pushes and checks the remote ref; exits 2 unless delivered |
| `vaultos sync pull` | Fetches, verifies and merges; stops on concurrent edits |
| `vaultos sync plan` | What a pull of the local checkout would change, by project and key name (never values); fetch first for current results |
| `vaultos sync accept-conflicts` | Fetches and merges, resolving concurrent edits by revision |
| `vaultos sync auto on [--interval SECONDS]`, `auto off` | Turns autosync in `vaultosd` on or off |
| `vaultos sync now` | Asks the running `vaultosd` for one round; exits 2 unless it succeeded |

Output never contains values. A record changed on one device only since the last sync merges as an ordinary update. A record changed on both, or any case the index cannot vouch for, is a conflict (`CONFLICTS_PENDING`): back up both devices, review `sync plan` (the higher revision wins, then the later timestamp; an exact tie goes to the same version on every device) and run `sync accept-conflicts` only if you accept that. A project or key name that already exists with another id refuses the merge instead of overwriting. A pull that changes the vault first copies `vault.enc` to `backups/` (the newest 20, and any from the last 30 days, are kept), and applies all its changes in one save. `vaultos sync init`, `trust` and autosync halts are recorded in the signed audit log (`sync_init`, `sync_trust`, `sync_halted`).

### Automatic sync

Autosync is off by default. Once a device can push and pull by hand, run `vaultos --stop-backend sync auto on` (interval 30 to 86400 seconds, default 120), then `vaultos start` and `vaultos unlock`. While unlocked, `vaultosd` runs a round about 1.5 seconds after unlocking, about 5 seconds after each change, and on the interval; it pauses while locked. A round holds the vault only for its local steps, so agents are served while Git talks to the remote.

Autosync never accepts conflicts or bypasses a check. Network failures (`REMOTE_UNREACHABLE`, a rejected or unverified push) and a busy vault are retried next round, and a failed local commit (`COMMIT_FAILED`) for up to three rounds in a row. Anything else, such as `CONFLICTS_PENDING`, `SIGNATURE_INVALID` or diverged history, halts autosync: it writes `sync_halted` to the audit log and the reason to `vaultosd.log`, and waits. Fix the cause by hand (`vaultos --stop-backend sync pull`, review, `accept-conflicts` if appropriate), then restart `vaultosd` or run `vaultos sync now`, which also clears the halt.

`vaultos sync now` uses the session token in the private `daemon.json`, so it works only for your account; requests that carry an agent token are refused. `/status` without that token, which is what the MCP `vault_status` tool and `vaultos-agent status` report, shows only `enabled`, `state`, `halted`, `lastSyncAt` and `peerStalled` (a peer's heartbeat older than 48 hours or reporting uncommitted files). Error text and peer labels need the session token (`vaultos status`).

### Stop conditions

A signature, recipient, replay or unreadable-record error is a stop condition: restore trusted copies or investigate; do not bypass validation. The same repository rules as format 1 apply. Sync commits, reads and deletes only files under names it writes. A file such as Finder's `.DS_Store` that only your checkout has is left alone. One that arrives in a commit in `records/`, `tombstones/` or `manifests/` makes every device refuse to pull (`Unexpected file in the sync repository`) until someone removes it with `git rm`. A stray file Git tracks in `machines/` or `peers/` is taken out of the repository by the next push. A change to any other tracked file, a `.gitignore`, `.gitattributes` or `.gitmodules`, or an ignore rule outside the checkout that hides a file sync wrote, stops a push. Repository hooks are disabled for sync's Git commands.

### Keys and removal

Remote Git history keeps old ciphertext. Deleting a record, changing the password or adding a Secret Key does not erase that history, and there is no way yet to remove a device from a group or rotate its keys: to drop a device, start a new sync repository with new enrolments. See [SECURITY.md](../SECURITY.md#sync-format-2).

## Desktop app (sync format 1)

The desktop app and `node cli.cjs` keep using format 1 with a format v3 vault. Install Git and [age](https://github.com/FiloSottile/age). The default checkout is `sync-repository` inside preview data. `VAULTOS_SYNC_REPO` can select another absolute path for source/CLI usage. GUI sync uses its process environment. The preview refuses a nonempty checkout without its own format marker.

### First device

With the app quit, initialize a dedicated empty local checkout with `git init -b main /absolute/new/sync-repository`, set a repository-local Git author name/email you want recorded, and add the private remote with `git remote add origin <your-private-remote>`. Set `VAULTOS_SYNC_REPO` to that directory when invoking the CLI.

Run `node cli.cjs sync init 'Device A'`. Enter the vault password at the hidden prompt. Save the returned **public identity JSON** for verification on your other device. Run `node cli.cjs sync push`; require `delivered:true` and matching source/remote commits. A receipt proves remote Git acceptance, not that another device has pulled.

### Add another device

1. Clone that private sync repository into a new directory on device B. Create a separate preview vault on B; do not copy a live machine identity.
2. Initialize B with `sync init 'Device B'` and obtain B's public identity using `sync identity`.
3. Independently verify A's and B's age and signing public keys (or the displayed fingerprint) through a trusted channel. Trusting JSON fetched only from the same Git remote does not authenticate it.
4. On each device, save the verified peer JSON to a file and run `node cli.cjs sync trust /absolute/peer-identity.json`. Both need to trust each other **before encrypting to the expanded recipient list**.
5. Transfer B's public enrollment metadata (`machines/<id>.json` and its added public recipient) through the dedicated repository using Git. Review the staged paths. Never add `sync-age.key`, `sync-signing.key`, or any other file from a vault's private data directory.
6. A must fetch this recipient change and run `sync push` to encrypt current records for B. B can then `sync pull`. The push reports `reencryptedForNewRecipients:true` when the recipient set changes. Do not report an unreadable pull as success.

### Routine use

`sync status` fetches and reports transport and record drift. `sync push` encrypts changed records, signs ciphertext digests, commits only known sync paths, pushes, and checks the remote ref. `sync pull` fetches before verification/merge. Status exits 2 unless fully in sync; failed deliveries also exit 2 for automation.

Over SSH, one round's fetch, push and verifying fetch share a single connection. VaultOS runs `ssh` with `ControlMaster=auto`, `ControlPersist=300` and a control socket in a private (mode 0700) `vaultos-ssh-<uid>` folder under the system temporary directory, so the next round within five minutes reuses it too. It skips this when you set `GIT_SSH_COMMAND`, `GIT_SSH` or `core.sshCommand`, which also lets you turn it off, and when that folder is not private to you.

If content differs, inspect `sync plan` (local checkout only; fetch separately first) or the desktop's status/conflict output. Conflicts follow the same rules as format 2; use `sync accept-conflicts` only if you accept the proposed winner. The app stores an encrypted local backup before merging.

### Automatic sync

Autosync is off by default. After a device can push and pull manually, enable **Sync automatically** in desktop Settings (stored as `autoSync: { enabled, intervalSeconds }`, interval 30–86400 seconds, default 120). The process that currently owns the unlocked vault (the desktop, a one-shot backend, or the `--service` backend) then pulls and pushes on that interval and about 5 seconds after each local change. It is paused while the vault is locked.

Autosync never accepts conflicts. If a pull would need acceptance, or verification fails, or Git history diverges, it stops and reports the state until you act: review the plan and pull with acceptance in the desktop. Network failures are retried on the next round, and so is a failed local commit (`COMMIT_FAILED`) for up to three rounds in a row. Before it fetches, a round commits files an earlier round wrote but did not commit, only if the checkout passes the same signature checks as a pull. It never commits or discards any other change; if one blocks a rebase, autosync stops with `LOCAL_SYNC_REPO_DIRTY`.

`node cli.cjs sync now` asks the running owner to perform one round; it needs no password and exits 2 unless the round delivered. It uses the owner's session token, so it works only for your account, and agents cannot request it. The MCP `vault_status` tool reports sync health: autosync state, last successful sync, the last error, and `peerStalled`.

### Keys

Format 1 uses separate private age and Ed25519 keys (`sync-age.key`, `sync-signing.key`), stored locally with mode 0600. The vault passphrase does not encrypt them. Remote Git history retains old ciphertext; deleting a record or changing the vault password does not erase that history or revoke another peer's access. Peer removal and key rotation require a new sync group with new keys.
