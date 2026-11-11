# Optional encrypted Git sync

Sync is for your own trusted devices. Each enrolled device can decrypt all records in its sync group. Start with disposable vaults, use a **new private Git repository** that holds nothing else, and keep sync off until you configure it. No Git credentials are stored in the vault or published by the project; configure transport through your normal Git tools.

VaultOS 0.3 uses **sync format 2**, in the desktop app and in the command-line tools (`vaultos`, `vaultosd`), with a format v4 vault. Sync format 1, which VaultOS 0.2 and earlier used with format v3 vaults, is retired: 0.3 stops with `UNSUPPORTED_REPOSITORY` on a format 1 repository, and nothing converts one. To move a sync group to 0.3, upgrade every device's vault (the desktop's **Upgrade this vault**, or `vaultos upgrade`), then start a **new, empty** sync repository and enrol each device again.

## Sync format 2

The checkout is `sync-repository` inside the data directory, or the absolute path in `VAULTOS_SYNC_REPO`. Set it the same way for the app, `vaultos` and `vaultosd`; `vaultos start` passes its environment on. Git is needed; no `age` binary is. In the desktop, **Settings → Sync** sets up this device, shows its identity, trusts a peer, pushes and pulls, and turns on **Sync automatically**; the steps below use the CLI, and each has the same rules in the app. Every `vaultos sync` command except `now` opens the vault itself and asks for the master password, so quit the app or stop a running `vaultosd` first, or add `--stop-backend`.

### What it stores

A device's keys are made by `vaultos sync init` and kept **inside the encrypted vault**: an X25519 age key that receives records, and an Ed25519 key that signs. Nothing about sync is kept in a plaintext key file, so a stolen data directory without the password (and Secret Key, if set) does not open the sync repository. The repository holds:

| Path | Contents |
| --- | --- |
| `vaultos-sync.json` | `{"app":"VaultOS-Preview","version":2}` |
| `recipients.txt` | The age public key of every device |
| `machines/<id>.json` | Each device's public identity: id, label, signing and age public keys |
| `records/<hash>.age`, `tombstones/<hash>.age` | One age file per record or deletion, encrypted to every recipient; the name is a SHA-256 of the record's id |
| `manifests/<id>.json` | Each device's Ed25519-signed manifest: a counter, the newest push it had seen from every other device, and every ciphertext file with its digest and the push that wrote it |
| `peers/<id>.json` | Each device's signed heartbeat |

A file verifies only if some manifest signs it and no manifest that had seen the push which wrote it lists it differently or not at all: an older ciphertext restored from Git history is refused as `ROLLBACK`, even while a stale manifest from another device still signs it. A manifest that names a push newer than the checkout holds, or a device whose manifest is gone, is refused the same way. A committed `.gitignore`, `.gitattributes` or `.gitmodules` anywhere in the checkout stops sync (remove it with `git rm`), and a push refuses to commit if a Git filter or line-ending rule would store other bytes than sync wrote.

Manifests sign ciphertext digests, not plaintext. Unlike the retired format 1, they carry no per-record content hash or fingerprint, so the repository cannot be used to guess low-entropy values. Signatures are domain-separated (`vaultos/v4/sync-manifest`, `vaultos/v4/sync-heartbeat`), so a manifest signature cannot be replayed as a heartbeat or as anything the vault signs.

The local index (`sync-index.json` in the data directory) remembers what was last synced, each peer's latest counter and the recipient list. Its record hashes are keyed with a key derived from this device's signing key, and the whole file carries an HMAC under another, so it reveals nothing to someone who copies it, and a modified index stops sync with `Invalid sync index; restore a trusted backup`. `vaultos backup` copies it with the vault and audit log. A device restored without it still continues its push counter from its manifest in the repository, but forgets which manifests it had seen, so it cannot tell a complete older copy of the repository from the current one.

### Set up from the repository address

The short way, in the app (**Settings → Sync**) or with the CLI. Create an empty private repository, then on each device:

```sh
vaultos --stop-backend sync setup git@example.com:you/vaultos-sync.git 'Device A'
```

The first device starts the repository and pushes. Every later device clones it and lists the devices already there:

```sh
vaultos sync pending                  # each waiting device, with its code
vaultos sync approve DEVICE_ID 'A1B2 C3D4 E5F6 0718'
vaultos sync push
```

A device's code is the first 64 bits of its fingerprint. Each device shows its own (`vaultos sync identity`, or **This device** in the app). Approve a device only when the code listed for it is the code that device shows for itself; the repository cannot vouch for it. Both sides approve each other: the new device approves the existing ones and pushes, then an existing device runs `sync pending`, approves the new one and pushes, which encrypts every record for it. Then pull on the new device. In the app the same steps are **Set up sync**, **Codes match, add it** and **Sync now**.

The address must not contain a password or token. The sections below do the same by hand.

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
| `vaultos sync devices` | Lists the trusted devices with their ids, and the removed ones |
| `vaultos sync untrust DEVICE_ID` | Removes a device, or confirms a removal made on another device; see [Remove a device](#remove-a-device) |
| `vaultos sync status` | Fetches and reports one state for the whole group; exits 2 unless `IN_SYNC` |
| `vaultos sync push` | Encrypts changed records, signs the manifest, commits only sync's own files, pushes and checks the remote ref; exits 2 unless delivered |
| `vaultos sync pull` | Fetches, verifies and merges; stops on concurrent edits |
| `vaultos sync plan` | What a pull of the local checkout would change, by project and key name (never values); fetch first for current results |
| `vaultos sync accept-conflicts` | Fetches and merges, resolving concurrent edits by revision |
| `vaultos sync auto on [--interval SECONDS]`, `auto off` | Turns autosync in `vaultosd` on or off |
| `vaultos sync now` | Asks the running `vaultosd` for one round; exits 2 unless it succeeded |

Over SSH, one round's fetch, push and verifying fetch share a single connection. VaultOS runs `ssh` with `ControlMaster=auto`, `ControlPersist=300` and a control socket in a private (mode 0700) `vaultos-ssh-<uid>` folder under the system temporary directory, so the next round within five minutes reuses it too. It skips this when you set `GIT_SSH_COMMAND`, `GIT_SSH` or `core.sshCommand`, which also lets you turn it off, and when that folder is not private to you.

Output never contains values. A record changed on one device only since the last sync merges as an ordinary update. A record changed on both, or any case the index cannot vouch for, is a conflict (`CONFLICTS_PENDING`): back up both devices, review `sync plan` (the higher revision wins, then the later timestamp; an exact tie goes to the same version on every device) and run `sync accept-conflicts` only if you accept that. A project or key name that already exists with another id refuses the merge instead of overwriting. A pull that changes the vault first copies `vault.enc` to `backups/` (the newest 20, and any from the last 30 days, are kept), and applies all its changes in one save. `vaultos sync init`, `trust` and autosync halts are recorded in the signed audit log (`sync_init`, `sync_trust`, `sync_halted`).

### Automatic sync

Autosync is off by default. Once a device can push and pull by hand, turn on **Sync automatically** in the app's Settings, or run `vaultos --stop-backend sync auto on` (interval 30 to 86400 seconds, default 120), then `vaultos start` and `vaultos unlock`. While unlocked, whichever process owns the vault (the app, the background service or `vaultosd`) runs a round about 1.5 seconds after unlocking, about 5 seconds after each change, and on the interval; it pauses while locked. A round holds the vault only for its local steps, so agents are served while Git talks to the remote.

Autosync never accepts conflicts or bypasses a check. Network failures (`REMOTE_UNREACHABLE`, a rejected or unverified push) and a busy vault are retried next round, and a failed local commit (`COMMIT_FAILED`) for up to three rounds in a row. Anything else, such as `CONFLICTS_PENDING`, `SIGNATURE_INVALID` or diverged history, halts autosync: it writes `sync_halted` to the audit log and the reason to `vaultosd.log`, and waits. Fix the cause by hand (`vaultos --stop-backend sync pull`, review, `accept-conflicts` if appropriate), then restart `vaultosd` or run `vaultos sync now`, which also clears the halt.

`vaultos sync now` uses the session token in the private `daemon.json`, so it works only for your account; requests that carry an agent token are refused. `/status` without that token, which is what the MCP `vault_status` tool and `vaultos-agent status` report, shows only `enabled`, `state`, `halted`, `lastSyncAt` and `peerStalled` (a peer's heartbeat older than 48 hours or reporting uncommitted files). Error text and peer labels need the session token (`vaultos status`).

### Stop conditions

A signature, recipient, replay or unreadable-record error is a stop condition: restore trusted copies or investigate; do not bypass validation. Sync commits, reads and deletes only files under names it writes. A file such as Finder's `.DS_Store` that only your checkout has is left alone. One that arrives in a commit in `records/`, `tombstones/` or `manifests/` makes every device refuse to pull (`Unexpected file in the sync repository`) until someone removes it with `git rm`. A stray file Git tracks in `machines/` or `peers/` is taken out of the repository by the next push. A change to any other tracked file, a `.gitignore`, `.gitattributes` or `.gitmodules`, or an ignore rule outside the checkout that hides a file sync wrote, stops a push. Repository hooks are disabled for sync's Git commands.

### Remove a device

To drop a lost or retired device, run this on a device you still have (or use **Settings → Sync → Remove a device** in the app):

```sh
vaultos sync devices            # ids, labels and fingerprints of the devices this vault trusts
vaultos sync untrust DEVICE_ID
```

`untrust` fetches first when the remote can be reached. It then stops trusting the device, takes its key out of `recipients.txt`, deletes its manifest, identity and heartbeat, writes a signed removal to `revoked/<id>.json`, and pushes, which encrypts every record and tombstone again for the devices that remain. If the remote cannot be reached, the device is still removed here and the next sync round sends it. The removal is recorded in the signed audit log (`sync_untrust`).

Every other device then stops syncing and says which device was removed and where. Run the same `vaultos sync untrust DEVICE_ID` there to confirm it. One device cannot end another's trust on its own: if the message names a removal you did not make, the device that signed it may be the compromised one. Remove that device instead, which also discards the removals it signed, and restore the repository to the commit before its changes with Git.

A removed device is told so at its next sync and can no longer pull or push. Its manifest reappearing, or its key reappearing in `recipients.txt`, stops sync on the others.

Removal protects what changes afterwards. The removed device keeps its own copy of the vault, and the repository's Git history keeps ciphertext it can still decrypt, so change every secret that matters after removing a lost device. A device cannot remove itself, and there is no key rotation for a device that stays.

### History

Remote Git history keeps old ciphertext. Deleting a record, removing a device, changing the password or adding a Secret Key does not erase that history. See [SECURITY.md](../SECURITY.md#sync-format-2).

### An interrupted push

A push names the files it is about to write in `sync-push.journal` in the data directory (authenticated with a key derived from this device's signing key, and holding file names only) and removes it once its manifest signs them. If the push stops in between (a crash, a power cut), the next `vaultos sync push`, `vaultos sync pull` or autosync round writes those files again and signs them before anything else is checked. They are never decrypted or trusted as they were left. Until then `vaultos sync plan` and `status` report `Unsigned or modified ciphertext`. A file the journal does not name is refused as before.

