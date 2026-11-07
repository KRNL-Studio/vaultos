# Backups, recovery, migration, and removal

The preview uses `~/Library/Application Support/VaultOS-Preview` on macOS and `~/.config/VaultOS-Preview` (or `$XDG_CONFIG_HOME/VaultOS-Preview`) on Linux. It never searches or migrates older app data automatically. The directory is private (0700); sensitive files are 0600. Keep backups on encrypted storage with appropriate access controls.

## Back up

Quit the preview, then copy `vault.enc` to a new backup location. Or, from a source checkout:

```sh
node cli.cjs backup /absolute/new/backup-directory
```

This copies only the encrypted vault. The command overwrites `vault.enc` in the chosen directory, so choose a new dated directory for each snapshot. You must retain the corresponding passphrase. Do not send backups in bug reports or commit them to the public source repository.

A pull that changes the vault also keeps its own copy of `vault.enc` in `backups/` inside the data directory. Only the newest 20 of those, plus any from the last 30 days, are kept, so they do not replace your own dated backups. Other files you place in `backups/` are never deleted.

Sync users additionally need the whole private preview data directory for their machine identity, signing key and replay state. This directory includes sensitive local keys and audit metadata; encrypt the backup itself. Avoid restoring the same machine identity on two simultaneously active devices. Enroll a new machine for a new installation.

## Test recovery without touching a working vault

Create a new private directory outside any existing installation. Copy your backed-up `vault.enc` there, set its mode to 0600, and use the source CLI with `VAULTOS_DATA_DIR=/absolute/new/recovery-directory node cli.cjs projects`. It prompts for a password without echo. Confirm the expected project names. The CLI does not print values; `inject` can deliberately export to a protected test folder when needed.

The preview can read older supported encrypted envelopes and migrate their schema. Always perform this on a copy in a new directory first. It does not migrate prior apps' Keychain services, token files, install paths, launch agents, or sync repositories (see [Importing from the earlier vault-os fork](#importing-from-the-earlier-vault-os-fork) for the one explicit import command). Existing agent grants and sync identities deserve review; a fresh vault with deliberately entered credentials is the safest preview evaluation path.

For actual replacement, quit all processes owning that **preview** directory, preserve the current files elsewhere, then place the verified backup there. Unlock and review agent access. A restored vault may restore previously revoked agent tokens; reissue or revoke them before restarting integrations. Never replace a file while the vault is open.

## Importing from the earlier vault-os fork

If you used the earlier `vault-os` fork, you can import its data directory once, explicitly, into a **new, empty** preview data directory. Nothing does this automatically. Quit the earlier app and any background service it runs, and quit VaultOS, then from a source checkout:

```sh
node cli.cjs import-legacy --from /absolute/path/to/earlier/vault-os --plan
node cli.cjs import-legacy --from /absolute/path/to/earlier/vault-os
```

The earlier directory is `~/Library/Application Support/vault-os` on macOS and `~/.config/vault-os` (or `$XDG_CONFIG_HOME/vault-os`) on Linux. Set `VAULTOS_DATA_DIR` first to import somewhere other than the default preview directory.

- `--plan` decrypts a temporary copy and prints counts, records that fail this build's validation (by project and key name and the rule, never values), name collisions, previously denied keys and history entries that cannot be undone here. It writes nothing.
- The import refuses if the target already has a vault, if `--from` is the target, if either app is running, or if any record fails validation. Fix reported records in the earlier app and retry.
- The vault is re-encrypted with this build's envelope and migrated to format v3. The earlier directory is only read; its plaintext password file (`backend.key`), session file, Keychain entries and sync state are never read or copied. Set up a new sync group afterwards with `sync init`.
- Agents keep their token hashes, so existing agent tokens keep working, but they start with no project or folder access. Grant access in Settings → Agents or with `agents grant`, or pass `--grant-all-existing-agents` to give every non-revoked agent all-access grants.
- A shared agent token file (`agent-token`, or `agents/NAME.token`) whose hash matches an enrolled agent is copied to `<data directory>/agents/NAME.token` (0600); set `VAULTOS_AGENT=NAME` for that agent's bridge. Tokens are never printed.
- This build has no separate "denied" state: keys denied in the earlier app arrive held for approval. Deny (which removes them) or approve them in VaultOS.
- `audit.log` is copied with an import entry appended, and `backups/*.enc` are copied unchanged. Those backups remain in the earlier envelope and password; this build can read them.
- The PDF export password and approval relay hash carry over. `--lock-policy soft|hard` and `--auto-sync` set those options. Background access stays off unless you pass `--remember-password`, which stores the master password in the macOS Keychain or Linux Secret Service (the import refuses if neither is available); add `--touch-id` to turn on Touch ID unlock.

To roll back, quit VaultOS and remove the new preview data directory. The earlier data directory is unchanged.

## Password rotation

Settings → Change master password verifies the current password and re-encrypts the live vault. It then attempts to update optional Keychain storage and each decryptable file in the local `backups` directory. Review the returned outcomes. Keep both old and new passwords until you have verified every file: failure partway through can leave files using different passwords. External backups and sync history do not change. Rotate leaked credentials at their issuing services as well.

There is no password reset, escrow key, or server recovery. Losing both your passphrase and accessible remembered Keychain item means losing access to that encrypted vault.

## Concurrent process or disk errors

A process ownership lock prevents desktop/backend/CLI overlap. A disk hash check prevents stale writers from overwriting a changed vault. Close the other **preview** process and unlock again. Dead-process locks recover automatically; an invalid or empty lock may require inspection and manual removal after confirming no preview process is running. Do not remove locks just to force a concurrent write. On I/O failure, preserve the directory and check disk space and permissions before retrying.

## Uninstall

Quit **VaultOS** (menu bar → **Quit VaultOS**; closing the window leaves it in the menu bar), remove its MCP client entry, and delete the preview app. Preserve an encrypted backup if needed. To forget background access, disable it in Settings or click Lock before quitting. Its Keychain service begins with `org.vaultos.preview.`; delete only the matching preview entry if manual cleanup is necessary. Then remove only the preview data directory and your preview agent token file. The app creates a login item only if you turned on **Open at login**: turn it off in Settings first, or remove `~/Library/LaunchAgents/org.vaultos.preview.desktop.plist` (Linux: `~/.config/autostart/org.vaultos.preview.desktop.desktop`). It creates no automatic updater or system service.

On Linux, the remembered password is a Secret Service item whose `service` attribute begins with `org.vaultos.preview.`; disabling background access removes it, or delete only that item in a keyring manager such as Seahorse. If you installed the backend unit, run `systemctl --user disable --now vaultos-preview-backend.service` and remove `~/.config/systemd/user/vaultos-preview-backend.service`. Then remove the install folder (default `~/.local/opt/vaultos-preview`) and `~/.local/share/applications/org.vaultos.preview.desktop`.
