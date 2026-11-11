# Backups, recovery, migration, and removal

The preview uses `~/Library/Application Support/VaultOS-Preview` on macOS and `~/.config/VaultOS-Preview` (or `$XDG_CONFIG_HOME/VaultOS-Preview`) on Linux. It never searches or migrates older app data automatically. The directory is private (0700); sensitive files are 0600. Keep backups on encrypted storage with appropriate access controls.

The `vaultos` command below ships inside the app: `VaultOS.app/Contents/Helpers/vaultos` on macOS, `vaultos` in the install folder on Linux.

## Back up

Quit VaultOS (and stop the background service if you installed it), then:

```sh
vaultos backup /absolute/new/dated-backup-directory
```

This copies `vault.enc`, the signed audit log (`audit-v4.log`) and the sync index, never tokens or other credentials. Choose a new dated directory for each snapshot. Restoring needs the master password and, if the vault has one, its Secret Key: keep both, separately from the backup. The Emergency Kit (Settings → Secret Key → Save Emergency Kit, or `vaultos secret-key kit FILE`) is a printable page with the key. Do not send backups in bug reports or commit them to the public source repository.

A pull that changes the vault, and the upgrade from an 0.2 vault, keep their own copies of `vault.enc` in `backups/` inside the data directory. Only the newest 20 pull copies, plus any from the last 30 days, are kept, so they do not replace your own dated backups. Other files you place in `backups/` are never deleted.

A device's sync keys are inside the encrypted vault, so a backup carries them. Avoid restoring the same vault on two simultaneously active devices in one sync group; enrol a new device for a new installation.

## Test recovery without touching a working vault

Create a new private directory outside any existing installation. Copy your backed-up files there, set their mode to 0600, and run `VAULTOS_DATA_DIR=/absolute/new/recovery-directory vaultos projects`. It prompts for the password without echo (add `--secret-key-file PATH` if the vault has a Secret Key). Confirm the expected project names. The CLI does not print values; `vaultos inject PROJECT /absolute/protected/test/.env` can deliberately export to a protected test folder when needed.

For actual replacement, quit all processes owning that **preview** directory, preserve the current files elsewhere, then place the verified backup there. Unlock and review agent access. A restored vault may restore previously revoked agent tokens; reissue or revoke them before restarting integrations. Never replace a file while the vault is open.

## Upgrading from 0.2

VaultOS 0.3 stores vaults in format v4. It opens a vault from 0.2 or an earlier preview (format v3) only to upgrade it, and only when you ask: the app shows **Upgrade this vault** on the unlock screen, and `vaultos upgrade` does the same from a terminal. The upgrade checks the new file against the old one before replacing anything and keeps the old file as `backups/vault-v3-<time>-<hash>.enc`. It is one-way: 0.2 cannot open the upgraded vault. Test it on a copy in a new `VAULTOS_DATA_DIR` first.

Projects, agents and their grants, approvals, settings and history carry over; agent tokens keep working. Sync does not: 0.3 uses sync format 2, so set up a new, empty sync repository afterwards ([sync guide](SYNC.md)). A password 0.2 remembered in the Keychain was stored by a different program, so macOS may ask once before 0.3 reads it. An always-on service installed for 0.2 runs the old Node backend: uninstall it and install the 0.3 one ([agent setup](AGENTS.md#background-access)).

After upgrading:

- Point each MCP client at the bridge inside the app and restart agent sessions that were already running. A session started before the upgrade keeps the 0.2 bridge, which can only report that VaultOS is not running.
- If 0.2 ran as a service, finish with `scripts/install-service-macos.sh` or `scripts/install-linux.sh --enable-service`; a `vaultosd` started by hand does not come back after a restart.
- Anything that read `session.json` and a localhost port must change: 0.3 writes `daemon.json` and listens on a Unix socket that accepts only the vault's user. A helper that runs as another account, root included, is refused.
- `/status` reports both `locked` and `unlocked`.

The one-time import from the earlier `vault-os` fork (`import-legacy`) is not part of 0.3. To import such a vault, use the 0.2 release's `cli.cjs import-legacy` into a new data directory, then upgrade that vault with 0.3.

## Password rotation

Settings → Change master password (or `vaultos rotate-password`) verifies the current password and re-encrypts the live vault. It then attempts to update optional Keychain storage and each decryptable file in the local `backups` directory. Review the returned outcomes. Keep both old and new passwords until you have verified every file: failure partway through can leave files using different passwords. External backups and sync history do not change. Rotate leaked credentials at their issuing services as well.

There is no password reset, escrow key, or server recovery. Losing your password (or the Secret Key of a vault that has one) and any accessible remembered Keychain item means losing access to that encrypted vault.

## Concurrent process or disk errors

A process ownership lock prevents the app, the background service, `vaultosd` and the CLI from owning the vault at once. A check of the file before each save prevents stale writers from overwriting a changed vault. Close the other **preview** process and unlock again. Dead-process locks recover automatically; an invalid or empty lock may require inspection and manual removal after confirming no preview process is running. Do not remove locks just to force a concurrent write. On I/O failure, preserve the directory and check disk space and permissions before retrying.

## Uninstall

Quit **VaultOS** (menu bar → **Quit VaultOS**; closing the window leaves it in the menu bar), remove its MCP client entry, and delete the app. Preserve an encrypted backup if needed. To forget background access, turn it off in Settings or click Lock before quitting. Its Keychain service begins with `org.vaultos.preview.`; delete only the matching preview entry if manual cleanup is necessary. If you installed the background service, run `scripts/install-service-macos.sh --uninstall` from a source checkout (or `launchctl bootout gui/$(id -u)/org.vaultos.preview.backend` and remove `~/Library/LaunchAgents/org.vaultos.preview.backend.plist`). Then remove only the preview data directory and your preview agent token file. The app creates a login item only if you turned on **Open at login**: turn it off in Settings first, or remove `~/Library/LaunchAgents/org.vaultos.preview.desktop.plist` (Linux: `~/.config/autostart/org.vaultos.preview.desktop.desktop`). It creates no automatic updater.

On Linux, the remembered password is a Secret Service item whose `service` attribute begins with `org.vaultos.preview.`; turning off background access removes it, or delete only that item in a keyring manager such as Seahorse. If you installed the background unit, run `systemctl --user disable --now vaultos-preview-backend.service` and remove `~/.config/systemd/user/vaultos-preview-backend.service`. Then remove the install folder (default `~/.local/opt/vaultos-preview`) and `~/.local/share/applications/org.vaultos.preview.desktop`.
