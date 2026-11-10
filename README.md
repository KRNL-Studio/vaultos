# VaultOS

**Your project secrets, on your Mac. Give coding agents the access they need.**

VaultOS is a local desktop vault with an MCP bridge. Organize credentials by project, approve an agent's projects and output folders, and let it write a working environment file without returning the secret values in its tool response.

[Download the macOS preview](https://github.com/KRNL-Studio/vaultos/releases) · [Agent setup](docs/AGENTS.md) · [Security model](SECURITY.md) · [Contribute](CONTRIBUTING.md)

> **Unsigned preview:** early software for evaluation, without Developer ID signing or Apple notarization. Start with test credentials and keep independent backups. Security regression tests are included; this project has not received an independent security audit.

<img src="docs/images/vaultos-preview.png" alt="VaultOS showing a synthetic example credential" width="480">

## Why use it?

- **Fewer secrets in chat.** `inject_secrets` writes approved keys to an approved file; its response contains names and counts, not values. Revealing a value requires a separate, off-by-default permission.
- **A human controls access.** Enroll and revoke individual agents. Choose their projects, output directories, and scopes. Agents cannot widen their own permissions.
- **Protect existing credentials.** Human-owned entries require explicit delegation before an agent can edit them. Agent-created credentials start awaiting approval for injection.
- **Local by default.** No account, hosted vault service, telemetry, or automatic cloud upload. Password remembering is optional and uses macOS Keychain or the Linux Secret Service, without a plaintext fallback.
- **Practical daily tools.** A menu bar item, a Quick Access panel (⇧⌘Space) to find and copy a key from any app, search across every project, expiry metadata, short-lived clipboard copies, encrypted PDF export, password rotation, encrypted backups, and guarded undo.
- **Secrets for programs, not prompts.** `vault://` references with `vaultos read`, `render` and `run` (output masked); a `run` scope so an agent can start an allowed command with secrets it never sees; and `vaultos scan` to catch the vault's values in files, staged changes and Git history.
- **SSH keys and commit signing.** An opt-in SSH agent serves your Ed25519 keys to ssh and Git, asking for Touch ID before each new program signs, and agents can ask for time-boxed access that you confirm.
- **A full password manager too.** Logins, API keys, notes, SSH keys, databases, servers and certificates with tags, favorites and custom fields; one-time codes; a password and passphrase generator; a Trash and archive; per-item versions; encrypted attachments; Watchtower for weak, reused, old and expiring secrets with an opt-in breach check; and import from 1Password, Bitwarden and CSV.
- **Optional encrypted sync.** Use a separate Git repository with age encryption, pinned peer signing identities, tamper checks, and explicit conflict acceptance.

Injection reduces accidental disclosure in tool transcripts. **It does not stop an agent with filesystem or shell access from reading the resulting file.** VaultOS is not an operating-system sandbox or an enterprise access-control service. Read the [threat model](SECURITY.md) before deciding what to store.

## Install on macOS

1. Download the ZIP and matching `.sha256` from the [preview release](https://github.com/KRNL-Studio/vaultos/releases). Choose `arm64` for Apple Silicon or `x64` for Intel. The deployment target is macOS 13 or later; see release notes for versions actually tested.
2. In the download folder, run `shasum -a 256 -c <download-name>.zip.sha256` and confirm `OK`. This checks file integrity; it does not authenticate a publisher independently of GitHub. Releases from the release workflow also carry signed build provenance: `gh attestation verify <download-name>.zip --repo KRNL-Studio/vaultos` checks that this repository's workflow built the file from the tagged source.
3. Extract **VaultOS.app** and put it in a folder of your choice. It can coexist with other vault applications.
4. Try opening it. If macOS blocks the unidentified developer, follow Apple's [per-app Open Anyway instructions](https://support.apple.com/en-us/102445) in **System Settings → Privacy & Security**, only after you have verified and decided to trust the download. Managed Macs may disallow this. Do not disable Gatekeeper globally.
5. Create a new vault using a unique passphrase of at least 12 characters. Optionally add a Secret Key, which the device keeps and a stolen vault file cannot be opened without. There is no password reset or recovery service.

The app is a small native program (Rust, with the system's own web view for its pages). The MCP bridge (`vaultos-mcp`), the agent shell client (`vaultos-agent`), the CLI (`vaultos`), the headless owner (`vaultosd`), the Git signing helper (`vaultos-ssh-sign`) and the browser extension's helper (`vaultos-browser`) ship inside it, in `VaultOS.app/Contents/Helpers`, with the extension in `Contents/Resources/extension`. Git is needed only for optional sync. A vault from VaultOS 0.2 opens only to be upgraded, when you choose **Upgrade this vault**; read [Upgrading from 0.2](docs/RECOVERY.md#upgrading-from-02) first.

### First five minutes

Create an **Example App** project and add a disposable credential. In **Settings → Agents**, enroll your coding tool with `read` and `inject`, select that project, and approve its project folder. Save the one-time token in a private file and follow [MCP setup](docs/AGENTS.md). Ask the agent to inject the chosen key into that folder's `.env`; check the application works without asking it to print the file.

Use **Lock** when finished. While the desktop is running, Lock, system sleep, screen lock, or 15 minutes without a privileged desktop action stop the local API and clear the decrypted application state. Closing the window locks the vault the same way. On macOS VaultOS then stays in the menu bar, locked, until you reopen it, unlock Quick Access, or choose **Quit VaultOS**; turn the menu bar item off in **Settings** to quit when the window closes. Optional opt-in settings change this posture: background access with the always-on service ([background access](docs/AGENTS.md#background-access)) keeps agents served after the window closes, until a Lock, screen lock, sleep or idle lock blocks it; a soft lock policy keeps agents served while the Mac is locked; autosync keeps [Git sync](docs/SYNC.md) running in the background, and on Macs with Touch ID **Settings → Touch ID** can unlock the window and confirm reveals, exports, approvals and agent changes with a fingerprint, falling back to the master password. Read [SECURITY.md](SECURITY.md) before enabling them.

### Menu bar and Quick Access

The menu bar item shows whether the vault is locked, how many agent records await approval, and sync health, and opens Quick Access, the window, Lock and Settings. Press **⇧⌘Space** anywhere to open Quick Access: type part of a key, project, username or website, then **⏎** copies the value, **⌘C** the username, **⌘O** opens the website and **⌘⏎** shows the key in VaultOS. Quick Access never receives values; the main process copies them. In the window, **⌘K** searches every project. **Settings → Menu bar & Quick Access** changes the shortcut, turns the menu bar item off, opens VaultOS at login (in the menu bar, locked) and turns on notifications for pending approvals and expiring keys. On Linux the tray icon is off by default (**Settings → Tray & Quick Access**), works only where the desktop shows tray icons, and the shortcut is **Ctrl+Shift+Space**.

### Secrets for programs and SSH

`vaultos run --project "Example App" -- npm start` starts a program with that project's values in its environment and masks them in its output; `vaultos read "vault://Example App/DB_URL"` prints one value and `vaultos render config.tmpl -o config.yml` fills a template. While the app is unlocked each of these asks for Touch ID. `vaultos scan --staged` in a pre-commit hook stops a commit that contains one of your values (`vaultos scan --update-index` once first).

Turn on **Settings → SSH agent** to use SSH key items with ssh and Git. The panel shows the `IdentityAgent` line for `~/.ssh/config` and the Git settings for signing commits with `vaultos-ssh-sign`. See [SECURITY.md](SECURITY.md#boundaries-and-limitations) for what an approval covers.

### Browser extension

The **VaultOS (Preview)** extension fills and saves website logins in Chrome, Chromium, Brave, Edge, Arc, Helium, Vivaldi and Safari. In **Settings → Browsers** choose **Set up browsers** (or run `vaultos browser install`). Then, in each browser, open `chrome://extensions`, turn on **Developer mode**, choose **Load unpacked** and pick `VaultOS.app/Contents/Resources/extension` (on Linux, `extension` in the install folder). Click the extension's toolbar icon, choose **Pair with VaultOS** and confirm in VaultOS when it shows the same code. Focus a login field on a site you have a login for and press the **V** button to fill it, or choose a login in the toolbar popup; each login shows the host it was saved for. After you sign in with a new password, the next page offers **Save**, or **Update** for the login it changes. Logins are offered only on their own site, over HTTPS (http only on localhost); see [SECURITY.md](SECURITY.md#boundaries-and-limitations). Load the extension only from VaultOS's own folder: an unpacked extension's ID can be copied.

In Safari 16.4 or later, the extension comes with the app: open VaultOS once from `/Applications`, then turn on **VaultOS** in Safari → Settings → Extensions and allow it on the sites you use (a preview build that is not notarized also needs Safari's Develop → **Allow Unsigned Extensions**, which Safari turns off again when it quits). Pair it from its toolbar popup as above. Safari reaches only the default data folder, not one set with `VAULTOS_DATA_DIR`. Safari cannot tell the extension whether a page covers its controls, so it shows no **V** button: fill from the toolbar popup, and save or update a login from the popup after you sign in.

In Chromium browsers the extension is also a passkey provider. When a site asks to create a passkey or sign in with one, VaultOS opens its own small window naming the site: choose **Save passkey in VaultOS**, pick one of your passkeys for that site, or choose **Use another device or security key** to let the browser handle it as before. A new passkey goes into the site's login for that username, or into a new login in the **Logins** project, in a **Passkey** section; it syncs with the vault. Unless the site says verification is unnecessary, VaultOS also asks for Touch ID; a site that requires it gets the browser's own passkey dialog where there is no Touch ID. When VaultOS has no passkey for the site, is locked or not paired, or the site asks for a security key, the browser's own passkey dialog appears instead. Passkey autofill in a site's username field, Safari and importing passkeys from other managers are not supported yet.

## Install on Linux

Linux support is a preview with less testing than macOS. The app needs the system's WebKitGTK 4.1 and, for the tray icon, libayatana-appindicator3. Releases include an x64 tarball; from a source checkout, install it with `scripts/install-linux.sh --from <download-name>.tar.gz`, which checks the `.sha256` beside it. To build instead (x64 or arm64, this machine's architecture), install Rust, Node.js 22+ and, on Debian/Ubuntu, `libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev`:

```sh
npm run dist:linux          # dist/vaultos-preview-linux-<arch> and a tar.gz
scripts/install-linux.sh    # installs to ~/.local/opt/vaultos-preview (--prefix to change)
```

The installer adds an app-menu entry and does not use root. Optional password remembering uses the Secret Service through `secret-tool` (package `libsecret-tools` on Debian/Ubuntu, `libsecret` on Fedora) and a running keyring such as GNOME Keyring. Without them, background access is unavailable; there is no plaintext fallback. `--enable-service` also installs and starts a systemd user unit that runs the installed app as the background service. It is never enabled by default and still unlocks only after you enable background access in Settings. Screen lock is read from logind, which most screen lockers update.

## Storage and recovery

Preview data lives in `~/Library/Application Support/VaultOS-Preview` on macOS and `~/.config/VaultOS-Preview` (or `$XDG_CONFIG_HOME/VaultOS-Preview`) on Linux, with a separate `org.vaultos.preview` Keychain or Secret Service namespace. It does not automatically import older applications' data, tokens, sync repositories, or Keychain entries. `VAULTOS_DATA_DIR` can select an **absolute, new directory** for testing.

Back up with `vaultos backup` (or copy `vault.enc`) and keep its password, and its Secret Key if it has one. Sync keys are inside the vault; the sync index beside it is part of the backup. Read [backup, recovery, migration, and uninstall](docs/RECOVERY.md) before using real credentials.

## Run from source

Install Rust with rustup (it fetches the toolchain pinned in `rust-toolchain.toml`), Node.js 22+ for the build and test scripts, and on macOS the command-line developer tools:

```sh
git clone https://github.com/KRNL-Studio/vaultos.git
cd vaultos
npm start                # a debug build of the desktop
```

Tests use temporary synthetic vaults.

```sh
cargo test --workspace
npm run check
npm run test:desktop     # macOS with an interactive desktop
npm run dist:mac         # unsigned app for this Mac's architecture
VAULTOS_ARCH=x64 npm run dist:mac
npm run dist:linux       # unsigned Linux tar.gz, on Linux for its own architecture
```

See [development and release instructions](CONTRIBUTING.md), [architecture](docs/ARCHITECTURE.md), and [optional sync](docs/SYNC.md).

## Give your agent the instructions

Point an agent at [AGENTS.md](AGENTS.md) or ask it to read
[skills/vaultos/SKILL.md](skills/vaultos/SKILL.md). The skill covers macOS and Linux
installation, MCP connection, grants, daily secret operations, updates,
backups, and troubleshooting.
For clients supporting Agent Skills, install the complete `skills/vaultos/` folder
using the client's skill installation mechanism; keep its `references/` directory.
Clients supporting named skill invocation can then use `$vaultos`.

Example request: “Use the VaultOS skill to connect this agent to my preview vault
with read and inject access to my project.” The skill provides instructions; the
human still unlocks the vault and grants access in the desktop. It contains no
credentials and does not automatically change client configuration.

## Project status

This first public preview prioritizes a small, inspectable local workflow. Remaining release milestones include independent security review, Developer ID signing and notarization, broader macOS/Intel runtime coverage, accessibility review, and usability improvements to conflict resolution. No automatic updater is enabled; install future releases explicitly after backing up.

Built and maintained by [@rohit3a](https://github.com/rohit3a). Contributions, reproducible bug reports using synthetic data, and security review are welcome. Licensed under [MIT](LICENSE); dependencies retain their own licenses.
