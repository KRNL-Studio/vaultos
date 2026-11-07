# VaultOS

**Your project secrets, on your Mac. Give coding agents the access they need.**

VaultOS is a local desktop vault with an MCP bridge. Organize credentials by project, approve an agent's projects and output folders, and let it write a working environment file without returning the secret values in its tool response.

[Download the macOS preview](https://github.com/rohit3a/vaultos/releases) · [Agent setup](docs/AGENTS.md) · [Security model](SECURITY.md) · [Contribute](CONTRIBUTING.md)

> **Unsigned preview:** early software for evaluation, without Developer ID signing or Apple notarization. Start with test credentials and keep independent backups. Security regression tests are included; this project has not received an independent security audit.

<img src="docs/images/vaultos-preview.png" alt="VaultOS showing a synthetic example credential" width="480">

## Why use it?

- **Fewer secrets in chat.** `inject_secrets` writes approved keys to an approved file; its response contains names and counts, not values. Revealing a value requires a separate, off-by-default permission.
- **A human controls access.** Enroll and revoke individual agents. Choose their projects, output directories, and scopes. Agents cannot widen their own permissions.
- **Protect existing credentials.** Human-owned entries require explicit delegation before an agent can edit them. Agent-created credentials start awaiting approval for injection.
- **Local by default.** No account, hosted vault service, telemetry, or automatic cloud upload. Password remembering is optional and uses macOS Keychain or the Linux Secret Service, without a plaintext fallback.
- **Practical daily tools.** A menu bar item, a Quick Access panel (⇧⌘Space) to find and copy a key from any app, search across every project, expiry metadata, short-lived clipboard copies, encrypted PDF export, password rotation, encrypted backups, and guarded undo.
- **Optional encrypted sync.** Use a separate Git repository with age encryption, pinned peer signing identities, tamper checks, and explicit conflict acceptance.

Injection reduces accidental disclosure in tool transcripts. **It does not stop an agent with filesystem or shell access from reading the resulting file.** VaultOS is not an operating-system sandbox or an enterprise access-control service. Read the [threat model](SECURITY.md) before deciding what to store.

## Install on macOS

1. Download the ZIP and matching `.sha256` from the [preview release](https://github.com/rohit3a/vaultos/releases). Choose `arm64` for Apple Silicon or `x64` for Intel. The deployment target is macOS 13 or later; see release notes for versions actually tested.
2. In the download folder, run `shasum -a 256 -c <download-name>.zip.sha256` and confirm `OK`. This checks file integrity; it does not authenticate a publisher independently of GitHub.
3. Extract **VaultOS.app** and put it in a folder of your choice. It can coexist with other vault applications.
4. Try opening it. If macOS blocks the unidentified developer, follow Apple's [per-app Open Anyway instructions](https://support.apple.com/en-us/102445) in **System Settings → Privacy & Security**, only after you have verified and decided to trust the download. Managed Macs may disallow this. Do not disable Gatekeeper globally.
5. Create a new vault using a unique passphrase of at least 12 characters. There is no password reset or recovery service.

The desktop download includes its runtime. Node.js is needed only for source development, the MCP bridge, and the recovery CLI. Git and age are needed only for optional sync.

### First five minutes

Create an **Example App** project and add a disposable credential. In **Settings → Agents**, enroll your coding tool with `read` and `inject`, select that project, and approve its project folder. Save the one-time token in a private file and follow [MCP setup](docs/AGENTS.md). Ask the agent to inject the chosen key into that folder's `.env`; check the application works without asking it to print the file.

Use **Lock** when finished. While the desktop is running, Lock, system sleep, screen lock, or 15 minutes without a privileged desktop action stop the local API and clear the decrypted application state. Closing the window locks the vault the same way. On macOS VaultOS then stays in the menu bar, locked, until you reopen it, unlock Quick Access, or choose **Quit VaultOS**; turn the menu bar item off in **Settings** to quit when the window closes. If you explicitly enabled background Keychain access, the bridge can start a separate backend after the window closes. Manual lock blocks that until a human unlocks again. The separate headless backend does not monitor screen-lock events; disable background access or use Lock before closing if you need that boundary. Optional opt-in settings change this posture: a soft lock policy keeps agents served while the Mac is locked, an always-on service ([`scripts/install-service-macos.sh`](scripts/install-service-macos.sh)) takes over whenever the window is closed, autosync keeps [Git sync](docs/SYNC.md) running in the background, and on Macs with Touch ID (with background access on) **Settings → Touch ID** can unlock the window and confirm reveals, exports, approvals and agent changes with a fingerprint, falling back to the master password. Read [SECURITY.md](SECURITY.md) before enabling them.

### Menu bar and Quick Access

The menu bar item shows whether the vault is locked, how many agent records await approval, and sync health, and opens Quick Access, the window, Lock and Settings. Press **⇧⌘Space** anywhere to open Quick Access: type part of a key, project, username or website, then **⏎** copies the value, **⌘C** the username, **⌘O** opens the website and **⌘⏎** shows the key in VaultOS. Quick Access never receives values; the main process copies them. In the window, **⌘K** searches every project. **Settings → Menu bar & Quick Access** changes the shortcut, turns the menu bar item off, opens VaultOS at login (in the menu bar, locked) and turns on notifications for pending approvals and expiring keys. On Linux the tray icon is off by default (**Settings → Tray & Quick Access**), works only where the desktop shows tray icons, and the shortcut is **Ctrl+Shift+Space**.

## Install on Linux

Linux support is a source-built preview: no Linux release artifact is published, and the tested desktop target remains macOS. On an x64 or arm64 desktop with Node.js 22+, from a checkout:

```sh
npm ci
npm run dist:linux          # this machine's architecture; VAULTOS_ARCH=x64|arm64 overrides
scripts/install-linux.sh    # installs to ~/.local/opt/vaultos-preview (--prefix to change)
```

The installer adds an app-menu entry and a launcher and does not use root. If the kernel restricts unprivileged user namespaces (Ubuntu 24.04+), Chromium's sandbox needs a root-owned setuid `chrome-sandbox`: the installer prints the exact `sudo` command, or runs it with `--harden`. Until then the launcher starts the app with `--no-sandbox` and says so on stderr.

Optional password remembering uses the Secret Service through `secret-tool` (package `libsecret-tools` on Debian/Ubuntu, `libsecret` on Fedora) and a running keyring such as GNOME Keyring. Without them, background access is unavailable; there is no plaintext fallback. `--enable-service` also installs and starts a systemd user unit for this checkout's headless backend. It is never enabled by default and still unlocks only after you enable background access in Settings. Electron does not report screen-lock events on Linux, so screen lock does not lock the vault there; use **Lock**.

## Storage and recovery

Preview data lives in `~/Library/Application Support/VaultOS-Preview` on macOS and `~/.config/VaultOS-Preview` (or `$XDG_CONFIG_HOME/VaultOS-Preview`) on Linux, with a separate `org.vaultos.preview` Keychain or Secret Service namespace. It does not automatically import older applications' data, tokens, sync repositories, or Keychain entries. `VAULTOS_DATA_DIR` can select an **absolute, new directory** for testing.

Back up `vault.enc` and remember its password. Optional sync has separate machine keys and trust state. Read [backup, recovery, migration, and uninstall](docs/RECOVERY.md) before using real credentials.

## Run from source

Use Node.js 22 or later, npm, and macOS command-line developer tools for the native helper:

```sh
git clone https://github.com/rohit3a/vaultos.git
cd vaultos
npm ci
npm run build:native
npm start
```

The desktop release targets macOS; Linux builds come from `npm run dist:linux` (see above). Core tests run on both. To include the optional sync tests, install `age` (`brew install age` on macOS, or your distribution's package). Tests use temporary synthetic vaults.

```sh
npm run check
npm run test:ui          # macOS with an interactive desktop
npm run dist:mac         # unsigned preview for this Mac's architecture
VAULTOS_ARCH=x64 npm run dist:mac
npm run dist:linux       # unsigned Linux tar.gz; also cross-builds on macOS
```

See [development and release instructions](CONTRIBUTING.md), [architecture](docs/ARCHITECTURE.md), and [optional sync](docs/SYNC.md).

## Give your agent the instructions

Point an agent at [AGENTS.md](AGENTS.md) or ask it to read
[skills/vaultos/SKILL.md](skills/vaultos/SKILL.md). The skill covers macOS installation,
MCP connection, grants, daily secret operations, updates, backups, and troubleshooting.
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
