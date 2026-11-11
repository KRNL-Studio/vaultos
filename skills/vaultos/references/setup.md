# Install and connect

## Identify the target

Determine whether the app and MCP client run on this machine or another host.
Inspect OS and architecture using non-secret metadata. For SSH work, run checks on
the target host; paths refer to that host. The stdio bridge and the vault's owner
must run on the same machine and user: the owner serves agents on a private Unix
socket that accepts only that user. A client on another machine needs an explicitly
configured remote stdio transport; never expose the socket to the network.

Reuse the intended preview installation when present. Do not install over another
vault or search its credential files. Defaults for this project:

| Item | Value |
| --- | --- |
| App | `VaultOS.app` (macOS), `~/.local/opt/vaultos-preview/vaultos-preview` (Linux) |
| Tools in the app | `vaultos`, `vaultos-agent`, `vaultos-mcp`, `vaultosd`: `VaultOS.app/Contents/Helpers/` on macOS, the install folder on Linux |
| macOS data | `~/Library/Application Support/VaultOS-Preview` |
| Linux data | `~/.config/VaultOS-Preview` (or `$XDG_CONFIG_HOME/VaultOS-Preview`) |
| Keychain / Secret Service prefix | `org.vaultos.preview.` |
| Linux desktop entry | `org.vaultos.preview.desktop` |
| Optional data override | `VAULTOS_DATA_DIR`, an absolute directory |
| MCP entry point | `vaultos-mcp` from the app, with no arguments |
| Agent credential | `VAULTOS_AGENT_TOKEN_FILE`, an absolute private (0600) file path, or `VAULTOS_AGENT=NAME` for `<data dir>/agents/NAME.token`. With one enrolled agent neither is needed; `VAULTOS_AGENT=auto` picks the agent named after the calling program |

Use a new absolute data directory for testing. Setting the bridge's data override
does not change the app's directory: both processes need the same setting.

## Install on macOS

The easiest path is the [preview release](https://github.com/KRNL-Studio/vaultos/releases).
Choose `arm64` for Apple Silicon or `x64` for Intel. The deployment target is
macOS 13+; check the release notes for versions actually tested. Download the ZIP
and matching checksum, and run this in the download directory, substituting the
actual filename:

```sh
shasum -a 256 -c <download-name>.zip.sha256
```

Require `OK` before extraction. A checksum checks integrity, not publisher identity
independently of GitHub. Extract and place the app in the chosen folder without
replacing an existing different installation. A download named `notarized` is
signed and notarized and opens normally; one named `unsigned` is not. If that one
is blocked, the human can use
Apple's [per-app Open Anyway flow](https://support.apple.com/en-us/102445) after
deciding to trust it. Do not disable Gatekeeper or strip quarantine as an
installation shortcut. Managed Macs may prohibit opening it.

To build from source instead, install Rust (rustup fetches the toolchain pinned in
`rust-toolchain.toml`), Node.js 22+ for the build scripts, Git, and the macOS
command-line developer tools. From a chosen parent directory, use a new checkout
name if `vaultos` already exists:

```sh
git clone https://github.com/KRNL-Studio/vaultos.git
cd vaultos
npm run dist:mac        # dist/VaultOS-darwin-<arch>/VaultOS.app, unsigned
```

`npm start` runs a debug build instead. Launching the GUI requires an interactive
desktop session. Creating or unlocking the vault requires the human's password
entry; a new passphrase must be at least 12 characters. No password reset service
exists.

### An 0.2 vault

A vault created by VaultOS 0.2 or earlier opens only to be upgraded: the unlock
screen offers **Upgrade this vault**. The upgrade is one-way and keeps a backup;
never start it, or run `vaultos upgrade`, unless the human asked. Sync from 0.2
does not carry over (see the [sync guide](../../../docs/SYNC.md)).

## Install on Linux

The release has an x64 tarball; other architectures build from source. The app
needs the system's WebKitGTK 4.1 and, for the tray icon, libayatana-appindicator3.
From a source checkout, with the tarball and its `.sha256` downloaded:

```sh
scripts/install-linux.sh --from /absolute/path/to/<download-name>.tar.gz
```

To build instead, install Rust, Node.js 22+ and the WebKitGTK development packages
(on Debian/Ubuntu: `libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev
libxdo-dev`), then `npm run dist:linux` and `scripts/install-linux.sh`. The
installer is per-user and does not use root. Do not pass `--enable-service` during
routine setup: it installs a systemd user unit that keeps the vault served after
the window closes. Background access on Linux needs `secret-tool` (libsecret) and an
unlocked keyring such as GNOME Keyring.

## Headless (no window)

On a server or terminal-only machine, the tools from the app (or
`cargo build --release --locked` in a checkout, which puts them in
`target/release/`) run a vault without the desktop. Keep `vaultosd` next to
`vaultos` or on `PATH`. The human then runs, typing the password at the hidden
prompts:

```sh
vaultos init
vaultos add "Example App" EXAMPLE_API_KEY
vaultos agents enroll NAME --token-file /absolute/private/NAME.token --projects "Example App" --roots /absolute/project
vaultos start
vaultos unlock
```

`vaultos add` creates the project and asks for the value at a hidden prompt (or
reads it from a pipe); the human types or pipes it, never an agent, and never as an
argument. `vaultos init --new-secret-key-file PATH` also requires a Secret Key; then
every command that opens the vault needs `--secret-key-file PATH`, and
`vaultos secret-key kit FILE` writes its Emergency Kit, a printable PDF with the
key, to a new 0600 file. Commands that
change the vault directly need it to themselves (`--stop-backend`, then `start` and
`unlock` again). `vaultosd` starts locked, and no agent client starts it. Its log
is `vaultosd.log` in the data directory.

## Enroll and configure

1. Have the human open and unlock the app, create a test project and disposable
   key, then use **Settings → Agents** to enroll this client. Start with `read`
   and `inject`, select the intended project, and approve an existing project
   folder. Empty project/folder grants do not mean unrestricted access.
2. The token appears once. Have the human save it with an editor into a private
   file outside source control, with parent mode `0700` and file mode `0600`.
   Never put it in chat, shell command arguments/history, or client inline JSON.
   An agent can prepare paths and permissions without reading the token. Lost
   tokens are reissued through the desktop; the previous token stops working.
   Headless alternative for the human: `vaultos agents enroll NAME
   --token-file /absolute/private/NAME.token --projects "Example App" --roots
   /absolute/project` prompts for the master password and writes the token to
   that file without printing it.
3. Add a stdio MCP entry using the client's supported settings or add-server
   command. Preserve all existing entries and inspect only relevant configuration.
   This common JSON shape is an example, not a universal client format:

```json
{
  "mcpServers": {
    "vaultos": {
      "command": "/Applications/VaultOS.app/Contents/Helpers/vaultos-mcp",
      "env": {
        "VAULTOS_AGENT_TOKEN_FILE": "/absolute/private/folder/agent-token"
      }
    }
  }
}
```

Resolve every placeholder on the target host, including the app's actual location
(on Linux, `~/.local/opt/vaultos-preview/vaultos-mcp` expanded to an absolute
path). `~` and shell variables are not automatically expanded in JSON. If using
custom storage, add the same absolute `VAULTOS_DATA_DIR` as the app. Do not
configure the internal session token as the agent token. The environment token
override is supported, but the private file is preferred.

## Verify connection

Reconnect/restart this client's MCP server, discover its tools, then:

1. Call `whoami` and verify identity, scopes, project IDs, and approved roots.
   `vault_status` reports owner availability and version information; it alone
   does not prove agent authentication.
2. Call `list_projects`, then `list_secrets` for the intended project. Empty lists
   can mean missing grants. Never infer access to another project.
3. For an authorized smoke test, inject a disposable, human-approved key to a new
   file inside the approved folder. Example tool arguments (replace placeholders):

```json
{
  "project": "Example App",
  "target_path": "/absolute/project/.env.vaultos-test",
  "format": "dotenv",
  "keys": ["EXAMPLE_API_KEY"],
  "merge": true
}
```

Check returned key names/counts, any `heldForApproval` result, and file
existence/permissions without printing contents. Ensure the output is Git-ignored
before writing it. Report success only when the intended key was written; an
empty export is not success. Remove only the disposable smoke-test file when
finished. For real application setup, inject only the task's requested keys.
