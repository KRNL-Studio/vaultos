# Install and connect

## Identify the target

Determine whether the app and MCP client run on this Mac or another host. Inspect
OS/architecture, Node version, and the intended checkout using non-secret metadata.
For SSH work, run checks on the target host; paths and `localhost` refer to that
host. The stdio bridge and vault backend must run on the same machine. A client on
another machine needs an explicitly configured remote stdio transport; do not
expose the vault's localhost HTTP API to the network to make it connect.

Reuse the intended preview installation when present. Do not install over another
vault or search its credential files. Defaults for this project:

| Item | Value |
| --- | --- |
| App | `VaultOS.app` |
| macOS data | `~/Library/Application Support/VaultOS-Preview` |
| Linux data | `~/.config/VaultOS-Preview` (or `$XDG_CONFIG_HOME/VaultOS-Preview`) |
| Keychain / Secret Service prefix | `org.vaultos.preview.` |
| Linux install | `~/.local/opt/vaultos-preview`, `org.vaultos.preview.desktop` |
| Optional data override | `VAULTOS_DATA_DIR`, an absolute directory |
| MCP entry point | `mcp/server.mjs` in a source checkout (desktop app), or the `vaultos-mcp` binary (Rust tools) |
| Agent credential | `VAULTOS_AGENT_TOKEN_FILE`, an absolute private (0600) file path, or `VAULTOS_AGENT=NAME` for `<data dir>/agents/NAME.token` |

Use a new absolute data directory for testing. Setting the bridge's data override
does not change the desktop's directory: both processes need the same setting.

## Choose desktop or Rust tools

The desktop app uses a format v3 vault and the Node bridge. The headless Rust
tools (`vaultosd`, `vaultos`, `vaultos-agent`, `vaultos-mcp`) use a format v4
vault, which the desktop cannot open yet. Use the desktop unless the user asked
for the Rust tools or a headless setup; never run `vaultos upgrade` on the user's
vault unless they asked for it. For the Rust tools, skip to
[Rust tools](#rust-tools).

## Install the desktop

The easiest path is the [macOS preview release](https://github.com/rohit3a/vaultos/releases).
Choose `arm64` for Apple Silicon or `x64` for Intel. The deployment target is
macOS 13+; check the release notes for versions actually tested. Download the ZIP
and matching checksum, and run this in the download directory, substituting the
actual filename:

```sh
shasum -a 256 -c <download-name>.zip.sha256
```

Require `OK` before extraction. A checksum checks integrity, not publisher identity
independently of GitHub. Extract and place the preview app in the chosen app
folder without replacing an existing different installation. It includes its own
runtime. The public preview is unsigned and not notarized. If blocked, the human
can use Apple's [per-app Open Anyway flow](https://support.apple.com/en-us/102445)
after deciding to trust it. Do not disable Gatekeeper or strip quarantine as an
installation shortcut. Managed Macs may prohibit opening it.

Alternatively, to run the desktop from source, use Node.js 22+, npm, Git, and
macOS command-line developer tools. From a chosen parent directory, use a new
checkout name if `vaultos` already exists:

```sh
git clone https://github.com/rohit3a/vaultos.git
cd vaultos
npm ci
npm run build:native
npm start
```

Launching the GUI requires an interactive macOS session. Creating/unlocking the
vault requires the human's password entry; a new passphrase must be at least 12
characters. No password reset service exists.

### Linux

There is no Linux release download. On an x64 or arm64 Linux desktop with Node.js
22+, build and install from a checkout:

```sh
npm ci
npm run dist:linux
scripts/install-linux.sh
```

The installer is per-user and does not use root. If it reports that the Chromium
sandbox needs a setuid helper (Ubuntu 24.04+), relay the printed `sudo` command to
the human rather than running sudo yourself; `--harden` runs it only when the user
asked for that. Do not pass `--enable-service` during routine setup: it installs a
systemd user unit that keeps a headless backend running. Background access on
Linux needs `secret-tool` (libsecret) and an unlocked keyring such as GNOME Keyring.

## Prepare the MCP bridge

The desktop ZIP does not install a global MCP executable. Obtain a source checkout
on the same host, ideally checked out at the desktop release tag. With Node.js 22+
and npm available, run in that checkout:

```sh
npm ci --omit=dev --ignore-scripts
```

This is a bridge-only dependency install. It omits Electron, so `npm start` will
not work there until a full `npm ci`. An existing full development install can
already run the bridge; do not replace it just to omit dependencies.

The bridge works while the desktop is open and unlocked. Optional background
startup also requires explicit desktop opt-in to remembered password access, plus
`npm run build:native` in the bridge checkout on macOS or `secret-tool` on Linux. Do not enable it as part of routine
setup; see the operating reference for its different lock behavior. The optional
always-on service (`scripts/install-service-macos.sh`, with `--print` to review and
`--uninstall` to remove, or `scripts/install-linux.sh --enable-service` on Linux)
builds on the same opt-in; install it only when requested.

## Rust tools

With Rust installed (rustup fetches the pinned toolchain), build in a source
checkout on the target host:

```sh
cargo build --release --locked
```

The four binaries are in `target/release/`; keep `vaultosd` next to `vaultos` or
on `PATH`. The human then runs, typing the password at the hidden prompts:

```sh
vaultos init
vaultos add "Example App" EXAMPLE_API_KEY
vaultos agents enroll NAME --token-file /absolute/private/NAME.token --projects "Example App" --roots /absolute/project
vaultos start
vaultos unlock
```

`vaultos add` creates the project and asks for the value at a hidden prompt (or
reads it from a pipe); the human types or pipes it, never an agent, and never as an
argument. `vaultos init --new-secret-key-file PATH` also requires a Secret Key; then every
command that opens the vault needs `--secret-key-file PATH`. Commands that change
the vault directly need it to themselves (`--stop-backend`, then `start` and
`unlock` again). `vaultosd` starts locked, and no agent client starts it. Its log
is `vaultosd.log` in the data directory. Configure the MCP client with the
absolute path to `vaultos-mcp` as `command`, no `args`, and the same `env` as the
example below; then verify as described there.

## Enroll and configure

1. Have the human open/unlock the preview, create a test project and disposable
   key, then use **Settings → Agents** to enroll this client. Start with `read`
   and `inject`, select the intended project, and approve an existing project
   folder. Empty project/folder grants do not mean unrestricted access.
2. The token appears once. Have the human save it with an editor into a private
   file outside source control, with parent mode `0700` and file mode `0600`.
   Never put it in chat, shell command arguments/history, or client inline JSON.
   An agent can prepare paths and permissions without reading the token. Lost
   tokens are reissued through the desktop; the previous token stops working.
   Headless alternative for the human: `node cli.cjs agents enroll NAME
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
      "command": "/absolute/path/to/node",
      "args": ["/absolute/path/to/vaultos/mcp/server.mjs"],
      "env": {
        "VAULTOS_AGENT_TOKEN_FILE": "/absolute/private/folder/agent-token"
      }
    }
  }
}
```

Resolve every placeholder on the target host. `~` and shell variables are not
automatically expanded in JSON. Find Node with `command -v node` on that host;
GUI clients may not inherit an interactive shell's PATH. If using custom storage,
add the same absolute `VAULTOS_DATA_DIR` as the desktop. Do not configure the
internal session token as the agent token. The environment token override is
supported, but the private file is preferred.

## Verify connection

Reconnect/restart this client's MCP server, discover its tools, then:

1. Call `whoami` and verify identity, scopes, project IDs, and approved roots.
   `vault_status` reports backend availability/version information; it alone does
   not prove agent authentication.
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
