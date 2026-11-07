# Connect a coding agent

For an agent-readable installation and management playbook, start at
[the portable VaultOS skill](../skills/vaultos/SKILL.md). Copy its whole folder
when installing it in a skill-aware client; this page is the shorter manual setup guide.

There are two ways to run VaultOS for agents:

- **The desktop app** (format v3 vault, covered first). The desktop manages authorization and the Node MCP bridge forwards calls to its localhost API. You need Node.js 22+ and a source checkout with `npm ci --omit=dev --ignore-scripts` for the bridge; the desktop ZIP alone does not install a global MCP command.
- **The Rust tools** (format v4 vault, headless preview): `vaultosd`, `vaultos`, `vaultos-agent` and `vaultos-mcp`. See [Rust tools](#rust-tools-format-v4-preview). The desktop app cannot open a v4 vault yet, so use one or the other for a given vault.

1. Open and unlock VaultOS. Create a project and a disposable test key.
2. In Settings → Agents, enroll the tool. Select `read` and `inject`, that project's checkbox, and its output folder. Additional scopes grant additional authority; leave `reveal` off unless you deliberately want raw secrets in model context.
3. Copy the one-time agent token into a private file outside the project repository. Create its parent folder with mode 0700 and the file with mode 0600. Use an editor; do not paste it into shell history or commit it. If lost, reissue it in the desktop; the old token stops working.
4. Add an MCP stdio server to your client's configuration. Replace paths with your actual absolute paths. The example contains no live token:

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

The bridge and `vaultos-agent` find their token in this order: `VAULTOS_AGENT_TOKEN`; `VAULTOS_AGENT_TOKEN_FILE` (absolute, a regular file owned by you with mode 0600); then, when `VAULTOS_AGENT=NAME` is set, `<data directory>/agents/NAME.token` with the same checks. A token file that exists but is unsafe is an error, not a silent fallback. They never guess an identity from the process tree.

Client configuration locations vary. Use your client's documented MCP settings. If you selected a custom `VAULTOS_DATA_DIR`, set the same absolute path in the bridge environment. Never point the preview at an existing production vault directory. Tokens are credentials: the environment token override is supported for controlled automation, but a private token file avoids embedding one in client settings.

5. Restart the MCP connection. Ask the agent to call `whoami`, `list_projects`, and `list_secrets`. Then request `inject_secrets` for the approved project and an absolute `.env` path in the approved folder. Keep `.env` ignored by Git. Do not ask the agent to print or read the file if your aim is avoiding transcript disclosure.

## Scope reference

| Scope | Permits |
| --- | --- |
| `read` | List/search metadata for approved projects |
| `inject` | Write approved record values into approved folders |
| `add` | Create records and projects; new records require injection approval |
| `edit:own` | Update that agent's records |
| `edit:delegated` | Update records explicitly delegated to it |
| `delete:own` | Delete that agent's records |
| `reveal` | Return raw secret values and content fingerprints |

Agents cannot enroll, widen scopes or folders, approve their own records, adopt human-owned records, change settings, or undo human history via HTTP/MCP. Revoke a token in the desktop to stop future API calls. Revocation does not erase files or values already disclosed.

`import_env` accepts `createProject: true`. It creates the project only when no project with that name exists, requires the same `add` scope as `create_project`, and validates the source path first. An existing project that is not approved for the agent is still refused.

### All-access grants

Project and folder grants are deny-by-default: empty lists mean nothing. A human can instead tick **All projects, including future ones** (`allProjects`) or **Any folder** (`anyRoot`) in Settings → Agents, or pass `--all-projects` / `--any-root` to the admin CLI. Both default off and no HTTP/MCP call can set them. `allProjects` covers every current and future project within the agent's scopes. `anyRoot` allows reading `.env` files from and injecting into any absolute path the account can write, except the vault data directory (checked after resolving symlinks); the final path component must not be a symlink. Prefer explicit grants.

`inject_secrets` supports dotenv, JSON, and shell formats. JSON merge preserves unrelated object keys. Dotenv merge preserves unrelated variables but rewrites formatting/comments. Shell output requires `merge:false` and must be sourced deliberately by the target program. An explicitly empty key list exports no keys; omitted keys requests all permitted, approved records.

## Rust tools (format v4 preview)

The Rust tools run without the desktop and use a format v4 vault: Argon2id, an optional Secret Key, per-item encryption, an authenticated file and a signed audit chain (see [SECURITY.md](../SECURITY.md#format-v4-rust-core)). Build them from a source checkout with Rust installed (the toolchain in `rust-toolchain.toml` is fetched by rustup):

```sh
cargo build --release --locked
```

This puts `vaultosd`, `vaultos`, `vaultos-agent` and `vaultos-mcp` in `target/release/`. Keep `vaultosd` next to `vaultos` or on `PATH`. They use the same data directory and `VAULTOS_DATA_DIR` override as the desktop, so for testing set a new absolute `VAULTOS_DATA_DIR` for every one of them.

| Program | Role |
| --- | --- |
| `vaultosd` | Holds the vault and serves the agent API on a Unix socket. Starts locked. `--idle-lock-minutes N` locks after N minutes without a request; `--wait` waits for the app to release the vault (for a login service) |
| `vaultos` | The human's CLI: create, upgrade, unlock, lock and manage the vault, agents, approvals and sync. Prompts for the master password; never prints values or tokens |
| `vaultos-agent` | The agent's shell client, with the same commands as the Node one below |
| `vaultos-mcp` | The agent's stdio MCP bridge, with the same tools as the Node bridge |

### Set up

The human runs these; each password prompt is hidden, and `--password-stdin` reads it from stdin instead.

```sh
vaultos init                                  # add --new-secret-key-file /absolute/private/vault.secret-key to require a Secret Key
vaultos add "Example App" EXAMPLE_API_KEY      # creates the project; asks for the value at a hidden prompt
vaultos agents enroll NAME --token-file /absolute/private/NAME.token --projects "Example App" --roots /absolute/project
vaultos start
vaultos unlock
```

To keep an existing desktop vault instead, quit the desktop and run `vaultos upgrade`. It backs up the v3 file first; after it, only the Rust tools can open the vault. With a Secret Key, pass `--secret-key-file PATH` to every command that opens the vault, including `vaultos unlock`.

`vaultos add` reads the value from a hidden prompt, from stdin when it is piped, or, with `--password-stdin`, from the lines after the password; it refuses a value passed as an argument. `vaultos import PROJECT /absolute/file.env` stores every `KEY=VALUE` in an env file. Both create the project if it does not exist, and keys a human adds need no approval before injection.

`vaultos start` runs `vaultosd` in the background and sends its messages (never values) to `vaultosd.log` (mode 0600) in the data directory. `vaultos status`, `lock` and `stop` talk to it. Commands that read or change the vault directly (`add`, `import`, `agents`, `pending`, `approver`, `rotate-password`, `secret-key`, `projects`, `keys`, `inject`, `sync` except `sync now`) need it to themselves: add `--stop-backend` to stop `vaultosd` first, then `vaultos start` and `vaultos unlock` again.

`vaultosd` listens on `vaultosd.sock` in the data directory and writes `daemon.json` (mode 0600) with the socket's path, its process id and a random session token. When the data directory's path is too long for a socket, the socket goes in `$XDG_RUNTIME_DIR/vaultos`, else in `vaultos-UID` in the temporary folder; that folder must be a real directory owned by you with no group or other access, or `vaultosd` refuses to start. Browsers cannot reach a Unix socket, and requests with browser headers are refused anyway. Unlike the Node bridge, the Rust clients do not start `vaultosd`: when it is not running they say so (exit code 3).

### Connect an agent

```json
{
  "mcpServers": {
    "vaultos": {
      "command": "/absolute/path/to/vaultos/target/release/vaultos-mcp",
      "env": {
        "VAULTOS_AGENT_TOKEN_FILE": "/absolute/private/folder/agent-token"
      }
    }
  }
}
```

Token discovery is the same as the Node bridge. Add `VAULTOS_DATA_DIR` to `env` for a nondefault directory. `vault_status` reports whether `vaultosd` runs and is unlocked, its version and format, the bridge version, and public sync health (`state`, `halted`, `lastSyncAt`, `peerStalled`); sync error text is shown only to the owner (`vaultos status`).

### Human commands

```sh
vaultos agents list
vaultos agents grant NAME --all-projects             # or --projects A,B | --no-projects, --roots | --any-root | --no-roots, --scopes
vaultos agents revoke NAME
vaultos pending list
vaultos pending approve PROJECT KEY                  # or --all [--project P]
vaultos pending deny PROJECT KEY
vaultos approver set --token-file /absolute/private/approver.token   # also: approver status, approver clear
vaultos rotate-password
vaultos secret-key set --new-secret-key-file /absolute/private/vault.secret-key    # or: secret-key remove
vaultos backup /absolute/new/dated-backup-directory
vaultos inject PROJECT /absolute/project/.env       # replaces the file
```

These behave like the Node admin CLI below, with the same rules for token files. `vaultos inject` uses human authority and replaces its target; agents use `vaultos-agent inject`, which merges. Run `vaultos help COMMAND` for each command's options. Sync commands are in [the sync guide](SYNC.md#sync-format-2-vaultos-and-vaultosd).

## Shell agents: `vaultos-agent`

Agents that work through a shell can use `node agent-cli.cjs` (the `vaultos-agent` bin of a source checkout, for the desktop app) or the Rust `vaultos-agent` (for `vaultosd`), with the same token discovery and grants as the bridge:

```sh
vaultos-agent status | whoami | projects | pending
vaultos-agent keys PROJECT
vaultos-agent search TEXT
vaultos-agent inject PROJECT /absolute/project/.env --keys A,B --format dotenv
printf %s "$VALUE" | vaultos-agent add PROJECT KEY --note "optional"
vaultos-agent import PROJECT /absolute/project/.env [--create-project]
vaultos-agent sync
```

Output is JSON and never contains values. `add` reads the value from stdin only and refuses one passed as an argument. `--replace` turns off merging. `sync` asks the running owner to sync; the Node backend reports when it has no sync route, and `vaultosd` refuses it because sync is an owner action (a human runs `vaultos sync now`). Exit codes: 2 usage, 3 not running, 4 locked, 5 token problem.

## Admin CLI (desktop app)

Human-only grant and approval work on a desktop (v3) vault can be done headlessly from a source checkout; for a v4 vault use [the `vaultos` commands](#human-commands). Every command asks for the master password at a hidden prompt (or reads it from stdin with `--password-stdin`) and claims the vault, so quit the desktop first; `--stop-backend` asks a running headless backend to stop. Keychain-only authorization is deliberately not offered, because any process running as you could use it to grant itself access.

```sh
node cli.cjs agents list
node cli.cjs agents enroll NAME --token-file /absolute/private/NAME.token --scopes read,inject --projects "Example App" --roots /absolute/project
node cli.cjs agents grant NAME --all-projects        # or --projects A,B | --no-projects, --roots | --any-root | --no-roots, --scopes
node cli.cjs agents revoke NAME
node cli.cjs pending list
node cli.cjs pending approve PROJECT KEY             # or --all [--project P]
node cli.cjs pending deny PROJECT KEY                # removes the agent-created record (undo via history)
node cli.cjs approver set --token-file /absolute/private/approver.token
node cli.cjs rotate-password
```

`enroll` writes a fresh token to the file (mode 0600, parent created 0700) and never prints it; enrolling an existing name reissues its token and invalidates the old one. `grant` replaces only the dimensions you name. To use the per-agent default, write the token to `<data directory>/agents/NAME.token` and set `VAULTOS_AGENT=NAME`. `rotate-password` uses the same recoverable rotation as the desktop; with `--password-stdin` the second line is the new password. Restart a backend afterwards.

## Approval relay

An external approver (for example a phone-notification daemon you run) can relay your approve/deny decisions with `POST /pending/decide` and body `{"project","key","approve":true|false}`. It needs the session bearer token and an `X-Vault-Approver` secret whose SHA-256 is stored in the vault by `node cli.cjs approver set --token-file PATH`; agent tokens are not accepted. The relay is off until configured, decides only keys that are awaiting approval, and denial removes the agent-created record. `approver clear` turns it off. The desktop's pending banner also has **Approve all**.

## Optional background helper (desktop app)

The bridge works with the downloaded desktop while the app is open and unlocked. To let the source bridge start its headless backend after the desktop closes, also run `npm run build:native` in that source checkout on macOS (requires command-line developer tools). This builds the same preview-namespaced Keychain helper locally. On Linux no build step is needed; the backend reads the remembered password through `secret-tool` (libsecret) and a running keyring such as GNOME Keyring. Without that, keep the desktop open; the bridge never falls back to a plaintext password file. Background access must still be enabled deliberately in desktop Settings.

For an always-available backend, run `scripts/install-service-macos.sh` from that same checkout. It installs a per-user LaunchAgent (`org.vaultos.preview.backend`) that runs `backend.cjs --service`: it waits while the desktop owns the vault, takes over when the window closes, and exits if background access is off. Pass `--data-dir` or `--sync-repo` only for nondefault absolute paths, `--print` to review the property list first, and `--uninstall` to remove it. `vault_status` reports sync health when autosync is enabled.

## Locked or unavailable

With the Rust tools, run `vaultos start` and `vaultos unlock`; nothing starts `vaultosd` for an agent. For the desktop app, unlock the desktop. Errors distinguish a running but locked vault from one that is not running. When nothing answers, the bridge (and `vaultos-agent`) tries to start the backend unless a human lock blocks it: with the default data directory it first asks the `vaultos-preview-backend` systemd user unit (Linux) or the `org.vaultos.preview.backend` LaunchAgent (macOS) if one is installed, otherwise it spawns a one-shot `backend.cjs` that serves until the desktop takes over (it does not reclaim the vault afterwards; only an installed service does). A `session.json.starting` lock in the data directory keeps concurrent bridges from starting duplicates. The backend still unlocks only when background access (macOS Keychain or Linux Secret Service) was explicitly enabled. `vault_status` adds sync health and the bridge file's SHA-256 so stale copies are detectable. A connection interruption after a write is ambiguous: inspect the result before retrying. The bridge does not blindly replay writes.
