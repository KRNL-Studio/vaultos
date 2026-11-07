# Connect a coding agent

For an agent-readable installation and management playbook, start at
[the portable VaultOS skill](../skills/vaultos/SKILL.md). Copy its whole folder
when installing it in a skill-aware client; this page is the shorter manual setup guide.

The process that owns the unlocked vault serves agents on a private Unix socket: the VaultOS app while it is unlocked, the optional [background service](#background-access) after the window closes, or `vaultosd` run from a terminal. Agents reach it through two programs that ship with the app:

| Program | macOS | Linux (default install) |
| --- | --- | --- |
| `vaultos-mcp`, the stdio MCP bridge | `/Applications/VaultOS.app/Contents/Helpers/vaultos-mcp` | `~/.local/opt/vaultos-preview/vaultos-mcp` |
| `vaultos-agent`, the shell client | `/Applications/VaultOS.app/Contents/Helpers/vaultos-agent` | `~/.local/opt/vaultos-preview/vaultos-agent` |

Use the path where you actually put the app. Neither program needs Node.js, keeps vault state or starts anything: each call is one request to the owner, which enforces the agent's scopes, project and folder grants and approvals.

1. Open and unlock VaultOS. Create a project and a disposable test key.
2. In Settings → Agents, enroll the tool. Select `read` and `inject`, that project's checkbox, and its output folder. Additional scopes grant additional authority; leave `reveal` off unless you deliberately want raw secrets in model context.
3. Copy the one-time agent token into a private file outside the project repository. Create its parent folder with mode 0700 and the file with mode 0600. Use an editor; do not paste it into shell history or commit it. If lost, reissue it in the desktop; the old token stops working.
4. Add an MCP stdio server to your client's configuration. Replace paths with your actual absolute paths. The example contains no live token:

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

The bridge and `vaultos-agent` find their token in this order: `VAULTOS_AGENT_TOKEN`; `VAULTOS_AGENT_TOKEN_FILE` (absolute, a regular file owned by you with mode 0600); then, when `VAULTOS_AGENT=NAME` is set, `<data directory>/agents/NAME.token` with the same checks. A token file that exists but is unsafe is an error, not a silent fallback. They never guess an identity from the process tree.

Client configuration locations vary. Use your client's documented MCP settings. If you selected a custom `VAULTOS_DATA_DIR`, set the same absolute path in the bridge environment. Never point the preview at an existing production vault directory. Tokens are credentials: the environment token override is supported for controlled automation, but a private token file avoids embedding one in client settings.

5. Restart the MCP connection. Ask the agent to call `whoami`, `list_projects`, and `list_secrets`. Then request `inject_secrets` for the approved project and an absolute `.env` path in the approved folder. Keep `.env` ignored by Git. Do not ask the agent to print or read the file if your aim is avoiding transcript disclosure.

`vault_status` reports whether the owner runs and is unlocked, its version and vault format, the bridge version, and public sync health (`state`, `halted`, `lastSyncAt`, `peerStalled`); sync error text is shown only to the owner (`vaultos status`).

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

Agents cannot enroll, widen scopes or folders, approve their own records, adopt human-owned records, change settings, or undo human history via the API or MCP. Revoke a token in the desktop to stop future API calls. Revocation does not erase files or values already disclosed.

`import_env` accepts `createProject: true`. It creates the project only when no project with that name exists, requires the same `add` scope as `create_project`, and validates the source path first. An existing project that is not approved for the agent is still refused.

### All-access grants

Project and folder grants are deny-by-default: empty lists mean nothing. A human can instead tick **All projects, including future ones** (`allProjects`) or **Any folder** (`anyRoot`) in Settings → Agents, or pass `--all-projects` / `--any-root` to `vaultos agents grant`. Both default off and no API or MCP call can set them. `allProjects` covers every current and future project within the agent's scopes. `anyRoot` allows reading `.env` files from and injecting into any absolute path the account can write, except the vault data directory (checked after resolving symlinks); the final path component must not be a symlink. Prefer explicit grants.

`inject_secrets` supports dotenv, JSON, and shell formats. JSON merge preserves unrelated object keys. Dotenv merge preserves unrelated variables but rewrites formatting/comments. Shell output requires `merge:false` and must be sourced deliberately by the target program. An explicitly empty key list exports no keys; omitted keys requests all permitted, approved records.

## Shell agents: `vaultos-agent`

Agents that work through a shell use `vaultos-agent`, with the same token discovery and grants as the bridge:

```sh
vaultos-agent status | whoami | projects | pending
vaultos-agent keys PROJECT
vaultos-agent search TEXT
vaultos-agent inject PROJECT /absolute/project/.env --keys A,B --format dotenv
printf %s "$VALUE" | vaultos-agent add PROJECT KEY --note "optional"
vaultos-agent import PROJECT /absolute/project/.env [--create-project]
```

Output is JSON and never contains values. `add` reads the value from stdin only and refuses one passed as an argument. `--replace` turns off merging. Sync is an owner action, so agents cannot request a round. Exit codes: 2 usage, 3 not running, 4 locked, 5 token problem.

## Human CLI: `vaultos`

`vaultos` ships next to the bridge (`VaultOS.app/Contents/Helpers/vaultos` on macOS). Commands that read or change the vault directly ask for the master password at a hidden prompt (or read it from stdin with `--password-stdin`) and claim the vault, so lock or close the desktop window first (VaultOS may stay in the menu bar, locked, without owning the vault); `--stop-backend` first asks a running owner (`vaultosd` or the background service) to stop. Keychain-only authorization is deliberately not offered, because any process running as you could use it to grant itself access. With a Secret Key, pass `--secret-key-file PATH` to every command that opens the vault.

```sh
vaultos agents list
vaultos agents enroll NAME --token-file /absolute/private/NAME.token --scopes read,inject --projects "Example App" --roots /absolute/project
vaultos agents grant NAME --all-projects             # or --projects A,B | --no-projects, --roots | --any-root | --no-roots, --scopes
vaultos agents revoke NAME
vaultos pending list
vaultos pending approve PROJECT KEY                  # or --all [--project P]
vaultos pending deny PROJECT KEY                     # removes the agent-created record (undo via history)
vaultos approver set --token-file /absolute/private/approver.token   # also: approver status, approver clear
vaultos rotate-password
vaultos secret-key set --new-secret-key-file /absolute/private/vault.secret-key    # or: secret-key remove
vaultos backup /absolute/new/dated-backup-directory
vaultos inject PROJECT /absolute/project/.env        # replaces the file
```

`enroll` writes a fresh token to the file (mode 0600, parent created 0700) and never prints it; enrolling an existing name reissues its token and invalidates the old one. `grant` replaces only the dimensions you name. To use the per-agent default, write the token to `<data directory>/agents/NAME.token` and set `VAULTOS_AGENT=NAME`. `rotate-password` uses the same recoverable rotation as the desktop; with `--password-stdin` the second line is the new password. `vaultos backup` copies `vault.enc`, the audit log and the sync index, never tokens or other credentials. `vaultos inject` uses human authority and replaces its target; agents use `vaultos-agent inject`, which merges. Run `vaultos help COMMAND` for each command's options. Sync commands are in [the sync guide](SYNC.md).

### Without the desktop

The same tools run a vault with no window, for a server or a terminal-only setup. The human runs these; each password prompt is hidden.

```sh
vaultos init                                  # add --new-secret-key-file /absolute/private/vault.secret-key to require a Secret Key
vaultos add "Example App" EXAMPLE_API_KEY      # creates the project; asks for the value at a hidden prompt
vaultos agents enroll NAME --token-file /absolute/private/NAME.token --projects "Example App" --roots /absolute/project
vaultos start
vaultos unlock
```

`vaultos add` reads the value from a hidden prompt, from stdin when it is piped, or, with `--password-stdin`, from the lines after the password; it refuses a value passed as an argument. `vaultos import PROJECT /absolute/file.env` stores every `KEY=VALUE` in an env file. Both create the project if it does not exist, and keys a human adds need no approval before injection.

`vaultos start` runs `vaultosd` in the background and sends its messages (never values) to `vaultosd.log` (mode 0600) in the data directory. `vaultos status`, `lock` and `stop` talk to it. `vaultosd --idle-lock-minutes N` locks after N minutes without a request.

`vaultosd` (like the app) listens on `vaultosd.sock` in the data directory and writes `daemon.json` (mode 0600) with the socket's path, its process id and a random session token. When the data directory's path is too long for a socket, the socket goes in `$XDG_RUNTIME_DIR/vaultos`, else in `vaultos-UID` in the temporary folder; that folder must be a real directory owned by you with no group or other access, or the owner refuses to start. The socket accepts only peers running as your user. Browsers cannot reach a Unix socket, and requests with browser headers are refused anyway.

## Approval relay

An external approver (for example a phone-notification daemon you run) can relay your approve/deny decisions with `POST /pending/decide` and body `{"project","key","approve":true|false}`. It needs the session token from `daemon.json` and an `X-Vault-Approver` secret whose SHA-256 is stored in the vault by `vaultos approver set --token-file PATH`; agent tokens are not accepted. The relay is off until configured, decides only keys that are awaiting approval, and denial removes the agent-created record. `approver clear` turns it off. The desktop's pending banner also has **Approve all**.

## Background access

By default agents are served only while the app is open and unlocked. Closing the window locks the vault, and Lock, screen lock, sleep and 15 idle minutes lock it fully. To keep agents working with the window closed:

1. In **Settings → Background access**, turn on background access. It remembers the master password in the macOS Keychain or, on Linux, the Secret Service (`secret-tool` from libsecret and a running keyring such as GNOME Keyring); there is no plaintext fallback.
2. Install the background service, which is the app's own program run as `VaultOS --service` without windows:
   - macOS: `scripts/install-service-macos.sh` from a source checkout of the same version installs a per-user LaunchAgent (`org.vaultos.preview.backend`). `--app PATH` names the app if it is not `/Applications/VaultOS.app`; `--data-dir` and `--sync-repo` take nondefault absolute paths, `--print` shows the property list first, and `--uninstall` removes it. Its log is `~/Library/Logs/VaultOS-Preview/backend.log`.
   - Linux: `scripts/install-linux.sh --enable-service` installs and starts the `vaultos-preview-backend` systemd user unit.

The service waits while a VaultOS window owns the vault and takes over when the window closes; opening the app asks it to stop, and it stands by until the window lets go. It never serves after a full lock: Lock, screen lock, sleep and idle (with the default hard lock policy) clear the remembered password and block the service until you unlock in the app again. It stops for good (exit status 0, so neither launchd nor systemd restarts it in a loop, with the reason in its log) when there is no vault, background access is off, or the remembered password or Secret Key no longer opens the vault. The service itself does not watch for screen lock; use Lock before leaving if you need that boundary. Nothing installs it automatically.

## Locked or unavailable

Errors distinguish a running but locked vault (exit code 4 from `vaultos-agent`) from one that is not running (exit code 3). Nothing starts an owner for an agent: the human opens and unlocks the app, or runs `vaultos start` and `vaultos unlock`, or relies on an installed background service. A connection interruption after a write is ambiguous: inspect the result before retrying. The bridge does not blindly replay writes.
