# Connect a coding agent

For an agent-readable installation and management playbook, start at
[the portable VaultOS skill](../skills/vaultos/SKILL.md). Copy its whole folder
when installing it in a skill-aware client; this page is the shorter manual setup guide.

The desktop manages authorization. The MCP bridge forwards calls to its localhost API. You need Node.js 22+ and a source checkout with `npm ci --omit=dev --ignore-scripts` for the bridge; the desktop ZIP alone does not install a global MCP command.

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

## Shell agents: `vaultos-agent`

Agents that work through a shell can use `node agent-cli.cjs` (the `vaultos-agent` bin of a source checkout) with the same token discovery and grants as the bridge:

```sh
vaultos-agent status | whoami | projects | pending
vaultos-agent keys PROJECT
vaultos-agent search TEXT
vaultos-agent inject PROJECT /absolute/project/.env --keys A,B --format dotenv
printf %s "$VALUE" | vaultos-agent add PROJECT KEY --note "optional"
vaultos-agent import PROJECT /absolute/project/.env [--create-project]
vaultos-agent sync
```

Output is JSON and never contains values. `add` reads the value from stdin only and refuses one passed as an argument. `--replace` turns off merging. `sync` asks the running owner to sync and reports that clearly when the owner has no sync route. Exit codes: 2 usage, 3 not running, 4 locked, 5 token problem.

## Admin CLI

Human-only grant and approval work can be done headlessly from a source checkout. Every command asks for the master password at a hidden prompt (or reads it from stdin with `--password-stdin`) and claims the vault, so lock or close the desktop window first (VaultOS may stay in the menu bar, locked, without owning the vault); `--stop-backend` asks a running headless backend to stop. Keychain-only authorization is deliberately not offered, because any process running as you could use it to grant itself access.

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

## Optional background helper

The bridge works with the downloaded desktop while the app is open and unlocked. To let the source bridge start its headless backend after the desktop window closes or locks, also run `npm run build:native` in that source checkout on macOS (requires command-line developer tools). This builds the same preview-namespaced Keychain helper locally. On Linux no build step is needed; the backend reads the remembered password through `secret-tool` (libsecret) and a running keyring such as GNOME Keyring. Without that, keep the desktop open; the bridge never falls back to a plaintext password file. Background access must still be enabled deliberately in desktop Settings.

For an always-available backend, run `scripts/install-service-macos.sh` from that same checkout. It installs a per-user LaunchAgent (`org.vaultos.preview.backend`) that runs `backend.cjs --service`: it waits while the desktop owns the vault, takes over when the window closes, and exits if background access is off. Pass `--data-dir` or `--sync-repo` only for nondefault absolute paths, `--print` to review the property list first, and `--uninstall` to remove it. `vault_status` reports sync health when autosync is enabled.

## Locked or unavailable

Unlock the desktop. Errors distinguish a running but locked vault from one that is not running. When nothing answers, the bridge (and `vaultos-agent`) tries to start the backend unless a human lock blocks it: with the default data directory it first asks the `vaultos-preview-backend` systemd user unit (Linux) or the `org.vaultos.preview.backend` LaunchAgent (macOS) if one is installed, otherwise it spawns a one-shot `backend.cjs` that serves until the desktop takes over (it does not reclaim the vault afterwards; only an installed service does). A `session.json.starting` lock in the data directory keeps concurrent bridges from starting duplicates. The backend still unlocks only when background access (macOS Keychain or Linux Secret Service) was explicitly enabled. `vault_status` adds sync health and the bridge file's SHA-256 so stale copies are detectable. A connection interruption after a write is ambiguous: inspect the result before retrying. The bridge does not blindly replay writes.
