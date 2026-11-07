# Use and manage VaultOS

## Daily MCP operations

Use tool discovery for the installed version's full schemas. These are the public
bridge tool names; a client may prefix them with a server namespace.

| Tool | Arguments / purpose | Required scope |
| --- | --- | --- |
| `vault_status` | `{}`; backend/bridge version, availability and sync health (`sync.state`, `lastSyncAt`, `error`, `peerStalled`) | Not an authentication check |
| `whoami` | `{}`; current identity and grants | Enrolled identity |
| `list_projects` | `{}`; approved projects | `read` |
| `list_secrets` | `{project}`; names and metadata, no values | `read` |
| `search` | `{query}`; approved project/key/provider matches | `read` |
| `list_pending` | `{}`; records awaiting human injection approval | `read` |
| `create_project` | `{name}`; creates and grants this agent the new project | `add` |
| `set_secret` | `{project,key,value,...}`; add/update a record | `add`, `edit:own`, or `edit:delegated` as applicable |
| `import_env` | `{project,env_path,createProject?}`; reads a file inside approved roots into an approved project; `createProject:true` creates a missing project | `add`; applicable edit scope for existing records |
| `inject_secrets` | `{project,target_path,format?,keys?,merge?}`; write approved values to an approved path | `inject` |
| `delete_secret` | `{project,key}`; delete this agent's record | `delete:own` |
| `reveal_secret` | `{project,key}`; returns a raw value to the client/model | `reveal` |
| `compare` | `{}`; secret-derived fingerprints for approved projects | `reveal` |

Existing projects must be approved for this agent. `edit:delegated` additionally
requires explicit record delegation; scope alone does not grant ownership.
Agent-created records need human approval before injection. Enrollment, scope and
folder changes, approval, delegation, adoption, revocation, settings, and history
undo are desktop operations; there are no MCP tools to self-approve them.

For new real credentials, prefer human entry in the desktop or authorized
`import_env` rather than transporting values in a `set_secret` tool argument.
Import creates its project only with `createProject: true` and only when no project of that name exists; an existing unapproved project stays refused. Inspect its `keys` and `refused` results;
it can partially succeed. Never read the input file into chat to perform import.
Metadata includes user-entered notes and identifiers, so avoid dumping it into
public reports. Expiry fields are reminders, not automatic provider rotation.

## Shell client

Agents without MCP can run `node /absolute/path/to/vaultos/agent-cli.cjs` (the
`vaultos-agent` bin, for the desktop app) or the Rust `vaultos-agent` binary (for
`vaultosd`) with the same token configuration: `status`, `whoami`,
`projects`, `keys`, `search`, `inject PROJECT FILE [--keys A,B] [--format F]
[--replace]`, `add PROJECT KEY` (value on stdin only), `import PROJECT FILE
[--create-project]`, `sync` and `pending`. Output never contains values. Never
pass a value as an argument. Exit code 3 means not running and 4 means locked;
report either to the human instead of retrying in a loop.

## Injection details

- Use absolute target paths within granted existing folders and select the keys
  needed for the application. Omitted `keys` requests all eligible records;
  `keys: []` requests none. New unapproved records remain held for approval.
- Default `format` is `dotenv` and `merge` is `true`. Dotenv merge preserves
  unrelated variables but rewrites comments/formatting. JSON merge preserves
  unrelated object keys. Consider existing files before writing; do not display
  their contents to make that decision.
- `shell` requires `merge: false`, which replaces the target. Use a new file or
  an explicitly intended replacement. Do not source a dotenv file as shell code.
- Responses omit values; generated files contain plaintext. Check application
  behavior without logging its environment. Do not commit output files or copy
  their contents into diagnostic reports.
- After an interrupted write, inspect metadata or the intended effect before
  retrying. The bridge deliberately does not replay ambiguous mutations.

## Access and locking

Use `whoami` to diagnose missing access. Have the human change only the necessary
grant in Settings → Agents when the requested task requires it. `allProjects` and
`anyRoot` in `whoami` are human-granted all-access options; do not ask for them
when a specific project or folder grant would do. Reissuing a token
requires updating its private file and reconnecting the bridge. Revocation stops
future API calls; it neither removes exported files nor revokes provider keys.

The desktop's **Lock** stops its API, clears decrypted application state, attempts
to remove the remembered password, and blocks background unlock until a human
unlocks again. While the desktop runs, sleep, screen lock (macOS only), and 15 minutes
without a privileged desktop action also lock it.

Closing the desktop stops its API. If the user explicitly enabled background
access (macOS: Keychain plus the bridge's native helper; Linux: Secret Service), the
bridge can start a separate backend, as can the optional Linux systemd unit. That headless backend **does not monitor screen lock**. Keep
background access off, or use Lock before closing, when that boundary is needed.
Do not enable password remembering to work around an unavailable or locked vault.

With the Rust tools, `vaultosd` starts locked and only a human `vaultos unlock`
opens it; there is no remembered-password unlock. `vaultos lock` and `vaultos
stop` are the human's; `--idle-lock-minutes` is the only automatic lock, and it
does not observe screen lock or sleep.

Two further opt-in settings weaken this boundary and are the human's decision:
the **soft lock** policy (screen lock, sleep and idle lock only the window while
agents keep working; Lock stays a full lock), and the always-on service installed
by `scripts/install-service-macos.sh` (`backend.cjs --service`, which takes over
whenever no window owns the vault). Do not enable either, or install the service,
unless the user's task asks for it.

On a Mac, the human may turn on optional Touch ID settings. With confirmations on,
desktop actions such as enrolling an agent, re-issuing a token or approving keys ask
for Touch ID or the master password; only the human can answer. Touch ID guards the
window, not agent tokens or the API.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| MCP command missing / module not found | Check absolute Node and checkout paths on the target host; install locked bridge dependencies. |
| Enroll/configure-token error | Check private token file existence/mode and configured path without reading it; ask the human to enroll/reissue if needed, then reconnect. |
| Locked | The vault is running but locked, or a human lock blocks background start. Ask the human to unlock the correct preview desktop. |
| Not running | Nothing answered and no backend could start or unlock in the background. Match data directories; background startup is optional. |
| No projects / permission denied | Inspect `whoami`; check scopes, project IDs, and canonical folder grants in the desktop. Do not switch to privileged CLI access. |
| Keys held for approval | Use `list_pending`; human approval is needed before injection. |
| Output path refused | Choose an ordinary file inside an approved folder, spelled as `whoami` shows the folder (symbolic links resolved, such as `/private/var` rather than `/var` on macOS). Do not weaken path validation or target the vault directory. |
| Another process owns the vault / stale writer | Identify the exact preview process and data directory; close it normally and unlock again. Never kill unrelated apps or delete live lock files. |
| Write failed after disconnect | Determine whether it applied before retrying; preserve data on disk errors. |

## Update, back up, and recover

There is no automatic updater. Identify the installed version and source checkout,
back up before updating, and use a published release's notes/checksums. Replace
only the intended preview app after quitting it. For the bridge, keep local source
changes intact; use a clean checkout for the chosen release tag if necessary and
install from its lockfile. Rebuild the native helper if using background startup.
Preserve the token/data paths, reconnect, and repeat identity and injection
verification with synthetic data. Do not regenerate a working vault to fix an
upgrade problem.

From the source checkout, `node cli.cjs help` describes the recovery/admin CLI.
For an explicitly requested backup, quit the relevant preview and run:

```sh
node cli.cjs backup /absolute/new/dated-backup-directory
```

Use the correct `VAULTOS_DATA_DIR` when nondefault. This copies encrypted
`vault.enc` without a password prompt. The command overwrites the destination's
`vault.enc`, so choose a new directory. It does not include sync machine keys.
Keep backups private and on encrypted storage; do not upload them to the public
source repository.

Read [recovery instructions](https://github.com/rohit3a/vaultos/blob/main/docs/RECOVERY.md)
before restoring, rotating passwords, migrating, or removing data. Recovery is
tested in a fresh directory first. A restored vault can restore revoked tokens.
Password rotation can leave backups using different passwords when an individual
rewrite fails; retain both until outcomes are verified. External backups do not
rotate automatically. The human uses the CLI's hidden local password prompt;
do not put real passwords into chat, tool arguments, or shell pipelines.

The CLI's `agents`, `pending`, `approver` and `rotate-password` commands are the
human's headless equivalents of desktop grants and approvals (see the connection
guide). They need the master password, which only the human types. Never run them
to grant your own access or approve your own records. `import-legacy` is a
one-time human migration from the earlier vault-os fork; do not run it for them.

The CLI uses human authority and is not a substitute for denied MCP operations.
In particular, CLI `inject` replaces the destination (`merge: false`), unlike the
MCP default. Do not use it for routine enrolled-agent injection.

## Optional sync and removal

Sync is a separate opt-in task. Read
[the sync guide](https://github.com/rohit3a/vaultos/blob/main/docs/SYNC.md) first.
It needs Git, age, a dedicated private sync repository, and verified peer signing
identities. Whole peers are trusted; sync is not per-project agent access control.
Machine keys and replay state need encrypted backup. Do not automatically trust
peers, push data, or accept conflicts while installing or connecting MCP.

`sync status` fetches remote data and can update local sync state; it is not a
pure read. `sync plan` previews the local checkout. A successful push means Git
received data, not that another machine applied it. Resolve the guide's trust and
conflict checks before describing devices as synchronized.

Autosync is off by default; the human enables it in Settings. `node cli.cjs sync now`
asks the running owner for one round without a password. If `vault_status` shows a
halted state such as `CONFLICTS_PENDING`, report it; accepting conflicts is a human
review step in the desktop, never something to automate.

The Rust tools use sync format 2 (`vaultos sync init|identity|trust|status|push|pull|plan|accept-conflicts|auto|now`),
which keeps the device's sync keys inside the vault and needs no `age` binary. It
cannot share a repository with the desktop's format 1; moving means a new, empty
repository. `vaultos sync auto on` and `accept-conflicts` are the human's
decisions, as above. An agent's `vault_status` shows only the sync state and
flags; the reason for a halt is in `vaultos status` and `vaultosd.log`.

For requested uninstall, disable background access or Lock, quit the identified
preview, and remove only its MCP entry and app. Preserve data and encrypted
backups unless deletion was requested. See the recovery guide for targeted
preview data, token, Keychain/Secret Service and Linux service cleanup; do not
remove another vault's files, launch agents, services, or keys.
