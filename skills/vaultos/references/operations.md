# Use and manage VaultOS

## Daily MCP operations

Use tool discovery for the installed version's full schemas. These are the public
bridge tool names; a client may prefix them with a server namespace.

| Tool | Arguments / purpose | Required scope |
| --- | --- | --- |
| `vault_status` | `{}`; owner/bridge version, availability and sync health (`state`, `halted`, `lastSyncAt`, `peerStalled`) | Not an authentication check |
| `whoami` | `{}`; current identity and grants | Enrolled identity |
| `list_projects` | `{}`; approved projects | `read` |
| `list_secrets` | `{project}`; names and metadata, no values | `read` |
| `search` | `{query}`; approved project/key/provider matches | `read` |
| `list_pending` | `{}`; records awaiting human injection approval | `read` |
| `create_project` | `{name}`; creates and grants this agent the new project | `add` |
| `set_secret` | `{project,key,value,kind?,tags?,...}`; add/update a record | `add`, `edit:own`, or `edit:delegated` as applicable |
| `import_env` | `{project,env_path,createProject?}`; reads a file inside approved roots into an approved project; `createProject:true` creates a missing project | `add`; applicable edit scope for existing records |
| `inject_secrets` | `{project,target_path,format?,keys?,merge?}`; write approved values to an approved path | `inject` |
| `delete_secret` | `{project,key}`; move this agent's record to the Trash (the human can restore it for 30 days) | `delete:own` |
| `reveal_secret` | `{project,key}`; returns a raw value to the client/model | `reveal` |
| `compare` | `{}`; secret-derived fingerprints for approved projects | `reveal` |
| `run_with_secrets` | `{project,command,cwd,keys?,timeout_seconds?}`; starts an allowed command in an approved folder with the project's values and returns its masked output | `run` and an allowed command |
| `request_access` | `{project,scopes,minutes?,reason}`; asks the human for temporary scopes on one project (1-60 minutes) | Enrolled identity; the human confirms |

Prefer `run_with_secrets` to `inject_secrets` when the task is to run a command:
the values never reach a file or the conversation. Only commands in `whoami`'s
`runCommands` can run; ask the human to add one rather than wrapping a command in
`sh -c`. Never try to print, encode or exfiltrate values through an allowed
command: masking is a guard against accidents, and doing so breaks the human's trust
in the grant.

Use `request_access` only when the user's task needs access you lack, with a
reason the human can judge; one request, then tell the user if it is refused.
Granted scopes cover that project for the minutes granted and end when the vault
locks. Do not ask repeatedly or for more scopes or time than the task needs.

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
Items the human archived or moved to the Trash are absent for agents, so a key
that disappeared may be there: ask the human rather than recreating it. Concealed
and one-time code custom fields are never sent to agents.

## Shell client

Agents without MCP can run `vaultos-agent`, which ships next to `vaultos-mcp` in
the app, with the same token configuration: `status`, `whoami`,
`projects`, `keys`, `search`, `inject PROJECT FILE [--keys A,B] [--format F]
[--replace]`, `add PROJECT KEY` (value on stdin only), `import PROJECT FILE
[--create-project]`, `pending`, `run PROJECT [--keys A,B] -- COMMAND` (run scope;
masked output) and `request-access --project P --scope S --reason R [--minutes N]`. Output never contains values. Never
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

The desktop's **Lock** stops its API, clears decrypted application state, removes
the remembered password, and blocks background unlock until a human unlocks
again. While the desktop runs, sleep, screen lock, and 15 minutes without a
privileged desktop action also lock it. Closing the window locks it too.

Nothing starts the vault for an agent. Agents are served after the window closes
only if the human turned on background access (remembered password in the
Keychain or Secret Service) **and** installed the background service
(`scripts/install-service-macos.sh`, or `scripts/install-linux.sh
--enable-service`), which runs the app as `VaultOS --service`. That service **does
not monitor screen lock**, and a full lock blocks it until a human unlocks. Do not
enable password remembering or install the service to work around an
unavailable or locked vault.

For a headless vault, `vaultosd` starts locked and only a human `vaultos unlock`
opens it. `vaultos lock` and `vaultos stop` are the human's;
`--idle-lock-minutes` is its only automatic lock, and it does not observe screen
lock or sleep.

The **soft lock** policy (screen lock, sleep and idle lock only the window while
agents keep working; Lock stays a full lock) also weakens this boundary and is the
human's decision. Do not enable it, background access or the service unless the
user's task asks for it.

On a Mac, the human may turn on optional Touch ID settings. With confirmations on,
desktop actions such as enrolling an agent, re-issuing a token or approving keys ask
for Touch ID or the master password; only the human can answer. Touch ID guards the
window, not agent tokens or the API.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| MCP command missing | Check the absolute path to `vaultos-mcp` inside the installed app on the target host. |
| Enroll/configure-token error | Check private token file existence/mode and configured path without reading it; ask the human to enroll/reissue if needed, then reconnect. |
| Locked | The vault is running but locked. Ask the human to unlock the correct preview app (or run `vaultos unlock` for a headless vault). |
| Not running | Nothing owns the vault: the app is closed and no background service is serving. Match data directories; ask the human to open and unlock the app. |
| No projects / permission denied | Inspect `whoami`; check scopes, project IDs, and canonical folder grants in the desktop. Do not switch to privileged CLI access. |
| Keys held for approval | Use `list_pending`; human approval is needed before injection. |
| Output path refused | Choose an ordinary file inside an approved folder, spelled as `whoami` shows the folder (symbolic links resolved, such as `/private/var` rather than `/var` on macOS). Do not weaken path validation or target the vault directory. |
| Another process owns the vault / stale writer | Identify the exact preview process and data directory; close it normally and unlock again. Never kill unrelated apps or delete live lock files. |
| Write failed after disconnect | Determine whether it applied before retrying; preserve data on disk errors. |

## Update, back up, and recover

There is no automatic updater. Identify the installed version, back up before
updating, and use a published release's notes/checksums. Replace only the
intended preview app after quitting it; the bridge and CLI update with it, so MCP
entries that point into the app keep working. An installed background service
from 0.2 runs the old Node backend and must be reinstalled for 0.3. Preserve the
token/data paths, reconnect, and repeat identity and injection verification with
synthetic data. Do not regenerate a working vault to fix an upgrade problem, and
do not start the one-way upgrade of an 0.2 vault unless the human asked.

`vaultos help` describes the recovery/admin CLI that ships in the app. For an
explicitly requested backup, quit the relevant preview and run:

```sh
vaultos backup /absolute/new/dated-backup-directory
```

Use the correct `VAULTOS_DATA_DIR` when nondefault. This copies `vault.enc`, the
audit log and the sync index (the memory of which sync manifests were seen); the
sync keys are inside the vault. No tokens are copied. Choose a new directory for
each snapshot. Keep backups private and on encrypted storage; do not upload them
to the public source repository.

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
to grant your own access or approve your own records.

The CLI uses human authority and is not a substitute for denied MCP operations.
In particular, CLI `inject` replaces the destination (`merge: false`), unlike the
MCP default. Do not use it for routine enrolled-agent injection.

## Optional sync and removal

Sync is a separate opt-in task. Read
[the sync guide](https://github.com/rohit3a/vaultos/blob/main/docs/SYNC.md) first.
It needs Git, a dedicated private sync repository, and verified peer signing
identities. Whole peers are trusted; sync is not per-project agent access control.
The sync index (replay state) needs encrypted backup. Do not automatically trust
peers, push data, or accept conflicts while installing or connecting MCP.

`sync status` fetches remote data and can update local sync state; it is not a
pure read. `sync plan` previews the local checkout. A successful push means Git
received data, not that another machine applied it. Resolve the guide's trust and
conflict checks before describing devices as synchronized.

VaultOS 0.3 uses sync format 2 (in Settings → Sync, or `vaultos sync
init|identity|trust|status|push|pull|plan|accept-conflicts|auto|now`), which keeps
the device's sync keys inside the vault and needs no `age` binary. It refuses an
0.2 (format 1) repository; moving means a new, empty repository.

Autosync is off by default; the human enables it in Settings or with `vaultos sync
auto on`. `vaultos sync now` asks the running owner for one round without a
password. If `vault_status` shows a halted state such as `CONFLICTS_PENDING`,
report it; accepting conflicts is a human review step, never something to
automate. An agent's `vault_status` shows only the sync state and flags; the
reason for a halt is in `vaultos status`.

For requested uninstall, disable background access or Lock, have the human turn
off Open at login if it is on, quit the identified preview from its menu bar item
(closing the window leaves it running, locked), and remove only its MCP entry and app. Preserve data and encrypted
backups unless deletion was requested. See the recovery guide for targeted
preview data, token, Keychain/Secret Service and Linux service cleanup; do not
remove another vault's files, launch agents, services, or keys.
