---
name: vaultos
description: Install VaultOS on macOS or Linux, connect its MCP bridge to a coding agent, and manage project secrets, access, backups, updates, and troubleshooting. Use when the user asks to set up or operate VaultOS.
---

# VaultOS

VaultOS is a local desktop vault for macOS and Linux with an enrolled-agent MCP bridge that ships inside the app. It can
write approved secrets into approved project files without returning their values
in the MCP response. The resulting files are plaintext: this does not isolate
secrets from an agent that can read the filesystem or run arbitrary shell commands.

## Choose the workflow

- **Install or connect:** read [references/setup.md](references/setup.md). Identify
  the target host and OS, install mode, app location, data directory, and MCP client.
  Complete authorized setup; leave password entry, enrollment, and grants to the
  human in the desktop. Verify the resulting identity before using secrets.
- **Use or manage:** read [references/operations.md](references/operations.md).
  Use the enrolled MCP tools for normal operations. It includes scopes, injection
  behavior, troubleshooting, updates, recovery, and optional sync boundaries.

For current implementation details, consult the installed version's tool schemas
and the [public source](https://github.com/KRNL-Studio/vaultos). Client tool names may
have a namespace prefix. Discover available tools instead of inventing commands.

## Operating boundaries

- Preserve existing vault applications, data, client entries, and Keychain items.
  This preview has its own namespace; migration is a separate requested task.
- Never ask for a master password or enrollment token in chat. The user enters
  passwords in the desktop or its hidden local CLI prompt, and stores the
  enrollment token in a private file. Do not read or display that file or internal
  `daemon.json`; the bridge consumes them itself.
- Prefer `inject_secrets` with the keys needed for the task. Do not read the output
  file, echo environment values, or use `reveal_secret` merely to verify injection.
  Keep generated secret files outside version control.
- A permission denial is an access boundary. Do not work around it with the
  recovery CLI, the owner's session token, the daemon socket, or direct vault
  access. Human grants and secret approval happen in the desktop.
- Installing a skill does not authorize enabling remembered passwords, trusting a
  sync peer, uploading backups, changing provider credentials, or deleting data.
  Perform those only when included in the user's task.

Report what was installed or changed, the verified identity/access and operation
result, and any remaining human step. Include paths or key names only as needed;
never include secret values or claim the app is signed, audited, or a sandbox.
