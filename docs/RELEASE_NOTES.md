VaultOS is a local vault for project credentials with scoped coding-agent access through MCP. Injection writes an approved environment file without returning values in the tool response. This preview runs on **macOS and Linux**.

This is an **evaluation preview**. The macOS downloads named `notarized` are signed with a Developer ID and notarized by Apple, and open like any other app. The downloads named `unsigned`, and the Linux tarball, come from the public release workflow: the macOS ones carry only an ad-hoc integrity signature. Start with synthetic credentials and keep independent backups. VaultOS has not received an independent security audit.

## Downloads

- macOS `arm64` (Apple Silicon) and `x64` (Intel) ZIPs with **VaultOS.app**. Deployment target: macOS 13+. The MCP bridge and CLIs are inside it, in `VaultOS.app/Contents/Helpers`.
- Linux `x64` tarball. Install it per user with `scripts/install-linux.sh --from <tarball>` from a source checkout; it needs the system's WebKitGTK 4.1. See the README.
- Verify the matching `.sha256` before opening. A CycloneDX JSON inventory of the Rust crates is attached for each build. Each archive and inventory also has signed GitHub build provenance: `gh attestation verify <download> --repo KRNL-Studio/vaultos` checks that the release workflow of this repository built it from the tagged source. That provenance covers the `unsigned` ZIPs, the tarball and the inventories. The `notarized` ZIPs are built and signed on the maintainer's Mac from the same tag, because the signing identity is not in CI: they carry a checksum and Apple's notarization ticket, not GitHub provenance.
- Builds use a separate preview data, Keychain and Secret Service namespace. Nothing installs a login service or imports another vault on its own.

## New in 0.3

- **Rust throughout.** The app is a Tauri shell around the same pages in the system web view; the agent API, CLIs, MCP bridge and sync are Rust. No Electron, Chromium or Node.js runtime ships.
- **Vault format v4.** Argon2id, an optional Secret Key, per-project keys, separately sealed item metadata and secrets, a whole-file MAC and a signed audit chain.
- **Agents over a private socket.** The app serves agents on a Unix socket that accepts only your user. Point MCP clients at `VaultOS.app/Contents/Helpers/vaultos-mcp`; tool names and schemas are unchanged.
- **Background access** is `VaultOS --service`, installed only by `scripts/install-service-macos.sh` or `scripts/install-linux.sh --enable-service`.
- **Sync format 2**, in the app and the CLI, with keys inside the vault and no `age` binary. A lost or retired device can be removed (`vaultos sync untrust`), and each other device confirms the removal.

## Fixed in preview.4

- `VAULTOS_AGENT=auto` finds the agent when the calling program is installed under a version number, as Claude's desktop sessions are on Linux: it matches the folders in the program's path as well as its file name.

## New in preview.3

- **Sync from the repository address.** Settings → Sync sets a device up from the address alone and adds another device after you compare a short code on both. `vaultos sync setup`, `pending` and `approve` do the same from a terminal.
- **Agent identity.** One enrolled agent needs no `VAULTOS_AGENT`; `VAULTOS_AGENT=auto` picks the agent named after the calling program.
- `/status` reports `unlocked` as well as `locked`, and the upgrade notes cover services, running agent sessions and helpers that read the old session file.

## Fixed in preview.2

- Setting up sync after upgrading from 0.2 no longer stops at the first push with "Invalid sync index": enrolling sets the earlier version's index aside.
- Two display faults on the home screen: an empty gap under the search field and a focus ring around the heading.

## Upgrading from 0.2

A 0.2 vault opens only to be upgraded, when you choose **Upgrade this vault**. The upgrade is one-way and keeps the old file in `backups/`. Sync from 0.2 (format 1) does not carry over: start a new, empty sync repository. Reinstall an always-on service, and update MCP entries that ran `node .../mcp/server.mjs`. `import-legacy` is not in 0.3. Read docs/RECOVERY.md first.

## Before real credentials

Read SECURITY.md, docs/AGENTS.md, docs/SYNC.md and docs/RECOVERY.md. Agents with filesystem or shell access can read injected files. Optional sync trusts whole devices; it is not a multi-user access-control system.

## Testing

Release automation runs the Rust tests, the desktop flow and service-mode tests, and the packaged app smoke test on **macOS 15 Apple Silicon** and **macOS 15 Intel**, and the Rust tests plus Linux packaging on **Ubuntu**. macOS 13 is the deployment target and has not been separately exercised.
