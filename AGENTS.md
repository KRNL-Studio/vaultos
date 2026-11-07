# Working with VaultOS

For installing, connecting to, or operating VaultOS, read
[skills/vaultos/SKILL.md](skills/vaultos/SKILL.md). It routes to setup and
management instructions, including the human enrollment steps and MCP examples.
The complete `skills/vaultos/` directory is portable; copying only `SKILL.md`
loses its references. Loading the skill does not install the app or grant access.

## Repository development

Read [CONTRIBUTING.md](CONTRIBUTING.md) for build and release commands and
[SECURITY.md](SECURITY.md) before changing authorization, persistence, encryption,
or sync. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for component boundaries.

- Use the Rust toolchain pinned in `rust-toolchain.toml` (rustup installs it) and
  Node.js 22+ for the scripts. Build with `--locked`.
- For code changes run `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace` and `npm run check`. On
  macOS with an interactive desktop, `npm run test:desktop` runs the desktop flow
  and service mode.
- Manual app tests must use a new absolute `VAULTOS_DATA_DIR` and synthetic
  credentials. Never test against an existing user's vault, tokens, or Keychain
  items. UI tests require an interactive macOS desktop; Linux core tests do not
  establish macOS packaging or runtime compatibility.
- Preserve the `VaultOS-Preview` data directory and `org.vaultos.preview`
  namespaces. Do not add automatic migration or enable background access by
  default. Enforce agent permissions in the owner's API and the desktop's Rust
  command handlers, never only in the pages.
- Keep secret values, live vault files, tokens, private machine paths, and
  personal configuration out of commits, test fixtures, logs, and screenshots.
- When changing tools or setup, update the portable skill references and
  [docs/AGENTS.md](docs/AGENTS.md) alongside the implementation. For documentation
  changes, validate links and examples; do not add tests that merely assert prose.

Only publish or perform releases within the user's requested scope. Release
artifacts remain unsigned previews unless signing and notarization actually pass.
