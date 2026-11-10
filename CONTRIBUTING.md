# Contributing to VaultOS

Small, focused pull requests are welcome. Start with an issue for a new feature or a change to the security model. Use private vulnerability reporting for security bugs. Never attach real vaults, agent tokens, customer records, personal device paths, or credentials to a patch, screenshot, log, or issue.

## Development

VaultOS is a Rust workspace (`crates/`) with a Tauri desktop shell around the pages in `renderer/`. Install Rust with rustup (the toolchain is pinned in `rust-toolchain.toml` and fetched on first use) and Node.js 22+, which runs the build, test and packaging scripts; there are no npm dependencies. On macOS install the command-line developer tools. On Linux the desktop needs the WebKitGTK 4.1, appindicator, librsvg and libxdo development packages (`libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev` on Debian/Ubuntu), and remembered passwords use `secret-tool` from libsecret. `npm start` runs a debug build of the desktop. `node scripts/make-tray-icons.mjs` regenerates the menu bar icons in `build/tray`. Set `VAULTOS_DATA_DIR` to a new absolute directory when manually testing; do not use your daily vault. Tests create and remove their own temporary synthetic data.

| Crate | Role |
| --- | --- |
| `vaultos-core` | Vault format v4, the store, the audit chain, the v3 upgrade, file safety, process hardening |
| `vaultos-daemon` (`vaultosd`) | The owner: the agent API on a Unix socket, guard loop, autosync. The desktop and service mode embed it |
| `vaultos-client` | Finding the owner and the agent token for the CLIs and the bridge |
| `vaultos-mcp` | The stdio MCP bridge |
| `vaultos-cli` (`vaultos`, `vaultos-agent`) | The human CLI and the agent shell client |
| `vaultos-sync` | Sync format 2 |
| `vaultos-desktop` (`VaultOS`) | The Tauri app: windows, menu bar, Quick Access, keyring, Touch ID, export, service mode |

- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo clippy -p vaultos-desktop --features ui-test --all-targets -- -D warnings` and `cargo test --workspace`: what CI runs on Linux and macOS. CI also runs `cargo deny check` (advisories, licences and sources; `deny.toml`).
- `npm run check`: script syntax, matching versions in `package.json`, `Cargo.toml` and `tauri.conf.json`, distribution notices, and the Linux installer tests.
- `VAULTOS_E2E_CHROMIUM=/path/to/chromium cargo test -p vaultos-cli --test browser`: also loads the extension into a headless Chromium (or Chrome for Testing; branded Chrome ignores `--load-extension`) with a new profile, pairs it, fills a login with real clicks and saves another, against a synthetic vault. Set `VAULTOS_E2E_NO_SANDBOX=1` where Chromium's sandbox cannot start (Ubuntu's AppArmor user-namespace restriction). Without `VAULTOS_E2E_CHROMIUM` that test does nothing.
- `npm run test:desktop`: drives a `ui-test` debug build of the desktop through setup, reveal, lock and unlock races, search, Quick Access isolation, close-to-menu-bar and lock on sleep, then service mode (waiting, unlocking with a remembered synthetic password, the window's hand-over, a manual lock, a wrong password). It needs an interactive desktop session and writes and removes its own Keychain items. The `ui-test` feature refuses release builds.
- `cargo bench -p vaultos-core`: rough timings for key derivation, unlock, list, save and reveal.
- `sh scripts/fuzz.sh [SECONDS]` runs every fuzz target for SECONDS each (default 30), after `rustup toolchain install nightly-2026-11-01 --profile minimal` and `cargo install cargo-fuzz --version 0.13.2 --locked`. The targets cover the vault file, Secret Key and v3 envelope parsers, `.env` files, `vault://` references and templates, `otpauth://` URIs, web addresses for the browser extension, SSH agent messages and keys, import files (the 1Password ZIP reader included), and masking, which must not depend on how output is read and must leave no value behind. CI runs each for 30 seconds on every pull request; `fuzz.yml` runs each for ten minutes nightly and keeps the corpus. One target: `cargo +nightly-2026-11-01 fuzz run -O mask_stream`.
- `npm run dist:mac`: builds and packages `VaultOS.app` (the app plus `vaultos`, `vaultos-agent`, `vaultos-mcp` and `vaultosd`), an unsigned ZIP, its checksum and a CycloneDX inventory of the Rust crates. `VAULTOS_ARCH=x64` builds for Intel; the default is the build machine's architecture. `node scripts/test-packaged.mjs` then checks signatures, start-up times and memory and runs the packaged tools against a synthetic vault.
- `npm run dist:linux`: the same for Linux, on Linux and for its own architecture only. `scripts/install-linux.sh --help` describes the per-user install and the opt-in systemd unit. The archive itself is deterministic (sorted names, fixed owners, modes and times from `SOURCE_DATE_EPOCH` or the last commit, gzip without a timestamp), but builds are not yet bit-for-bit reproducible: `vaultos`, `vaultosd` and the desktop program can differ between two builds of the same tree, in the order the compiler emits a few functions.

The provider table is `crates/vaultos-desktop/src/providers.json`; `crates/vaultos-core/src/providers.json` holds its ids and key names, and a desktop test fails until the two agree.

Describe the observed problem, resulting behavior, and relevant verification in your PR. Changes to encryption, grants, persistence, sync trust, or serialization need tests that exercise the security boundary. Keep unrelated formatting out of follow-up patches. Documentation-only changes need accurate links and examples, not redundant implementation tests.

## Architecture conventions

Keep authorization in the Rust process (the owner's API and the desktop's command handlers), never only in page controls. Treat encrypted remote data and local output paths as untrusted. Do not silently recover corruption by disabling a security control. Do not log values or add telemetry. Preserve opt-in background access and preview namespaces. Every new dependency adds attack surface: explain its purpose and license, and keep `cargo deny check` passing.

## Releases

The checked-in workflows test the source and packaged app on Apple Silicon and Intel macOS and on Ubuntu, and upload the macOS ZIPs and the Linux tarball as workflow artifacts. Nothing is published automatically on pull requests. To publish, create a reviewed version tag and dispatch the release workflow from that tag (**Use workflow from → Tags**), naming the same tag as its input; build provenance records the commit the workflow ran from. The workflow rejects nonmatching version tags and attaches unsigned ZIPs, the Linux tarball, checksums, and dependency inventories to a GitHub prerelease.

For a local build, use a clean checkout with the lockfiles, run checks on Linux and macOS, build both architectures, then verify the checksums, package inventory, and launch on supported hardware. Confirm that only synthetic screenshots are included and no runtime vault files, tokens, signing credentials, personal build paths or private history are in the source or artifacts. Record which architectures and OS versions were actually exercised; a cross-build is not a runtime test.

Signed builds accept `VAULTOS_SIGN_IDENTITY` (a Developer ID Application identity in the build machine's Keychain) and notarization credentials: `VAULTOS_NOTARY_PROFILE` (a `notarytool` Keychain profile), or an App Store Connect API key as `VAULTOS_NOTARY_KEY` (absolute path of a private, mode-0600 `.p8` file), `VAULTOS_NOTARY_KEY_ID` and `VAULTOS_NOTARY_ISSUER`. `scripts/package-mac.mjs` then signs every program with the hardened runtime and a secure timestamp, verifies the signature, notarizes, staples, checks Gatekeeper's assessment, and only then names the ZIP `notarized`; without them it signs ad hoc and names it `unsigned`. Delete the `.p8` copy after the build. Never check certificates, provisioning files, passwords, or Keychain exports into this repository. Public CI produces **unsigned** previews; signing and notarization are not represented as available until a build has actually passed them.

## Community

Follow [the code of conduct](CODE_OF_CONDUCT.md). The maintainer reviews contributions and release decisions in public. There is no guaranteed support SLA. Contributions are accepted under the project's MIT license; third-party material must include compatible provenance and notices.
