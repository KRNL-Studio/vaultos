# Contributing to VaultOS

Small, focused pull requests are welcome. Start with an issue for a new feature or a change to the security model. Use private vulnerability reporting for security bugs. Never attach real vaults, agent tokens, customer records, personal device paths, or credentials to a patch, screenshot, log, or issue.

## Development

Use Node.js 22+ and npm. Clone the repository, run `npm ci`, and install `age` for sync tests. Before macOS tests, run `VAULTOS_BUILD_TEST_HELPER=1 npm run build:native` to compile the disposable-Keychain and private-pasteboard test helpers; they are excluded from distribution. On macOS, install command-line developer tools and run `npm run build:native` (the Keychain and clipboard helpers), then `npm start`. `node scripts/make-tray-icons.mjs` regenerates the menu bar icons in `build/tray`. On Linux, no native helper is needed (`npm run build:native` skips); remembered passwords use `secret-tool` from libsecret. Set `VAULTOS_DATA_DIR` to a new absolute directory when manually testing; do not use your daily vault. Tests create and remove their own temporary synthetic data.

- `npm run check`: syntax/asset checks and security/integration tests.
- `npm run test:ui`: macOS desktop setup, project/reveal/lock/unlock, and renderer isolation checks, search, Quick Access isolation, and close-to-menu-bar locking. Requires an interactive desktop. Writes a synthetic screenshot to `docs/images`.
- `npm audit`: review current dependency advisories. Update the lockfile with any dependency change.
- `npm run dist:mac`: package an unsigned native preview ZIP and checksum on macOS. `VAULTOS_ARCH=x64` builds for Intel; the default uses the build machine's architecture.
- `npm run dist:linux`: package an unsigned Linux tar.gz, checksum and inventory for x64 or arm64 (`VAULTOS_ARCH`). It can cross-build on macOS, but only a launch on Linux tests it. `scripts/install-linux.sh --help` describes the per-user install, sandbox hardening and the opt-in systemd backend unit.

Describe the observed problem, resulting behavior, and relevant verification in your PR. Changes to encryption, grants, persistence, sync trust, or serialization need tests that exercise the security boundary. Keep unrelated formatting out of follow-up patches. Documentation-only changes need accurate links and examples, not redundant implementation tests.

## Architecture conventions

Keep authorization in the main process/API, never only in renderer controls. Treat encrypted remote data and local output paths as untrusted. Do not silently recover corruption by disabling a security control. Do not log values or add telemetry. Preserve opt-in background access and preview namespaces. Every new dependency adds attack surface: explain its purpose and license.

## Releases

The checked-in macOS workflow tests the source and packaged application on Apple Silicon (macOS 14) and Intel (macOS 15), then uploads both architecture artifacts. It does not publish a release automatically on pull requests. Linux packages are not built or published by CI yet. To publish, create a reviewed version tag and dispatch the release workflow for that exact tag. The workflow rejects nonmatching version tags and attaches unsigned ZIPs, checksums, and dependency inventory to a GitHub prerelease.

For a local build, use a clean checkout with the lockfile, run checks on Linux and macOS, build both architectures, then verify the ZIP checksums, package inventory, and launch on supported hardware. Confirm that only synthetic screenshots are included and no runtime vault files, tokens, signing credentials, personal build paths or private history are in the source or artifacts. Record which architectures and OS versions were actually exercised; a cross-build is not a runtime test.

Future signed builds accept `VAULTOS_SIGN_IDENTITY` and `VAULTOS_NOTARY_PROFILE` on a dedicated macOS release machine with its own configured Developer ID identity and `notarytool` Keychain profile. The script enables hardened runtime, signs, notarizes, and verifies the application. Never check certificates, provisioning files, passwords, or Keychain exports into this repository. Public CI currently produces **unsigned** previews; signing/notarization is not represented as available.

## Community

Follow [the code of conduct](CODE_OF_CONDUCT.md). The maintainer reviews contributions and release decisions in public. There is no guaranteed support SLA. Contributions are accepted under the project's MIT license; third-party material must include compatible provenance and notices.
