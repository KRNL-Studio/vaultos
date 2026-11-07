# Third-party notices

VaultOS source and its original artwork are MIT licensed. Provider names identify supported credential categories; they do not imply endorsement. Third-party provider logo artwork is not bundled.

The programs are built from Rust crates published on crates.io, including Tauri, tokio, hyper, rmcp, age, the RustCrypto crates, serde and clap. Each keeps its own licence, almost all MIT or Apache-2.0. `deny.toml` lists every licence the build accepts and the few crates under MPL-2.0 (cssparser, cssparser-macros, dtoa-short, selectors, option-ext) or BSL-1.0; `cargo deny check licenses` verifies it. Exact versions and checksums are in `Cargo.lock`, and each release attaches a CycloneDX inventory of the crates compiled into the shipped programs. The inventory is not a vulnerability-free certification.

The app's pages run in the operating system's own web view (WKWebView on macOS, WebKitGTK on Linux), which is not bundled. Git is an optional external program installed separately by the user.
