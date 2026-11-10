#!/bin/sh
# Runs every fuzz target in fuzz/ for SECONDS each (default 30), with the pinned nightly
# toolchain and the workspace's lockfile. Needs cargo-fuzz:
#   rustup toolchain install nightly-2026-11-01 --profile minimal
#   cargo install cargo-fuzz --version 0.13.2 --locked
# A crash leaves its input in fuzz/artifacts/<target>/; corpora grow in fuzz/corpus/.
set -eu
seconds=${1:-30}
toolchain=nightly-2026-11-01
cd "$(dirname "$0")/.."
cp Cargo.lock fuzz/Cargo.lock
for target in $(cargo "+$toolchain" fuzz list); do
    echo "== $target ($seconds s)"
    cargo "+$toolchain" fuzz run -O "$target" -- -max_total_time="$seconds" -rss_limit_mb=2048
done
