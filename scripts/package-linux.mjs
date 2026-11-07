// Packages the Linux desktop app (vaultos-preview) with vaultos, vaultos-agent, vaultos-mcp and
// vaultosd as an unsigned tar.gz with a checksum and a CycloneDX inventory. Build it on Linux
// for that machine's architecture: the app links the system's WebKitGTK, so it cannot be
// cross-built. scripts/install-linux.sh installs the result for the current user.
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { budget, build, checksum, sbom, TOOLS, version } from "./rust-dist.mjs";

if (process.platform !== "linux") throw new Error("Build Linux artifacts on Linux; use npm run dist:mac on macOS");
const arch = process.env.VAULTOS_ARCH || process.arch;
if (arch !== process.arch) throw new Error(`Build ${arch} on a ${arch} machine; this one is ${process.arch}`);
const triple = {
    arm64: "aarch64-unknown-linux-gnu",
    x64: "x86_64-unknown-linux-gnu"
}[arch];
if (!triple) throw new Error("Supported architectures: arm64, x64");

const v = version();
const release = build();
const executable = "vaultos-preview";
const folder = path.resolve("dist", `${executable}-linux-${arch}`);
rmSync(folder, {
    recursive: true,
    force: true
});
mkdirSync(folder, {
    recursive: true
});
copyFileSync(path.join(release, "vaultos-desktop"), path.join(folder, executable));
for (const tool of TOOLS) copyFileSync(path.join(release, tool), path.join(folder, tool));
for (const file of [ executable, ...TOOLS ]) chmodSync(path.join(folder, file), 0o755);
copyFileSync("build/icon_1024.png", path.join(folder, `${executable}.png`));
for (const notice of [ "LICENSE", "THIRD_PARTY_NOTICES.md" ]) copyFileSync(notice, path.join(folder, notice));

const archive = path.resolve("dist", `VaultOS-${v}-linux-${arch}-unsigned.tar.gz`);
execFileSync("tar", [ "-czf", archive, "-C", path.dirname(folder), path.basename(folder) ], {
    stdio: "inherit"
});
budget(path.basename(folder), folder, 80);
budget(path.basename(archive), archive, 30);
checksum(archive);
sbom(triple, archive.replace(/\.tar\.gz$/, ".cdx.json"));
console.log("Built " + archive);
