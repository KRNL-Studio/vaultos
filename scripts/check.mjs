import { readdirSync, readFileSync, existsSync } from "node:fs";

import path from "node:path";

import { execFileSync } from "node:child_process";

import { version } from "./rust-dist.mjs";

const excluded = new Set([ ".git", "node_modules", "dist", "out", "target" ]);

function walk(dir) {
    return readdirSync(dir, {
        withFileTypes: true
    }).flatMap(e => excluded.has(e.name) ? [] : e.isDirectory() ? walk(path.join(dir, e.name)) : [ path.join(dir, e.name) ]);
}

const files = walk(".");

for (const file of files.filter(f => /\.(js|cjs|mjs)$/.test(f))) execFileSync(process.execPath, [ "--check", file ], {
    stdio: "pipe"
});

for (const required of [ "LICENSE", "SECURITY.md", "THIRD_PARTY_NOTICES.md" ]) if (!existsSync(required)) throw new Error("Missing distribution notice: " + required);

const p = JSON.parse(readFileSync("package.json")), lock = JSON.parse(readFileSync("package-lock.json"));

if (p.version !== lock.packages[""].version) throw new Error("Lockfile version differs");

if (p.version !== version()) throw new Error(`package.json is ${p.version}; the Cargo workspace is ${version()}`);

const tauri = JSON.parse(readFileSync("crates/vaultos-desktop/tauri.conf.json"));

if (tauri.version !== version()) throw new Error(`tauri.conf.json is ${tauri.version}; the Cargo workspace is ${version()}`);

const extension = JSON.parse(readFileSync("extension/manifest.json"));

if (extension.version_name !== version() || extension.version !== version().replace(/-.*$/, "")) throw new Error(`extension/manifest.json is ${extension.version_name}; the Cargo workspace is ${version()}`);

console.log("Script syntax, versions and distribution notices checked.");
