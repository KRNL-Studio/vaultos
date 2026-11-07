// Shared by the packagers: the workspace version, checksums, size budgets and a CycloneDX
// inventory of the Rust crates compiled into the shipped programs.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

// The desktop app and the tools it ships: vaultos-desktop, vaultos and vaultos-agent,
// vaultos-mcp, vaultosd.
export const PACKAGES = [ "vaultos-desktop", "vaultos-cli", "vaultos-mcp", "vaultos-daemon" ];
export const TOOLS = [ "vaultos", "vaultos-agent", "vaultos-mcp", "vaultosd" ];

export function version() {
    const toml = readFileSync("Cargo.toml", "utf8");
    const found = /^\[workspace\.package\][^[]*?^version\s*=\s*"([^"]+)"/ms.exec(toml);
    if (!found) throw new Error("No workspace version in Cargo.toml");
    return found[1];
}

export function build(triple) {
    const args = [ "build", "--release", "--locked", ...PACKAGES.flatMap(p => [ "-p", p ]) ];
    if (triple) args.push("--target", triple);
    execFileSync("cargo", args, {
        stdio: "inherit"
    });
    return path.resolve("target", ...triple ? [ triple ] : [], "release");
}

export function checksum(file) {
    const sum = createHash("sha256").update(readFileSync(file)).digest("hex");
    writeFileSync(file + ".sha256", `${sum}  ${path.basename(file)}\n`);
}

export function size(p) {
    const s = statSync(p);
    if (!s.isDirectory()) return s.size;
    return readdirSync(p).reduce((n, e) => n + size(path.join(p, e)), 0);
}

// Fails the build when an artifact outgrows its budget, so growth is a decision.
export function budget(label, p, limitMiB) {
    const mib = size(p) / 1048576;
    console.log(`${label}: ${mib.toFixed(1)} MiB (budget ${limitMiB} MiB)`);
    if (mib > limitMiB) throw new Error(`${label} is over its size budget`);
}

// Every crate compiled into the shipped programs for this target: normal and build
// dependencies reachable from PACKAGES, without dev-dependencies.
export function sbom(triple, file) {
    const meta = JSON.parse(execFileSync("cargo", [ "metadata", "--format-version", "1", "--locked", "--filter-platform", triple ], {
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024
    }));
    const byId = new Map(meta.packages.map(p => [ p.id, p ]));
    const nodes = new Map(meta.resolve.nodes.map(n => [ n.id, n ]));
    const roots = meta.packages.filter(p => PACKAGES.includes(p.name) && meta.workspace_members.includes(p.id));
    const seen = new Set();
    const queue = roots.map(p => p.id);
    while (queue.length) {
        const id = queue.pop();
        if (seen.has(id)) continue;
        seen.add(id);
        for (const dep of nodes.get(id)?.deps || []) {
            if (dep.dep_kinds.some(k => k.kind !== "dev")) queue.push(dep.pkg);
        }
    }
    const components = [ ...seen ].map(id => byId.get(id)).filter(p => !meta.workspace_members.includes(p.id)).sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version)).map(p => ({
        type: "library",
        name: p.name,
        version: p.version,
        purl: `pkg:cargo/${p.name}@${p.version}`,
        ...p.license ? {
            licenses: [ {
                expression: p.license
            } ]
        } : {}
    }));
    const doc = {
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        version: 1,
        metadata: {
            component: {
                type: "application",
                name: "VaultOS",
                version: version()
            }
        },
        components: components
    };
    writeFileSync(file, JSON.stringify(doc, null, 1) + "\n");
}
