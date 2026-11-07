// Smoke-tests a packaged VaultOS.app against a temporary vault with synthetic values: the
// signature, the bundled tools and their start-up time, a CLI round trip through the bundled
// vaultosd, and the desktop app starting and quitting cleanly.
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";
import { TOOLS } from "./rust-dist.mjs";

const app = path.resolve(process.env.VAULTOS_TEST_APP || `dist/VaultOS-darwin-${process.arch}/VaultOS.app`);
const bin = path.join(app, "Contents", "Helpers");
const dir = mkdtempSync(path.join(realpathSync(tmpdir()), "vaultos-package-test-"));
const env = {
    ...process.env,
    VAULTOS_DATA_DIR: path.join(dir, "data")
};
const password = "synthetic-packaged-password\n";
const run = (tool, args, input) => {
    const r = spawnSync(path.join(bin, tool), args, {
        env: env,
        input: input,
        encoding: "utf8",
        timeout: 120000
    });
    assert.equal(r.status, 0, `${tool} ${args.join(" ")} failed: ${r.stderr}`);
    return r.stdout;
};
const sleep = ms => new Promise(r => setTimeout(r, ms));

try {
    execFileSync("/usr/bin/codesign", [ "--verify", "--deep", "--strict", app ]);
    // Speed budget: a warm start of each tool, as an agent's shell or MCP client sees it.
    for (const tool of TOOLS) {
        run(tool, [ "--version" ]);
        const t = performance.now();
        run(tool, [ "--version" ]);
        const ms = performance.now() - t;
        console.log(`${tool} --version: ${ms.toFixed(0)} ms`);
        assert(ms < 250, `${tool} starts too slowly`);
    }
    run("vaultos", [ "--password-stdin", "init" ], password);
    run("vaultos", [ "start" ]);
    try {
        run("vaultos", [ "--password-stdin", "unlock" ], password);
        assert.equal(JSON.parse(run("vaultos", [ "status" ])).unlocked, true, "the bundled vaultosd unlocks");
    } finally {
        run("vaultos", [ "stop" ]);
    }

    const child = spawn(path.join(app, "Contents", "MacOS", "VaultOS"), [], {
        env: env,
        stdio: "ignore"
    });
    const exited = new Promise(r => child.once("exit", (code, signal) => r({
        code: code,
        signal: signal
    })));
    await sleep(3000);
    assert.equal(child.exitCode, null, "the desktop app keeps running");
    const rss = Number(execFileSync("/bin/ps", [ "-o", "rss=", "-p", String(child.pid) ], {
        encoding: "utf8"
    }).trim()) / 1024;
    console.log(`VaultOS resident memory after start: ${rss.toFixed(0)} MiB`);
    assert(rss < 120, "the desktop app uses too much memory at start");
    child.kill("SIGTERM");
    const done = await Promise.race([ exited, sleep(10000).then(() => null) ]);
    assert(done, "the desktop app quits on SIGTERM");
    assert.equal(done.code, 0, "the desktop app quits cleanly");
    console.log("Packaged app passed: signature, bundled tools, CLI round trip through vaultosd, desktop start and clean quit.");
} finally {
    rmSync(dir, {
        recursive: true,
        force: true
    });
}
