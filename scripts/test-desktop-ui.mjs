// Runs the desktop UI flow (scripts/desktop-ui-flow.js) in a `ui-test` debug build of the Tauri
// app, against a new vault in a temporary folder. Needs an interactive desktop session.
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const dir = mkdtempSync(path.join(realpathSync(tmpdir()), "vaultos-desktop-ui-"));
const data = path.join(dir, "data");

// A sync checkout whose remote does not exist, so a pull fails before it touches the vault.
const syncRepo = path.join(dir, "sync-repository");
execFileSync("git", [ "init", "-q", syncRepo ]);
execFileSync("git", [ "-C", syncRepo, "remote", "add", "origin", path.join(dir, "unreachable.git") ]);

// The test must not take the human's Quick Access shortcut while it runs.
mkdirSync(data, {
    recursive: true,
    mode: 0o700
});
writeFileSync(path.join(data, "desktop-prefs.json"), JSON.stringify({
    shortcut: ""
}), {
    mode: 0o600
});

let binary = process.env.VAULTOS_DESKTOP_BIN;
if (!binary) {
    execFileSync("cargo", [ "build", "-q", "-p", "vaultos-desktop", "--features", "ui-test" ], {
        cwd: root,
        stdio: "inherit"
    });
    binary = path.join(root, "target", "debug", "vaultos-desktop");
}

const code = await new Promise(resolve => {
    const child = spawn(binary, [], {
        env: {
            ...process.env,
            VAULTOS_DATA_DIR: data,
            VAULTOS_SYNC_REPO: syncRepo,
            VAULTOS_UI_TEST_SCRIPT: path.join(root, "scripts", "desktop-ui-flow.js")
        },
        stdio: [ "ignore", "ignore", "pipe" ]
    });
    const timer = setTimeout(() => {
        console.error("Desktop flow timed out.");
        child.kill("SIGTERM");
    }, 180000);
    let rest = "";
    const other = [];
    child.stderr.on("data", chunk => {
        const lines = (rest + chunk).split("\n");
        rest = lines.pop();
        for (const line of lines) {
            if (line.startsWith("ui-test: ")) console.log(line.slice(9)); else other.push(line);
        }
    });
    child.on("exit", status => {
        clearTimeout(timer);
        // The app's own output helps only when the flow fails.
        if (status !== 0 && other.length) console.error(other.slice(-40).join("\n"));
        resolve(status ?? 1);
    });
});
rmSync(dir, {
    recursive: true,
    force: true
});
process.exit(code);
