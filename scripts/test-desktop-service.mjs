// Background access (`VaultOS --service`) against a new vault in a temporary folder, with a
// synthetic password the app itself remembers in the keychain and forgets at the end: no
// remembered password, unlock and serve, the window's hand-over, a manual lock, a clean quit,
// a password left in the keychain after background access was turned off, and a wrong
// remembered password. Uses a `ui-test` debug build.
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

const root = path.resolve(import.meta.dirname, "..");
if (!process.env.VAULTOS_DESKTOP_BIN) {
    execFileSync("cargo", [ "build", "-q", "-p", "vaultos-desktop", "--features", "ui-test", "-p", "vaultos-cli", "-p", "vaultos-daemon" ], {
        cwd: root,
        stdio: "inherit"
    });
}
const debug = path.join(root, "target", "debug");
const app = process.env.VAULTOS_DESKTOP_BIN || path.join(debug, "vaultos-desktop");
const dir = mkdtempSync(path.join(realpathSync(tmpdir()), "vaultos-desktop-service-"));
const data = path.join(dir, "data");
const env = {
    ...process.env,
    VAULTOS_DATA_DIR: data
};
const password = "synthetic-service-password";
const sleep = ms => new Promise(r => setTimeout(r, ms));
const cli = (args, input) => spawnSync(path.join(debug, "vaultos"), args, {
    env: env,
    input: input,
    encoding: "utf8",
    timeout: 60000
});
const status = () => {
    try {
        return JSON.parse(cli([ "status" ]).stdout);
    } catch {
        return {};
    }
};
const until = async (probe, what, ms = 60000) => {
    for (const end = Date.now() + ms; Date.now() < end; await sleep(250)) if (probe()) return;
    throw new Error(`timed out waiting for ${what}`);
};
const remember = pw => assert.equal(spawnSync(app, [ "--ui-test-remember" ], {
    env: env,
    input: pw + "\n"
}).status, 0, "the app remembers the synthetic password");
const service = () => {
    const child = spawn(app, [ "--service" ], {
        env: env,
        stdio: [ "ignore", "ignore", "pipe" ]
    });
    child.log = "";
    child.stderr.on("data", d => child.log += d);
    child.done = new Promise(r => child.once("exit", code => r(code)));
    return child;
};
const quit = async child => {
    child.kill("SIGTERM");
    const code = await Promise.race([ child.done, sleep(10000).then(() => "running") ]);
    assert.equal(code, 0, `the service quits cleanly on SIGTERM\n${child.log}`);
};

let running = null;
try {
    assert.equal(cli([ "--password-stdin", "init" ], password + "\n").status, 0, "init");

    running = service();
    await until(() => running.log.includes("waiting for the remembered password"), "the service to wait without a remembered password");
    await quit(running);

    remember(password);
    running = service();
    await until(() => status().unlocked === true, "the service to unlock with the remembered password");

    // The window takes over the same way: it asks the server to stop. The service waits,
    // then serves again once the vault is free.
    assert.equal(cli([ "stop" ]).status, 0, "stop");
    await until(() => running.log.includes("the window took over; standing by"), "the hand-over");
    await until(() => status().unlocked === true, "the service to serve again");

    // A manual lock (the window's Lock) blocks background access until a human unlock.
    writeFileSync(path.join(data, "locked"), "");
    assert.equal(cli([ "stop" ]).status, 0, "stop");
    await until(() => running.log.includes("a manual lock needs a human unlock"), "the manual lock to block the service");
    assert.equal(status().running, false, "a manual lock keeps the vault closed");
    await quit(running);

    rmSync(path.join(data, "locked"));
    // Background access turned off in the vault, but the keychain kept the password.
    assert.equal(spawnSync(app, [ "--ui-test-background-off" ], {
        env: env,
        input: password + "\n"
    }).status, 0, "background access turned off in the vault");
    running = service();
    const off = await Promise.race([ running.done, sleep(60000).then(() => "running") ]);
    assert.equal(off, 0, `a stale remembered password stops the service\n${running.log}`);
    assert.match(running.log, /background access is off/, "the log says background access is off");
    assert.equal(status().running, false, "the vault stays closed");

    remember(password);
    remember("synthetic-wrong-password");
    running = service();
    const code = await Promise.race([ running.done, sleep(60000).then(() => "running") ]);
    // Status 0, so launchd and systemd do not restart it in a loop; the log says why.
    assert.equal(code, 0, `a wrong remembered password stops the service\n${running.log}`);
    assert.match(running.log, /did not open the vault/, "the log says why the service stopped");
    running = null;
    console.log("Service mode passed: waits without a remembered password, unlocks and serves, hands over to the window, honours a manual lock, quits cleanly, ignores a password left behind after background access was turned off, refuses a wrong password.");
} finally {
    if (running && running.exitCode === null) running.kill("SIGKILL");
    spawnSync(app, [ "--ui-test-forget" ], {
        env: env
    });
    rmSync(dir, {
        recursive: true,
        force: true
    });
}
