"use strict";

const fs = require("node:fs");

const path = require("node:path");

const crypto = require("node:crypto");

const {regularFile: regularFile} = require("./fs-safe");

function readSession(file) {
    try {
        regularFile(file, {
            maxBytes: 4096
        });
        const s = JSON.parse(fs.readFileSync(file, "utf8"));
        if (s.app !== "VaultOS-Preview" || !Number.isInteger(s.port) || s.port < 1 || s.port > 65535 || !/^[a-f0-9]{64}$/.test(s.token)) return null;
        return s;
    } catch {
        return null;
    }
}

async function probeSession(file, timeoutMs = 1e3) {
    const s = readSession(file);
    if (!s) return null;
    try {
        const r = await fetch(`http://127.0.0.1:${s.port}/status`, {
            signal: AbortSignal.timeout(timeoutMs),
            redirect: "error"
        });
        return r.ok && (await r.json()).app === "VaultOS-Preview" ? s : null;
    } catch {
        return null;
    }
}

const pidAlive = pid => {
    try {
        process.kill(pid, 0);
        return true;
    } catch (e) {
        return e.code === "EPERM";
    }
};

// A live owner can miss one probe while a sync round holds its event loop. While the
// process named in the session file still exists, give it a few longer chances.
async function findOwner(file) {
    const live = await probeSession(file);
    if (live) return live;
    const s = readSession(file);
    if (!s || !Number.isInteger(s.pid) || s.pid <= 0 || s.pid === process.pid) return null;
    for (let i = 0; i < 4 && pidAlive(s.pid); i++) {
        const again = await probeSession(file, 2500);
        if (again) return again;
    }
    return null;
}

// The pid holding owner.lock, if that process is alive. Does not claim anything.
function lockOwner(dataDir, name = "owner.lock") {
    const file = path.join(dataDir, name);
    try {
        regularFile(file, {
            maxBytes: 128
        });
        const pid = Number(fs.readFileSync(file, "utf8"));
        return Number.isInteger(pid) && pid > 0 && pidAlive(pid) ? pid : null;
    } catch {
        return null;
    }
}

async function requestShutdown(file) {
    const s = await findOwner(file);
    if (!s) return true;
    try {
        await fetch(`http://127.0.0.1:${s.port}/shutdown`, {
            method: "POST",
            headers: {
                authorization: `Bearer ${s.token}`
            },
            signal: AbortSignal.timeout(1e3),
            redirect: "error"
        });
    } catch {}
    for (let i = 0; i < 20; i++) {
        if (!await probeSession(file, 200)) return true;
        await new Promise(r => setTimeout(r, 100));
    }
    return false;
}

// Takes over a lock whose process is gone. The file is renamed aside first and removed only
// if it is still the dead process's; a lock another process (this app or the Rust one)
// created meanwhile is put back. Unlinking by name instead could delete a live lock.
function takeOver(file, held) {
    const aside = `${file}.stale-${crypto.randomBytes(6).toString("hex")}`;
    try {
        fs.renameSync(file, aside);
    } catch (e) {
        if (e.code === "ENOENT") return;
        throw e;
    }
    let current = null;
    try {
        current = fs.readFileSync(aside, "utf8");
    } catch {}
    if (current !== held) {
        // Put the live lock back. It is never deleted unless it is back in place: if a newer
        // lock already took its name, or it cannot be restored, it stays aside.
        let restored = false;
        try {
            fs.linkSync(aside, file);
            restored = true;
        } catch (e) {
            if (e.code !== "EEXIST" && !fs.existsSync(file)) {
                try {
                    fs.renameSync(aside, file);
                } catch {}
            }
        }
        if (restored) fs.unlinkSync(aside);
        throw new Error("Another VaultOS process owns this vault");
    }
    fs.unlinkSync(aside);
}

function claim(dataDir, name = "owner.lock") {
    const file = path.join(dataDir, name);
    for (let i = 0; i < 2; i++) {
        try {
            const fd = fs.openSync(file, "wx", 384);
            fs.writeFileSync(fd, String(process.pid));
            fs.closeSync(fd);
            return () => {
                try {
                    if (fs.readFileSync(file, "utf8") === String(process.pid)) fs.unlinkSync(file);
                } catch {}
            };
        } catch (e) {
            if (e.code !== "EEXIST") throw e;
            regularFile(file, {
                maxBytes: 128
            });
            const held = fs.readFileSync(file, "utf8");
            const pid = Number(held);
            if (!Number.isInteger(pid) || pid <= 0) throw new Error("Invalid owner lock; inspect it before removing it");
            try {
                process.kill(pid, 0);
                throw new Error("Another VaultOS process owns this vault");
            } catch (err) {
                if (err.code !== "ESRCH") throw err;
            }
            takeOver(file, held);
        }
    }
    throw new Error("Could not claim vault");
}

module.exports = {
    readSession: readSession,
    probeSession: probeSession,
    findOwner: findOwner,
    pidAlive: pidAlive,
    lockOwner: lockOwner,
    requestShutdown: requestShutdown,
    claim: claim
};
