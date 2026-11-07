"use strict";

// Copies secret values for the desktop. On macOS the native helper marks the copy as
// concealed and transient (clipboard managers skip it) and current-host-only (Universal
// Clipboard does not send it to other devices). Elsewhere, or if the helper is missing, it
// falls back to plain text. Either way one timer clears the copy after `clearAfterMs` if it
// is still on the clipboard; a newer copy replaces the timer instead of being cut short.

const fs = require("node:fs");

const path = require("node:path");

const {execFileSync: execFileSync} = require("node:child_process");

const {sha256: sha256} = require("./crypto");

function defaultHelper() {
    return __dirname.endsWith("app.asar") && process.resourcesPath ? path.join(process.resourcesPath, "vaultos-clipboard") : path.join(__dirname, "build", "native", "vaultos-clipboard");
}

function runHelper(helper, request) {
    const out = execFileSync(helper, [], {
        input: JSON.stringify(request),
        timeout: 3e3,
        maxBuffer: 64 * 1024,
        stdio: [ "pipe", "pipe", "ignore" ]
    });
    return JSON.parse(out.toString("utf8"));
}

class SecureClipboard {
    constructor(clipboard, {platform: platform = process.platform, helper: helper = defaultHelper(), run: run = runHelper, clearAfterMs: clearAfterMs = 3e4} = {}) {
        this.clipboard = clipboard;
        this.helper = platform === "darwin" && fs.existsSync(helper) ? helper : null;
        this.run = run;
        this.clearAfterMs = clearAfterMs;
        this.copied = null;
        this.timer = null;
    }
    // Returns "concealed" when the helper wrote it, "plain" for the fallback.
    write(text) {
        if (typeof text !== "string") throw new Error("Nothing to copy");
        this.clear();
        let mode = "plain";
        if (this.helper) {
            try {
                const r = this.run(this.helper, {
                    action: "write",
                    text: text
                });
                if (Number.isInteger(r.changeCount)) {
                    this.copied = {
                        changeCount: r.changeCount
                    };
                    mode = "concealed";
                }
            } catch {}
        }
        if (mode === "plain") {
            this.clipboard.writeText(text);
            this.copied = {
                digest: sha256(text)
            };
        }
        this.timer = setTimeout(() => this.clear(), this.clearAfterMs);
        if (this.timer.unref) this.timer.unref();
        return mode;
    }
    // Clears our copy if it is still there; never clears something copied after it.
    clear() {
        clearTimeout(this.timer);
        this.timer = null;
        const copied = this.copied;
        this.copied = null;
        if (!copied) return;
        try {
            if (copied.changeCount !== undefined) this.run(this.helper, {
                action: "clear",
                changeCount: copied.changeCount
            }); else if (sha256(this.clipboard.readText()) === copied.digest) this.clipboard.clear();
        } catch {}
    }
}

module.exports = {
    SecureClipboard: SecureClipboard,
    runHelper: runHelper
};
