"use strict";

// Desktop preferences that must work while the vault is locked: the Quick Access shortcut
// is registered before unlock, and the menu bar decides what closing the window does. They
// hold no secrets, so they live in a small plaintext file beside the vault, like the
// Touch ID hint. Only the unlocked desktop window can change them.

const fs = require("node:fs");

const path = require("node:path");

const {regularFile: regularFile, atomicWrite: atomicWrite} = require("./fs-safe");

const FILE = "desktop-prefs.json";

const DEFAULT_SHORTCUT = "Shift+CommandOrControl+Space";

const MODIFIERS = new Set([ "Command", "Cmd", "Control", "Ctrl", "CommandOrControl", "CmdOrCtrl", "Alt", "Option", "AltGr", "Shift", "Super", "Meta" ]);

const NAMED_KEYS = new Set([ "Space", "Tab", "Enter", "Return", "Backspace", "Delete", "Insert", "Home", "End", "PageUp", "PageDown", "Up", "Down", "Left", "Right", "Escape", "Esc", "Plus" ]);

const BOOLEANS = [ "menuBar", "launchAtLogin", "notifyApprovals", "notifyExpiry" ];

function defaults(platform = process.platform) {
    return {
        // Linux trays depend on the desktop environment, so closing the window quits there
        // unless the human turns the menu bar item on.
        menuBar: platform === "darwin",
        shortcut: DEFAULT_SHORTCUT,
        launchAtLogin: false,
        notifyApprovals: false,
        notifyExpiry: false
    };
}

// Electron accelerator syntax, limited to combinations that make sense as a global
// shortcut: one or more modifiers and one key, or a function key alone. "" disables it.
function validAccelerator(value) {
    if (value === "") return true;
    if (typeof value !== "string" || value.length > 64) return false;
    const parts = value.split("+");
    const key = parts.pop();
    if (!key || parts.some(p => !MODIFIERS.has(p)) || new Set(parts).size !== parts.length) return false;
    const fn = /^F([1-9]|1[0-9]|2[0-4])$/.test(key);
    const ok = fn || NAMED_KEYS.has(key) || /^[A-Z0-9]$/.test(key) || /^[)!@#$%^&*(:;=<,_\-.>?/~`{\]|[}"']$/.test(key);
    return ok && (fn || parts.length > 0);
}

function load(dataDir, platform = process.platform) {
    const prefs = defaults(platform);
    const file = path.join(dataDir, FILE);
    try {
        regularFile(file, {
            optional: true,
            maxBytes: 4096
        });
        if (!fs.existsSync(file)) return prefs;
        const saved = JSON.parse(fs.readFileSync(file, "utf8"));
        for (const k of BOOLEANS) if (typeof saved[k] === "boolean") prefs[k] = saved[k];
        if (validAccelerator(saved.shortcut)) prefs.shortcut = saved.shortcut;
    } catch {}
    return prefs;
}

function save(dataDir, patch, platform = process.platform) {
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) throw new Error("Invalid desktop preferences");
    for (const [k, v] of Object.entries(patch)) {
        if (BOOLEANS.includes(k)) {
            if (typeof v !== "boolean") throw new Error(`Invalid ${k} preference`);
        } else if (k === "shortcut") {
            if (!validAccelerator(v)) throw new Error("Use one or more modifier keys and one key, like Shift+CommandOrControl+Space");
        } else throw new Error("Unknown desktop preference");
    }
    const prefs = {
        ...load(dataDir, platform),
        ...patch
    };
    atomicWrite(path.join(dataDir, FILE), JSON.stringify(prefs));
    return prefs;
}

module.exports = {
    DEFAULT_SHORTCUT: DEFAULT_SHORTCUT,
    defaults: defaults,
    validAccelerator: validAccelerator,
    load: load,
    save: save
};
