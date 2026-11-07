"use strict";

const {test} = require("node:test"), assert = require("node:assert/strict");

const fs = require("node:fs"), os = require("node:os"), path = require("node:path");

const prefs = require("../desktop-prefs");

function dir(t) {
    const d = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "vaultos-prefs-"));
    t.after(() => fs.rmSync(d, { recursive: true, force: true }));
    return d;
}

test("defaults keep the menu bar on macOS only and enable the Quick Access shortcut", () => {
    assert.equal(prefs.defaults("darwin").menuBar, true);
    assert.equal(prefs.defaults("linux").menuBar, false);
    assert.equal(prefs.defaults("darwin").shortcut, "Shift+CommandOrControl+Space");
    assert.equal(prefs.defaults("darwin").notifyApprovals, false);
});

test("accelerators need a modifier and one key, except function keys", () => {
    for (const ok of [ "", "Shift+CommandOrControl+Space", "Alt+Cmd+K", "F13", "Control+Option+P", "CmdOrCtrl+Shift+/" ]) assert.equal(prefs.validAccelerator(ok), true, ok);
    for (const bad of [ "Space", "K", "Shift+Shift+K", "Hyper+K", "Cmd+", "Cmd+KK", "Cmd+K+L", 42, null, "Cmd+".padEnd(80, "K") ]) assert.equal(prefs.validAccelerator(bad), false, String(bad));
});

test("saved preferences round-trip privately and ignore a damaged file", t => {
    const d = dir(t);
    assert.deepEqual(prefs.load(d, "darwin"), prefs.defaults("darwin"));
    prefs.save(d, { shortcut: "Alt+Cmd+K", notifyApprovals: true }, "darwin");
    const loaded = prefs.load(d, "darwin");
    assert.equal(loaded.shortcut, "Alt+Cmd+K");
    assert.equal(loaded.notifyApprovals, true);
    assert.equal(loaded.menuBar, true);
    assert.equal(fs.statSync(path.join(d, "desktop-prefs.json")).mode & 0o777, 0o600);
    fs.writeFileSync(path.join(d, "desktop-prefs.json"), "{not json");
    assert.deepEqual(prefs.load(d, "darwin"), prefs.defaults("darwin"));
    fs.writeFileSync(path.join(d, "desktop-prefs.json"), JSON.stringify({ shortcut: "K", menuBar: "yes", launchAtLogin: true }));
    const partial = prefs.load(d, "darwin");
    assert.equal(partial.shortcut, prefs.DEFAULT_SHORTCUT);
    assert.equal(partial.menuBar, true);
    assert.equal(partial.launchAtLogin, true);
});

test("saving rejects unknown keys, wrong types and invalid shortcuts", t => {
    const d = dir(t);
    assert.throws(() => prefs.save(d, { theme: "dark" }), /Unknown desktop preference/);
    assert.throws(() => prefs.save(d, { menuBar: "on" }), /Invalid menuBar/);
    assert.throws(() => prefs.save(d, { shortcut: "Space" }), /modifier/);
    assert.throws(() => prefs.save(d, [ ]), /Invalid desktop preferences/);
    assert.equal(fs.existsSync(path.join(d, "desktop-prefs.json")), false);
});
