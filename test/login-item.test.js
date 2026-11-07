"use strict";

const {test} = require("node:test"), assert = require("node:assert/strict");

const fs = require("node:fs"), os = require("node:os"), path = require("node:path");

const login = require("../login-item");

function home(t) {
    const d = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "vaultos-login-"));
    t.after(() => fs.rmSync(d, { recursive: true, force: true }));
    return d;
}

test("macOS login item is a per-user LaunchAgent that starts hidden, and is removed when off", t => {
    const h = home(t), opts = { platform: "darwin", home: h, dataDir: "/tmp/synthetic data & <dir>" };
    const file = path.join(h, "Library", "LaunchAgents", "org.vaultos.preview.desktop.plist");
    login.setEnabled(true, [ "/Applications/VaultOS.app/Contents/MacOS/VaultOS", "--hidden" ], opts);
    const plist = fs.readFileSync(file, "utf8");
    assert.match(plist, /<string>\/Applications\/VaultOS.app\/Contents\/MacOS\/VaultOS<\/string><string>--hidden<\/string>/);
    assert.match(plist, /synthetic data &amp; &lt;dir&gt;/);
    assert.match(plist, /<key>RunAtLoad<\/key><true\/>/);
    login.setEnabled(false, null, opts);
    assert.equal(fs.existsSync(file), false);
    login.setEnabled(false, null, opts);
});

test("Linux autostart entry quotes its command", t => {
    const h = home(t), opts = { platform: "linux", home: h, env: {} };
    login.setEnabled(true, [ "/opt/Vault OS/vaultos", "--hidden" ], opts);
    const entry = fs.readFileSync(path.join(h, ".config", "autostart", "org.vaultos.preview.desktop.desktop"), "utf8");
    assert.match(entry, /^Exec="\/opt\/Vault OS\/vaultos" "--hidden"$/m);
});

test("turning it off removes only the item that starts this data directory", t => {
    const h = home(t), cmd = [ "/Applications/VaultOS.app/Contents/MacOS/VaultOS", "--hidden" ];
    const file = login.itemPath({ platform: "darwin", home: h });
    login.setEnabled(true, cmd, { platform: "darwin", home: h });
    login.setEnabled(false, null, { platform: "darwin", home: h, dataDir: "/tmp/synthetic-test-vault" });
    assert.equal(fs.existsSync(file), true, "a test vault leaves the default vault's item alone");
    login.setEnabled(false, null, { platform: "darwin", home: h });
    assert.equal(fs.existsSync(file), false);
    const lh = home(t), lopts = { platform: "linux", home: lh, env: {}, dataDir: "/tmp/synthetic-a" };
    login.setEnabled(true, cmd, lopts);
    login.setEnabled(false, null, { ...lopts, dataDir: null });
    assert.equal(fs.existsSync(login.itemPath(lopts)), true);
    login.setEnabled(false, null, lopts);
    assert.equal(fs.existsSync(login.itemPath(lopts)), false);
});

test("a data directory with a line break cannot splice the entry", t => {
    const h = home(t);
    for (const dataDir of [ "/tmp/a\nExec=evil", "relative/dir", "/tmp/a\0b" ]) {
        assert.throws(() => login.setEnabled(true, [ "/opt/vaultos" ], { platform: "linux", home: h, env: {}, dataDir }), /Invalid data directory/);
    }
});

test("rejects commands with control characters and refuses to follow a symlink", t => {
    const h = home(t), opts = { platform: "darwin", home: h };
    assert.throws(() => login.setEnabled(true, [ "/bin/app\n<evil>" ], opts), /Invalid login command/);
    const file = login.itemPath(opts);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.symlinkSync(path.join(h, "elsewhere"), file);
    assert.throws(() => login.setEnabled(true, [ "/bin/app" ], opts), /symbolic link/);
});
