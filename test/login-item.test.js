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

test("rejects commands with control characters and refuses to follow a symlink", t => {
    const h = home(t), opts = { platform: "darwin", home: h };
    assert.throws(() => login.setEnabled(true, [ "/bin/app\n<evil>" ], opts), /Invalid login command/);
    const file = login.itemPath(opts);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.symlinkSync(path.join(h, "elsewhere"), file);
    assert.throws(() => login.setEnabled(true, [ "/bin/app" ], opts), /symbolic link/);
});
