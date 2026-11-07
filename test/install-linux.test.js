"use strict";

const {test} = require("node:test"), assert = require("node:assert/strict");

const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), {spawnSync} = require("node:child_process");

const script = path.resolve(__dirname, "..", "scripts", "install-linux.sh");
const PROGRAMS = [ "vaultos-preview", "vaultos", "vaultos-agent", "vaultos-mcp", "vaultosd", "vaultos-ssh-sign" ];

// On macOS, a stand-in for Linux's uname lets the installer's logic run in CI there too.
const DARWIN_UNAME = `#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) /usr/bin/uname "$@" ;; esac\n`;

function fixture(t) {
    const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "vaultos-install-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const shims = path.join(dir, "shims"), log = path.join(dir, "log");
    fs.mkdirSync(shims);
    fs.mkdirSync(log);
    const write = (file, body) => fs.writeFileSync(file, body, { mode: 0o700 });
    if (process.platform === "darwin") write(path.join(shims, "uname"), DARWIN_UNAME);
    write(path.join(shims, "systemctl"), `#!/bin/sh\necho "$*" >> "${log}/systemctl"\n`);
    write(path.join(shims, "sudo"), `#!/bin/sh\necho "$*" >> "${log}/sudo"\n`);
    const arch = process.platform === "darwin" || process.arch !== "arm64" ? "x64" : "arm64";
    const build = path.join(dir, "build", `vaultos-preview-linux-${arch}`);
    fs.mkdirSync(build, { recursive: true });
    for (const program of PROGRAMS) write(path.join(build, program), `#!/bin/sh\necho "${program} $*" > "${log}/launched"\n`);
    fs.writeFileSync(path.join(build, "vaultos-preview.png"), "synthetic");
    const env = {
        HOME: path.join(dir, "home"),
        XDG_DATA_HOME: path.join(dir, "data-home"),
        XDG_CONFIG_HOME: path.join(dir, "config-home"),
        PATH: [ shims, "/usr/bin", "/bin", "/usr/sbin", "/sbin" ].join(path.delimiter)
    };
    fs.mkdirSync(env.HOME);
    const run = (...args) => spawnSync("bash", [ script, "--from", build, ...args ], { env, encoding: "utf8" });
    return { dir, log, env, run, build, prefix: path.join(dir, "home", ".local", "opt", "vaultos-preview") };
}

test("Linux installer writes the app, tools and desktop entry without root or a service", {
    skip: process.platform === "win32"
}, t => {
    const {log, env, run, prefix} = fixture(t);
    for (let i = 0; i < 2; i++) {
        const r = run();
        assert.equal(r.status, 0, r.stderr);
        assert.match(r.stdout, /service\s+not installed/);
    }
    for (const program of PROGRAMS) assert(fs.statSync(path.join(prefix, program)).mode & 0o100, program);
    const desktop = fs.readFileSync(path.join(env.XDG_DATA_HOME, "applications", "org.vaultos.preview.desktop"), "utf8");
    assert(desktop.includes(`Exec="${prefix}/vaultos-preview"`));
    assert(desktop.includes(`Icon=${prefix}/vaultos-preview.png`));
    assert(!fs.existsSync(path.join(env.XDG_CONFIG_HOME, "systemd")));
    assert(!fs.existsSync(path.join(log, "systemctl")));
    assert(!fs.existsSync(path.join(log, "sudo")));
    assert(!fs.existsSync(path.join(log, "launched")), "installing runs none of the programs");
    assert.deepEqual(fs.readdirSync(path.dirname(prefix)), [ "vaultos-preview" ]);
});

test("Linux installer refuses an incomplete build and a folder that is not a VaultOS install", {
    skip: process.platform === "win32"
}, t => {
    const {dir, run, build, prefix} = fixture(t);
    const other = path.join(dir, "other");
    fs.mkdirSync(other);
    fs.writeFileSync(path.join(other, "keep.txt"), "synthetic");
    const r = run("--prefix", other);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /not a VaultOS install/);
    assert.deepEqual(fs.readdirSync(other), [ "keep.txt" ]);
    assert.notEqual(run("--prefix", "relative/path").status, 0);
    fs.rmSync(path.join(build, "vaultosd"));
    const missing = run();
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /vaultosd is missing/);
    assert(!fs.existsSync(prefix));
});

test("Linux installer verifies an archive checksum before installing it", {
    skip: process.platform === "win32"
}, t => {
    const {dir, env, prefix} = fixture(t);
    const build = path.join(dir, "build"), archive = path.join(dir, "vaultos-linux.tar.gz");
    const [folder] = fs.readdirSync(build);
    assert.equal(spawnSync("tar", [ "-czf", archive, "-C", build, folder ]).status, 0);
    const install = () => spawnSync("bash", [ script, "--from", archive ], { env, encoding: "utf8" });
    fs.writeFileSync(archive + ".sha256", "0".repeat(64) + "  vaultos-linux.tar.gz\n");
    assert.notEqual(install().status, 0);
    assert(!fs.existsSync(prefix));
    const digest = require("node:crypto").createHash("sha256").update(fs.readFileSync(archive)).digest("hex");
    fs.writeFileSync(archive + ".sha256", digest + "  vaultos-linux.tar.gz\n");
    const r = install();
    assert.equal(r.status, 0, r.stderr);
    assert(fs.existsSync(path.join(prefix, "vaultosd")));
});

test("Linux installer writes and enables the background unit only with --enable-service", {
    skip: process.platform === "win32"
}, t => {
    const {log, env, run, prefix} = fixture(t);
    const r = run("--enable-service");
    assert.equal(r.status, 0, r.stderr);
    const unit = fs.readFileSync(path.join(env.XDG_CONFIG_HOME, "systemd", "user", "vaultos-preview-backend.service"), "utf8");
    assert(unit.includes(`ExecStart="${prefix}/vaultos-preview" --service`));
    assert(!/@[A-Z]+@/.test(unit));
    assert.equal(fs.readFileSync(path.join(log, "systemctl"), "utf8"), "--user daemon-reload\n--user enable --now vaultos-preview-backend.service\n");
});
