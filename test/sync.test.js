"use strict";

const {test: test} = require("node:test"), assert = require("node:assert/strict");

const fs = require("node:fs"), os = require("node:os"), path = require("node:path");

const {Store: Store} = require("../store"), {Sync: Sync, findTool: findTool, pruneBackups: pruneBackups} = require("../sync");

function make(t) {
    const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "vaultos-sync-test-"));
    t.after(() => fs.rmSync(dir, {
        recursive: true,
        force: true
    }));
    const a = new Store(path.join(dir, "a")), b = new Store(path.join(dir, "b"));
    a.init("synthetic-password-a");
    b.init("synthetic-password-b");
    const repo = path.join(dir, "repo"), sa = new Sync(a, repo), sb = new Sync(b, repo);
    const ia = sa.init("Machine A"), ib = sb.init("Machine B");
    sa.trustMachine(ib);
    sb.trustMachine(ia);
    return {
        a: a,
        b: b,
        sa: sa,
        sb: sb,
        repo: repo,
        dir: dir
    };
}

test("sync merges synthetic records and propagates a deletion without disclosing values", t => {
    const {a: a, b: b, sa: sa, sb: sb} = make(t);
    a.createProject("Example");
    a.setSecret("Example", {
        key: "API_KEY",
        value: "synthetic-sync-private"
    });
    sa.push();
    sb.pull();
    assert.equal(b.revealSecret("Example", "API_KEY").value, "synthetic-sync-private");
    b.setSecret("Example", {
        key: "SECOND",
        value: "b"
    });
    sb.push();
    sa.pull();
    assert.equal(a.revealSecret("Example", "SECOND").value, "b");
    a.deleteSecret("Example", "SECOND");
    sa.push();
    sb.pull();
    assert(!b.listSecrets("Example").some(x => x.key === "SECOND"));
});

test("a pull decrypts only ciphertext it has not already read, and forgets it on lock", t => {
    const {a: a, b: b, sa: sa, sb: sb} = make(t);
    a.createProject("Example");
    for (const key of [ "ONE", "TWO", "THREE" ]) a.setSecret("Example", {
        key: key,
        value: `synthetic-${key}`
    });
    sa.push();
    let calls = 0;
    const age = sb.age.bind(sb);
    sb.age = (...args) => {
        if (args[0][0] === "-d") calls++;
        return age(...args);
    };
    sb.pull();
    assert.equal(calls, 3);
    calls = 0;
    sb.pull();
    assert.equal(calls, 0);
    a.setSecret("Example", {
        key: "TWO",
        value: "synthetic-changed"
    });
    sa.push();
    sb.pull();
    assert.equal(calls, 1);
    assert.equal(b.revealSecret("Example", "TWO").value, "synthetic-changed");
    // A remembered payload is a copy: changing the merged record locally does not alter it.
    b.setSecret("Example", {
        key: "ONE",
        value: "synthetic-local-edit"
    });
    calls = 0;
    const plan = sb.pull({
        apply: false
    });
    assert.equal(calls, 0);
    assert.equal(plan.updated.length + plan.added.length + plan.conflicts.length, 0);
    assert.equal(b.revealSecret("Example", "ONE").value, "synthetic-local-edit");
    b.lock();
    b.unlock("synthetic-password-b");
    calls = 0;
    sb.pull({
        apply: false
    });
    assert.equal(calls, 3);
});

test("sync rejects recipient injection, signing key substitution, tampered ciphertext and replay", t => {
    const {a: a, sa: sa, repo: repo} = make(t);
    a.createProject("Example");
    a.setSecret("Example", {
        key: "API_KEY",
        value: "synthetic-only"
    });
    sa.push();
    const recipients = fs.readFileSync(sa.recipientsPath, "utf8");
    fs.appendFileSync(sa.recipientsPath, "age1unapproved\n");
    assert.throws(() => sa.encryptTo({
        test: true
    }), /Unapproved/);
    fs.writeFileSync(sa.recipientsPath, recipients);
    const mf = path.join(repo, "manifests", sa.machineId() + ".json"), original = fs.readFileSync(mf);
    const m = JSON.parse(original);
    m.manifest.counter++;
    fs.writeFileSync(mf, JSON.stringify(m));
    assert(sa.verifyManifests().problems.includes("BAD SIGNATURE"));
    fs.writeFileSync(mf, original);
    const file = path.join(repo, "records", fs.readdirSync(path.join(repo, "records"))[0]), bytes = fs.readFileSync(file);
    fs.appendFileSync(file, "bad");
    assert(sa.verifyManifests().problems.some(x => x.includes("ciphertext")));
    fs.writeFileSync(file, bytes);
    sa.push();
    sa.verifyManifests();
    fs.writeFileSync(mf, original);
    assert(sa.verifyManifests().problems.some(x => x.includes("ROLLBACK")));
});

test("sync refuses concurrent edits until explicitly accepted and preserves a backup", t => {
    const {a: a, b: b, sa: sa, sb: sb} = make(t);
    a.createProject("Example");
    a.setSecret("Example", {
        key: "KEY",
        value: "base"
    });
    sa.push();
    sb.pull();
    a.setSecret("Example", {
        key: "KEY",
        value: "left"
    });
    b.setSecret("Example", {
        key: "KEY",
        value: "right"
    });
    b.setSecret("Example", {
        key: "KEY",
        value: "right-again"
    });
    sb.push();
    assert.throws(() => sa.pull(), /Concurrent/);
    sa.pull({
        acceptConflicts: true
    });
    assert.equal(a.revealSecret("Example", "KEY").value, "right-again");
    assert(fs.readdirSync(path.join(a.dataDir, "backups")).length > 0);
});

test("an edit made on one device reaches the other as an update, not a conflict", t => {
    const {a: a, b: b, sa: sa, sb: sb} = make(t);
    a.createProject("Example");
    a.setSecret("Example", {
        key: "KEY",
        value: "base"
    });
    sa.push();
    sb.pull();
    // Edit on A only: B has not touched the record since its last sync.
    a.setSecret("Example", {
        key: "KEY",
        value: "edited-on-a"
    });
    sa.push();
    const plan = sb.pull();
    assert.equal(plan.conflicts.length, 0);
    assert.equal(b.revealSecret("Example", "KEY").value, "edited-on-a");
    // And back the other way, created and edited on B.
    b.setSecret("Example", {
        key: "FROM_B",
        value: "one"
    });
    sb.push();
    sa.pull();
    b.setSecret("Example", {
        key: "FROM_B",
        value: "two"
    });
    sb.push();
    assert.equal(sa.pull().conflicts.length, 0);
    assert.equal(a.revealSecret("Example", "FROM_B").value, "two");
    // A local edit with an unchanged remote stays local until the next push.
    a.setSecret("Example", {
        key: "KEY",
        value: "local-only"
    });
    assert.equal(sa.pull().conflicts.length, 0);
    assert.equal(a.revealSecret("Example", "KEY").value, "local-only");
});

test("a pull that keeps a local edit leaves it for the next push instead of stranding it", t => {
    const {a: a, b: b, sa: sa, sb: sb} = make(t);
    a.createProject("Example");
    a.setSecret("Example", {
        key: "KEY",
        value: "base"
    });
    sa.push();
    sb.pull();
    a.setSecret("Example", {
        key: "KEY",
        value: "edited-on-a"
    });
    sa.push();
    b.setSecret("Example", {
        key: "KEY",
        value: "edited-on-b"
    });
    b.setSecret("Example", {
        key: "KEY",
        value: "edited-on-b-again"
    });
    const plan = sb.pull({
        acceptConflicts: true
    });
    assert.equal(plan.conflicts[0].resolution, "local");
    assert.equal(b.revealSecret("Example", "KEY").value, "edited-on-b-again");
    assert.equal(sb.status().outgoing, 1, "the kept local edit must count as not yet pushed");
    assert.equal(sb.push().written, 1, "the kept local edit must be written by the next push");
    sa.pull({
        acceptConflicts: true
    });
    assert.equal(a.revealSecret("Example", "KEY").value, "edited-on-b-again");
    assert.equal(a.contentFingerprint(), b.contentFingerprint());
    assert.equal(sb.push().written, 0, "records that match the repository are not rewritten");
});

test("a push index that marks unpushed edits as published is repaired by the next pull", t => {
    const {a: a, b: b, sa: sa, sb: sb} = make(t);
    a.createProject("Example");
    a.setSecret("Example", {
        key: "KEY",
        value: "base"
    });
    sa.push();
    sb.pull();
    b.setSecret("Example", {
        key: "KEY",
        value: "stranded-edit"
    });
    const idx = sb.readIndex();
    for (const [ref, e] of sb.localRecords()) idx.records[ref] = e.hash;
    sb.writeIndex(idx);
    assert.equal(sb.push().written, 0);
    sb.pull({
        acceptConflicts: true
    });
    assert.equal(sb.push().written, 1);
    sa.pull({
        acceptConflicts: true
    });
    assert.equal(a.revealSecret("Example", "KEY").value, "stranded-edit");
});

test("conflicts with equal revision and timestamp resolve to the same winner on both devices", t => {
    const {a: a, b: b, sa: sa, sb: sb} = make(t);
    a.createProject("Example");
    a.setSecret("Example", {
        key: "KEY",
        value: "base"
    });
    sa.push();
    sb.pull();
    const stamp = (new Date).toISOString();
    for (const [store, value] of [ [ a, "tie-a" ], [ b, "tie-b" ] ]) {
        store.setSecret("Example", {
            key: "KEY",
            value: value
        });
        store.findSecret(store.findProject("Example"), "KEY").updatedAt = stamp;
        store.persist();
    }
    sa.push();
    const planB = sb.pull({
        acceptConflicts: true
    });
    sb.push();
    sa.pull({
        acceptConflicts: true
    });
    assert.equal(planB.conflicts.length, 1);
    assert.equal(a.contentFingerprint(), b.contentFingerprint(), "both devices must keep the same version");
    assert([ "tie-a", "tie-b" ].includes(a.revealSecret("Example", "KEY").value));
});

test("new approved recipients receive re-encrypted existing records", t => {
    const {a: a, sa: sa, sb: sb, repo: repo, dir: dir} = make(t);
    a.createProject("Example");
    a.setSecret("Example", {
        key: "K",
        value: "existing-synthetic"
    });
    sa.push();
    sb.pull();
    const c = new Store(path.join(dir, "c"));
    c.init("synthetic-password-c");
    const sc = new Sync(c, repo), ic = sc.init("Machine C");
    sc.trustMachine(sa.identity());
    sc.trustMachine(sb.identity());
    sa.trustMachine(ic);
    const result = sa.push();
    assert(result.reencryptedForNewRecipients);
    sc.pull();
    assert.equal(c.revealSecret("Example", "K").value, "existing-synthetic");
});

test("Git transport verifies a real remote receipt and refuses unrelated changes", async t => {
    const {a: a, sa: sa, repo: repo, dir: dir} = make(t), {execFileSync: execFileSync} = require("node:child_process");
    const git = (...args) => execFileSync("git", args, {
        stdio: "pipe",
        env: {
            ...process.env,
            GIT_CONFIG_NOSYSTEM: "1"
        }
    });
    const remote = path.join(dir, "remote.git");
    git("init", "--bare", "--initial-branch=main", remote);
    git("-C", repo, "init", "-b", "main");
    git("-C", repo, "config", "user.name", "Synthetic Test");
    git("-C", repo, "config", "user.email", "test@example.invalid");
    git("-C", repo, "remote", "add", "origin", remote);
    a.createProject("Example");
    a.setSecret("Example", {
        key: "K",
        value: "transport-synthetic"
    });
    const result = await sa.pushRemote();
    assert(result.delivered, JSON.stringify(result));
    assert.equal(result.remoteCommit, result.sourceCommit);
    // A file only this checkout has is left alone: not published, not deleted, not a reason to stop.
    fs.writeFileSync(path.join(repo, "unrelated.txt"), "must not publish");
    assert((await sa.pushRemote()).delivered);
    // Once it is given to Git, it is a change to the sync repository that sync did not make.
    git("-C", repo, "add", "unrelated.txt");
    await assert.rejects(sa.pushRemote(), /unrelated changes; refusing to commit: "unrelated\.txt"/);
    assert(!git("--git-dir", remote, "ls-tree", "--name-only", "HEAD").toString().includes("unrelated"));
    assert(fs.existsSync(path.join(repo, "unrelated.txt")));
});

test("CLI sync pull prints why it stopped, and keeps file errors generic", async t => {
    const {a: a, repo: repo, dir: dir} = make(t), {execFileSync: execFileSync, execFile: execFile} = require("node:child_process");
    const git = (...args) => execFileSync("git", args, {
        stdio: "pipe",
        env: {
            ...process.env,
            GIT_CONFIG_NOSYSTEM: "1"
        }
    });
    git("-C", repo, "init", "-b", "main");
    git("-C", repo, "remote", "add", "origin", path.join(dir, "unreachable.git"));
    a.createProject("Example");
    a.setSecret("Example", {
        key: "API_KEY",
        value: "synthetic-cli-private"
    });
    a.lock();
    const cli = (...args) => new Promise(resolve => {
        const child = execFile(process.execPath, [ path.resolve("cli.cjs"), ...args, "--password-stdin" ], {
            env: {
                PATH: process.env.PATH,
                HOME: dir,
                GIT_CONFIG_NOSYSTEM: "1",
                VAULTOS_DATA_DIR: a.dataDir,
                VAULTOS_SYNC_REPO: repo
            },
            timeout: 6e4
        }, (error, stdout, stderr) => resolve({
            code: error ? error.code : 0,
            output: stdout + stderr
        }));
        // A CLI that refuses before it reads stdin exits and closes it; the write then fails with EPIPE.
        child.stdin.on("error", () => {});
        child.stdin.end("synthetic-password-a\n");
    });
    const pulled = await cli("sync", "pull");
    assert.equal(pulled.code, 1);
    assert.match(pulled.output, /cannot update the sync repo: .*unreachable\.git/);
    assert(!pulled.output.includes("synthetic-cli-private"));
    const missing = path.join(dir, "missing-peer.json");
    const trusted = await cli("sync", "trust", missing);
    assert.equal(trusted.code, 1);
    assert.match(trusted.output, /File operation failed; check permissions and paths/);
    assert(!trusted.output.includes(missing), "file errors do not print paths");
});

test("a slow remote leaves the process responsive, and overlapping remote rounds run one at a time", async t => {
    const {a: a, sa: sa, repo: repo, dir: dir} = make(t), {execFileSync: execFileSync} = require("node:child_process");
    const git = (...args) => execFileSync("git", args, {
        stdio: "pipe"
    });
    const remote = path.join(dir, "remote.git"), slow = path.join(dir, "slow-ssh");
    // A stand-in for SSH that takes 300 ms to connect, then runs git's command locally.
    fs.writeFileSync(slow, '#!/bin/sh\nsleep 0.3\nshift\nexec sh -c "$1"\n', {
        mode: 448
    });
    const saved = [ process.env.GIT_SSH_COMMAND, process.env.GIT_SSH_VARIANT ];
    process.env.GIT_SSH_COMMAND = slow;
    process.env.GIT_SSH_VARIANT = "simple";
    t.after(() => {
        for (const [i, name] of [ "GIT_SSH_COMMAND", "GIT_SSH_VARIANT" ].entries()) if (saved[i] === undefined) delete process.env[name]; else process.env[name] = saved[i];
    });
    git("init", "--bare", "--initial-branch=main", remote);
    git("-C", repo, "init", "-b", "main");
    git("-C", repo, "config", "user.name", "Synthetic Test");
    git("-C", repo, "config", "user.email", "test@example.invalid");
    git("-C", repo, "remote", "add", "origin", `slowhost:${remote}`);
    a.createProject("Example");
    a.setSecret("Example", {
        key: "K",
        value: "slow-remote-synthetic"
    });
    const other = new Sync(a, repo);
    let active = 0, most = 0, ticks = 0;
    for (const s of [ sa, other ]) {
        const push = s.git.push.bind(s.git);
        s.git.push = async () => {
            most = Math.max(most, ++active);
            try {
                return await push();
            } finally {
                active--;
            }
        };
    }
    const timer = setInterval(() => ticks++, 20);
    const results = await Promise.all([ sa.pushRemote(), other.pushRemote() ]);
    clearInterval(timer);
    for (const r of results) assert(r.delivered, JSON.stringify(r));
    assert.equal(most, 1);
    assert(ticks >= 10, `event loop ticked ${ticks} times during the slow pushes`);
});

test("SSH connection reuse uses a private socket directory and yields to the user's own SSH setup", {
    skip: process.platform === "win32"
}, async t => {
    const {repo: repo} = make(t), {execFileSync: execFileSync} = require("node:child_process"), {sshReuseEnv: sshReuseEnv} = require("../git");
    const git = (...args) => execFileSync("git", [ "-C", repo, ...args ], {
        stdio: "pipe"
    });
    const saved = process.env.GIT_SSH_COMMAND;
    delete process.env.GIT_SSH_COMMAND;
    t.after(() => {
        if (saved !== undefined) process.env.GIT_SSH_COMMAND = saved;
    });
    git("init", "-b", "main");
    git("remote", "add", "origin", "git@example.invalid:synthetic/vault.git");
    const env = await sshReuseEnv(repo, "origin");
    const socket = /ControlPath=(\S+)$/.exec(env.GIT_SSH_COMMAND || "")?.[1];
    assert(socket, JSON.stringify(env));
    const st = fs.statSync(path.dirname(socket));
    assert.equal(st.mode & 511, 448);
    assert.equal(st.uid, process.getuid());
    assert.match(env.GIT_SSH_COMMAND, /ControlMaster=auto/);
    git("config", "core.sshCommand", "ssh -i /synthetic/key");
    assert.deepEqual(await sshReuseEnv(repo, "origin"), {});
    git("config", "--unset", "core.sshCommand");
    process.env.GIT_SSH_COMMAND = "ssh -v";
    assert.deepEqual(await sshReuseEnv(repo, "origin"), {});
});

test("sync finds age where installers put it when PATH lacks it (the Dock's PATH on macOS)", {
    skip: process.platform === "win32"
}, t => {
    const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "vaultos-findtool-test-"));
    t.after(() => fs.rmSync(dir, {
        recursive: true,
        force: true
    }));
    // "system" stands in for launchd's /usr/bin:/bin:/usr/sbin:/sbin, which has no age on a Mac
    // (the real /usr/bin may have one, as on CI runners).
    const bin = path.join(dir, "bin"), system = path.join(dir, "system"), age = path.join(bin, "age");
    fs.mkdirSync(bin);
    fs.mkdirSync(system);
    fs.writeFileSync(age, "#!/bin/sh\n", {
        mode: 493
    });
    fs.writeFileSync(path.join(bin, "not-executable"), "", {
        mode: 420
    });
    assert.equal(findTool("age", {
        pathEnv: system,
        extraDirs: [ bin ]
    }), age);
    assert.equal(findTool("age", {
        pathEnv: bin,
        extraDirs: []
    }), age);
    // Not found anywhere, or not executable: the bare name, so the usual "not installed" error follows.
    assert.equal(findTool("age", {
        pathEnv: "",
        extraDirs: []
    }), "age");
    assert.equal(findTool("not-executable", {
        pathEnv: "",
        extraDirs: [ bin ]
    }), "not-executable");
});

test("pull backups keep the newest 20 and the last 30 days, and leave other files alone", t => {
    const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "vaultos-backups-"));
    t.after(() => fs.rmSync(dir, {
        recursive: true,
        force: true
    }));
    const now = Date.UTC(2026, 0, 31), day = 864e5;
    const name = (ms, i) => `${ms}-${i.toString(16).padStart(16, "0")}.enc`;
    for (let i = 0; i < 25; i++) fs.writeFileSync(path.join(dir, name(now - (40 + i) * day, i)), "synthetic");
    for (let i = 0; i < 5; i++) fs.writeFileSync(path.join(dir, name(now - i * day, 100 + i)), "synthetic");
    fs.writeFileSync(path.join(dir, "vault-2025-01-01.enc"), "synthetic");
    pruneBackups(dir, now);
    const left = fs.readdirSync(dir);
    assert.equal(left.length, 21);
    assert(left.includes("vault-2025-01-01.enc"));
    for (let i = 0; i < 5; i++) assert(left.includes(name(now - i * day, 100 + i)));
    for (let i = 0; i < 15; i++) assert(left.includes(name(now - (40 + i) * day, i)));
});

test("a sync format 2 repository (VaultOS 0.3) is refused without writing to it", t => {
    const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "vaultos-sync-test-"));
    t.after(() => fs.rmSync(dir, {
        recursive: true,
        force: true
    }));
    const store = new Store(path.join(dir, "a"));
    store.init("synthetic-password-a");
    const repo = path.join(dir, "repo");
    fs.mkdirSync(repo);
    fs.writeFileSync(path.join(repo, "vaultos-sync.json"), JSON.stringify({
        app: "VaultOS-Preview",
        version: 2
    }));
    assert.throws(() => new Sync(store, repo).init("Machine A"), /made by a newer VaultOS/);
    assert.deepEqual(fs.readdirSync(repo), [ "vaultos-sync.json" ]);
});
