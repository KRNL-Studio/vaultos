"use strict";

const fs = require("node:fs");

const path = require("node:path");

const {execFileSync: execFileSync} = require("node:child_process");

const crypto = require("node:crypto");

const {contentHash: contentHash, canonicalJson: canonicalJson, newSigningKey: newSigningKey, sign: sign, verify: verify, publicKeyOf: publicKeyOf, randomId: randomId} = require("./crypto");

const M = require("./model");

const {GitRepo: GitRepo} = require("./git");

const {atomicWrite: atomicWrite, regularFile: regularFile} = require("./fs-safe");

const opaque = ref => crypto.createHash("sha256").update(ref, "utf8").digest("hex");

// The files sync writes, by repository path. Anything else in its folders (Finder's .DS_Store,
// an editor's backup, the temporary file of an interrupted atomicWrite) is not sync's: it is
// never signed, decrypted, committed or deleted.
const SYNC_FILE = /^(?:(?:records|tombstones)\/[a-f0-9]{64}\.age|(?:machines|manifests|peers)\/[a-f0-9]{16}\.json|recipients\.txt|vaultos-sync\.json)$/;

const SYNC_DIR = /^(?:records|tombstones|machines|manifests|peers)\//;

const stray = file => SYNC_DIR.test(file) && !SYNC_FILE.test(file);

// Git's own control files. One in the checkout changes what Git commits (a .gitignore can keep
// out a record that this device's manifest signs) or the bytes it stores, so it is never left alone.
const GIT_CONTROL = /(?:^|\/)\.git(?:ignore|attributes|modules)$/;

// The desktop app, opened from the Dock or Finder, gets launchd's PATH (/usr/bin:/bin:/usr/sbin:/sbin),
// not the shell's. age installed with Homebrew or into ~/.local/bin is then invisible to it, sync
// fails with "age is not installed" and halts, while the same vault syncs from a terminal. So a tool
// missing from PATH is also looked for where installers put it.
const TOOL_DIRS = [ path.join(require("node:os").homedir(), ".local", "bin"), "/opt/homebrew/bin", "/usr/local/bin", "/home/linuxbrew/.linuxbrew/bin" ];

function findTool(name, {pathEnv: pathEnv = process.env.PATH || "", extraDirs: extraDirs = TOOL_DIRS} = {}) {
    if (process.platform === "win32") return name;
    for (const dir of [ ...pathEnv.split(path.delimiter).filter(Boolean), ...extraDirs ]) {
        const file = path.join(dir, name);
        try {
            fs.accessSync(file, fs.constants.X_OK);
            if (fs.statSync(file).isFile()) return file;
        } catch {}
    }
    return name;
}

// Verification failed. On one line: an autosync halt and its activity-log entry keep only the first.
const refusal = problems => Object.assign(new Error(`refusing to pull: ${problems.join("; ")}`), {
    state: "SIGNATURE_INVALID",
    status: 409
});

// Remote rounds now wait on the network, so two of them (autosync and a manual sync, say) could
// otherwise overlap in one checkout. Each repository runs one remote operation at a time, in call order.
const remoteQueues = new Map;

// Decrypting a sync file runs an age process, a few milliseconds each, and every pull read every
// record. Plaintext decrypted from byte-identical ciphertext with the same identity is reused
// instead. It is kept per in-memory vault object, so it goes with that object on lock or reload,
// copied in and out so a merge can never change what is remembered, and each pull keeps only the
// entries it used.
const decrypted = new WeakMap;

// A pull that changes the vault first copies vault.enc to backups/<ms>-<id>.enc. The newest
// BACKUPS_KEPT of those, and any younger than BACKUP_DAYS, are kept; other files there are
// never touched.
const PULL_BACKUP = /^(\d+)-[a-f0-9]{16}\.enc$/;

const BACKUPS_KEPT = 20;

const BACKUP_DAYS = 30;

const pruneBackups = (dir, now = Date.now()) => {
    const old = fs.readdirSync(dir).map(name => ({
        name: name,
        ms: Number(PULL_BACKUP.exec(name)?.[1])
    })).filter(b => b.ms).sort((x, y) => y.ms - x.ms).slice(BACKUPS_KEPT).filter(b => now - b.ms > BACKUP_DAYS * 864e5);
    for (const b of old) fs.rmSync(path.join(dir, b.name), {
        force: true
    });
};

function serialized(repo, fn) {
    const next = (remoteQueues.get(repo) || Promise.resolve()).then(() => fn());
    const settled = next.then(() => {}, () => {});
    remoteQueues.set(repo, settled);
    settled.then(() => {
        if (remoteQueues.get(repo) === settled) remoteQueues.delete(repo);
    });
    return next;
}

class Sync {
    constructor(store, repoDir) {
        this.store = store;
        this.repo = repoDir;
        this.dirs = {
            records: path.join(repoDir, "records"),
            tombstones: path.join(repoDir, "tombstones"),
            machines: path.join(repoDir, "machines"),
            manifests: path.join(repoDir, "manifests"),
            peers: path.join(repoDir, "peers")
        };
        this.recipientsPath = path.join(repoDir, "recipients.txt");
        this.identityPath = path.join(store.dataDir, "sync-age.key");
        this.signingKeyPath = path.join(store.dataDir, "sync-signing.key");
        this.machineIdPath = path.join(store.dataDir, "machine-id");
        this.indexPath = path.join(store.dataDir, "sync-index.json");
        this.git = new GitRepo(repoDir);
    }
    // The vault can lock while git waits on the network. Work that reads or changes the vault
    // after such a wait checks first and stops cleanly instead.
    requireUnlocked() {
        if (!this.store.isUnlocked()) throw Object.assign(new Error("Vault is locked"), {
            status: 423,
            state: "PAUSED_LOCKED"
        });
    }
    receipt(extra = {}) {
        const div = this.git.isRepo() ? this.git.divergence() : {
            ok: false
        };
        const unsent = this.git.isRepo() ? this.unsent() : null;
        return {
            sourceFingerprint: this.store.isUnlocked() ? this.store.contentFingerprint() : null,
            manifestCounter: (this.readIndex().lastPush || {}).counter || 0,
            machineId: this.machineId(),
            sourceCommit: this.git.isRepo() ? this.git.head() : null,
            remoteCommit: this.git.isRepo() ? this.git.remoteHead() : null,
            ahead: div.ok ? div.ahead : null,
            behind: div.ok ? div.behind : null,
            uncommitted: unsent ? unsent.length : null,
            ...extra
        };
    }
    // The checkout's changes that matter to a push, or null if Git cannot say: sync's own files,
    // which it commits, and changes it refuses to commit beside. The rest is left alone: a file
    // sync did not write in one of its folders, and any file only this checkout has (Finder's
    // .DS_Store, an editor's swap file), which this account made and nothing reads.
    changes() {
        const changed = this.git.changedPaths(), tracked = this.git.trackedPaths([ "." ]);
        if (!changed.ok || !tracked.ok) return null;
        const alone = f => !GIT_CONTROL.test(f) && (SYNC_DIR.test(f) || !tracked.files.has(f));
        return {
            own: changed.files.filter(f => SYNC_FILE.test(f)),
            stray: changed.files.filter(stray),
            unrelated: changed.files.filter(f => !SYNC_FILE.test(f) && !alone(f))
        };
    }
    // Changed paths that a push still has to commit or that stop it, or null if Git cannot say.
    unsent() {
        const changes = this.changes();
        return changes ? [ ...changes.own, ...changes.unrelated ] : null;
    }
    // The names in records/ or tombstones/ that sync writes and reads.
    syncFiles(dir) {
        return fs.existsSync(this.dirs[dir]) ? fs.readdirSync(this.dirs[dir]).filter(f => SYNC_FILE.test(`${dir}/${f}`)) : [];
    }
    pushRemote({message: message} = {}) {
        return serialized(this.repo, () => this.pushRemoteNow({
            message: message
        }));
    }
    async pushRemoteNow({message: message}) {
        const wrote = this.push();
        if (!this.git.isRepo()) {
            return {
                ...wrote,
                transport: "none",
                delivered: false,
                warning: `${this.repo} is not a git repo, so nothing left this machine`,
                receipt: this.receipt()
            };
        }
        const msg = message || `vault sync: ${wrote.written} record(s) from ${this.machineId()}`;
        const changes = this.changes();
        if (!changes) throw new Error("Cannot list the sync repository's changes; refusing to commit");
        if (changes.unrelated.length) throw new Error(`Sync repository contains unrelated changes; refusing to commit: ${changes.unrelated.slice(0, 3).map(f => JSON.stringify(f)).join(", ")}`);
        // An ignore rule outside the checkout (.git/info/exclude, a global excludes file) hides a
        // file sync wrote from `git status`. Committed without it, this device's manifest would
        // sign a file no peer receives, and every peer would refuse the repository.
        const ignored = this.git.ignoredPaths([ "records", "tombstones", "machines", "manifests", "peers", "recipients.txt", "vaultos-sync.json" ]);
        if (!ignored.ok) throw new Error(`cannot list the sync repository's files: ${ignored.error}`);
        const hidden = ignored.files.filter(f => SYNC_FILE.test(f));
        if (hidden.length) throw new Error(`Git ignores files sync wrote; refusing to commit: ${hidden.slice(0, 3).map(f => JSON.stringify(f)).join(", ")}`);
        // Sync's own files by name, never whole folders: `git add records` also published a
        // .DS_Store, which every peer then refused as unsigned ciphertext. A stray file Git
        // already tracks (committed by an older version or by hand, or removed with `git rm`)
        // is taken out of the repository instead; the local copy stays, untracked and ignored.
        // Verification has already refused any that arrived in a folder it checks.
        const tracked = this.git.trackedPaths([ "records", "tombstones", "machines", "manifests", "peers" ]);
        if (!tracked.ok) throw new Error(`cannot list the sync repository's files: ${tracked.error}`);
        const untrack = [ ...new Set([ ...changes.stray, ...tracked.files ]) ].filter(stray);
        const commit = this.git.commitPaths(changes.own.filter(f => !f.startsWith("peers/")), msg, {
            untrack: untrack
        });
        this.publishHeartbeat();
        const heartbeatCommit = this.git.commitPaths([ `peers/${this.machineId()}.json` ], `heartbeat: ${this.machineId()}`);
        // The next round commits whatever a failed commit left (commitLeftovers), so a failed
        // commit is worth retrying rather than a reason to stop.
        const failed = !commit.ok ? commit.error : !heartbeatCommit.ok ? `could not commit the sync receipt: ${heartbeatCommit.error}` : null;
        if (failed) {
            return {
                ...wrote,
                transport: "commit-failed",
                code: "COMMIT_FAILED",
                delivered: false,
                error: failed,
                receipt: this.receipt()
            };
        }
        const pushed = await this.git.push();
        if (!pushed.ok) {
            return {
                ...wrote,
                transport: "push-failed",
                delivered: false,
                code: pushed.code,
                error: pushed.error,
                committed: commit.committed,
                sourceCommit: commit.sha,
                receipt: this.receipt()
            };
        }
        const finalSha = this.git.head();
        return {
            ...wrote,
            transport: "ok",
            delivered: true,
            committed: commit.committed,
            sourceCommit: finalSha,
            remoteCommit: pushed.remoteSha,
            rebased: finalSha !== commit.sha,
            receipt: this.receipt({
                sourceCommit: finalSha,
                remoteCommit: pushed.remoteSha
            })
        };
    }
    pullRemote(options = {}) {
        return serialized(this.repo, () => this.pullRemoteNow(options));
    }
    async pullRemoteNow(options) {
        if (!this.git.isRepo()) {
            const merged = this.pull(options);
            return {
                ...merged,
                transport: "none",
                warning: `${this.repo} is not a git repo; merged only what was already local`
            };
        }
        this.commitLeftovers();
        const ff = await this.git.pullFF();
        if (!ff.ok) {
            const e = new Error(`cannot update the sync repo: ${ff.error}`);
            e.code = ff.code || "REMOTE_UNREACHABLE";
            e.status = 409;
            throw e;
        }
        this.requireUnlocked();
        // Another process may have saved the vault while git waited. Merge into its copy, not
        // the stale one in memory, and wait for a save still in progress.
        if (!this.store.reloadIfChanged() && this.store.changedOnDisk()) throw Object.assign(new Error("Another process is still saving the vault; the next round syncs its copy"), {
            state: "VAULT_BUSY",
            status: 409
        });
        const merged = this.pull(options);
        return {
            ...merged,
            transport: "ok",
            fetched: ff.changed,
            receipt: this.receipt()
        };
    }
    // A round that stops between writing its files and committing them (a failed commit, a
    // crash) leaves them in the working tree, and Git will not rebase onto a peer's commits
    // until they are committed or stashed. They are this machine's own output, regenerated and
    // signed by every push, so the next round commits them before it fetches. Files left alone
    // by changes() are skipped, as everywhere else. If anything else changed, nothing is committed
    // or discarded; leftovers that do not verify stay as they are and stop the round for the
    // reason a pull would give.
    commitLeftovers() {
        const changes = this.changes();
        if (!changes || changes.unrelated.length || !changes.own.length) return null;
        const files = changes.own;
        const id = this.machineId();
        const own = f => f === `manifests/${id}.json` || f === `peers/${id}.json` || /^(?:records|tombstones)\/[a-f0-9]{64}\.age$/.test(f);
        if (!files.every(own)) return null;
        // Checked, not remembered: if this round then halts and a human drops the commit, the
        // older manifest must not read as a rollback.
        const ver = this.verifyManifests({
            remember: false
        });
        if (ver.problems.length) throw refusal(ver.problems);
        const c = this.git.commitPaths(files, `vault sync: ${files.length} file(s) left uncommitted by an earlier round from ${id}`);
        if (!c.ok) throw Object.assign(new Error(`cannot commit what an earlier round left: ${c.error}`), {
            code: "COMMIT_FAILED",
            status: 409
        });
        return c;
    }
    statusRemote() {
        return serialized(this.repo, () => this.statusRemoteNow());
    }
    async statusRemoteNow() {
        const base = this.status();
        if (!this.git.isRepo()) {
            return {
                ...base,
                state: "NO_GIT_REPO",
                remoteReachable: false,
                detail: `${this.repo} is not a git repo; records go nowhere`
            };
        }
        const f = await this.git.fetch();
        const unsent = this.unsent();
        const div = f.ok ? this.git.divergence() : {
            ok: false
        };
        const out = {
            ...base,
            remoteReachable: f.ok,
            remote: this.git.remoteName(),
            sourceCommit: this.git.head(),
            remoteCommit: f.ok ? this.git.remoteHead() : null,
            ahead: div.ok ? div.ahead : null,
            behind: div.ok ? div.behind : null,
            uncommittedFiles: unsent || []
        };
        if (!f.ok) return {
            ...out,
            state: "REMOTE_UNREACHABLE",
            detail: f.error
        };
        if (unsent && unsent.length) return {
            ...out,
            state: "LOCAL_SYNC_REPO_DIRTY",
            detail: `${unsent.length} record file(s) written but never committed, so they have not left this machine`
        };
        if (div.ok && div.ahead > 0 && div.behind > 0) return {
            ...out,
            state: "GIT_HISTORY_DIVERGED"
        };
        if (div.ok && div.ahead > 0) return {
            ...out,
            state: "UNPUSHED_COMMITS"
        };
        if (div.ok && div.behind > 0) return {
            ...out,
            state: "BEHIND_REMOTE"
        };
        if (base.error) return {
            ...out,
            state: "SIGNATURE_INVALID",
            detail: base.error
        };
        if (base.unreadable && base.unreadable.length) {
            return {
                ...out,
                state: "UNREADABLE_RECORDS",
                detail: `${base.unreadable.length} file(s) in the sync repo will not decrypt: ${base.unreadable.slice(0, 3).map(u => u.file).join(", ")}`
            };
        }
        const peers = this.readPeers();
        const peerIssues = this.peerProblems();
        const drift = base.outgoing + (base.incoming ? base.incoming.added + base.incoming.updated + base.incoming.deleted : 0);
        if (drift !== 0) return {
            ...out,
            peers: peers,
            state: "RECORDS_OUT_OF_SYNC"
        };
        if (peerIssues.length) return {
            ...out,
            peers: peers,
            state: "PEER_STALLED",
            detail: peerIssues.join("; ")
        };
        return {
            ...out,
            peers: peers,
            state: "IN_SYNC"
        };
    }
    age(args, input) {
        return execFileSync(findTool("age"), args, {
            input: input,
            encoding: null,
            maxBuffer: 64 * 1024 * 1024,
            stdio: [ "pipe", "pipe", "pipe" ],
            timeout: 15e3
        });
    }
    requireAge() {
        try {
            execFileSync(findTool("age"), [ "--version" ], {
                stdio: "ignore"
            });
        } catch {
            throw new Error("age is not installed. Install age for optional sync; see docs/SYNC.md.");
        }
    }
    machineId() {
        try {
            return fs.readFileSync(this.machineIdPath, "utf8").trim();
        } catch {}
        const id = randomId();
        atomicWrite(this.machineIdPath, id);
        return id;
    }
    signingKey() {
        try {
            return fs.readFileSync(this.signingKeyPath, "utf8");
        } catch {}
        const {privateKey: privateKey} = newSigningKey();
        atomicWrite(this.signingKeyPath, privateKey);
        return privateKey;
    }
    readIndex() {
        regularFile(this.indexPath, {
            optional: true
        });
        if (!fs.existsSync(this.indexPath)) return {
            records: {},
            tombstones: {},
            lastPush: null,
            seenManifests: {}
        };
        const idx = JSON.parse(fs.readFileSync(this.indexPath, "utf8"));
        if (!idx || typeof idx.records !== "object" || typeof idx.tombstones !== "object") throw new Error("Invalid sync index; restore a trusted backup");
        return idx;
    }
    writeIndex(idx) {
        atomicWrite(this.indexPath, JSON.stringify(idx, null, 2));
    }
    ensureDirs() {
        const marker = path.join(this.repo, "vaultos-sync.json");
        if (!fs.existsSync(marker)) {
            if (fs.existsSync(this.repo) && fs.readdirSync(this.repo).some(x => x !== ".git")) throw new Error("Use a new, empty repository for preview sync");
            fs.mkdirSync(this.repo, {
                recursive: true,
                mode: 448
            });
            atomicWrite(marker, JSON.stringify({
                app: "VaultOS-Preview",
                version: 1
            }));
        }
        regularFile(marker, {
            maxBytes: 1024
        });
        const markerData = JSON.parse(fs.readFileSync(marker));
        if (markerData.app !== "VaultOS-Preview") throw new Error("Not a preview sync repository");
        // VaultOS 0.3 (the Rust core) writes sync format 2, which this preview cannot verify;
        // writing its own files there would make every 0.3 device refuse the repository.
        if (markerData.version !== 1) throw new Error("This sync repository was made by a newer VaultOS; this preview cannot read or write it");
        for (const d of Object.values(this.dirs)) {
            fs.mkdirSync(d, {
                recursive: true,
                mode: 448
            });
            if (fs.lstatSync(d).isSymbolicLink()) throw new Error("Sync directories cannot be symbolic links");
        }
    }
    encryptTo(obj) {
        this.verifyRecipients();
        if (!fs.existsSync(this.recipientsPath)) throw new Error("no recipients.txt. Run: vault-sync init");
        return this.age([ "-R", this.recipientsPath, "-o", "-" ], Buffer.from(canonicalJson(obj), "utf8"));
    }
    decryptBytes(bytes) {
        if (!fs.existsSync(this.identityPath)) throw new Error(`no age identity at ${this.identityPath}`);
        return JSON.parse(this.age([ "-d", "-i", this.identityPath ], bytes).toString("utf8"));
    }
    decryptFile(file) {
        if (!fs.existsSync(this.identityPath)) throw new Error(`no age identity at ${this.identityPath}`);
        const out = this.age([ "-d", "-i", this.identityPath, file ]);
        return JSON.parse(out.toString("utf8"));
    }
    decryptor() {
        const vault = this.store.vault, previous = vault && decrypted.get(vault) || new Map, next = new Map;
        if (vault) decrypted.set(vault, next);
        const identity = fs.existsSync(this.identityPath) ? crypto.createHash("sha256").update(fs.readFileSync(this.identityPath)).digest("hex") : "";
        return file => {
            let bytes;
            try {
                bytes = fs.readFileSync(file);
            } catch (e) {
                return {
                    ok: false,
                    error: String(e.message || e).split("\n")[0]
                };
            }
            const key = `${file}\0${crypto.createHash("sha256").update(bytes).digest("hex")}\0${identity}`;
            const hit = previous.get(key) || next.get(key);
            if (hit) {
                next.set(key, hit);
                return {
                    ok: true,
                    payload: structuredClone(hit)
                };
            }
            // age reads the bytes just hashed from stdin, so the file cannot change in between.
            const r = this.tryDecrypt(null, bytes);
            if (r.ok) next.set(key, structuredClone(r.payload));
            return r;
        };
    }
    tryDecrypt(file, bytes = null) {
        try {
            return {
                ok: true,
                payload: bytes ? this.decryptBytes(bytes) : this.decryptFile(file)
            };
        } catch (e) {
            return {
                ok: false,
                error: String(e.message || e).split("\n")[0]
            };
        }
    }
    init(label) {
        require("./validation").text(label, "machine label", 100);
        if (/[\r\n]/.test(label)) throw new Error("Invalid machine label");
        this.requireAge();
        this.ensureDirs();
        if (!fs.existsSync(this.identityPath)) {
            const out = execFileSync(findTool("age-keygen"), [], {
                encoding: "utf8",
                stdio: [ "ignore", "pipe", "pipe" ]
            });
            atomicWrite(this.identityPath, out);
        }
        const pub = execFileSync(findTool("age-keygen"), [ "-y", this.identityPath ], {
            encoding: "utf8"
        }).trim();
        regularFile(this.recipientsPath, {
            optional: true
        });
        let recipients = fs.existsSync(this.recipientsPath) ? fs.readFileSync(this.recipientsPath, "utf8") : "";
        if (!recipients.split("\n").some(l => l.trim() === pub)) {
            atomicWrite(this.recipientsPath, recipients + `# ${label}\n${pub}\n`);
        }
        const id = this.machineId();
        const signingPub = publicKeyOf(this.signingKey());
        atomicWrite(path.join(this.dirs.machines, `${id}.json`), JSON.stringify({
            id: id,
            label: label,
            signingPublicKey: signingPub,
            agePublicKey: pub,
            enrolledAt: (new Date).toISOString()
        }, null, 2));
        const identity = {
            id: id,
            label: label,
            signingPublicKey: signingPub,
            agePublicKey: pub
        };
        this.trustMachine(identity);
        return identity;
    }
    localRecords() {
        const out = new Map;
        for (const p of this.store.vault.projects || []) {
            for (const s of p.secrets || []) {
                const ref = `${p.id}:${s.id}`;
                out.set(ref, {
                    ref: ref,
                    projectId: p.id,
                    projectName: p.name,
                    record: M.pickRecord(s),
                    hash: M.recordHash(s)
                });
            }
        }
        return out;
    }
    localTombstones() {
        const out = new Map;
        for (const t of this.store.vault.tombstones || []) out.set(t.ref, t);
        return out;
    }
    push() {
        this.requireAge();
        this.ensureDirs();
        const validation = this.verifyManifests();
        if (validation.problems.length) throw Object.assign(new Error(validation.problems.join("; ")), {
            state: "SIGNATURE_INVALID"
        });
        const idx = this.readIndex();
        const local = this.localRecords();
        const tombs = this.localTombstones();
        const recipientsHash = (() => {
            try {
                return contentHash(fs.readFileSync(this.recipientsPath, "utf8"));
            } catch {
                return null;
            }
        })();
        const recipientsChanged = recipientsHash && idx.recipientsHash && idx.recipientsHash !== recipientsHash;
        if (recipientsChanged) idx.records = {};
        let written = 0, unchanged = 0, removed = 0;
        for (const [ref, entry] of local) {
            const file = path.join(this.dirs.records, `${opaque(ref)}.age`);
            if (idx.records[ref] === entry.hash && fs.existsSync(file)) {
                unchanged++;
                continue;
            }
            const payload = {
                ref: ref,
                projectId: entry.projectId,
                projectName: entry.projectName,
                record: entry.record,
                hash: entry.hash,
                pushedBy: this.machineId(),
                pushedAt: (new Date).toISOString()
            };
            atomicWrite(file, this.encryptTo(payload));
            idx.records[ref] = entry.hash;
            written++;
        }
        for (const ref of Object.keys(idx.records)) {
            if (local.has(ref)) continue;
            const file = path.join(this.dirs.records, `${opaque(ref)}.age`);
            try {
                fs.unlinkSync(file);
            } catch {}
            delete idx.records[ref];
            removed++;
        }
        if (recipientsChanged) idx.tombstones = {};
        for (const [ref, t] of tombs) {
            const file = path.join(this.dirs.tombstones, `${opaque(ref)}.age`);
            if (idx.tombstones[ref] === t.deletedAt && fs.existsSync(file)) continue;
            atomicWrite(file, this.encryptTo({
                ref: ref,
                deletedAt: t.deletedAt,
                by: t.by
            }));
            idx.tombstones[ref] = t.deletedAt;
        }
        const id = this.machineId();
        const prev = idx.lastPush ? idx.lastPush.counter || 0 : 0;
        const manifest = {
            machineId: id,
            counter: prev + 1,
            pushedAt: (new Date).toISOString(),
            fingerprint: this.store.contentFingerprint(),
            recordCount: local.size,
            records: Object.fromEntries([ ...local ].map(([r, e]) => [ r, e.hash ])),
            files: Object.fromEntries([ "records", "tombstones" ].flatMap(dir => this.syncFiles(dir).map(f => {
                const rel = dir + "/" + f;
                regularFile(path.join(this.repo, rel));
                return [ rel, crypto.createHash("sha256").update(fs.readFileSync(path.join(this.repo, rel))).digest("hex") ];
            })))
        };
        const signed = {
            manifest: manifest,
            signature: sign(this.signingKey(), manifest)
        };
        atomicWrite(path.join(this.dirs.manifests, `${id}.json`), JSON.stringify(signed, null, 2));
        idx.lastPush = {
            counter: manifest.counter,
            at: manifest.pushedAt,
            fingerprint: manifest.fingerprint
        };
        idx.recipientsHash = recipientsHash;
        this.writeIndex(idx);
        return {
            written: written,
            unchanged: unchanged,
            removed: removed,
            fingerprint: manifest.fingerprint,
            counter: manifest.counter,
            reencryptedForNewRecipients: !!recipientsChanged
        };
    }
    trustMachine(identity) {
        if (!identity || !/^[a-f0-9]{16}$/.test(identity.id) || !/^age1[a-z0-9]+$/.test(identity.agePublicKey)) throw new Error("Invalid peer identity");
        require("./validation").text(identity.label, "machine label", 100);
        if (crypto.createPublicKey(identity.signingPublicKey).asymmetricKeyType !== "ed25519") throw new Error("Expected Ed25519 signing key");
        const trusted = this.store.vault.syncTrust || {};
        const current = trusted[identity.id];
        if (current && (current.signingPublicKey !== identity.signingPublicKey || current.agePublicKey !== identity.agePublicKey)) throw new Error("Peer key changed; remove trust explicitly before replacing it");
        trusted[identity.id] = {
            id: identity.id,
            label: identity.label,
            signingPublicKey: identity.signingPublicKey,
            agePublicKey: identity.agePublicKey
        };
        this.store.vault.syncTrust = trusted;
        this.store.persist();
        return {
            id: identity.id,
            fingerprint: contentHash(trusted[identity.id])
        };
    }
    identity() {
        const id = this.machineId();
        const peer = (this.store.vault.syncTrust || {})[id];
        if (!peer) throw new Error("Initialize this machine first");
        return {
            ...peer,
            fingerprint: contentHash(peer)
        };
    }
    verifyRecipients() {
        const approved = new Set(Object.values(this.store.vault.syncTrust || {}).map(x => x.agePublicKey));
        const recipients = fs.readFileSync(this.recipientsPath, "utf8").split("\n").map(x => x.trim()).filter(x => x && !x.startsWith("#"));
        if (!recipients.length || recipients.some(x => !approved.has(x))) throw new Error("Unapproved encryption recipient; verify and trust the peer first");
    }
    verifyManifests({remember: remember = true} = {}) {
        const idx = this.readIndex(), problems = [], accepted = [];
        const trusted = this.store.vault.syncTrust || {};
        const present = new Set;
        // Sync never reads a file under a name it does not write. If only this checkout has one
        // (Finder's .DS_Store, an interrupted write's temporary file), this account made it and it
        // is ignored. One that arrived in a commit, as a file or a folder, came from a peer or the
        // remote and is refused like any unsigned change, as is every one when Git cannot say.
        const tracked = this.git.isRepo() ? this.git.trackedPaths([ "records", "tombstones", "manifests" ]) : {
            ok: false
        };
        const refused = name => !tracked.ok || [ ...tracked.files ].some(f => f === name || f.startsWith(name + "/"));
        for (const file of fs.existsSync(this.dirs.manifests) ? fs.readdirSync(this.dirs.manifests) : []) {
            if (!/^[a-f0-9]{16}\.json$/.test(file)) {
                if (refused(`manifests/${file}`)) problems.push("Invalid manifest filename");
                continue;
            }
            try {
                regularFile(path.join(this.dirs.manifests, file), {
                    maxBytes: 16 * 1024 * 1024
                });
                const signed = JSON.parse(fs.readFileSync(path.join(this.dirs.manifests, file), "utf8"));
                const m = signed.manifest, id = m?.machineId;
                present.add(id);
                if (file !== id + ".json" || !trusted[id]) {
                    problems.push("Untrusted sync machine");
                    continue;
                }
                if (!verify(trusted[id].signingPublicKey, m, signed.signature)) {
                    problems.push("BAD SIGNATURE");
                    continue;
                }
                if (!Number.isSafeInteger(m.counter) || m.counter < 1 || !m.files) {
                    problems.push("Unsupported manifest");
                    continue;
                }
                const hash = contentHash(m), seen = idx.seenManifests[id];
                if (seen && (m.counter < seen.counter || m.counter === seen.counter && seen.hash && seen.hash !== hash)) {
                    problems.push("ROLLBACK or manifest equivocation");
                    continue;
                }
                for (const [name, digest] of Object.entries(m.files)) if (!/^(records|tombstones)\/[a-f0-9]{64}\.age$/.test(name) || !/^[a-f0-9]{64}$/.test(digest)) throw new Error("Invalid manifest path");
                accepted.push({
                    id: id,
                    m: m,
                    hash: hash
                });
            } catch {
                problems.push("Invalid manifest");
            }
        }
        for (const id of Object.keys(idx.seenManifests)) if (!present.has(id)) problems.push("Previously seen manifest is missing");
        const signatures = new Map;
        for (const {m: m} of accepted) for (const [name, hash] of Object.entries(m.files)) {
            if (!signatures.has(name)) signatures.set(name, new Set);
            signatures.get(name).add(hash);
        }
        for (const dir of [ "records", "tombstones" ]) for (const file of fs.existsSync(this.dirs[dir]) ? fs.readdirSync(this.dirs[dir]) : []) {
            const rel = dir + "/" + file;
            if (!SYNC_FILE.test(rel)) {
                if (refused(rel)) problems.push(`Unexpected file in the sync repository: ${JSON.stringify(rel)}`);
                continue;
            }
            try {
                regularFile(path.join(this.repo, rel));
                const hash = crypto.createHash("sha256").update(fs.readFileSync(path.join(this.repo, rel))).digest("hex");
                if (!signatures.get(rel)?.has(hash)) problems.push("Unsigned or modified ciphertext");
            } catch {
                problems.push("Invalid sync file");
            }
        }
        for (const name of signatures.keys()) if (!fs.existsSync(path.join(this.repo, name))) {
            const tomb = "tombstones/" + path.basename(name);
            if (!name.startsWith("records/") || !fs.existsSync(path.join(this.repo, tomb))) problems.push("Signed ciphertext is missing");
        }
        if (!problems.length && remember) {
            for (const {id: id, m: m, hash: hash} of accepted) idx.seenManifests[id] = {
                counter: m.counter,
                hash: hash,
                at: m.pushedAt
            };
            this.writeIndex(idx);
        }
        return {
            checked: accepted.length,
            problems: problems
        };
    }
    pull({apply: apply = true} = {}) {
        this.requireAge();
        this.ensureDirs();
        const ver = this.verifyManifests();
        if (ver.problems.length) throw refusal(ver.problems);
        const remote = new Map;
        const unreadable = [];
        const decrypt = this.decryptor();
        for (const f of this.syncFiles("records")) {
            const r = decrypt(path.join(this.dirs.records, f));
            if (!r.ok) {
                unreadable.push({
                    file: `records/${f}`,
                    error: r.error
                });
                continue;
            }
            const payload = r.payload;
            if (!payload || f !== opaque(payload.ref) + ".age" || payload.ref !== payload.projectId + ":" + payload.record?.id || M.recordHash(payload.record) !== payload.hash) throw new Error("Invalid record binding");
            require("./validation").secret(payload.record);
            remote.set(payload.ref, payload);
        }
        const remoteTombs = new Map;
        for (const f of this.syncFiles("tombstones")) {
            const r = decrypt(path.join(this.dirs.tombstones, f));
            if (!r.ok) {
                unreadable.push({
                    file: `tombstones/${f}`,
                    error: r.error
                });
                continue;
            }
            if (!r.payload || f !== opaque(r.payload.ref) + ".age" || !Number.isFinite(Date.parse(r.payload.deletedAt))) throw new Error("Invalid tombstone binding");
            remoteTombs.set(r.payload.ref, r.payload);
        }
        const local = this.localRecords();
        // What this device last knew the repository held, per record: the merge base.
        const base = this.readIndex().records;
        const plan = {
            added: [],
            updated: [],
            deleted: [],
            conflicts: [],
            unchanged: 0,
            unreadable: unreadable
        };
        for (const [ref, rp] of remote) {
            const tomb = remoteTombs.get(ref);
            const lo = local.get(ref);
            if (!lo) {
                const localTomb = this.localTombstones().get(ref);
                if (localTomb && Date.parse(localTomb.deletedAt) > Date.parse(rp.pushedAt)) continue;
                plan.added.push(rp);
                continue;
            }
            if (lo.hash === rp.hash) {
                plan.unchanged++;
                continue;
            }
            if (tomb && Date.parse(tomb.deletedAt) > Date.parse(lo.record.updatedAt || 0)) {
                plan.deleted.push(ref);
                continue;
            }
            const lrev = lo.record.rev || 1, rrev = rp.record.rev || 1;
            // Three-way check against the merge base: a record changed on one side only since
            // the last sync is an ordinary update, not a conflict. The revision must agree too,
            // so a damaged index can never let an older copy replace a newer local edit.
            if (base[ref] && lo.hash === base[ref] && rrev > lrev) {
                plan.updated.push(rp);
                continue;
            }
            if (base[ref] && rp.hash === base[ref] && lrev > rrev) {
                plan.unchanged++;
                continue;
            }
            const lts = Date.parse(lo.record.updatedAt || 0), rts = Date.parse(rp.record.updatedAt || 0);
            // Equal revision and timestamp must break the same way on every device, or each
            // keeps its own version and accepting conflicts never converges. Content hash decides.
            const remoteWins = rrev > lrev || rrev === lrev && (rts > lts || rts === lts && rp.hash > lo.hash);
            plan.conflicts.push({
                ref: ref,
                key: lo.record.key,
                project: lo.projectName,
                localRev: lrev,
                remoteRev: rrev,
                localUpdatedAt: lo.record.updatedAt,
                remoteUpdatedAt: rp.record.updatedAt,
                resolution: remoteWins ? "remote" : "local"
            });
            if (remoteWins) plan.updated.push(rp);
        }
        for (const [ref, t] of remoteTombs) {
            const lo = local.get(ref);
            if (!lo) continue;
            if (plan.deleted.includes(ref)) continue;
            if (Date.parse(t.deletedAt) > Date.parse(lo.record.updatedAt || 0)) plan.deleted.push(ref);
        }
        plan.deletedProjects = [];
        const projectTombs = [ ...remoteTombs.keys() ].filter(r => r.startsWith("project:")).map(r => r.slice("project:".length));
        if (apply && plan.conflicts.length && !arguments[0]?.acceptConflicts) {
            const e = new Error("Concurrent edits detected. Back up both vaults and review the conflict plan before accepting its revisions");
            e.state = "CONFLICTS_PENDING";
            e.status = 409;
            e.conflicts = plan.conflicts.length;
            throw e;
        }
        if (apply && unreadable.length) {
            const e = new Error(`${unreadable.length} record file(s) in the sync repo could not be decrypted: ` + unreadable.slice(0, 3).map(u => u.file).join(", "));
            e.code = "UNREADABLE_RECORDS";
            e.status = 409;
            throw e;
        }
        if (!apply) {
            for (const pid of projectTombs) {
                const proj = (this.store.vault.projects || []).find(x => x.id === pid);
                if (!proj) continue;
                const live = (proj.secrets || []).filter(s2 => !plan.deleted.includes(`${pid}:${s2.id}`));
                if (live.length === 0) plan.deletedProjects.push({
                    id: pid,
                    name: proj.name
                });
            }
            return plan;
        }
        if (plan.added.length || plan.updated.length || plan.deleted.length || plan.deletedProjects.length) {
            const backupDir = path.join(this.store.dataDir, "backups");
            fs.mkdirSync(backupDir, {
                recursive: true,
                mode: 448
            });
            atomicWrite(path.join(backupDir, Date.now() + "-" + randomId() + ".enc"), fs.readFileSync(this.store.vaultPath));
            try {
                pruneBackups(backupDir);
            } catch {}
        }
        const rollback = JSON.parse(JSON.stringify(this.store.vault));
        try {
            for (const rp of [ ...plan.added, ...plan.updated ]) this.applyRecord(rp);
            for (const ref of plan.deleted) {
                this.removeRecord(ref);
                const t = remoteTombs.get(ref);
                this.store.tombstone(ref, t ? t.by : "sync", {
                    via: "pull"
                });
            }
            for (const pid of projectTombs) {
                const proj = (this.store.vault.projects || []).find(x => x.id === pid);
                if (!proj || (proj.secrets || []).length !== 0) continue;
                this.store.vault.projects = (this.store.vault.projects || []).filter(x => x.id !== pid);
                this.store.tombstone(`project:${pid}`, "sync", {
                    project: proj.name,
                    via: "pull"
                });
                plan.deletedProjects.push({
                    id: pid,
                    name: proj.name
                });
            }
            if (plan.added.length || plan.updated.length || plan.deleted.length || plan.deletedProjects.length) this.store.persist();
        } catch (e) {
            this.store.vault = rollback;
            throw e;
        }
        // The index tells push() which records the repository already holds. Mark only
        // records whose local copy matches the repository. A local edit kept by a conflict
        // resolution, or a record that exists only here, must stay unmarked so that the next
        // push writes it; marking every local record stranded those edits on this device.
        const idx = this.readIndex();
        const merged = this.localRecords();
        for (const [ref, rp] of remote) {
            const lo = merged.get(ref);
            if (!lo) continue;
            if (lo.hash === rp.hash) idx.records[ref] = lo.hash; else delete idx.records[ref];
        }
        for (const ref of merged.keys()) if (!remote.has(ref)) delete idx.records[ref];
        for (const ref of plan.deleted) delete idx.records[ref];
        this.writeIndex(idx);
        return plan;
    }
    applyRecord(payload) {
        const v = this.store.vault;
        let project = (v.projects || []).find(p => p.id === payload.projectId);
        if (!project) {
            if (v.projects.some(p => p.name.toLowerCase() === payload.projectName.toLowerCase())) throw new Error("Project name collision; resolve it before merging");
            project = {
                id: payload.projectId,
                name: payload.projectName,
                secrets: [],
                owner: M.HUMAN,
                createdAt: (new Date).toISOString(),
                updatedAt: (new Date).toISOString()
            };
            v.projects.push(project);
        }
        const i = (project.secrets || []).findIndex(s => s.id === payload.record.id);
        if (i === -1) {
            if (project.secrets.some(s => s.key === payload.record.key)) throw new Error("Secret name collision; resolve it before merging");
            project.secrets.push({
                ...payload.record
            });
        } else project.secrets[i] = {
            ...payload.record
        };
        project.updatedAt = (new Date).toISOString();
    }
    removeRecord(ref) {
        const [projectId, recordId] = ref.split(":");
        const project = (this.store.vault.projects || []).find(p => p.id === projectId);
        if (!project) return;
        project.secrets = (project.secrets || []).filter(s => s.id !== recordId);
    }
    publishHeartbeat() {
        this.ensureDirs();
        const unsent = this.git.isRepo() ? this.unsent() : null;
        const beat = {
            machineId: this.machineId(),
            at: (new Date).toISOString(),
            fingerprint: this.store.contentFingerprint(),
            records: this.localRecords().size,
            manifestCounter: (this.readIndex().lastPush || {}).counter || 0,
            uncommitted: unsent ? unsent.filter(f => !f.startsWith("peers/")).length : null,
            sourceCommit: this.git.isRepo() ? this.git.head() : null
        };
        const signed = {
            beat: beat,
            signature: sign(this.signingKey(), beat)
        };
        atomicWrite(path.join(this.dirs.peers, `${this.machineId()}.json`), JSON.stringify(signed, null, 2));
        return beat;
    }
    readPeers() {
        const out = [];
        if (!fs.existsSync(this.dirs.peers)) return out;
        for (const f of fs.readdirSync(this.dirs.peers)) {
            if (!f.endsWith(".json")) continue;
            let signed;
            try {
                signed = JSON.parse(fs.readFileSync(path.join(this.dirs.peers, f), "utf8"));
            } catch {
                continue;
            }
            const id = signed.beat && signed.beat.machineId;
            if (!/^[a-f0-9]{16}$/.test(id || "")) continue;
            if (!id || id === this.machineId()) continue;
            const mf = path.join(this.dirs.machines, `${id}.json`);
            let label = id, verified = false;
            if (fs.existsSync(mf)) {
                const machine = (this.store.vault.syncTrust || {})[id];
                if (!machine) {
                    out.push({
                        label: id,
                        verified: false
                    });
                    continue;
                }
                label = machine.label || id;
                verified = verify(machine.signingPublicKey, signed.beat, signed.signature);
            }
            const ageHours = (Date.now() - Date.parse(signed.beat.at)) / 36e5;
            out.push({
                ...signed.beat,
                label: label,
                verified: verified,
                ageHours: Math.round(ageHours * 10) / 10
            });
        }
        return out;
    }
    peerProblems({staleHours: staleHours = 48} = {}) {
        const problems = [];
        for (const p of this.readPeers()) {
            if (!p.verified) {
                problems.push(`${p.label}: heartbeat signature could not be verified`);
                continue;
            }
            if (p.uncommitted > 0) problems.push(`${p.label} has ${p.uncommitted} record file(s) written but never committed - they have not left that machine`);
            if (p.ageHours > staleHours) problems.push(`${p.label} has not reported for ${Math.round(p.ageHours)}h`);
        }
        return problems;
    }
    status() {
        const local = this.localRecords();
        const idx = this.readIndex();
        let remoteCount = 0;
        try {
            remoteCount = this.syncFiles("records").length;
        } catch {}
        let plan = null, error = null;
        try {
            plan = this.pull({
                apply: false
            });
        } catch (e) {
            error = e.message;
        }
        return {
            machineId: this.machineId(),
            localRecords: local.size,
            repoRecords: remoteCount,
            fingerprint: this.store.contentFingerprint(),
            lastPush: idx.lastPush,
            incoming: plan ? {
                added: plan.added.length,
                updated: plan.updated.length,
                deleted: plan.deleted.length,
                conflicts: plan.conflicts.length
            } : null,
            outgoing: plan ? [ ...local ].filter(([ref, e]) => idx.records[ref] !== e.hash).length : null,
            conflicts: plan ? plan.conflicts : [],
            unreadable: plan ? plan.unreadable || [] : [],
            error: error
        };
    }
}

module.exports = {
    Sync: Sync,
    opaque: opaque,
    findTool: findTool,
    pruneBackups: pruneBackups
};
