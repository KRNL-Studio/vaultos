"use strict";

const {test} = require("node:test"), assert = require("node:assert/strict");

const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");

const {SecureClipboard, runHelper} = require("../secure-clipboard");

function fakeBoard() {
    return {
        text: "",
        writeText(t) { this.text = t; },
        readText() { return this.text; },
        clear() { this.text = ""; }
    };
}

test("plain fallback clears only its own copy, and a newer copy resets the timer", async () => {
    const board = fakeBoard();
    const c = new SecureClipboard(board, { platform: "linux", clearAfterMs: 40 });
    assert.equal(c.write("synthetic-a"), "plain");
    await new Promise(r => setTimeout(r, 25));
    c.write("synthetic-b");
    await new Promise(r => setTimeout(r, 25));
    assert.equal(board.text, "synthetic-b", "copy A's timer must not clear copy B");
    await new Promise(r => setTimeout(r, 30));
    assert.equal(board.text, "");
    c.write("synthetic-c");
    board.text = "something the human copied later";
    c.clear();
    assert.equal(board.text, "something the human copied later");
});

test("helper writes go through stdin, and a failing helper falls back to plain text", () => {
    const board = fakeBoard(), calls = [];
    const helper = process.execPath; // any existing file; run() is faked
    const ok = new SecureClipboard(board, { platform: "darwin", helper, run: (h, req) => (calls.push(req), req.action === "write" ? { changeCount: 7 } : { cleared: true }) });
    assert.equal(ok.write("synthetic-x"), "concealed");
    assert.equal(board.text, "");
    ok.clear();
    assert.deepEqual(calls, [ { action: "write", text: "synthetic-x" }, { action: "clear", changeCount: 7 } ]);
    const broken = new SecureClipboard(board, { platform: "darwin", helper, run: () => { throw new Error("helper failed"); } });
    assert.equal(broken.write("synthetic-y"), "plain");
    assert.equal(board.text, "synthetic-y");
    broken.clear();
    assert.equal(board.text, "");
});

const testHelper = path.join(__dirname, "..", "build", "native", "vaultos-clipboard-test");

test("native helper marks copies concealed and transient on a private pasteboard", { skip: process.platform !== "darwin" || !fs.existsSync(testHelper) ? "needs VAULTOS_BUILD_TEST_HELPER=1 npm run build:native on macOS" : false }, t => {
    const pasteboard = "org.vaultos.preview.test." + crypto.randomBytes(6).toString("hex");
    t.after(() => runHelper(testHelper, { action: "release", pasteboard }));
    const { changeCount } = runHelper(testHelper, { action: "write", text: "synthetic-only", pasteboard });
    const seen = runHelper(testHelper, { action: "inspect", pasteboard });
    assert.equal(seen.text, "synthetic-only");
    for (const type of [ "org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType" ]) assert.ok(seen.types.includes(type), type);
    assert.deepEqual(runHelper(testHelper, { action: "clear", changeCount: changeCount - 1, pasteboard }), { cleared: false });
    assert.deepEqual(runHelper(testHelper, { action: "clear", changeCount, pasteboard }), { cleared: true });
    assert.equal(runHelper(testHelper, { action: "inspect", pasteboard }).text, null);
    assert.throws(() => runHelper(testHelper, { action: "inspect", pasteboard: "com.apple.general" }));
});
