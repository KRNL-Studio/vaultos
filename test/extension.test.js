"use strict";

// The extension's DOM-free helpers: pairing codes, browser names and field detection.
const test = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const S = require("../extension/shared.js");

test("pairing codes use the owner's alphabet and shape", () => {
    assert.equal(S.pairingCode(new Uint8Array(8)), "AAAA-AAAA");
    const code = S.pairingCode(Uint8Array.from([ 0, 1, 2, 3, 30, 31, 255, 128 ]));
    assert.match(code, /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}$/);
    assert.equal(code, "ABCD-9AHE");
});

test("names the browser from its brands", () => {
    assert.equal(S.browserName([ { brand: "Not.A/Brand" }, { brand: "Chromium" }, { brand: "Google Chrome" } ], false), "Chrome");
    assert.equal(S.browserName([ { brand: "Chromium" }, { brand: "Microsoft Edge" } ], false), "Edge");
    assert.equal(S.browserName([ { brand: "Chromium" } ], true), "Brave");
    assert.equal(S.browserName([], false), "Browser");
});

test("finds username and one-time code fields", () => {
    assert.ok(S.isUsername({ type: "email" }));
    assert.ok(S.isUsername({ type: "text", autocomplete: "username" }));
    assert.ok(S.isUsername({ type: "text", name: "login_id" }));
    assert.ok(!S.isUsername({ type: "text", name: "search" }));
    assert.ok(!S.isUsername({ type: "password", name: "user" }));
    assert.ok(S.isOtp({ type: "text", autocomplete: "one-time-code" }));
    assert.ok(S.isOtp({ type: "tel", label: "Verification code" }));
    assert.ok(!S.isOtp({ type: "password", name: "otp" }));
    assert.ok(!S.isOtp({ type: "text", name: "zip" }));
});

test("a submitted login matches the one just filled", () => {
    const a = { username: "alice", passwordHash: "aa" };
    assert.ok(S.sameLogin(a, { ...a }));
    assert.ok(!S.sameLogin(a, { username: "alice", passwordHash: "bb" }));
    assert.ok(!S.sameLogin(undefined, a));
});

test("fills only simple sign-in forms and saves the new password", () => {
    const cur = { autocomplete: "current-password" }, any = {}, fresh = { autocomplete: "new-password" };
    assert.equal(S.passwordField([ cur ], "fill"), 0);
    assert.equal(S.passwordField([ any ], "fill"), 0);
    assert.equal(S.passwordField([ fresh ], "fill"), -1);
    assert.equal(S.passwordField([ cur, fresh, fresh ], "fill"), -1);
    assert.equal(S.passwordField([ any, any ], "fill"), -1);
    assert.equal(S.passwordField([ cur, fresh, fresh ], "save"), 2);
    assert.equal(S.passwordField([ any ], "save"), 0);
    assert.equal(S.passwordField([ any, any ], "save"), -1);
    assert.equal(S.passwordField([], "save"), -1);
});

test("a login in a menu shows the host it was saved for", () => {
    assert.equal(S.loginDetail({ username: "alice", host: "admin.example.com", project: "Work" }), "alice · admin.example.com");
    assert.equal(S.loginDetail({ username: "", host: "example.com", project: "Work" }), "example.com");
    assert.equal(S.loginDetail({ project: "Work" }), "Work");
});

test("the manifest asks only for what the extension uses", () => {
    const m = JSON.parse(readFileSync(path.join(__dirname, "..", "extension", "manifest.json"), "utf8"));
    assert.deepEqual(m.permissions.sort(), [ "activeTab", "alarms", "nativeMessaging", "storage" ]);
    assert.equal(m.host_permissions, undefined);
    for (const pattern of m.content_scripts[0].matches) assert.match(pattern, /^(https:\/\/\*\/\*|http:\/\/(\*\.)?localhost\/\*|http:\/\/127\.0\.0\.1\/\*)$/);
});
