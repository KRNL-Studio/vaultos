"use strict";

const {test} = require("node:test"), assert = require("node:assert/strict");

const {searchItems, matchScore, hostOf} = require("../search");

const projects = [ {
    name: "Example App",
    secrets: [
        { key: "STRIPE_SECRET_KEY", provider: "stripe", value: "synthetic-1", updatedAt: "2026-01-02T00:00:00Z" },
        { key: "STRIPE", provider: "stripe", value: "synthetic-2", updatedAt: "2026-01-01T00:00:00Z" },
        { key: "DATABASE_URL", provider: "custom", value: "synthetic-3", note: "staging postgres", updatedAt: "2026-01-03T00:00:00Z" }
    ]
}, {
    name: "Client Site",
    secrets: [
        { key: "WordPress admin", provider: "password", username: "editor", url: "https://wp.example.test/wp-admin", password: "synthetic-4", updatedAt: "2026-01-04T00:00:00Z" }
    ]
} ];

test("exact beats prefix beats word start beats substring beats fuzzy", () => {
    assert.ok(matchScore("stripe", "stripe", true) > matchScore("stripe_secret_key", "stripe", true));
    assert.ok(matchScore("stripe_secret_key", "stripe", true) > matchScore("stripe_secret_key", "secret", true));
    assert.ok(matchScore("stripe_secret_key", "secret", true) > matchScore("stripe_secret_key", "cret", true));
    assert.ok(matchScore("stripe_secret_key", "cret", true) > matchScore("stripe_secret_key", "stsk", true));
    assert.ok(matchScore("stripe_secret_key", "stsk", true) > 0);
    assert.equal(matchScore("stripe_secret_key", "stsk", false), 0);
    assert.equal(matchScore("stripe_secret_key", "zz", true), 0);
});

test("results rank by match quality and never include values", () => {
    const r = searchItems(projects, "stripe");
    assert.deepEqual(r.map(x => x.key), [ "STRIPE", "STRIPE_SECRET_KEY" ]);
    for (const item of searchItems(projects, "")) {
        assert.equal(item.value, undefined);
        assert.equal(item.password, undefined);
        assert.equal(JSON.stringify(item).includes("synthetic-"), false);
    }
});

test("every token must match some field, across projects, usernames, hosts and notes", () => {
    assert.deepEqual(searchItems(projects, "client editor").map(x => x.key), [ "WordPress admin" ]);
    assert.deepEqual(searchItems(projects, "wp.example").map(x => x.key), [ "WordPress admin" ]);
    assert.deepEqual(searchItems(projects, "postgres").map(x => x.key), [ "DATABASE_URL" ]);
    assert.deepEqual(searchItems(projects, "example stripe nothing-here"), []);
    assert.equal(searchItems(projects, "client editor")[0].hasValue, true);
});

test("an empty query lists the most recently changed items first, within the limit", () => {
    const r = searchItems(projects, "  ", { limit: 2 });
    assert.deepEqual(r.map(x => x.key), [ "WordPress admin", "DATABASE_URL" ]);
});

test("hosts are read from URLs with or without a scheme", () => {
    assert.equal(hostOf("https://api.example.test/v1"), "api.example.test");
    assert.equal(hostOf("api.example.test/v1"), "api.example.test");
    assert.equal(hostOf("not a url"), "");
    assert.equal(hostOf(""), "");
});
