"use strict";

const {test} = require("node:test"), assert = require("node:assert/strict");

const {PROVIDERS} = require("../providers");

test("the Rust core's provider table matches providers.js", () => {
    const rust = require("../crates/vaultos-core/src/providers.json");
    assert.deepEqual(rust, PROVIDERS.map(p => ({ id: p.id, keys: p.keys })), "regenerate crates/vaultos-core/src/providers.json from providers.js");
});
