// Writes the v3 vault the Rust core's upgrade tests read: a vault made by this app's own
// Store, with synthetic values only, and its decrypted contents for comparison.
// Run: node scripts/make-rust-fixtures.mjs

import { createRequire } from "node:module";

import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";

import { tmpdir } from "node:os";

import path from "node:path";

const require = createRequire(import.meta.url);

const {Store} = require("../store.js");

const {Agents} = require("../agents.js");

const {decryptVault} = require("../crypto.js");

const PASSWORD = "synthetic-fixture-password";

const out = path.join(import.meta.dirname, "..", "crates", "vaultos-core", "tests", "fixtures");

const dir = mkdtempSync(path.join(realpathSync(tmpdir()), "vaultos-fixture-"));

try {
    const store = new Store(dir);
    store.init(PASSWORD);
    store.createProject("Example App");
    store.createProject("Second Project");
    store.setSecret("Example App", {
        key: "OPENAI_API_KEY",
        value: "synthetic-openai-value",
        note: "Synthetic fixture. Never a live credential."
    });
    store.setSecret("Example App", {
        key: "DATABASE_URL",
        value: "postgres://synthetic:synthetic@localhost/example",
        username: "synthetic",
        url: "http://localhost"
    });
    store.setSecret("Example App", {
        key: "LOGIN",
        password: "synthetic-login-password",
        email: "synthetic@example.invalid",
        expiresAt: "2030-01-01"
    });
    const agent = new Agents(store).enrol("Fixture Agent");
    // The token was never shown to anyone; replace its hash too so nothing resembles one.
    store.vault.agents[0].tokenHash = "0".repeat(64);
    store.persist();
    store.setSecret("Second Project", {
        key: "AGENT_MADE",
        value: "synthetic-agent-value"
    }, agent.ref);
    store.setSecret("Example App", {
        key: "OPENAI_API_KEY",
        value: "synthetic-openai-value-2"
    });
    store.setSecret("Example App", {
        key: "TEMPORARY",
        value: "synthetic-temporary"
    });
    store.deleteSecret("Example App", "TEMPORARY");
    store.delegate("Example App", "DATABASE_URL", agent.ref, true);
    store.setSettings({
        lockPolicy: "soft"
    });
    store.lock();
    const envelope = readFileSync(path.join(dir, "vault.enc"), "utf8");
    writeFileSync(path.join(out, "v3-vault.json"), envelope + "\n");
    const plain = decryptVault(JSON.parse(envelope), PASSWORD);
    writeFileSync(path.join(out, "v3-vault.plain.json"), JSON.stringify(plain, null, 2) + "\n");
    console.log(`Wrote ${path.relative(process.cwd(), out)}/v3-vault.json and v3-vault.plain.json`);
} finally {
    rmSync(dir, {
        recursive: true,
        force: true
    });
}
