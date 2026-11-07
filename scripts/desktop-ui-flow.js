"use strict";

// The desktop UI flow. scripts/test-desktop-ui.mjs injects this into both windows of a
// `ui-test` debug build. Each window waits for its phase, acts like the human, and moves the
// flow on through the `ui_test` command. Synthetic values only.
(() => {
    const password = "synthetic-ui-password";
    const value = "synthetic-demo-only";
    const isQuick = location.pathname.endsWith("/quick.html");
    const ui = (action, arg = null) => window.__TAURI__.core.invoke("ui_test", {
        action: action,
        arg: arg
    });
    const sleep = ms => new Promise(r => setTimeout(r, ms));
    const assert = (ok, message) => {
        if (!ok) throw new Error(message);
    };
    const until = async (probe, what, ms = 20000) => {
        const end = Date.now() + ms;
        for (;;) {
            let found = null;
            try {
                found = await probe();
            } catch {}
            if (found) return found;
            if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
            await sleep(50);
        }
    };
    const shown = e => !!e && e.getClientRects().length > 0;
    const named = (e, name, exact) => {
        const label = (e.getAttribute("aria-label") || e.textContent).trim();
        return exact ? label === name : label.includes(name);
    };
    const button = (name, exact = true) => until(() => [ ...document.querySelectorAll("button, [role=button], .crumb") ].find(b => shown(b) && named(b, name, exact)), `button ${name}`);
    const field = placeholder => until(() => [ ...document.querySelectorAll("input, textarea") ].find(e => shown(e) && e.placeholder === placeholder), `field ${placeholder}`);
    const query = selector => until(() => [ ...document.querySelectorAll(selector) ].find(shown), selector);
    const text = t => until(() => document.body.innerText.includes(t), `text ${t}`);
    const click = async name => (await button(name)).click();
    const fill = (e, v) => {
        e.focus();
        e.value = v;
        e.dispatchEvent(new Event("input", {
            bubbles: true
        }));
    };
    const mac = navigator.platform.startsWith("Mac");
    const press = (e, key, withModifier = false) => e.dispatchEvent(new KeyboardEvent("keydown", {
        key: key,
        bubbles: true,
        cancelable: true,
        metaKey: withModifier && mac,
        ctrlKey: withModifier && !mac
    }));
    const failure = async promise => {
        try {
            await promise;
            return null;
        } catch (e) {
            return e.message || String(e);
        }
    };
    const unlockRace = async (first, second) => {
        const a = window.vault.unlock(first);
        await sleep(30);
        return Promise.all([ a, window.vault.unlock(second) ]);
    };

    const phases = {
        // Setup, locked IPC, create, reveal, lock, unlock, popups, sync pull, search.
        main: async () => {
            await text("Set up your vault");
            assert(await failure(window.vault.projects()), "IPC must be locked before setup");
            fill(await field("Master password"), password);
            fill(await field("Confirm password"), password);
            await click("Create vault");
            (await button("New project", false)).click();
            fill(await field("Project name"), "Example App");
            await click("Add");
            await text("Add key");
            await window.vault.setSecret("Example App", {
                key: "DEMO_API_KEY",
                value: value,
                provider: "custom",
                note: "Synthetic example. Never a live credential."
            });
            (await button("Projects", false)).click();
            (await button("Example App", false)).click();
            await click("Reveal");
            await text(`Value: ${value}`);
            const name = await until(() => [ ...document.querySelectorAll("*") ].find(e => e.children.length === 0 && e.textContent.trim() === "DEMO_API_KEY"), "the credential name");
            const box = name.getBoundingClientRect();
            assert(box.width > 100 && box.height < 40, "the credential name stays readable beside its icon");
            await click("Lock");
            await button("Unlock");
            assert(!document.body.innerText.includes(value), "lock hides the revealed value");
            assert(await failure(window.vault.reveal("Example App", "DEMO_API_KEY")), "lock must revoke IPC access");
            fill(await field("Master password"), password);
            await click("Unlock");
            await button("Example App", false);
            assert(window.open("https://example.com") === null, "pages cannot open windows");
            assert(JSON.stringify(await ui("visible")) === "[\"main\"]", "no new window opened");
            const pull = await failure(window.vault.syncPull(false));
            assert(/cannot update the sync repo: .*unreachable\.git/.test(pull || ""), `a failed pull says why (got: ${pull})`);
            const found = await window.vault.search("demo");
            assert(found.length === 1 && found[0].key === "DEMO_API_KEY", "search finds the item");
            assert(!JSON.stringify(found).includes(value), "search results carry no values");
            press(document.body, "k", true);
            const box2 = await query(".searchbox input");
            fill(box2, "demo api");
            await query(".results .row.result");
            press(box2, "Enter");
            const card = await query(".secret.card.flash");
            assert(typeof window.quick === "undefined", "the main window has no Quick Access API");
            card.classList.remove("flash");
            await ui("setPhase", "quick");
            await ui("showQuick");
            await until(async () => await ui("phase") === "quick-done", "Quick Access", 30000);
            await query(".secret.card.flash");
            await until(async () => JSON.stringify(await ui("visible")) === "[\"main\"]", "Quick Access to hide after opening an item");
            await ui("setPhase", "closed");
            await ui("closeMain");
        },
        // Its own window and API: metadata only, then Mod+Enter opens the item in the main window.
        quick: async () => {
            const q = await query("#q:not([disabled])");
            assert(typeof window.vault === "undefined", "Quick Access has no main-window API");
            const found = await window.quick.search("demo");
            assert(found.length === 1, "Quick Access finds the item");
            assert(!JSON.stringify(found).includes(value), "Quick Access never receives values");
            fill(q, "DEMO");
            await query("#results li[aria-selected=true]");
            await ui("setPhase", "quick-done");
            press(q, "Enter", true);
        },
        // Closing the main window locked the vault; the app waits in the menu bar.
        closed: async () => {
            await until(async () => (await window.quick.state()).unlocked === false, "the vault to lock on close");
            const e = await failure(window.quick.search("demo"));
            assert(/Vault is locked/.test(e || ""), `a locked search is refused (got: ${e})`);
            await ui("setPhase", "reopened");
            await ui("reopen");
        },
        // Overlapping unlocks run one at a time: a wrong password delays the attempt behind it,
        // and a wrong attempt never gives back the ownership a correct one gained.
        reopened: async () => {
            await text("VaultOS is locked");
            fill(await field("Master password"), password);
            await click("Unlock");
            await button("Example App", false);
            await click("Lock");
            await button("Unlock");
            const [ wrong, delayed ] = await unlockRace("synthetic-wrong-password", password);
            assert(wrong.ok === false, "a wrong password fails");
            assert(/Wait a moment/.test(delayed.error || ""), "the queued attempt honours the delay");
            assert(await ui("ownerLock") === null, "a failed unlock releases the vault");
            await sleep(1200);
            const [ right, after ] = await unlockRace(password, "synthetic-wrong-password");
            assert(right.ok === true && after.ok === false, "the right password unlocks; the late wrong one fails");
            assert(await ui("ownerLock") === String(await ui("pid")), "the app still owns the vault");
            await ui("finish", {
                ok: true,
                report: "Desktop flow passed: setup, locked IPC, create, reveal, lock, unlock, blocked popups, sync pull reason, search, Quick Access, close to menu bar, overlapping unlocks."
            });
        }
    };
    const mine = isQuick ? [ "quick", "closed" ] : [ "main", "reopened" ];

    const run = async () => {
        const done = new Set();
        for (;;) {
            const phase = await ui("phase") || "main";
            if (mine.includes(phase) && !done.has(phase)) {
                done.add(phase);
                try {
                    await phases[phase]();
                } catch (e) {
                    await ui("finish", {
                        ok: false,
                        report: `${phase}: ${e.message} | ${location.href} | Page: ${document.body.innerText.slice(0, 400).replace(/\s+/g, " ")}`
                    });
                }
            }
            await sleep(100);
        }
    };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run); else run();
})();
