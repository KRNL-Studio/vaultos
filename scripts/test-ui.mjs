import { _electron as electron } from "playwright";

import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, realpathSync, writeFileSync } from "node:fs";

import { tmpdir } from "node:os";

import path from "node:path";

import assert from "node:assert/strict";

import { execFileSync } from "node:child_process";

const dir = mkdtempSync(path.join(realpathSync(tmpdir()), "vaultos-ui-test-"));

// A sync checkout whose remote does not exist, so a pull fails before it touches the vault.
const syncRepo = path.join(dir, "sync-repository");

execFileSync("git", [ "init", "-q", syncRepo ]);

execFileSync("git", [ "-C", syncRepo, "remote", "add", "origin", path.join(dir, "unreachable.git") ]);

// The test must not take the human's Quick Access shortcut while it runs.
mkdirSync(path.join(dir, "data"), {
    recursive: true,
    mode: 0o700
});

writeFileSync(path.join(dir, "data", "desktop-prefs.json"), JSON.stringify({
    shortcut: ""
}), {
    mode: 0o600
});

const mainWindow = "vaultos-preview://app/index.html";

const app = await electron.launch({
    args: [ "." ],
    env: {
        ...process.env,
        VAULTOS_DATA_DIR: path.join(dir, "data"),
        VAULTOS_SYNC_REPO: syncRepo
    }
});

try {
    const page = await app.firstWindow();
    await page.waitForSelector("text=Set up your vault");
    const denied = await page.evaluate(async () => {
        try {
            await window.vault.projects();
            return false;
        } catch {
            return true;
        }
    });
    assert(denied, "IPC must be locked before setup");
    await page.getByPlaceholder("Master password", {
        exact: true
    }).fill("synthetic-ui-password");
    await page.getByPlaceholder("Confirm password").fill("synthetic-ui-password");
    await page.getByRole("button", {
        name: "Create vault",
        exact: true
    }).click();
    await page.getByRole("button", {
        name: "New project"
    }).click();
    await page.getByPlaceholder("Project name").fill("Example App");
    await page.getByRole("button", {
        name: "Add",
        exact: true
    }).click();
    await page.waitForSelector("text=Add key");
    await page.evaluate(async () => {
        await window.vault.setSecret("Example App", {
            key: "DEMO_API_KEY",
            value: "synthetic-demo-only",
            provider: "custom",
            note: "Synthetic example. Never a live credential."
        });
    });
    await page.getByRole("button", {
        name: "Projects",
        exact: false
    }).first().click();
    await page.getByRole("button", {
        name: "Example App",
        exact: false
    }).click();
    await page.getByRole("button", {
        name: "Reveal",
        exact: true
    }).click();
    assert(await page.getByText("Value: synthetic-demo-only").isVisible());
    const keyBounds=await page.getByText('DEMO_API_KEY',{exact:true}).boundingBox();
    assert(keyBounds && keyBounds.width>100 && keyBounds.height<40,'Credential name must remain readable beside its icon');
    mkdirSync("docs/images", {
        recursive: true
    });
    await page.screenshot({
        path: "docs/images/vaultos-preview.png"
    });
    await page.getByRole("button", {
        name: "Lock",
        exact: true
    }).click();
    await page.getByRole("button", {
        name: "Unlock",
        exact: true
    }).waitFor();
    assert(!await page.getByText("Value: synthetic-demo-only").count());
    const locked = await page.evaluate(async () => {
        try {
            await window.vault.reveal("Example App", "DEMO_API_KEY");
            return false;
        } catch {
            return true;
        }
    });
    assert(locked, "Lock must revoke IPC access");
    await page.getByPlaceholder("Master password", {
        exact: true
    }).fill("synthetic-ui-password");
    await page.getByRole("button", {
        name: "Unlock",
        exact: true
    }).click();
    await page.getByRole("button", {
        name: "Example App",
        exact: false
    }).waitFor();
    const attempted = await page.evaluate(() => window.open("https://example.com"));
    assert.equal(attempted, null);
    assert.equal((await app.windows()).length, 1);
    const pullError = await page.evaluate(async () => {
        try {
            await window.vault.syncPull(false);
            return null;
        } catch (e) {
            return e.message;
        }
    });
    assert.match(pullError, /cannot update the sync repo: .*unreachable\.git/, "a failed pull says why, not that a file operation failed");
    // Search returns metadata only, and Enter opens the item in its project.
    const found = await page.evaluate(() => window.vault.search("demo"));
    assert.equal(found.length, 1);
    assert.equal(found[0].key, "DEMO_API_KEY");
    assert(!JSON.stringify(found).includes("synthetic-demo-only"), "search results carry no values");
    await page.keyboard.press(process.platform === "darwin" ? "Meta+K" : "Control+K");
    await page.locator(".searchbox input").fill("demo api");
    await page.locator(".results .row.result").first().waitFor();
    await page.locator(".searchbox input").press("Enter");
    await page.locator(".secret.card.flash").waitFor();
    // Quick Access: its own window and preload. The main window cannot use its channels.
    const quickOpened = app.waitForEvent("window");
    await app.evaluate(({Menu}) => {
        const find = items => {
            for (const item of items) {
                if (item.label === "Quick Access…") return item;
                const inner = item.submenu && find(item.submenu.items);
                if (inner) return inner;
            }
            return null;
        };
        find(Menu.getApplicationMenu().items).click();
    });
    const quick = await quickOpened;
    await quick.waitForSelector("#q:not([disabled])");
    assert.equal(await quick.evaluate(() => typeof window.vault), "undefined", "Quick Access has no main-window API");
    const quickFound = await quick.evaluate(() => window.quick.search("demo"));
    assert.equal(quickFound.length, 1);
    assert(!JSON.stringify(quickFound).includes("synthetic-demo-only"), "Quick Access never receives values");
    const crossed = await app.evaluate(async ({BrowserWindow}, url) => {
        const w = BrowserWindow.getAllWindows().find(x => x.webContents.getURL() === url);
        return w.webContents.executeJavaScript("typeof window.quick");
    }, mainWindow);
    assert.equal(crossed, "undefined", "the main window has no Quick Access API");
    await quick.fill("#q", "DEMO");
    await quick.locator("#results li[aria-selected=true]").waitFor();
    await quick.locator("#q").press(process.platform === "darwin" ? "Meta+Enter" : "Control+Enter");
    await page.locator(".secret.card.flash").waitFor();
    assert.equal(await app.evaluate(({BrowserWindow}) => BrowserWindow.getAllWindows().filter(w => w.isVisible()).length), 1, "Quick Access hides after opening an item");
    let main = page;
    if (process.platform === "darwin") {
        // Closing the window locks the vault and leaves VaultOS in the menu bar.
        const closed = page.waitForEvent("close");
        await app.evaluate(({BrowserWindow}, url) => BrowserWindow.getAllWindows().find(w => w.webContents.getURL() === url).close(), mainWindow);
        await closed;
        assert.equal((await quick.evaluate(() => window.quick.state())).unlocked, false, "closing the window locks the vault");
        await assert.rejects(quick.evaluate(() => window.quick.search("demo")), /Vault is locked/);
        const reopened = app.waitForEvent("window");
        await app.evaluate(({app}) => app.emit("activate"));
        const again = await reopened;
        await again.waitForSelector("text=VaultOS is locked");
        await again.getByPlaceholder("Master password", {
            exact: true
        }).fill("synthetic-ui-password");
        await again.getByRole("button", {
            name: "Unlock",
            exact: true
        }).click();
        await again.getByRole("button", {
            name: "Example App",
            exact: false
        }).waitFor();
        main = again;
    }
    // Overlapping unlocks run one at a time: a wrong password delays the attempt queued behind
    // it, and a wrong attempt never gives back ownership a correct one gained.
    await main.getByRole("button", {
        name: "Lock",
        exact: true
    }).click();
    await main.getByRole("button", {
        name: "Unlock",
        exact: true
    }).waitFor();
    const ownerLock = path.join(dir, "data", "owner.lock");
    const race = order => main.evaluate(pws => Promise.all(pws.map(pw => window.vault.unlock(pw))), order);
    const [wrongFirst, delayed] = await race([ "synthetic-wrong-password", "synthetic-ui-password" ]);
    assert.equal(wrongFirst.ok, false);
    assert.match(delayed.error, /Wait a moment/, "the queued attempt honours the delay the failure set");
    assert(!existsSync(ownerLock), "a failed unlock releases the vault");
    await new Promise(r => setTimeout(r, 1200));
    const [right, wrongAfter] = await race([ "synthetic-ui-password", "synthetic-wrong-password" ]);
    assert.equal(right.ok, true);
    assert.equal(wrongAfter.ok, false);
    assert(existsSync(ownerLock), "a later wrong attempt does not release the unlocked vault");
    assert.equal(readFileSync(ownerLock, "utf8"), String(await app.evaluate(() => process.pid)));
    console.log("Desktop flow passed: setup, locked IPC, create, reveal, lock, unlock, blocked popups, sync pull reason, search, Quick Access, close to menu bar, overlapping unlocks. Synthetic screenshot saved.");
} finally {
    await app.close();
    rmSync(dir, {
        recursive: true,
        force: true
    });
}
