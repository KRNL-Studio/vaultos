"use strict";

const {app: app, BrowserWindow: BrowserWindow, ipcMain: ipcMain, dialog: dialog, protocol: protocol, powerMonitor: powerMonitor, clipboard: clipboard, systemPreferences: systemPreferences, Tray: Tray, Menu: Menu, globalShortcut: globalShortcut, nativeImage: nativeImage, shell: shell, screen: screen, Notification: Notification} = require("electron");

const fs = require("node:fs");

const path = require("node:path");

const {Store: Store} = require("./store");

const {Agents: Agents} = require("./agents");

const {startApi: startApi} = require("./api");

const {requestShutdown: requestShutdown, claim: claim} = require("./session");

const {AutoSync: AutoSync, syncRepo: syncRepo} = require("./autosync");

const {safeEqual: safeEqual} = require("./crypto");

const {searchItems: searchItems} = require("./search");

const desktopPrefs = require("./desktop-prefs");

const loginItem = require("./login-item");

const {SecureClipboard: SecureClipboard} = require("./secure-clipboard");

const {defaultDataDir: defaultDataDir} = require("./paths");

const {nodeError: nodeError} = require("./fs-safe");

const {PROVIDERS: PROVIDERS} = require("./providers");

const M = require("./model");

const {HumanAuth: HumanAuth, touchIdUnlockStatus: touchIdUnlockStatus, weakensSecurity: weakensSecurity, checkTouchIdPatch: checkTouchIdPatch} = require("./human-auth");

app.setName("VaultOS");

app.setPath("userData", path.join(defaultDataDir(), "desktop"));

protocol.registerSchemesAsPrivileged([ {
    scheme: "vaultos-preview",
    privileges: {
        standard: true,
        secure: true,
        supportFetchAPI: true
    }
} ]);

const store = new Store;

let win, api, autoSync, release, humanUnlocked = false, timer, failed = 0, retryAt = 0;

// The menu bar item, the Quick Access panel and desktop preferences. `quitting` separates a
// real quit from closing the window, which keeps the app in the menu bar when it is on.
let quick = null, tray = null, quitting = false, shortcutError = "", pendingCommand = null, lastPending = 0, expiryNoticeDay = "";

const URL_HOME = "vaultos-preview://app/index.html";

const URL_QUICK = "vaultos-preview://app/quick.html";

const backendOnly = process.argv.includes("--backend");

const startHidden = process.argv.includes("--hidden");

const isMac = process.platform === "darwin";

let prefs = desktopPrefs.load(store.dataDir);

// Touch ID is optional and off by default. Human-only handlers below call gate(); it does
// nothing unless the human turned on touchId.humanActions.
let prompting = 0;

const humanAuth = new HumanAuth({
    canPrompt: () => typeof systemPreferences.canPromptTouchID === "function" && systemPreferences.canPromptTouchID(),
    // While the system Touch ID sheet has focus, Quick Access must not hide itself on blur.
    prompt: reason => {
        prompting++;
        return systemPreferences.promptTouchID(reason).finally(() => {
            prompting--;
            if (quick && !quick.isDestroyed() && quick.isVisible()) quick.focus();
        });
    },
    verifyPassword: pw => store.isUnlocked() && safeEqual(pw, store.password)
});

const gate = (reason, options) => humanAuth.require(store.touchIdSettings().humanActions, reason, options);

function unlockStatus() {
    const unlocked = store.isUnlocked();
    return touchIdUnlockStatus({
        available: humanAuth.available(),
        exists: store.exists(),
        blocked: store.isAutoUnlockBlocked(),
        unlocked: unlocked,
        settings: unlocked ? store.getSettings() : null,
        hint: unlocked ? null : store.touchIdHint()
    });
}

const csp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'none'; connect-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'";

// A copied value is cleared after 30 seconds, or at Lock, if it is still on the clipboard.
// On macOS it is also marked concealed and kept off Universal Clipboard (secure-clipboard.js).
const secureClipboard = new SecureClipboard(clipboard);

const clearCopied = () => secureClipboard.clear();

// Lock also hides Quick Access and tells it to forget its results.
function lockQuick() {
    if (!quick || quick.isDestroyed()) return;
    quick.webContents.send("quick:locked");
    hideQuick();
}

function lock({forget: forget = true} = {}) {
    humanUnlocked = false;
    lockQuick();
    clearCopied();
    humanAuth.reset();
    clearTimeout(timer);
    if (forget) {
        try {
            store.blockAutoUnlock();
        } catch {}
        try {
            store.keyring.clear();
        } catch {}
    }
    if (autoSync) {
        autoSync.stop();
        autoSync = null;
    }
    if (api) {
        api.server.close();
        api.server.closeAllConnections();
        api = null;
    }
    store.clearSession();
    store.lock();
    if (release) {
        release();
        release = null;
    }
    if (win && !win.isDestroyed()) win.webContents.send("vault:locked");
    refreshTray();
}

// Locks only the window: the human must unlock again to view or change anything, while
// this process keeps owning the vault and serving enrolled agents.
function lockWindow() {
    humanUnlocked = false;
    lockQuick();
    humanAuth.reset();
    clearTimeout(timer);
    if (win && !win.isDestroyed()) win.webContents.send("vault:locked");
    refreshTray();
}

// Screen lock, sleep and idle follow the vault's lock policy (hard unless the human chose soft).
function autoLock(trigger) {
    if (store.lockAction(trigger) === "ui") lockWindow(); else lock();
}

function touch() {
    clearTimeout(timer);
    if (humanUnlocked) timer = setTimeout(() => autoLock("idle"), 15 * 60 * 1e3);
}

// Two unlocks can overlap (a Touch ID prompt and a typed password, or a double submit).
// Each waits for the one already in flight instead of claiming the vault or starting the
// API a second time.
let owning = null, serving = null;

function own() {
    if (release) return Promise.resolve();
    if (!owning) owning = (async () => {
        if (!await requestShutdown(store.sessionPath)) throw new Error("Close the other VaultOS instance before unlocking");
        if (!release) release = claim(store.dataDir);
    })().finally(() => {
        owning = null;
    });
    return owning;
}

function serve() {
    if (api) return Promise.resolve();
    if (!serving) serving = (async () => {
        const sync = new AutoSync(store, {
            log: m => console.error(`VaultOS: ${m}`)
        });
        const started = await startApi(store, {
            autoSync: sync
        });
        // Locked while the server was starting: lock() found nothing to stop, so stop it here.
        if (!store.isUnlocked()) {
            started.server.close();
            started.server.closeAllConnections();
            return;
        }
        autoSync = sync;
        api = started;
        store.writeSession(api.port, api.token);
        autoSync.start();
    })().finally(() => {
        serving = null;
    });
    return serving;
}

// Each window has its own channel prefix and preload. A call is accepted only from that
// exact window's main frame at its own page, so Quick Access cannot reach the main window's
// settings, agent or sync operations.
const fromWindow = (event, w, url) => !!w && !w.isDestroyed() && event.sender === w.webContents && event.senderFrame === w.webContents.mainFrame && event.senderFrame.url === url;

function register(prefix, trusted, channel, fn, publicCall) {
    ipcMain.handle(prefix + channel, async (event, ...args) => {
        if (!trusted(event)) throw new Error("Untrusted IPC sender");
        if (!publicCall && (!humanUnlocked || !store.isUnlocked())) throw new Error("Vault is locked");
        if (!publicCall) touch();
        try {
            if (!publicCall) store.reloadIfChanged();
            return await fn(...args);
        } catch (e) {
            throw new Error(e instanceof SyntaxError ? "Invalid file format" : nodeError(e) ? "File operation failed; check permissions and retry" : e.message);
        }
    });
}

const handle = (channel, fn, publicCall = false) => register("vault:", e => fromWindow(e, win, URL_HOME), channel, fn, publicCall);

const quickHandle = (channel, fn, publicCall = false) => register("quick:", e => fromWindow(e, quick, URL_QUICK), channel, fn, publicCall);

const desktopState = () => ({
    exists: store.exists(),
    unlocked: humanUnlocked && store.isUnlocked(),
    isMac: isMac,
    dataDir: store.dataDir,
    shortcut: prefs.shortcut,
    touchId: (t => ({
        available: humanAuth.available(),
        enabled: t.enabled,
        ready: t.ready,
        autoPrompt: t.ready && t.autoPrompt
    }))(unlockStatus())
});

handle("state", desktopState, true);

handle("providers", () => PROVIDERS, true);

handle("init", async pw => {
    if (Date.now() < retryAt) return {
        ok: false,
        error: "Wait a moment before trying again"
    };
    await own();
    try {
        store.init(pw);
        store.allowAutoUnlock();
        humanUnlocked = true;
        humanAuth.markProven();
        await serve();
        touch();
        return {
            ok: true
        };
    } catch (e) {
        lock({
            forget: false
        });
        throw e;
    }
}, true);

// After any human unlock (main window or Quick Access): the main window leaves its lock
// screen, the menu bar updates, and expiring keys are announced if the human asked for it.
function afterUnlock() {
    if (win && !win.isDestroyed()) win.webContents.send("vault:unlocked");
    refreshTray();
    notifyExpiring();
}

async function unlockWithPassword(pw) {
    const r = await unlockPasswordInner(pw);
    if (r.ok) afterUnlock();
    return r;
}

async function unlockWithTouchId() {
    const r = await unlockTouchIdInner();
    if (r.ok) afterUnlock();
    return r;
}

handle("unlock", unlockWithPassword, true);

handle("unlockTouchId", unlockWithTouchId, true);

async function unlockPasswordInner(pw) {
    if (typeof pw !== "string" || pw.length > 1024) return {
        ok: false,
        error: "Invalid password"
    };
    if (Date.now() < retryAt) return {
        ok: false,
        error: "Wait a moment before trying again"
    };
    await own();
    try {
        if (store.isUnlocked()) {
            if (!safeEqual(pw, store.password)) throw new Error("Wrong password");
        } else store.unlock(pw);
        store.allowAutoUnlock();
        store.writeTouchIdHint();
        humanUnlocked = true;
        humanAuth.markProven();
        failed = 0;
        await serve();
        touch();
        return {
            ok: true
        };
    } catch {
        retryAt = Date.now() + Math.min(3e4, 500 * 2 ** Math.min(++failed, 6));
        if (!store.isUnlocked() && release) {
            release();
            release = null;
        }
        return {
            ok: false,
            error: "Could not unlock. Check the password and vault file."
        };
    }
}

// Touch ID opens the window with the password the Keychain remembers, through the same
// checks as a typed unlock. Cancel or failure leaves the password field as the fallback.
async function unlockTouchIdInner() {
    if (Date.now() < retryAt) return {
        ok: false,
        error: "Wait a moment before trying again"
    };
    const status = unlockStatus();
    if (!status.ready) return {
        ok: false,
        error: status.error
    };
    try {
        await humanAuth.prompt("unlock VaultOS");
    } catch {
        return {
            ok: false,
            canceled: true,
            error: "Touch ID was not confirmed. Enter the master password."
        };
    }
    try {
        await own();
    } catch (e) {
        humanAuth.reset();
        throw e;
    }
    const wasUnlocked = store.isUnlocked();
    try {
        if (store.isAutoUnlockBlocked()) throw new Error("blocked");
        const pw = store.keyring.get();
        if (!pw) throw new Error("no remembered password");
        if (wasUnlocked) {
            if (!safeEqual(pw, store.password)) throw new Error("stale remembered password");
        } else store.unlock(pw);
        const s = store.getSettings();
        if (!s.touchId.unlock || !s.rememberPassword) throw new Error("Touch ID unlock is off");
        store.writeTouchIdHint();
        humanUnlocked = true;
        humanAuth.markProven();
        failed = 0;
        await serve();
        touch();
        return {
            ok: true
        };
    } catch {
        if (!wasUnlocked) {
            if (store.isUnlocked()) store.writeTouchIdHint();
            store.lock();
            if (release) {
                release();
                release = null;
            }
        }
        humanAuth.reset();
        return {
            ok: false,
            error: "Touch ID unlock is unavailable. Enter the master password."
        };
    }
}

// Answers a NEED_PASSWORD refusal: verifies the master password in memory without changing
// the vault, then the renderer retries the action within the grace window.
handle("confirmHuman", pw => humanAuth.confirmPassword(pw));

handle("lock", () => {
    lock();
    return {
        ok: true
    };
});

handle("projects", () => store.listProjects());

handle("createProject", name => store.createProject(name));

handle("deleteProject", id => store.deleteProject(id));

handle("secrets", project => store.listSecrets(project));

handle("setSecret", (project, secret) => store.setSecret(project, secret));

handle("deleteSecret", (project, key) => store.deleteSecret(project, key));

handle("reveal", async (project, key) => {
    await gate("reveal a secret value");
    return store.revealSecret(project, key);
});

async function copyValue(project, key) {
    await gate("copy a secret value");
    const secret = store.revealSecret(project, key);
    const value = secret.value || secret.password;
    if (!value) throw new Error("This key has no value to copy");
    return {
        ok: true,
        mode: secureClipboard.write(value)
    };
}

handle("copy", copyValue);

// Metadata only: names, usernames, hosts and notes, ranked. Values never leave the store.
const search = q => {
    if (typeof q !== "string" || q.length > 256) throw new Error("Invalid search");
    return searchItems(store.vault.projects, q, {
        limit: 100
    }).map(({score: _score, ...item}) => item);
};

handle("search", search);

// The main window asks for a navigation request (from the menu bar, app menu or Quick Access)
// once it has booted, and again whenever one arrives.
handle("takeCommand", () => {
    const c = pendingCommand;
    pendingCommand = null;
    return c;
}, true);

handle("getDesktopPrefs", () => desktopPrefsState());

handle("setDesktopPrefs", async patch => {
    const before = prefs;
    prefs = desktopPrefs.save(store.dataDir, patch);
    try {
        if (patch && patch.launchAtLogin !== undefined && patch.launchAtLogin !== before.launchAtLogin) applyLoginItem();
    } catch (e) {
        prefs = desktopPrefs.save(store.dataDir, {
            launchAtLogin: before.launchAtLogin
        });
        throw new Error(`Open at login could not be changed: ${e.message}`);
    }
    applyPrefs();
    return desktopPrefsState();
});

handle("getSettings", () => store.getSettings());

handle("setSettings", async patch => {
    const current = store.getSettings();
    checkTouchIdPatch(patch, current, humanAuth.available());
    if (weakensSecurity(patch, current)) await gate("change security settings");
    const result = store.setSettings(patch);
    if (autoSync) autoSync.refresh();
    return result;
});

handle("changePassword", async (oldPw, newPw) => {
    await gate("change the master password", {
        password: oldPw
    });
    return store.changePassword(oldPw, newPw);
});

handle("export", async project => {
    const password = store.vault.settings.exportPassword;
    if (!password) return {
        ok: false,
        error: "Set an export password in Settings first"
    };
    await gate("export secret values");
    const result = await dialog.showSaveDialog(win, {
        title: "Export encrypted PDF",
        defaultPath: "vault-export.pdf",
        filters: [ {
            name: "PDF",
            extensions: [ "pdf" ]
        } ]
    });
    if (result.canceled || !result.filePath) return {
        ok: false,
        canceled: true
    };
    if (!humanUnlocked) throw new Error("Vault is locked");
    if (result.filePath === store.dataDir || result.filePath.startsWith(store.dataDir + path.sep)) throw new Error("Export outside the vault data directory");
    await require("./export").exportProjectPdf(store.exportData(project), result.filePath, password, (new Date).toISOString());
    return {
        ok: true
    };
});

const agents = () => new Agents(store);

handle("agents", () => agents().list());

handle("enrolAgent", async (name, scopes, projects, roots, wildcards) => {
    await gate("enrol an agent");
    return agents().enrol(name, scopes, projects, roots, wildcards);
});

handle("reissueAgent", async id => {
    await gate("issue an agent token");
    return agents().reissue(id);
});

handle("revokeAgent", async id => {
    await gate("revoke an agent");
    return agents().revoke(id);
});

handle("setAgentScopes", async (id, scopes) => {
    await gate("change agent scopes");
    return agents().setScopes(id, scopes);
});

handle("setAgentAccess", async (id, projects, roots, wildcards) => {
    await gate("change agent access");
    return agents().setAccess(id, projects, roots, wildcards);
});

handle("chooseFolder", async () => {
    const r = await dialog.showOpenDialog(win, {
        properties: [ "openDirectory" ]
    });
    return r.canceled ? null : fs.realpathSync(r.filePaths[0]);
});

handle("allScopes", () => M.ALL_SCOPES);

handle("delegate", async (...args) => {
    await gate("delegate a key to an agent");
    return store.delegate(...args);
});

handle("adopt", async (...args) => {
    await gate("adopt an agent's key");
    return store.adopt(...args);
});

// Approve all: one confirmation and one save. Either every listed key is approved or none is.
handle("approveInjectAll", async items => {
    if (!Array.isArray(items) || items.length > 5e3 || !items.every(i => i && typeof i.project === "string" && typeof i.key === "string")) throw new Error("Invalid approval list");
    await gate("approve keys for .env");
    return store.batch(() => items.map(i => store.approveInject(i.project, i.key, true)));
});

handle("approveInject", async (...args) => {
    await gate("approve keys for .env");
    return store.approveInject(...args);
});

handle("pending", () => store.pendingApprovals());

handle("history", limit => store.listHistory(limit));

handle("revert", id => store.revert(id));

handle("audit", limit => store.readAudit(limit));

const sync = () => new (require("./sync").Sync)(store, syncRepo(store));

handle("syncStatus", async () => ({
    ...await sync().statusRemote(),
    autoSync: autoSync ? autoSync.status() : null
}));

handle("syncPush", async () => {
    const r = await sync().pushRemote();
    if (autoSync && r.delivered) autoSync.clearHalt();
    return r;
});

handle("syncPull", async accept => {
    const r = await sync().pullRemote({
        acceptConflicts: accept === true
    });
    if (autoSync) autoSync.clearHalt();
    return {
        added: r.added.map(p => ({
            project: p.projectName,
            key: p.record.key
        })),
        updated: r.updated.map(p => ({
            project: p.projectName,
            key: p.record.key
        })),
        deleted: r.deleted,
        conflicts: r.conflicts,
        unchanged: r.unchanged
    };
});

handle("syncInit", label => sync().init(label));

handle("syncIdentity", () => sync().identity());

handle("syncTrust", async identity => {
    await gate("trust a sync peer");
    return sync().trustMachine(identity);
});

handle("quit", () => app.quit(), true);

// Quick Access: unlock, search, copy, open. It never receives a secret value.
quickHandle("state", desktopState, true);

quickHandle("unlock", unlockWithPassword, true);

quickHandle("unlockTouchId", unlockWithTouchId, true);

quickHandle("confirmHuman", pw => humanAuth.confirmPassword(pw));

quickHandle("search", search);

quickHandle("hide", () => hideQuick(), true);

const quickRecord = (project, key) => {
    const p = store.findProject(project);
    const s = p && store.findSecret(p, key);
    if (!s) throw new Error("That item no longer exists");
    return s;
};

quickHandle("copy", async (project, key, field = "value") => {
    let result;
    if (field === "value") result = await copyValue(project, key); else if (field === "username" || field === "email") {
        const text = quickRecord(project, key)[field];
        if (!text) throw new Error(`This item has no ${field}`);
        clipboard.writeText(text);
        result = {
            ok: true,
            mode: "plain"
        };
    } else throw new Error("Unknown field");
    hideQuick();
    return result;
});

quickHandle("openUrl", (project, key) => {
    const url = quickRecord(project, key).url || "";
    let parsed;
    try {
        parsed = new URL(/^[a-z][a-z0-9+.-]*:/i.test(url) ? url : `https://${url}`);
    } catch {}
    if (!parsed || ![ "https:", "http:" ].includes(parsed.protocol)) throw new Error("This item has no web address to open");
    hideQuick();
    shell.openExternal(parsed.href);
    return {
        ok: true
    };
});

quickHandle("open", (project, key) => {
    quickRecord(project, key);
    hideQuick({
        returnFocus: false
    });
    showMain({
        name: "project",
        project: project,
        focusKey: key
    });
    return {
        ok: true
    };
});

quickHandle("openMain", () => {
    hideQuick({
        returnFocus: false
    });
    showMain();
    return {
        ok: true
    };
}, true);

function harden(w) {
    w.webContents.setWindowOpenHandler(() => ({
        action: "deny"
    }));
    w.webContents.on("will-navigate", e => e.preventDefault());
    w.webContents.on("will-attach-webview", e => e.preventDefault());
}

function quickWindow() {
    if (quick && !quick.isDestroyed()) return quick;
    quick = new BrowserWindow({
        width: 640,
        height: 420,
        show: false,
        frame: false,
        resizable: false,
        minimizable: false,
        maximizable: false,
        fullscreenable: false,
        skipTaskbar: true,
        alwaysOnTop: true,
        title: "Quick Access",
        backgroundColor: "#00000000",
        transparent: true,
        hasShadow: true,
        ...isMac ? {
            type: "panel"
        } : {},
        webPreferences: {
            preload: path.join(__dirname, "preload-quick.js"),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true,
            webSecurity: true,
            devTools: !app.isPackaged
        }
    });
    harden(quick);
    if (isMac) quick.setVisibleOnAllWorkspaces(true, {
        visibleOnFullScreen: true
    });
    quick.on("blur", () => {
        if (!prompting) hideQuick();
    });
    quick.on("closed", () => {
        quick = null;
    });
    quick.loadURL(URL_QUICK);
    return quick;
}

// Upper third of the display under the pointer, like Spotlight.
function placeQuick(q) {
    const area = screen.getDisplayNearestPoint(screen.getCursorScreenPoint()).workArea;
    const [w, h] = q.getSize();
    q.setPosition(Math.round(area.x + (area.width - w) / 2), Math.round(area.y + area.height * .2));
}

function showQuick() {
    if (backendOnly) return;
    const q = quickWindow();
    placeQuick(q);
    const reveal = () => {
        if (q.isDestroyed()) return;
        q.webContents.send("quick:show");
        q.show();
        q.focus();
    };
    if (q.webContents.isLoading()) q.webContents.once("did-finish-load", reveal); else reveal();
}

function hideQuick({returnFocus: returnFocus = true} = {}) {
    if (!quick || quick.isDestroyed() || !quick.isVisible()) return;
    quick.hide();
    // Give focus back to the app the human was in, unless VaultOS has its own window open.
    if (returnFocus && isMac && (!win || win.isDestroyed() || !win.isVisible())) app.hide();
}

const toggleQuick = () => quick && !quick.isDestroyed() && quick.isVisible() ? hideQuick() : showQuick();

// Opens (or creates) the main window and asks it to go somewhere: the project holding an
// item, Settings, or the search box. A locked window keeps the request until unlock.
function showMain(command = null) {
    if (backendOnly) return;
    if (command) pendingCommand = command;
    if (isMac && app.dock) app.dock.show();
    if (isMac) app.focus({
        steal: true
    });
    if (!win || win.isDestroyed()) window(); else {
        if (win.isMinimized()) win.restore();
        win.show();
        win.focus();
    }
    if (command && !win.webContents.isLoading()) win.webContents.send("vault:command");
}

// Closing the window keeps VaultOS in the menu bar (the vault still locks) only while the
// menu bar item exists; otherwise it quits as before.
const keepRunning = () => !quitting && !backendOnly && prefs.menuBar && !!tray;

function trayImage(attention) {
    const name = attention ? "trayAttention" : "tray";
    const img = nativeImage.createFromPath(path.join(__dirname, "build", "tray", isMac ? `${name}Template.png` : `${name}Light.png`));
    if (isMac) img.setTemplateImage(true);
    return img;
}

function syncLine() {
    const s = autoSync ? autoSync.status() : null;
    if (!s || !s.enabled) return null;
    if (s.halted) return "Sync stopped: needs your attention";
    if (s.running) return "Syncing…";
    return s.lastSyncAt ? `Synced ${new Date(s.lastSyncAt).toLocaleTimeString([], {
        hour: "numeric",
        minute: "2-digit"
    })}` : "Sync on";
}

function refreshTray() {
    if (!tray || tray.isDestroyed()) return;
    const unlocked = store.isUnlocked();
    let pending = 0;
    try {
        if (unlocked) pending = store.pendingApprovals().length;
    } catch {}
    const sync = unlocked ? syncLine() : null;
    const attention = pending > 0 || !!(autoSync && autoSync.status().halted);
    tray.setImage(trayImage(attention));
    tray.setToolTip(unlocked ? pending ? `VaultOS: ${pending} awaiting approval` : "VaultOS: unlocked" : "VaultOS: locked");
    const status = !unlocked ? "Locked" : humanUnlocked ? "Unlocked" : "Serving agents · window locked";
    tray.setContextMenu(Menu.buildFromTemplate([ {
        label: status,
        enabled: false
    }, ...pending ? [ {
        label: `${pending} key${pending === 1 ? "" : "s"} awaiting approval…`,
        click: () => showMain({
            name: "projects"
        })
    } ] : [], ...sync ? [ {
        label: sync,
        enabled: false
    } ] : [], {
        type: "separator"
    }, {
        label: "Quick Access…",
        accelerator: prefs.shortcut || undefined,
        registerAccelerator: false,
        click: () => showQuick()
    }, {
        label: "Open VaultOS",
        click: () => showMain()
    }, {
        label: "Lock Now",
        enabled: unlocked,
        click: () => lock()
    }, {
        type: "separator"
    }, {
        label: "Settings…",
        click: () => showMain({
            name: "settings"
        })
    }, {
        type: "separator"
    }, {
        label: "Quit VaultOS",
        click: () => app.quit()
    } ]));
    // Notifications name no keys: they can show on the lock screen.
    if (prefs.notifyApprovals && pending > lastPending && Notification.isSupported()) {
        const n = new Notification({
            title: "Agent key awaiting approval",
            body: `${pending} key${pending === 1 ? " is" : "s are"} held back from .env until you approve.`
        });
        n.on("click", () => showMain({
            name: "projects"
        }));
        n.show();
    }
    lastPending = pending;
}

function notifyExpiring() {
    if (!prefs.notifyExpiry || !Notification.isSupported() || !store.isUnlocked()) return;
    const today = (new Date).toISOString().slice(0, 10);
    if (expiryNoticeDay === today) return;
    const soon = Date.now() + 7 * 864e5;
    let count = 0;
    for (const p of store.vault.projects || []) for (const s of p.secrets || []) if (s.expiresAt && Date.parse(s.expiresAt) <= soon) count++;
    expiryNoticeDay = today;
    if (!count) return;
    const n = new Notification({
        title: "Keys expiring soon",
        body: `${count} key${count === 1 ? " expires" : "s expire"} within 7 days or already expired.`
    });
    n.on("click", () => showMain({
        name: "projects"
    }));
    n.show();
}

function applyShortcut() {
    globalShortcut.unregisterAll();
    shortcutError = "";
    if (backendOnly || !prefs.shortcut) return;
    try {
        if (!globalShortcut.register(prefs.shortcut, toggleQuick)) shortcutError = "Another app is using this shortcut. Choose a different one.";
    } catch {
        shortcutError = "This shortcut can't be used. Choose a different one.";
    }
}

function applyTray() {
    if (backendOnly) return;
    if (!prefs.menuBar) {
        if (tray && !tray.isDestroyed()) tray.destroy();
        tray = null;
        return;
    }
    if (!tray || tray.isDestroyed()) {
        try {
            tray = new Tray(trayImage(false));
        } catch {
            tray = null;
            return;
        }
        if (!isMac) tray.on("click", () => showMain());
    }
    refreshTray();
}

const loginCommand = () => [ process.execPath, ...app.isPackaged ? [] : [ app.getAppPath() ], "--hidden" ];

function applyLoginItem() {
    loginItem.setEnabled(prefs.launchAtLogin, loginCommand(), {
        dataDir: process.env.VAULTOS_DATA_DIR ? store.dataDir : null
    });
}

function applyPrefs() {
    applyShortcut();
    applyTray();
    Menu.setApplicationMenu(appMenu());
}

function desktopPrefsState() {
    return {
        ...prefs,
        shortcutError: shortcutError,
        trayAvailable: !!tray || !prefs.menuBar,
        loginItemSupported: !!loginItem.itemPath()
    };
}

function appMenu() {
    const settings = {
        label: "Settings…",
        accelerator: "CommandOrControl+,",
        click: () => showMain({
            name: "settings"
        })
    };
    const lockItem = {
        label: "Lock VaultOS",
        accelerator: "CommandOrControl+L",
        click: () => lock()
    };
    const quickItem = {
        label: "Quick Access…",
        accelerator: prefs.shortcut || undefined,
        registerAccelerator: false,
        click: () => showQuick()
    };
    const find = {
        label: "Search…",
        accelerator: "CommandOrControl+F",
        click: () => showMain({
            name: "search"
        })
    };
    return Menu.buildFromTemplate([ ...isMac ? [ {
        label: "VaultOS",
        submenu: [ {
            role: "about"
        }, {
            type: "separator"
        }, settings, lockItem, {
            type: "separator"
        }, {
            role: "services"
        }, {
            type: "separator"
        }, {
            role: "hide"
        }, {
            role: "hideOthers"
        }, {
            role: "unhide"
        }, {
            type: "separator"
        }, {
            role: "quit"
        } ]
    } ] : [], {
        label: "File",
        submenu: [ quickItem, ...isMac ? [] : [ settings, lockItem ], {
            type: "separator"
        }, isMac ? {
            role: "close"
        } : {
            role: "quit"
        } ]
    }, {
        role: "editMenu"
    }, {
        label: "View",
        submenu: [ find, ...app.isPackaged ? [] : [ {
            type: "separator"
        }, {
            role: "reload"
        }, {
            role: "toggleDevTools"
        } ] ]
    }, {
        role: "windowMenu"
    }, {
        role: "help",
        submenu: [ {
            label: "VaultOS on GitHub",
            click: () => shell.openExternal("https://github.com/rohit3a/vaultos#readme")
        }, {
            label: "Security Model",
            click: () => shell.openExternal("https://github.com/rohit3a/vaultos/blob/main/SECURITY.md")
        } ]
    } ]);
}

function window() {
    win = new BrowserWindow({
        width: 480,
        height: 740,
        minWidth: 380,
        minHeight: 500,
        title: "VaultOS",
        backgroundColor: "#0d0d0d",
        show: false,
        ...process.platform === "darwin" ? {
            titleBarStyle: "hiddenInset",
            trafficLightPosition: {
                x: 14,
                y: 18
            }
        } : {},
        webPreferences: {
            preload: path.join(__dirname, "preload.js"),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true,
            webSecurity: true,
            devTools: !app.isPackaged
        }
    });
    harden(win);
    win.webContents.session.setPermissionRequestHandler((_w, _p, cb) => cb(false));
    win.webContents.session.setPermissionCheckHandler(() => false);
    win.loadURL(URL_HOME);
    win.once("ready-to-show", () => win.show());
    // Closing the window always locks the vault, as before. With the menu bar item on, the
    // app then waits there, locked, instead of quitting.
    win.on("closed", () => {
        win = null;
        lock({
            forget: false
        });
        if (keepRunning()) {
            if (isMac && app.dock) app.dock.hide();
        } else app.quit();
    });
}

if (!app.requestSingleInstanceLock()) app.quit(); else {
    app.on("second-instance", () => showMain());
    app.whenReady().then(async () => {
        protocol.handle("vaultos-preview", request => {
            const u = new URL(request.url);
            const relative = decodeURIComponent(u.pathname).slice(1);
            const root = path.join(__dirname, "renderer");
            const file = path.resolve(root, relative);
            if (u.host !== "app" || !file.startsWith(root + path.sep) || !/\.(html|js|css|png)$/.test(file)) return new Response(null, {
                status: 404
            });
            try {
                const types = {
                    ".html": "text/html",
                    ".js": "text/javascript",
                    ".css": "text/css",
                    ".png": "image/png"
                };
                return new Response(fs.readFileSync(file), {
                    headers: {
                        "content-type": types[path.extname(file)],
                        "content-security-policy": csp,
                        "cache-control": "no-store"
                    }
                });
            } catch {
                return new Response(null, {
                    status: 404
                });
            }
        });
        powerMonitor.on("lock-screen", () => autoLock("screen"));
        powerMonitor.on("suspend", () => autoLock("suspend"));
        if (backendOnly) {
            if (app.dock) app.dock.hide();
            await own();
            if (store.autoUnlock()) await serve(); else app.quit();
        } else {
            applyPrefs();
            store.onPersist(() => refreshTray());
            // Keeps the sync line and approval count current while nothing else changes.
            setInterval(refreshTray, 3e4).unref();
            if (prefs.launchAtLogin) try {
                applyLoginItem();
            } catch {}
            if (startHidden && keepRunning()) {
                if (isMac && app.dock) app.dock.hide();
            } else window();
        }
        app.on("activate", () => showMain());
    }).catch(() => {
        process.stderr.write("VaultOS could not start. Close other preview instances and retry.\n");
        app.quit();
    });
}

app.on("before-quit", () => {
    quitting = true;
    lock({
        forget: false
    });
});

app.on("will-quit", () => globalShortcut.unregisterAll());

app.on("window-all-closed", () => {
    if (!keepRunning()) app.quit();
});

process.on("exit", () => {
    store.clearSession();
    if (release) release();
});

for (const sig of [ "SIGINT", "SIGTERM", "SIGHUP" ]) process.on(sig, () => app.quit());
