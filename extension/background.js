// The extension's service worker: the only part that talks to VaultOS, through the native
// messaging host. It holds the pairing key in this extension's IndexedDB, which content
// scripts (running in pages' origins) cannot open, and never gives it to a page. Page URLs
// come from the browser (`sender.url`), never from the page; the app decides what may be
// filled where.
"use strict";

importScripts("shared.js");

const HOST = "org.vaultos.preview.browser";
const api = globalThis.browser ?? globalThis.chrome;
const S = globalThis.VaultOSShared;
/** Safari sends native messages to the app extension inside VaultOS.app; it has no ports to it. */
const SAFARI = api.runtime.getURL("").startsWith("safari-web-extension:");
/** How long a submitted login waits for the human to choose Save. */
const SAVE_WINDOW_MS = 2 * 60 * 1000;
/** How long the login filled in a tab is remembered, to know which one a new password is for. */
const FILLED_MS = 15 * 60 * 1000;
const NO_HOST = "The VaultOS browser helper is not set up. In VaultOS, open Settings and choose Set up browsers.";

function database() {
    return new Promise((resolve, reject) => {
        const r = indexedDB.open("vaultos", 1);
        r.onupgradeneeded = () => r.result.createObjectStore("pairing");
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
    });
}

async function pairingKey(value) {
    const db = await database();
    return new Promise((resolve, reject) => {
        const store = db.transaction("pairing", value === undefined ? "readonly" : "readwrite").objectStore("pairing");
        const r = value === undefined ? store.get("key") : value === null ? store.delete("key") : store.put(value, "key");
        r.onsuccess = () => resolve(value === undefined ? r.result ?? null : null);
        r.onerror = () => reject(r.error);
    });
}

async function native(message) {
    try {
        const reply = await api.runtime.sendNativeMessage(HOST, message);
        return reply ?? { ok: false, code: "no_host", error: NO_HOST };
    } catch {
        return { ok: false, code: "no_host", error: NO_HOST };
    }
}

/** An operation with the pairing key; a key the app no longer knows is forgotten. */
async function call(op, params) {
    const key = await pairingKey();
    if (!key) return { ok: false, code: "unpaired", error: "Pair this browser with VaultOS first." };
    const r = await native({ ...params, op, key });
    if (!r.ok && r.code === "unpaired") await pairingKey(null);
    return r;
}

async function sha256(text) {
    const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(d), b => b.toString(16).padStart(2, "0")).join("");
}

function hostOf(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return "";
    }
}

const session = api.storage.session;
let pairing = null;

const expired = (k, v) => !v || (k.startsWith("save:") && Date.now() - v.at > SAVE_WINDOW_MS) || (k.startsWith("filled:") && Date.now() - v.at > FILLED_MS);

/** Removes submitted passwords nobody saved in time, and old fill records. */
async function purge() {
    const all = await session.get(null);
    const old = Object.keys(all).filter(k => expired(k, all[k]));
    if (old.length) await session.remove(old);
}

async function stored(k) {
    const v = (await session.get(k))[k];
    if (!v || !expired(k, v)) return v || null;
    await session.remove(k);
    return null;
}

api.alarms.onAlarm.addListener(a => {
    if (a.name === "purge") purge();
});
api.tabs.onRemoved.addListener(tabId => session.remove([ `save:${tabId}`, `filled:${tabId}` ]));
purge();

/**
 * The login a submitted password would update: the one filled in this tab if it has the same
 * username, else the only saved login for the site with that username. `"several"` when
 * there is more than one and none was filled, so the human changes it in the app.
 */
async function target(p, tabId) {
    const r = await call("logins", { url: p.url });
    if (!r.ok) return null;
    const same = r.logins.filter(l => l.username === p.username);
    const filled = await stored(`filled:${tabId}`);
    const was = filled && same.find(l => l.projectId === filled.projectId && l.itemId === filled.itemId);
    if (was) return was;
    if (same.length > 1) return "several";
    return same[0] || null;
}

const fromPopup = s => s.id === api.runtime.id && !s.tab && typeof s.url === "string" && s.url.startsWith(api.runtime.getURL(""));
const fromPage = s => s.id === api.runtime.id && Boolean(s.tab) && typeof s.url === "string" && /^https?:\/\//.test(s.url);

const popupOps = {
    async state() {
        const status = await native({ op: "status" });
        if (!status.ok) return status;
        const key = await pairingKey();
        let paired = null;
        if (key && status.running && status.unlocked) {
            const who = await call("whoami", {});
            paired = who.ok ? who.name : null;
        } else if (key) paired = "";
        return { ok: true, running: status.running, unlocked: status.unlocked, paired, pairing };
    },
    async pair(m) {
        if (pairing) return { ok: false, code: "busy", error: "A pairing is already waiting for you in VaultOS." };
        const code = S.pairingCode(crypto.getRandomValues(new Uint8Array(8)));
        pairing = { code, error: null };
        // The popup closes when the app takes focus, so the pairing finishes here. An open
        // native port keeps this worker running while the human decides.
        let done = false;
        const finish = async r => {
            if (done) return;
            done = true;
            if (r.ok && r.key) await pairingKey(r.key);
            pairing = r.ok ? null : { code, error: r.error || NO_HOST };
            setTimeout(() => { if (pairing && pairing.code === code) pairing = null; }, 30_000);
        };
        const request = { op: "pair", name: String(m.name || "Browser").slice(0, 60), code };
        if (SAFARI) {
            native(request).then(finish);
            return { ok: true, code };
        }
        const port = api.runtime.connectNative(HOST);
        port.onMessage.addListener(r => {
            port.disconnect();
            finish(r || {});
        });
        port.onDisconnect.addListener(() => finish({ ok: false, error: NO_HOST }));
        port.postMessage(request);
        return { ok: true, code };
    },
    async forget() {
        await pairingKey(null);
        return { ok: true };
    },
    async tabLogins(m) {
        const tab = await api.tabs.get(m.tabId);
        if (!tab.url || !/^https?:\/\//.test(tab.url)) return { ok: true, logins: [] };
        return call("logins", { url: tab.url });
    },
    async fillTab(m) {
        // The page's own script asks to fill, so its address comes from the browser.
        await api.tabs.sendMessage(m.tabId, { op: "fill", projectId: m.projectId, itemId: m.itemId }, { frameId: 0 });
        return { ok: true };
    },
    // A login submitted in the tab, offered here too (and only here where pages get no
    // controls). The tab's own records, as the page's top frame would see them.
    async tabPendingSave(m) {
        return pageOps.pendingSave(m, { tab: { id: m.tabId }, frameId: 0 });
    },
    async tabSave(m) {
        return pageOps.save(m, { tab: { id: m.tabId }, frameId: 0 });
    },
    async tabDismissSave(m) {
        return pageOps.dismissSave(m, { tab: { id: m.tabId }, frameId: 0 });
    }
};

const pageOps = {
    async logins(m, s) {
        return call("logins", { url: s.url });
    },
    async fill(m, s) {
        const r = await call("fill", { url: s.url, projectId: String(m.projectId || ""), itemId: String(m.itemId || "") });
        if (r.ok) {
            const filled = { username: r.username, passwordHash: await sha256(r.password || ""), projectId: String(m.projectId), itemId: String(m.itemId), at: Date.now() };
            await session.set({ [`filled:${s.tab.id}`]: filled });
        }
        return r;
    },
    async offerSave(m, s) {
        let username = String(m.username || "").slice(0, 256);
        const password = String(m.password || "");
        if (!password || password.length > 4096) return { ok: true, offered: false };
        const filled = await stored(`filled:${s.tab.id}`);
        // A change-password form often shows no username: it is the one just filled.
        if (!username && filled) username = filled.username;
        if (S.sameLogin(filled, { username, passwordHash: await sha256(password) })) return { ok: true, offered: false };
        await session.set({ [`save:${s.tab.id}`]: { url: s.url, username, password, at: Date.now() } });
        await api.alarms.create("purge", { when: Date.now() + SAVE_WINDOW_MS + 1000 });
        return { ok: true, offered: true };
    },
    async pendingSave(m, s) {
        if (s.frameId !== 0) return { ok: true, pending: null };
        const p = await stored(`save:${s.tab.id}`);
        if (!p) return { ok: true, pending: null };
        const t = await target(p, s.tab.id);
        // Several logins could be meant: none is offered, rather than one picked.
        if (t === "several") return { ok: true, pending: null };
        const update = t ? { name: t.name, project: t.project } : null;
        return { ok: true, pending: { username: p.username, site: hostOf(p.url), update } };
    },
    async save(m, s) {
        const k = `save:${s.tab.id}`;
        const p = await stored(k);
        await session.remove(k);
        if (!p) return { ok: false, code: "expired", error: "Nothing is waiting to be saved." };
        const t = await target(p, s.tab.id);
        if (t === "several") return { ok: false, code: "conflict", error: "Several logins for this site use this username; change the password in VaultOS." };
        const ids = t ? { projectId: t.projectId, itemId: t.itemId } : {};
        return call("save", { url: p.url, username: p.username, password: p.password, ...ids });
    },
    async dismissSave(m, s) {
        await session.remove(`save:${s.tab.id}`);
        return { ok: true };
    }
};

api.runtime.onMessage.addListener((m, sender, respond) => {
    const op = m && typeof m.op === "string" ? m.op : "";
    let handler = null;
    if (Object.hasOwn(popupOps, op) && fromPopup(sender)) handler = popupOps[op];
    else if (Object.hasOwn(pageOps, op) && fromPage(sender)) handler = pageOps[op];
    if (!handler) {
        respond({ ok: false, code: "refused", error: "Not allowed" });
        return false;
    }
    handler(m, sender).then(respond, e => respond({ ok: false, code: "error", error: String(e && e.message || e) }));
    return true;
});
