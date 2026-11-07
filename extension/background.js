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
/** How long a submitted login waits for the human to choose Save. */
const SAVE_WINDOW_MS = 2 * 60 * 1000;
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
        const port = api.runtime.connectNative(HOST);
        port.onMessage.addListener(r => {
            port.disconnect();
            finish(r || {});
        });
        port.onDisconnect.addListener(() => finish({ ok: false, error: NO_HOST }));
        port.postMessage({ op: "pair", name: String(m.name || "Browser").slice(0, 60), code });
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
    }
};

const pageOps = {
    async logins(m, s) {
        return call("logins", { url: s.url });
    },
    async fill(m, s) {
        const r = await call("fill", { url: s.url, projectId: String(m.projectId || ""), itemId: String(m.itemId || "") });
        if (r.ok) {
            await session.set({ [`filled:${s.tab.id}`]: { username: r.username, passwordHash: await sha256(r.password || "") } });
        }
        return r;
    },
    async offerSave(m, s) {
        const username = String(m.username || "").slice(0, 256), password = String(m.password || "");
        if (!password || password.length > 4096) return { ok: true, offered: false };
        const filled = (await session.get(`filled:${s.tab.id}`))[`filled:${s.tab.id}`];
        if (S.sameLogin(filled, { username, passwordHash: await sha256(password) })) return { ok: true, offered: false };
        await session.set({ [`save:${s.tab.id}`]: { url: s.url, username, password, at: Date.now() } });
        return { ok: true, offered: true };
    },
    async pendingSave(m, s) {
        if (s.frameId !== 0) return { ok: true, pending: null };
        const p = (await session.get(`save:${s.tab.id}`))[`save:${s.tab.id}`];
        if (!p || Date.now() - p.at > SAVE_WINDOW_MS) return { ok: true, pending: null };
        return { ok: true, pending: { username: p.username, site: hostOf(p.url) } };
    },
    async save(m, s) {
        const k = `save:${s.tab.id}`;
        const p = (await session.get(k))[k];
        await session.remove(k);
        if (!p || Date.now() - p.at > SAVE_WINDOW_MS) return { ok: false, code: "expired", error: "Nothing is waiting to be saved." };
        return call("save", { url: p.url, username: p.username, password: p.password });
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
