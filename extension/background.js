// The extension's service worker: the only part that talks to VaultOS, through the native
// messaging host. It also holds the page's passkey requests while the human decides in the
// extension's passkey window. It holds the pairing key in this extension's IndexedDB, which content
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

/**
 * Whether the tab's page shows a sign-in form again, which usually means the password was
 * refused; true when its content script cannot say. The in-page offer checks the same.
 */
async function signInShown(tabId) {
    try {
        return await api.tabs.sendMessage(tabId, { op: "signInShown" }, { frameId: 0 }) !== false;
    } catch {
        return true;
    }
}

/** Passkey requests waiting for the human in the extension's window, by request id. */
const passkeyRequests = new Map();
const PASSKEY_WINDOW = "passkey.html";
// The page's request is a message whose answer this worker holds; Chrome ends a worker
// whose one event runs five minutes, so a request ends first, as if it timed out.
const PASSKEY_WAIT_MAX = 4 * 60 * 1000;
const PASSKEY_WAIT_MIN = 15 * 1000;
// More credential IDs than this and VaultOS cannot tell which the site has: the browser's own.
const MAX_CREDENTIAL_LIST = 64;
const VERIFICATION = [ "required", "preferred", "discouraged" ];

const fromPasskeyWindow = s => s.id === api.runtime.id && typeof s.url === "string" && s.url.startsWith(api.runtime.getURL(PASSKEY_WINDOW));

function finishPasskey(id, result) {
    const r = passkeyRequests.get(id);
    if (!r) return;
    passkeyRequests.delete(id);
    clearTimeout(r.timer);
    r.resolve(result);
    if (r.windowId !== undefined) api.windows.remove(r.windowId).catch(() => {});
}

api.windows.onRemoved.addListener(windowId => {
    for (const [ id, r ] of passkeyRequests) if (r.windowId === windowId) finishPasskey(id, { ok: false, code: "cancel" });
});

const b64urlOk = (v, max) => typeof v === "string" && v.length <= Math.ceil(max / 3) * 4 && /^[A-Za-z0-9_-]*$/.test(v);

/** The parts of a page's request VaultOS uses, checked; null when it is not one. */
function passkeyRequest(kind, q) {
    if (!q || typeof q.rpId !== "string" || q.rpId.length > 253 || !b64urlOk(q.challenge, 1024)) return null;
    const ids = list => list === undefined ? [] : Array.isArray(list) && list.length <= MAX_CREDENTIAL_LIST && list.every(c => b64urlOk(c, 1023)) ? list : null;
    const userVerification = VERIFICATION.includes(q.userVerification) ? q.userVerification : "preferred";
    const timeout = Number.isFinite(q.timeout) && q.timeout > 0 ? Math.min(Math.max(q.timeout, PASSKEY_WAIT_MIN), PASSKEY_WAIT_MAX) : PASSKEY_WAIT_MAX;
    if (kind === "get") {
        const allow = ids(q.allow);
        return allow && { rpId: q.rpId, challenge: q.challenge, allow, userVerification, timeout };
    }
    const u = q.user || {};
    const exclude = ids(q.exclude);
    if (!b64urlOk(u.id, 64) || !exclude) return null;
    return {
        rpId: q.rpId,
        rpName: String(q.rpName || "").slice(0, 100),
        user: { id: u.id, name: String(u.name || "").slice(0, 256), displayName: String(u.displayName || "").slice(0, 256) },
        challenge: q.challenge,
        algorithms: Array.isArray(q.algorithms) ? q.algorithms.slice(0, 16).map(Number) : [],
        exclude,
        userVerification,
        timeout
    };
}

// pageOps.passkey: from the top frame's content script.
async function passkey(m, s) {
    if (s.frameId !== 0) return { ok: false, code: "fallback" };
    const kind = m.kind === "create" || m.kind === "get" ? m.kind : null;
    const q = kind && passkeyRequest(kind, m.request);
    if (!q) return { ok: false, code: "fallback" };
    // One request per tab: a new one replaces the one before.
    for (const [ id, r ] of passkeyRequests) if (r.tabId === s.tab.id) finishPasskey(id, { ok: false, code: "cancel" });
    if (!await pairingKey()) return { ok: false, code: "fallback" };
    let passkeys = [];
    if (kind === "get") {
        const r = await call("passkeys", { url: s.url, rpId: q.rpId, allow: q.allow });
        if (!r.ok || !r.passkeys.length) return { ok: false, code: "fallback" };
        passkeys = r.passkeys;
    } else {
        // VaultOS makes ES256 keys only; a site that takes none of them gets the browser's own.
        if (!q.algorithms.includes(-7)) return { ok: false, code: "fallback" };
        const status = await native({ op: "status" });
        if (!status.ok || !status.running || !status.unlocked) return { ok: false, code: "fallback" };
    }
    const id = S.pairingCode(crypto.getRandomValues(new Uint8Array(8)));
    const done = new Promise(resolve => passkeyRequests.set(id, { kind, tabId: s.tab.id, pageId: m.id, url: s.url, q, passkeys, resolve }));
    passkeyRequests.get(id).timer = setTimeout(() => finishPasskey(id, { ok: false, code: "cancel" }), q.timeout);
    try {
        const w = await api.windows.create({ url: api.runtime.getURL(`${PASSKEY_WINDOW}#${id}`), type: "popup", width: 420, height: 480, focused: true });
        const r = passkeyRequests.get(id);
        if (r) r.windowId = w.id;
        else api.windows.remove(w.id).catch(() => {});
    } catch {
        // No window, no choice: the browser's own WebAuthn instead.
        finishPasskey(id, { ok: false, code: "fallback" });
    }
    return done;
}

// pageOps.passkeyCancel: the page aborted its request.
async function passkeyCancel(m, s) {
    for (const [ id, r ] of passkeyRequests) if (r.tabId === s.tab.id && r.pageId === m.id) finishPasskey(id, { ok: false, code: "cancel" });
    return { ok: true };
}

const passkeyWindowOps = {
    /** What the window shows: the site the browser reports, never the page's own words alone. */
    async passkeyShow(m) {
        const r = passkeyRequests.get(String(m.id || ""));
        if (!r) return { ok: false, code: "expired", error: "This request is no longer waiting." };
        return {
            ok: true,
            kind: r.kind,
            site: hostOf(r.url),
            rpId: r.q.rpId,
            user: r.kind === "create" ? { name: r.q.user.name, displayName: r.q.user.displayName } : null,
            passkeys: r.passkeys.map(p => ({ projectId: p.projectId, itemId: p.itemId, name: p.name, username: p.username, project: p.project }))
        };
    },
    async passkeyAnswer(m) {
        const id = String(m.id || "");
        const r = passkeyRequests.get(id);
        if (!r) return { ok: false, code: "expired", error: "This request is no longer waiting." };
        if (m.choice === "other") {
            finishPasskey(id, { ok: false, code: "fallback" });
            return { ok: true };
        }
        if (m.choice === "cancel") {
            finishPasskey(id, { ok: false, code: "cancel" });
            return { ok: true };
        }
        let result;
        const { timeout, ...q } = r.q;
        if (r.kind === "create") {
            result = await call("passkeyCreate", { url: r.url, ...q });
            if (!result.ok && result.code === "conflict") result = { ok: false, code: "exists", error: result.error };
        } else {
            const pick = r.passkeys.find(p => p.projectId === m.projectId && p.itemId === m.itemId);
            if (!pick) return { ok: false, code: "usage", error: "Choose one of the passkeys shown." };
            result = await call("passkeyGet", {
                url: r.url,
                rpId: q.rpId,
                challenge: q.challenge,
                projectId: pick.projectId,
                itemId: pick.itemId,
                credentialId: pick.credentialId,
                userVerification: q.userVerification
            });
        }
        // The site requires verifying the human, and there is no Touch ID: the browser's own.
        if (!result.ok && result.code === "unverified") {
            finishPasskey(id, { ok: false, code: "fallback" });
            return { ok: true };
        }
        if (!result.ok && result.code !== "exists") return result;
        finishPasskey(id, result);
        return { ok: true };
    },
    /** The window's heartbeat, which keeps this worker running while the human decides. */
    async passkeyWait(m) {
        return { ok: true, waiting: passkeyRequests.has(String(m.id || "")) };
    }
};

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
        if (await signInShown(m.tabId)) return { ok: true, pending: null };
        return pageOps.pendingSave(m, { tab: { id: m.tabId }, frameId: 0 });
    },
    async tabSave(m) {
        if (await signInShown(m.tabId)) return { ok: false, code: "refused", error: "This page shows a sign-in form again, so the password may have been refused. Nothing was saved." };
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
    },
    passkey,
    passkeyCancel
};

api.runtime.onMessage.addListener((m, sender, respond) => {
    const op = m && typeof m.op === "string" ? m.op : "";
    let handler = null;
    if (Object.hasOwn(popupOps, op) && fromPopup(sender)) handler = popupOps[op];
    else if (Object.hasOwn(pageOps, op) && fromPage(sender)) handler = pageOps[op];
    else if (Object.hasOwn(passkeyWindowOps, op) && fromPasskeyWindow(sender)) handler = passkeyWindowOps[op];
    if (!handler) {
        respond({ ok: false, code: "refused", error: "Not allowed" });
        return false;
    }
    handler(m, sender).then(respond, e => respond({ ok: false, code: "error", error: String(e && e.message || e) }));
    return true;
});
