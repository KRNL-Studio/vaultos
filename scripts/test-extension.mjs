// Drives the unpacked extension in a headless Chromium with a new, empty profile: pairs it
// through the native messaging host, fills a login on a local page with real (trusted)
// clicks on the extension's controls, saves a new login after a form is submitted, and
// registers and signs in with a passkey through the extension's passkey window.
// Run by the `extension_end_to_end` test in crates/vaultos-cli/tests/browser.rs, which
// starts the owner with a synthetic vault and checks the vault afterwards. Environment:
// VAULTOS_E2E_CHROMIUM (a Chromium or Chrome for Testing binary; branded Chrome ignores
// --load-extension), VAULTOS_DATA_DIR, VAULTOS_E2E_HOST (the vaultos-browser program),
// VAULTOS_E2E_PORT (for the local page) and VAULTOS_E2E_PROFILE (an empty folder).
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const EXTENSION_ID = "dmimjgolkikglfcphbakbmkaafaadhnb";
const env = process.env;
const extension = path.resolve("extension");
const profile = env.VAULTOS_E2E_PROFILE;
const port = Number(env.VAULTOS_E2E_PORT);

const page = (title, body) => `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>${body}</body></html>`;
const PASSKEY_PAGE = `<p>Passkeys</p><script>
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
const sha = async b => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
// WebAuthn's DER signature as the r || s that WebCrypto verifies.
function p1363(der) {
    const d = new Uint8Array(der), out = new Uint8Array(64);
    let at = 2;
    for (const half of [ 0, 1 ]) {
        let v = d.slice(at + 2, at + 2 + d[at + 1]);
        at += 2 + d[at + 1];
        if (v.length === 33) v = v.slice(1);
        out.set(v, half * 32 + 32 - v.length);
    }
    return out;
}
const created = () => ({ rp: { name: "E2E" }, user: { id: enc.encode("user-alice"), name: "alice", displayName: "Alice" },
    challenge: crypto.getRandomValues(new Uint8Array(32)), pubKeyCredParams: [ { type: "public-key", alg: -7 } ], extensions: { credProps: true } });
async function register() {
    const c = await navigator.credentials.create({ publicKey: created() });
    window.cred = c;
    const client = JSON.parse(dec.decode(c.response.clientDataJSON));
    const auth = new Uint8Array(c.response.getAuthenticatorData());
    return { instance: c instanceof PublicKeyCredential && c.response instanceof AuthenticatorAttestationResponse, type: client.type, origin: client.origin,
        alg: c.response.getPublicKeyAlgorithm(), rk: c.getClientExtensionResults().credProps.rk, flags: auth[32],
        rp: b64(auth.slice(0, 32)) === b64(await sha(enc.encode("localhost"))), json: c.toJSON().rawId === c.id };
}
async function registerAgain() {
    try {
        await navigator.credentials.create({ publicKey: { ...created(), excludeCredentials: [ { type: "public-key", id: window.cred.rawId } ] } });
        return "made a second one";
    } catch (e) {
        return e.name;
    }
}
async function signIn() {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const a = await navigator.credentials.get({ publicKey: { challenge, rpId: "localhost", allowCredentials: [ { type: "public-key", id: window.cred.rawId } ] } });
    const key = await crypto.subtle.importKey("spki", window.cred.response.getPublicKey(), { name: "ECDSA", namedCurve: "P-256" }, false, [ "verify" ]);
    const auth = new Uint8Array(a.response.authenticatorData);
    const signed = new Uint8Array([ ...auth, ...await sha(a.response.clientDataJSON) ]);
    const client = JSON.parse(dec.decode(a.response.clientDataJSON));
    return { verified: await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, p1363(a.response.signature), signed),
        sameId: a.id === window.cred.id, challenge: client.challenge === b64(challenge), type: client.type, origin: client.origin,
        user: dec.decode(a.response.userHandle), instance: a.response instanceof AuthenticatorAssertionResponse };
}
</script>`;
const server = http.createServer((req, res) => {
    res.setHeader("content-type", "text/html; charset=utf-8");
    if (req.method === "POST") {
        req.resume();
        req.on("end", () => res.end(page("Welcome", "<p>Signed in</p>")));
        return;
    }
    if (req.url === "/done") return res.end(page("Welcome", "<p>Signed in</p>"));
    if (req.url === "/passkey") return res.end(page("Passkeys", PASSKEY_PAGE));
    res.end(page("Sign in", `<form method="post" action="/welcome" style="margin:40px">
<label>Email <input id="user" name="username" autocomplete="username" style="width:260px"></label><br><br>
<label>Password <input id="pass" type="password" name="password" autocomplete="current-password" style="width:260px"></label><br><br>
<button id="go" type="submit">Sign in</button></form>`));
});
await new Promise(r => server.listen(port, "127.0.0.1", r));

mkdirSync(path.join(profile, "NativeMessagingHosts"), { recursive: true });
writeFileSync(path.join(profile, "NativeMessagingHosts", "org.vaultos.preview.browser.json"), JSON.stringify({
    name: "org.vaultos.preview.browser",
    description: "VaultOS browser extension helper (test)",
    path: env.VAULTOS_E2E_HOST,
    type: "stdio",
    allowed_origins: [ `chrome-extension://${EXTENSION_ID}/` ]
}));

const chrome = spawn(env.VAULTOS_E2E_CHROMIUM, [
    "--headless=new", `--user-data-dir=${profile}`, "--remote-debugging-port=0", "--no-first-run",
    "--no-default-browser-check", "--disable-gpu", "--window-size=1200,900",
    `--disable-extensions-except=${extension}`, `--load-extension=${extension}`,
    ...env.VAULTOS_E2E_NO_SANDBOX ? [ "--no-sandbox" ] : [], "about:blank"
], { stdio: [ "ignore", "ignore", "pipe" ] });
let chromeLog = "";
chrome.stderr.on("data", d => { chromeLog = (chromeLog + d).slice(-4000); });

async function until(what, fn, ms = 20000) {
    const end = Date.now() + ms;
    for (;;) {
        const v = await fn().catch(() => null);
        if (v) return v;
        if (Date.now() > end) throw new Error(`Timed out waiting for ${what}`);
        await sleep(200);
    }
}

let ws;
try {
    const active = await until("DevToolsActivePort", async () => readFileSync(path.join(profile, "DevToolsActivePort"), "utf8"));
    const [ devPort, devPath ] = active.trim().split("\n");
    ws = new WebSocket(`ws://127.0.0.1:${devPort}${devPath}`);
    await new Promise((resolve, reject) => {
        ws.onopen = resolve;
        ws.onerror = reject;
    });
    let next = 0;
    const waiting = new Map(), targets = new Map();
    ws.onmessage = e => {
        const m = JSON.parse(e.data);
        if (m.id && waiting.has(m.id)) {
            const { resolve, reject } = waiting.get(m.id);
            waiting.delete(m.id);
            if (m.error) reject(new Error(`${m.error.message} ${m.error.data || ""}`));
            else resolve(m.result);
        } else if (m.method === "Target.targetCreated" || m.method === "Target.targetInfoChanged") {
            targets.set(m.params.targetInfo.targetId, m.params.targetInfo);
        }
    };
    const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
        const id = ++next;
        waiting.set(id, { resolve, reject });
        ws.send(JSON.stringify({ id, method, params, ...sessionId ? { sessionId } : {} }));
    });
    const evaluate = async (session, expression) => {
        const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, session);
        if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
        return r.result.value;
    };
    await send("Target.setDiscoverTargets", { discover: true });

    // Pair, as the popup's button does; the owner's test confirmation says yes.
    const worker = await until("the extension's service worker", async () => [ ...targets.values() ].find(t => t.type === "service_worker" && t.url.startsWith(`chrome-extension://${EXTENSION_ID}/`)));
    const { sessionId: sw } = await send("Target.attachToTarget", { targetId: worker.targetId, flatten: true });
    // The worker's target can appear before its script has run.
    await until("the service worker's script", () => evaluate(sw, `typeof popupOps === "object"`));
    const status = await evaluate(sw, `popupOps.state()`);
    if (!status.ok || !status.running || !status.unlocked || status.paired) throw new Error(`Unexpected state before pairing: ${JSON.stringify(status)}`);
    const started = await evaluate(sw, `popupOps.pair({ name: "E2E Chromium" })`);
    if (!started.ok || !/^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(started.code)) throw new Error(`Pairing did not start: ${JSON.stringify(started)}`);
    await until("the pairing key", () => evaluate(sw, `pairingKey().then(Boolean)`));
    const paired = await evaluate(sw, `popupOps.state()`);
    if (paired.paired !== "E2E Chromium") throw new Error(`Not paired: ${JSON.stringify(paired)}`);
    console.log(`paired with code ${started.code}`);

    const { targetId } = await send("Target.createTarget", { url: `http://localhost:${port}/login` });
    const { sessionId: tab } = await send("Target.attachToTarget", { targetId, flatten: true });
    await send("Runtime.enable", {}, tab);
    await until("the login page", () => evaluate(tab, `document.readyState === "complete" && Boolean(document.getElementById("user"))`));

    // Controls in the extension's closed shadow root, found the way DevTools shows them.
    const find = async (cls, text) => {
        const { root } = await send("DOM.getDocument", { depth: -1, pierce: true }, tab);
        const hits = [];
        const walk = (n, inUi) => {
            const attrs = Object.fromEntries((n.attributes || []).reduce((a, v, i, all) => i % 2 ? a : [ ...a, [ v, all[i + 1] ] ], []));
            const here = inUi || n.localName === "vaultos-ui";
            if (here && (attrs.class || "").split(" ").includes(cls)) hits.push(n);
            for (const c of [ ...n.children || [], ...n.shadowRoots || [] ]) walk(c, here);
        };
        walk(root, false);
        for (const n of hits) {
            if (!text) return n.backendNodeId;
            const { outerHTML } = await send("DOM.getOuterHTML", { backendNodeId: n.backendNodeId }, tab);
            if (outerHTML.includes(text)) return n.backendNodeId;
        }
        return null;
    };
    const click = async backendNodeId => {
        const { model } = await send("DOM.getBoxModel", { backendNodeId }, tab);
        const q = model.content;
        const x = (q[0] + q[2]) / 2, y = (q[1] + q[5]) / 2;
        for (const type of [ "mousePressed", "mouseReleased" ]) await send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 }, tab);
    };
    const clickPage = async selector => {
        const { root } = await send("DOM.getDocument", { depth: 0 }, tab);
        const { nodeId } = await send("DOM.querySelector", { nodeId: root.nodeId, selector }, tab);
        const { node } = await send("DOM.describeNode", { nodeId }, tab);
        await click(node.backendNodeId);
    };

    // A script's click does nothing; a person's opens the menu and fills.
    await clickPage("#user");
    const button = await until("the VaultOS button", () => find("button"));
    await send("DOM.resolveNode", { backendNodeId: button }, tab).then(({ object }) => send("Runtime.callFunctionOn", { objectId: object.objectId, functionDeclaration: "function () { this.click(); }" }, tab));
    await sleep(500);
    if (await find("item")) throw new Error("A script's click opened the menu");
    await click(button);
    const item = await until("the login in the menu", () => find("item", "alice"));
    // Controls act only once they have been visible for a moment.
    await sleep(700);
    await click(item);
    const values = await until("the filled login", async () => {
        const v = await evaluate(tab, `[document.getElementById("user").value, document.getElementById("pass").value]`);
        return v[0] && v[1] ? v : null;
    });
    if (values[0] !== "alice" || values[1] !== "synthetic-e2e-pass") throw new Error(`Filled the wrong values: ${values[0]}`);
    console.log("filled the login");

    // A new login, submitted: the next page offers to save it.
    await evaluate(tab, `(() => { const s = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
        s.call(document.getElementById("user"), "bob"); s.call(document.getElementById("pass"), "synthetic-e2e-new"); })()`);
    await clickPage("#go");
    await until("the welcome page", () => evaluate(tab, `document.title === "Welcome"`));
    const save = await until("the save offer", () => find("primary", "Save"));
    await sleep(700);
    await click(save);
    await until("the saved note", () => find("note", "Saved as"));
    console.log("saved the new login");

    // The popup offers a submitted login only where the page shows no sign-in form again.
    // The worker cannot read tabs' addresses, so the test's tab is the one whose content
    // script answers.
    const testTab = `(async () => {
        for (const t of await api.tabs.query({})) {
            try {
                await api.tabs.sendMessage(t.id, { op: "signInShown" }, { frameId: 0 });
                return t;
            } catch {}
        }
        throw new Error("No tab has the content script");
    })()`;
    const popupSave = async (url, op) => {
        await send("Page.navigate", { url }, tab);
        await until(url, () => evaluate(tab, `document.readyState === "complete" && location.href === ${JSON.stringify(url)}`));
        return evaluate(sw, `(async () => {
            const t = await ${testTab};
            await session.set({ [\`save:\${t.id}\`]: { url: ${JSON.stringify(url)}, username: "carol", password: "synthetic-e2e-refused", at: Date.now() } });
            return popupOps.${op}({ tabId: t.id });
        })()`);
    };
    await send("Page.enable", {}, tab);
    const refused = await popupSave(`http://localhost:${port}/login`, "tabPendingSave");
    if (!refused.ok || refused.pending !== null) throw new Error(`The popup offered a refused login: ${JSON.stringify(refused)}`);
    const notSaved = await popupSave(`http://localhost:${port}/login`, "tabSave");
    if (notSaved.ok) throw new Error("The popup saved a refused login");
    const offered = await popupSave(`http://localhost:${port}/done`, "tabPendingSave");
    if (!offered.ok || !offered.pending || offered.pending.username !== "carol") throw new Error(`The popup did not offer the login: ${JSON.stringify(offered)}`);
    await evaluate(sw, `${testTab}.then(t => popupOps.tabDismissSave({ tabId: t.id }))`);
    console.log("the popup offers saves only without a sign-in form");
    // Passkeys: the page's WebAuthn call opens the extension's window, where the human chooses.
    await send("Page.enable", {}, tab);
    await send("Page.navigate", { url: `http://localhost:${port}/passkey` }, tab);
    await until("the passkey page", () => evaluate(tab, `document.readyState === "complete" && typeof register === "function"`));
    const choose = async (call, selector) => {
        const seen = new Set([ ...targets.values() ].filter(t => t.url.includes("/passkey.html")).map(t => t.targetId));
        const pending = evaluate(tab, call);
        const win = await until("the passkey window", async () => [ ...targets.values() ].find(t => t.type === "page" && t.url.startsWith(`chrome-extension://${EXTENSION_ID}/passkey.html`) && !seen.has(t.targetId)));
        const { sessionId: w } = await send("Target.attachToTarget", { targetId: win.targetId, flatten: true });
        await until(`${selector} in the passkey window`, () => evaluate(w, `Boolean(document.querySelector(${JSON.stringify(selector)}))`));
        evaluate(w, `document.querySelector(${JSON.stringify(selector)}).click()`).catch(() => null);
        return pending;
    };
    const made = await choose(`register()`, "button.primary");
    const want = { instance: true, type: "webauthn.create", origin: `http://localhost:${port}`, alg: -7, rk: true, flags: 0x5d, rp: true, json: true };
    if (JSON.stringify(made) !== JSON.stringify(want)) throw new Error(`Unexpected passkey: ${JSON.stringify(made)}`);
    console.log("registered a passkey");
    const again = await choose(`registerAgain()`, "button.primary");
    if (again !== "InvalidStateError") throw new Error(`A second passkey for the account: ${again}`);
    const signedIn = await choose(`signIn()`, "li button");
    const wantIn = { verified: true, sameId: true, challenge: true, type: "webauthn.get", origin: `http://localhost:${port}`, user: "user-alice", instance: true };
    if (JSON.stringify(signedIn) !== JSON.stringify(wantIn)) throw new Error(`Unexpected sign-in: ${JSON.stringify(signedIn)}`);
    console.log("signed in with the passkey");
    await send("Browser.close").catch(() => null);
} catch (e) {
    console.error(e && e.stack || e);
    console.error(chromeLog);
    process.exitCode = 1;
} finally {
    if (ws) ws.close();
    chrome.kill();
    server.close();
}
