// Drives the unpacked extension in a headless Chromium with a new, empty profile: pairs it
// through the native messaging host, fills a login on a local page with real (trusted)
// clicks on the extension's controls, and saves a new login after a form is submitted.
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
const server = http.createServer((req, res) => {
    res.setHeader("content-type", "text/html; charset=utf-8");
    if (req.method === "POST") {
        req.resume();
        req.on("end", () => res.end(page("Welcome", "<p>Signed in</p>")));
        return;
    }
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
