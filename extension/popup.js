// The toolbar popup: pairing, a login waiting to be saved, and the logins for the current tab.
"use strict";

const api = globalThis.browser ?? globalThis.chrome;
const S = globalThis.VaultOSShared;
const main = document.getElementById("main");
const ask = m => api.runtime.sendMessage(m).catch(e => ({ ok: false, error: String(e && e.message || e) }));

function el(tag, className, text) {
    const e = document.createElement(tag);
    if (className) e.className = className;
    if (text !== undefined) e.textContent = text;
    return e;
}

function button(text, className, act) {
    const b = el("button", className, text);
    b.type = "button";
    b.addEventListener("click", act);
    return b;
}

function show(...nodes) {
    main.replaceChildren(...nodes);
}

let timer = null;
function again(ms) {
    clearTimeout(timer);
    timer = setTimeout(render, ms);
}

async function activeTab() {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    return tab || null;
}

async function render() {
    const st = await ask({ op: "state" });
    if (!st.ok) return show(el("p", "error", st.error || "VaultOS is not available."));
    if (st.pairing && !st.pairing.error) {
        again(1500);
        return show(
            el("p", null, "Confirm in VaultOS if it shows this code:"),
            el("div", "code", st.pairing.code),
            el("p", "muted", "The request waits two minutes.")
        );
    }
    if (!st.running) return show(el("p", null, "Open the VaultOS app to fill logins."));
    if (!st.unlocked) {
        again(3000);
        return show(el("p", null, "Unlock VaultOS to fill logins."));
    }
    if (!st.paired) {
        const nodes = [ el("p", null, "Pair this browser with VaultOS to fill and save logins.") ];
        if (st.pairing && st.pairing.error) nodes.push(el("p", "error", st.pairing.error));
        nodes.push(button("Pair with VaultOS", "primary", pair));
        return show(...nodes);
    }
    const nodes = [];
    const tab = await activeTab();
    const pending = tab ? await ask({ op: "tabPendingSave", tabId: tab.id }) : null;
    if (pending && pending.ok && pending.pending) nodes.push(saveOffer(tab, pending.pending));
    const r = tab ? await ask({ op: "tabLogins", tabId: tab.id }) : { ok: true, logins: [] };
    if (!r.ok) nodes.push(el("p", "error", r.error));
    else if (!r.logins.length) nodes.push(el("p", "muted", "No VaultOS logins for this page."));
    else {
        const list = el("ul");
        for (const login of r.logins) {
            const b = button("", null, async () => {
                const f = await ask({ op: "fillTab", tabId: tab.id, projectId: login.projectId, itemId: login.itemId });
                if (f.ok) window.close();
                else show(el("p", "error", f.error || "VaultOS could not fill this login."));
            });
            b.append(el("span", "name", login.name), el("span", "sub", S.loginDetail(login)));
            const li = el("li");
            li.append(b);
            list.append(li);
        }
        nodes.push(list);
    }
    const row = el("div", "row");
    row.append(el("span", "muted", `Paired as ${st.paired}`), button("Forget", null, forget));
    nodes.push(row);
    show(...nodes);
}

function saveOffer(tab, p) {
    const box = el("div", "offer");
    const who = p.username ? ` as ${p.username}` : "";
    if (p.update) box.append(el("p", "name", "Update this password in VaultOS?"), el("p", "sub", `${p.update.name} in ${p.update.project}${who}`));
    else box.append(el("p", "name", "Save this login in VaultOS?"), el("p", "sub", `${p.site}${who}`));
    const row = el("div", "row");
    row.append(button("Not now", null, async () => {
        await ask({ op: "tabDismissSave", tabId: tab.id });
        render();
    }), button(p.update ? "Update" : "Save", "primary", async () => {
        const s = await ask({ op: "tabSave", tabId: tab.id });
        show(el("p", s && s.ok ? null : "error", s && s.ok ? `${s.updated ? "Updated" : "Saved as"} “${s.key}” in ${s.project}` : s && s.error || "VaultOS could not save the login"));
    }));
    box.append(row);
    return box;
}

async function pair() {
    const brands = navigator.userAgentData ? navigator.userAgentData.brands : [];
    const isBrave = Boolean(navigator.brave);
    const isSafari = api.runtime.getURL("").startsWith("safari-web-extension:");
    const r = await ask({ op: "pair", name: S.browserName(brands, isBrave, isSafari) });
    if (!r.ok) return show(el("p", "error", r.error));
    render();
}

async function forget() {
    await ask({ op: "forget" });
    show(el("p", null, "This browser forgot its pairing. Unpair it in VaultOS Settings as well."));
}

render();
