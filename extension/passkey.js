// The extension's passkey window: the browser's own window, which no page can draw on or
// click in. It shows the site the browser reported for the request and lets the human pick a
// passkey, save a new one, or use another device instead.
"use strict";

const api = globalThis.browser ?? globalThis.chrome;
const main = document.getElementById("main");
const id = location.hash.slice(1);
const ask = m => api.runtime.sendMessage({ ...m, id }).catch(e => ({ ok: false, error: String(e && e.message || e) }));

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

async function answer(m, b) {
    for (const x of main.querySelectorAll("button")) x.disabled = true;
    b.textContent = "Working…";
    const r = await ask({ op: "passkeyAnswer", ...m });
    if (!r.ok) {
        main.replaceChildren(el("p", "error", r.error || "VaultOS could not do that."), button("Close", "", () => window.close()));
        return;
    }
    window.close();
}

function other() {
    return button("Use another device or security key", "", e => answer({ choice: "other" }, e.currentTarget));
}

async function render() {
    const r = await ask({ op: "passkeyShow" });
    if (!r.ok) {
        main.replaceChildren(el("p", "error", r.error || "This request is no longer waiting."));
        return;
    }
    const site = el("p");
    site.append(r.kind === "create" ? "Save a passkey for " : "Sign in to ", el("strong", "", r.site));
    if (r.rpId !== r.site) site.append(el("span", "sub", `for ${r.rpId}`));
    const nodes = [ site ];
    if (r.kind === "create") {
        const who = el("div", "offer");
        who.append(el("span", "name", r.user.displayName || r.user.name || "(no name)"));
        if (r.user.name && r.user.name !== r.user.displayName) who.append(el("span", "sub", r.user.name));
        nodes.push(who, el("p", "muted", "VaultOS keeps it in this login's item, in the Logins project when the site has none."));
        const save = button("Save passkey in VaultOS", "primary", e => answer({ choice: "create" }, e.currentTarget));
        nodes.push(save, other());
        main.replaceChildren(...nodes);
        save.focus();
    } else {
        const list = el("ul");
        for (const p of r.passkeys) {
            const b = button("", "", e => answer({ choice: "use", projectId: p.projectId, itemId: p.itemId }, e.currentTarget));
            b.append(el("span", "name", p.username || p.name), el("span", "sub", `${p.name} · ${p.project}`));
            const li = el("li");
            li.append(b);
            list.append(li);
        }
        nodes.push(list, other());
        main.replaceChildren(...nodes);
        list.querySelector("button")?.focus();
    }
    const cancel = button("Cancel", "", e => answer({ choice: "cancel" }, e.currentTarget));
    main.append(cancel);
}

document.addEventListener("keydown", e => {
    if (e.key === "Escape") answer({ choice: "cancel" }, document.createElement("button"));
});
// Keeps the extension's worker, which holds the request, running while the human decides.
setInterval(() => ask({ op: "passkeyWait" }).then(r => { if (r.ok && !r.waiting) window.close(); }), 10_000);
render();
