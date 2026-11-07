// In each page and frame: offers VaultOS logins next to login fields, fills the one chosen,
// and offers to save a login after it is submitted. Its controls live in a closed shadow
// root and act only on real clicks (`isTrusted`), so the page can neither read them nor
// press them. The service worker decides nothing from what the page says about itself.
"use strict";

(() => {
    const api = globalThis.browser ?? globalThis.chrome;
    const S = globalThis.VaultOSShared;
    if (!S || S.started) return;
    S.started = true;

    const ask = m => api.runtime.sendMessage(m).catch(() => null);

    let logins = null, fetchedAt = 0;
    async function loginsHere() {
        if (logins && Date.now() - fetchedAt < 30_000) return logins;
        const r = await ask({ op: "logins" });
        logins = r && r.ok ? r.logins : [];
        fetchedAt = Date.now();
        return logins;
    }

    function attrs(input) {
        const label = input.labels && input.labels[0] ? input.labels[0].textContent : input.getAttribute("aria-label");
        return { type: input.type, autocomplete: input.autocomplete, name: input.name, id: input.id, placeholder: input.placeholder, label };
    }

    function visible(el) {
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== "hidden" && !el.disabled && !el.readOnly;
    }

    function inputs(scope) {
        return Array.from((scope || document).querySelectorAll("input")).filter(visible);
    }

    /** The password field and username field of the form `field` is in. */
    function loginFields(field) {
        const scope = field.form || document;
        const all = inputs(scope);
        const password = field.type === "password" ? field : all.find(i => i.type === "password") || null;
        const ref = password || field;
        const before = all.filter(i => i !== ref && i.type !== "password" && (i.compareDocumentPosition(ref) & Node.DOCUMENT_POSITION_FOLLOWING));
        const username = S.isUsername(attrs(field)) ? field : before.reverse().find(i => S.isUsername(attrs(i))) || before[0] || null;
        const otp = all.find(i => S.isOtp(attrs(i))) || null;
        return { password, username, otp };
    }

    function kind(input) {
        if (!(input instanceof HTMLInputElement)) return null;
        if (input.type === "password") return "password";
        if (S.isOtp(attrs(input))) return "otp";
        if (S.isUsername(attrs(input)) && inputs(input.form || document).some(i => i.type === "password")) return "username";
        return null;
    }

    // Typing as a person would, so the page's own handlers see the value.
    function setValue(input, value) {
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
        input.focus();
        setter.call(input, value);
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
    }

    let host = null, root = null;
    function ui() {
        if (!host || !host.isConnected) {
            host = document.createElement("vaultos-ui");
            host.style.cssText = "all: initial; position: absolute; top: 0; left: 0; width: 0; height: 0; z-index: 2147483647;";
            root = host.attachShadow({ mode: "closed" });
            const style = document.createElement("style");
            style.textContent = S.CSS;
            const box = document.createElement("div");
            box.className = "vo";
            root.append(style, box);
            document.documentElement.append(host);
        }
        return root.querySelector(".vo");
    }

    // Clears the button and menus; a save offer stays until answered.
    function clear() {
        if (!root) return;
        for (const n of root.querySelectorAll(".vo > :not(.banner)")) n.remove();
    }

    function el(tag, className, text) {
        const e = document.createElement(tag);
        if (className) e.className = className;
        if (text !== undefined) e.textContent = text;
        return e;
    }

    /** Runs `act` for a real click only. */
    function onClick(e, act) {
        e.addEventListener("click", ev => {
            if (!ev.isTrusted) return;
            ev.preventDefault();
            ev.stopPropagation();
            act();
        });
    }

    function at(node, field, below) {
        const r = field.getBoundingClientRect();
        node.style.left = `${r.right + scrollX - (below ? Math.min(r.width, 320) : 24)}px`;
        node.style.top = below ? `${r.bottom + scrollY + 4}px` : `${r.top + scrollY + (r.height - 20) / 2}px`;
    }

    let current = null;
    function showButton(field) {
        clear();
        current = field;
        const b = el("button", "button", "V");
        b.type = "button";
        b.title = "Fill with VaultOS";
        at(b, field, false);
        onClick(b, () => showMenu(field));
        ui().append(b);
    }

    async function showMenu(field) {
        const list = await loginsHere();
        clear();
        const menu = el("div", "menu");
        menu.setAttribute("role", "menu");
        at(menu, field, true);
        if (!list.length) menu.append(el("div", "note", "No VaultOS logins for this site"));
        for (const login of list) {
            const item = el("button", "item");
            item.type = "button";
            item.setAttribute("role", "menuitem");
            item.append(el("span", "name", login.name), el("span", "sub", login.username || login.project));
            onClick(item, () => fill(login.projectId, login.itemId, field));
            menu.append(item);
        }
        ui().append(menu);
        const first = menu.querySelector("button");
        if (first) first.focus();
    }

    function note(field, text) {
        clear();
        const n = el("div", "menu");
        n.append(el("div", "note", text));
        if (field) at(n, field, true);
        ui().append(n);
        setTimeout(clear, 4000);
    }

    async function fill(projectId, itemId, field) {
        const r = await ask({ op: "fill", projectId, itemId });
        clear();
        if (!r || !r.ok) {
            note(field, r && r.error ? r.error : "VaultOS could not fill this login");
            return;
        }
        const f = field ? loginFields(field) : firstLoginForm();
        if (f.username && r.username) setValue(f.username, r.username);
        if (f.password && r.password) setValue(f.password, r.password);
        if (f.otp && r.otp) setValue(f.otp, r.otp);
    }

    function firstLoginForm() {
        const pw = inputs(document).find(i => i.type === "password");
        if (pw) return loginFields(pw);
        const otp = inputs(document).find(i => S.isOtp(attrs(i)));
        return { password: null, username: null, otp: otp || null };
    }

    document.addEventListener("focusin", e => {
        const t = e.target;
        if (!kind(t) || t === current) return;
        loginsHere().then(list => {
            if (list.length && document.activeElement === t) showButton(t);
        });
    }, true);

    document.addEventListener("keydown", e => {
        if (e.key === "Escape") {
            clear();
            current = null;
        }
        if (e.key === "Enter" && e.target instanceof HTMLInputElement && kind(e.target)) offer(e.target);
    }, true);

    document.addEventListener("submit", e => {
        const pw = e.target instanceof HTMLFormElement ? inputs(e.target).find(i => i.type === "password") : null;
        if (pw) offer(pw);
    }, true);

    document.addEventListener("click", e => {
        const b = e.target instanceof Element ? e.target.closest("button, input[type=submit]") : null;
        const form = b && b.form;
        const pw = form ? inputs(form).find(i => i.type === "password") : null;
        if (pw) offer(pw);
    }, true);

    let offered = "";
    async function offer(field) {
        const f = loginFields(field);
        if (!f.password || !f.password.value) return;
        const username = f.username ? f.username.value : "";
        if (offered === username + "\n" + f.password.value) return;
        offered = username + "\n" + f.password.value;
        const r = await ask({ op: "offerSave", username, password: f.password.value });
        // A page that logs in without loading another shows the offer itself.
        if (r && r.offered && window === top) setTimeout(showSaveOffer, 1500);
    }

    let banner = null;
    async function showSaveOffer() {
        if (banner) return;
        const r = await ask({ op: "pendingSave" });
        if (!r || !r.ok || !r.pending || banner) return;
        clear();
        const b = banner = el("div", "banner");
        b.setAttribute("role", "dialog");
        const who = r.pending.username ? ` as ${r.pending.username}` : "";
        b.append(el("div", "name", "Save this login in VaultOS?"), el("div", "sub", `${r.pending.site}${who}`));
        const row = el("div", "row");
        const no = el("button", "secondary", "Not now"), yes = el("button", "primary", "Save");
        const close = () => {
            b.remove();
            banner = null;
        };
        onClick(no, () => {
            ask({ op: "dismissSave" });
            close();
        });
        onClick(yes, async () => {
            const s = await ask({ op: "save" });
            close();
            note(null, s && s.ok ? `Saved as “${s.key}” in ${s.project}` : s && s.error || "VaultOS could not save the login");
        });
        row.append(no, yes);
        b.append(row);
        ui().append(b);
    }

    api.runtime.onMessage.addListener((m, sender) => {
        // The popup's Fill, relayed by the service worker.
        if (sender.id !== api.runtime.id || sender.tab || window !== top || !m || m.op !== "fill") return;
        fill(String(m.projectId), String(m.itemId), null);
    });

    // After a login form's page has gone; asked again in case its offer was still arriving.
    if (window === top) {
        showSaveOffer();
        setTimeout(showSaveOffer, 1200);
    }
})();
