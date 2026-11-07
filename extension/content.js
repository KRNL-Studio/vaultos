// In each page and frame: offers VaultOS logins next to login fields, fills the one chosen,
// and offers to save a login after it is submitted. Its controls live in a closed shadow
// root, so the page cannot read them, and act only on a real click (`isTrusted`) on a
// control that has been visible, unobscured and unaltered for a moment, so the page can
// neither press them nor trick a person into pressing a hidden one. The toolbar popup, which
// is the browser's own window, is the other way to fill. The service worker decides nothing
// from what the page says about itself.
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

    /** A field a person can see and type in: on the page, not transparent or hidden. */
    function visible(el) {
        if (el.disabled || el.readOnly) return false;
        const r = el.getBoundingClientRect();
        if (r.width < 2 || r.height < 2 || r.right + scrollX <= 0 || r.bottom + scrollY <= 0) return false;
        if (typeof el.checkVisibility === "function") return el.checkVisibility({ opacityProperty: true, visibilityProperty: true });
        return getComputedStyle(el).visibility !== "hidden";
    }

    function inputs(scope) {
        return Array.from((scope || document).querySelectorAll("input")).filter(visible);
    }

    const passwords = all => all.filter(i => i.type === "password");

    /** The username field before `ref` among `all`, or the field itself when it is one. */
    function usernameFor(field, ref, all) {
        if (field && field !== ref && S.isUsername(attrs(field))) return field;
        const before = all.filter(i => i !== ref && i.type !== "password" && (i.compareDocumentPosition(ref) & Node.DOCUMENT_POSITION_FOLLOWING));
        return before.reverse().find(i => S.isUsername(attrs(i))) || before[0] || null;
    }

    /**
     * The fields to fill in the form `field` is in. A form with several password fields, or
     * one for a new password, is for changing or choosing a password: nothing is filled.
     */
    function loginFields(field) {
        const all = inputs(field.form || document);
        const pws = passwords(all);
        const otp = all.find(i => S.isOtp(attrs(i))) || null;
        if (!pws.length) return { password: null, username: null, otp };
        const at = S.passwordField(pws.map(attrs), "fill");
        if (at < 0) return { password: null, username: null, otp: null };
        return { password: pws[at], username: usernameFor(field, pws[at], all), otp };
    }

    function kind(input) {
        if (!(input instanceof HTMLInputElement) || !visible(input)) return null;
        if (input.type === "password") return loginFields(input).password === input ? "password" : null;
        if (S.isOtp(attrs(input))) return "otp";
        if (S.isUsername(attrs(input)) && loginFields(input).password) return "username";
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

    // The host element is in the page, so its style is set `!important` inline (which the
    // page's style sheets cannot override) and put back if the page's script changes it.
    const HOST_STYLE = "all: initial !important; display: block !important; position: absolute !important; top: 0 !important; left: 0 !important; width: 0 !important; height: 0 !important; z-index: 2147483647 !important;";
    let host = null, root = null, hostStyle = "";
    function ui() {
        if (!host || !host.isConnected) {
            host = document.createElement("vaultos-ui");
            host.style.cssText = HOST_STYLE;
            hostStyle = host.style.cssText;
            root = host.attachShadow({ mode: "closed" });
            const style = document.createElement("style");
            style.textContent = S.CSS;
            const box = document.createElement("div");
            box.className = "vo";
            root.append(style, box);
            document.documentElement.append(host);
            new MutationObserver(() => {
                if (host.style.cssText === hostStyle) return;
                host.style.cssText = HOST_STYLE;
                clear(true);
            }).observe(host, { attributes: true });
        }
        return root.querySelector(".vo");
    }

    // Clears the button and menus, and with `all` a save offer too.
    function clear(all) {
        if (!root) return;
        for (const n of root.querySelectorAll(all ? ".vo > *" : ".vo > :not(.banner)")) n.remove();
        if (all) banner = null;
    }

    function el(tag, className, text) {
        const e = document.createElement(tag);
        if (className) e.className = className;
        if (text !== undefined) e.textContent = text;
        return e;
    }

    // When each control became visible to the browser's occlusion tracking: on top, uncovered,
    // fully opaque and not distorted (Intersection Observer v2). Zero while it is not.
    const DWELL_MS = 400;
    const seenSince = new WeakMap();
    let watcher = null;
    function watch(node) {
        if (typeof IntersectionObserver !== "function") return;
        watcher ??= new IntersectionObserver(entries => {
            for (const e of entries) seenSince.set(e.target, e.isVisible ? seenSince.get(e.target) || performance.now() : 0);
        }, { trackVisibility: true, delay: 100 });
        watcher.observe(node);
    }

    /** Runs `act` for a real click on the control once it has been visible for a moment. */
    function onClick(e, act) {
        watch(e);
        e.addEventListener("click", ev => {
            if (!ev.isTrusted) return;
            ev.preventDefault();
            ev.stopPropagation();
            const since = seenSince.get(e);
            if (!since || performance.now() - since < DWELL_MS) return;
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
            item.append(el("span", "name", login.name), el("span", "sub", S.loginDetail(login)));
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
        setTimeout(() => n.remove(), 4000);
    }

    async function fill(projectId, itemId, field) {
        const r = await ask({ op: "fill", projectId, itemId });
        clear();
        if (!r || !r.ok) {
            note(field, r && r.error ? r.error : "VaultOS could not fill this login");
            return;
        }
        const f = field ? loginFields(field) : firstLoginForm();
        if (!f.password && !f.otp) {
            note(field, "VaultOS fills only a sign-in form with one password field");
            return;
        }
        if (f.username && r.username) setValue(f.username, r.username);
        if (f.password && r.password) setValue(f.password, r.password);
        if (f.otp && r.otp) setValue(f.otp, r.otp);
    }

    function firstLoginForm() {
        const pw = passwords(inputs(document)).find(i => !S.isNewPassword(attrs(i)));
        if (pw) return loginFields(pw);
        const otp = inputs(document).find(i => S.isOtp(attrs(i)));
        return { password: null, username: null, otp: otp || null };
    }

    /** Whether the page shows a sign-in form, as it does again after a refused password. */
    const signInShown = () => passwords(inputs(document)).length > 0;

    document.addEventListener("focusin", e => {
        const t = e.target;
        if (!kind(t) || t === current) return;
        loginsHere().then(list => {
            if (list.length && document.activeElement === t) showButton(t);
        });
    }, true);

    // Only a person's own typing, clicks and submissions are taken as submitting a login.
    document.addEventListener("keydown", e => {
        if (!e.isTrusted) return;
        if (e.key === "Escape") {
            clear();
            current = null;
        }
        if (e.key === "Enter" && e.target instanceof HTMLInputElement) offer(e.target.form || document);
    }, true);

    document.addEventListener("submit", e => {
        if (e.isTrusted && e.target instanceof HTMLFormElement) offer(e.target);
    }, true);

    document.addEventListener("click", e => {
        if (!e.isTrusted) return;
        const b = e.target instanceof Element ? e.target.closest("button, input[type=submit]") : null;
        if (b && b.form) offer(b.form);
    }, true);

    let offered = "";
    async function offer(scope) {
        const all = inputs(scope);
        const pws = passwords(all).filter(i => i.value);
        const at = S.passwordField(pws.map(attrs), "save");
        if (at < 0) return;
        const password = pws[at];
        // A change-password form may keep the username in a field it does not show.
        const shown = usernameFor(null, password, all);
        const hidden = Array.from(scope.querySelectorAll("input")).find(i => i.type !== "password" && (i.autocomplete || "").includes("username"));
        const username = (shown && shown.value) || (hidden && hidden.value) || "";
        if (offered === username + "\n" + password.value) return;
        offered = username + "\n" + password.value;
        const r = await ask({ op: "offerSave", username, password: password.value });
        // A page that signs in without loading another shows the offer itself, once its
        // sign-in form has gone (a form still showing is most likely a refused password).
        if (r && r.offered && window === top) setTimeout(showSaveOffer, 1500);
    }

    let banner = null;
    async function showSaveOffer() {
        if (banner || signInShown()) return;
        const r = await ask({ op: "pendingSave" });
        if (!r || !r.ok || !r.pending || banner || signInShown()) return;
        clear();
        const p = r.pending;
        const b = banner = el("div", "banner");
        b.setAttribute("role", "dialog");
        const who = p.username ? ` as ${p.username}` : "";
        if (p.update) b.append(el("div", "name", "Update this password in VaultOS?"), el("div", "sub", `${p.update.name} in ${p.update.project}${who}`));
        else b.append(el("div", "name", "Save this login in VaultOS?"), el("div", "sub", `${p.site}${who}`));
        const row = el("div", "row");
        const no = el("button", "secondary", "Not now"), yes = el("button", "primary", p.update ? "Update" : "Save");
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
            note(null, s && s.ok ? `${s.updated ? "Updated" : "Saved as"} “${s.key}” in ${s.project}` : s && s.error || "VaultOS could not save the login");
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
