"use strict";

// Quick Access: type to search, ⏎ to copy. The panel only ever holds metadata; values are
// copied by the main process and never reach this page.

const $ = id => document.getElementById(id);

const q = $("q"), list = $("results"), msg = $("msg");

let items = [], selected = 0, searchToken = 0, unlocked = false, confirmResolve = null;

const cleanError = e => String(e?.message || e || "That didn't work. Try again.").replace(/^Error invoking remote method '[^']+': (Error: )?/, "");

const isMac = navigator.platform.startsWith("Mac");

function say(text, ok = false) {
    msg.textContent = text || "";
    msg.classList.toggle("ok", ok);
}

function mode(name) {
    unlocked = name === "search";
    $("locked").hidden = name !== "locked";
    $("confirm").hidden = name !== "confirm";
    list.hidden = name !== "search";
    $("hints").hidden = name !== "search";
    q.disabled = name !== "search";
    $("state").textContent = name === "locked" ? "Locked" : "VaultOS";
}

function forget() {
    items = [];
    selected = 0;
    q.value = "";
    list.textContent = "";
    $("pw").value = "";
    $("confirm-pw").value = "";
    if (confirmResolve) confirmResolve(false);
}

const initialOf = name => (String(name || "").trim().match(/[\p{L}\p{N}]/u) || [ "#" ])[0].toUpperCase();

function renderList() {
    list.textContent = "";
    if (!items.length) {
        const li = document.createElement("li");
        li.className = "empty";
        li.textContent = q.value.trim() ? "No matches. Try a project, username or website." : "Nothing here yet. Add keys in VaultOS.";
        list.append(li);
        return;
    }
    items.forEach((item, i) => {
        const li = document.createElement("li");
        li.setAttribute("role", "option");
        li.id = `opt-${i}`;
        li.setAttribute("aria-selected", String(i === selected));
        const tile = document.createElement("span");
        tile.className = "tile";
        tile.textContent = initialOf(item.key);
        const mid = document.createElement("div");
        mid.style.minWidth = "0";
        const name = document.createElement("div");
        name.className = "name";
        name.textContent = item.key;
        const sub = document.createElement("div");
        sub.className = "sub";
        sub.textContent = [ item.project, item.username || item.email, item.host ].filter(Boolean).join(" · ");
        mid.append(name, sub);
        const flag = document.createElement("span");
        flag.className = "flag";
        flag.textContent = item.hasValue ? item.injectApproved ? item.hasOtp ? "One-time code" : "" : "Held from .env" : item.hasOtp ? "One-time code" : "No value";
        li.append(tile, mid, flag);
        li.addEventListener("mousemove", () => {
            if (selected !== i) select(i);
        });
        li.addEventListener("click", () => {
            select(i);
            act("copy");
        });
        list.append(li);
    });
    q.setAttribute("aria-activedescendant", `opt-${selected}`);
}

function select(i) {
    if (!items.length) return;
    selected = (i + items.length) % items.length;
    for (const li of list.children) li.setAttribute("aria-selected", String(li.id === `opt-${selected}`));
    q.setAttribute("aria-activedescendant", `opt-${selected}`);
    const el = $(`opt-${selected}`);
    if (el) el.scrollIntoView({
        block: "nearest"
    });
}

async function runSearch() {
    const token = ++searchToken;
    try {
        const found = await window.quick.search(q.value);
        if (token !== searchToken || !unlocked) return;
        items = found.slice(0, 50);
        selected = 0;
        renderList();
    } catch (e) {
        if (cleanError(e).includes("Vault is locked")) return showLocked();
        say(cleanError(e));
    }
}

// A copy may need the master password when Touch ID confirmations are on and Touch ID could
// not be shown. The main process verifies it; the panel only collects it.
function askPassword(why) {
    return new Promise(resolve => {
        mode("confirm");
        $("confirm-why").textContent = why;
        const input = $("confirm-pw");
        input.value = "";
        input.focus();
        confirmResolve = ok => {
            confirmResolve = null;
            input.value = "";
            mode("search");
            q.focus();
            resolve(ok);
        };
    });
}

$("confirm-ok").addEventListener("click", async () => {
    const input = $("confirm-pw");
    try {
        const r = await window.quick.confirmHuman(input.value);
        if (r.ok) return confirmResolve && confirmResolve(true);
        say(r.error || "Wrong password");
    } catch (e) {
        say(cleanError(e));
    }
    input.value = "";
    input.focus();
});

$("confirm-cancel").addEventListener("click", () => confirmResolve && confirmResolve(false));

$("confirm-pw").addEventListener("keydown", e => {
    if (e.key === "Enter") $("confirm-ok").click();
    if (e.key === "Escape") {
        e.preventDefault();
        $("confirm-cancel").click();
    }
});

async function act(kind) {
    const item = items[selected];
    if (!item) return;
    say("");
    if (kind === "otp" && !item.hasOtp) return say("This item has no one-time code");
    const run = () => kind === "otp" ? window.quick.copyOtp(item.project, item.key) : kind === "copy" ? window.quick.copy(item.project, item.key, "value") : kind === "username" ? window.quick.copy(item.project, item.key, item.username ? "username" : "email") : kind === "url" ? window.quick.openUrl(item.project, item.key) : window.quick.open(item.project, item.key);
    try {
        await run();
    } catch (e) {
        const text = cleanError(e);
        if (text.startsWith("NEED_PASSWORD")) {
            if (await askPassword(text.replace(/^NEED_PASSWORD: /, ""))) {
                try {
                    await run();
                } catch (e2) {
                    say(cleanError(e2));
                }
            }
            return;
        }
        if (text.includes("Vault is locked")) return showLocked();
        say(text);
    }
}

q.addEventListener("input", () => {
    say("");
    runSearch();
});

q.addEventListener("keydown", e => {
    const mod = isMac ? e.metaKey : e.ctrlKey;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        select(selected + (e.key === "ArrowDown" ? 1 : -1));
    } else if (e.key === "Enter") {
        e.preventDefault();
        act(mod ? "open" : e.altKey ? "otp" : "copy");
    } else if (mod && e.key.toLowerCase() === "o") {
        e.preventDefault();
        act("url");
    } else if (mod && e.key.toLowerCase() === "c" && q.selectionStart === q.selectionEnd) {
        e.preventDefault();
        act("username");
    } else if (e.key === "Escape") {
        e.preventDefault();
        if (q.value) {
            q.value = "";
            runSearch();
        } else window.quick.hide();
    }
});

document.addEventListener("keydown", e => {
    if (e.key === "Escape" && !unlocked && $("confirm").hidden) window.quick.hide();
});

async function unlockWith(fn) {
    say("");
    try {
        const r = await fn();
        if (r.ok) return showSearch();
        say(r.error || "Could not unlock.");
    } catch (e) {
        say(cleanError(e));
    }
    $("pw").value = "";
    $("pw").focus();
}

$("unlock").addEventListener("click", () => unlockWith(() => window.quick.unlock($("pw").value)));

$("pw").addEventListener("keydown", e => {
    if (e.key === "Enter") $("unlock").click();
});

$("touch").addEventListener("click", () => unlockWith(() => window.quick.unlockTouchId()));

function showSearch() {
    $("pw").value = "";
    mode("search");
    q.focus();
    q.select();
    runSearch();
}

async function showLocked(autoTouch = false) {
    forget();
    mode("locked");
    let s = null;
    try {
        s = await window.quick.state();
    } catch {}
    const ready = !!(s && s.touchId && s.touchId.ready);
    $("touch").hidden = !ready;
    $("pw").focus();
    if (autoTouch && ready && s.touchId.autoPrompt) $("touch").click();
}

async function onShow() {
    say("");
    const s = await window.quick.state();
    if (s.unlocked) showSearch(); else showLocked(true);
}

window.quick.onShow(onShow);

window.quick.onLocked(() => showLocked(false));

window.addEventListener("blur", () => say(""));

onShow();
