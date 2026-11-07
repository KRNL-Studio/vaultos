"use strict";

// Typed items: kinds, tags, favorites, custom fields, the generator, one-time codes,
// attachments, versions, the Trash, Watchtower and imports. Loaded before app.js, whose
// helpers (el, esc, view, render, topbar, human) these functions use when they run.

const KINDS = [ [ "login", "Login" ], [ "api_key", "API key" ], [ "note", "Secure note" ], [ "ssh_key", "SSH key" ], [ "database", "Database" ], [ "server", "Server" ], [ "certificate", "Certificate" ] ];

const FIELD_KINDS = [ [ "text", "Text" ], [ "concealed", "Concealed" ], [ "url", "URL" ], [ "email", "Email" ], [ "date", "Date" ], [ "otp", "One-time code" ] ];

const kindLabel = k => (KINDS.find(([ id ]) => id === k) || [ "", "" ])[1];

const isSecretField = kind => kind === "concealed" || kind === "otp";

const RATING = {
    weak: "Weak",
    fair: "Fair",
    good: "Good",
    strong: "Strong"
};

function selectOf(options, value) {
    const s = el(`<select></select>`);
    for (const [ id, label ] of options) {
        const o = document.createElement("option");
        o.value = id;
        o.textContent = label;
        s.appendChild(o);
    }
    s.value = value;
    return s;
}

// A meter under a password field. Only the strength comes back from the app.
function strengthMeter(input) {
    const meter = el(`<div class="meter" aria-live="polite"><span class="bar"><span></span></span><span class="txt"></span></div>`);
    let token = 0, timer = null;
    const update = () => {
        clearTimeout(timer);
        timer = setTimeout(async () => {
            const t = ++token, v = input.value;
            if (!v) {
                meter.dataset.rating = "";
                meter.querySelector(".txt").textContent = "";
                return;
            }
            try {
                const r = await window.vault.strength(v);
                if (t !== token) return;
                meter.dataset.rating = r.rating;
                meter.querySelector(".txt").textContent = `${RATING[r.rating]} · about ${r.bits} bits`;
            } catch {}
        }, 150);
    };
    input.addEventListener("input", update);
    update();
    return meter;
}

// The generator: a recipe in, a value out; "Use" puts it in the field.
function openGenerator(target) {
    const modal = el(`<div class="modal" role="dialog" aria-modal="true" aria-label="Password generator"><div class="box card wide"><div class="card-head"><h3 class="card-title">Generate</h3></div><div class="card-body">
      <div class="provider-grid gen-kinds"></div>
      <div class="gen-opts"></div>
      <div class="val mono gen-out"></div>
      <div class="note gen-bits"></div>
      <div class="row2"><button class="btn ghost">Cancel</button><button class="btn ghost">Again</button><button class="btn primary">Use</button></div></div></div></div>`);
    const recipe = {
        kind: "random",
        length: 24,
        digits: true,
        symbols: true,
        avoidAmbiguous: false,
        words: 5,
        separator: "-",
        capitalize: true,
        number: true
    };
    const kinds = modal.querySelector(".gen-kinds"), opts = modal.querySelector(".gen-opts");
    const out = modal.querySelector(".gen-out"), bits = modal.querySelector(".gen-bits");
    const [ cancel, again, use ] = modal.querySelectorAll(".row2 button");
    let value = "";
    const close = () => {
        value = "";
        out.textContent = "";
        modal.remove();
    };
    const toggle = (name, label) => {
        const row = el(`<label class="chkrow"><input type="checkbox" class="chk" /> <span></span></label>`);
        row.querySelector("span").textContent = label;
        const box = row.querySelector("input");
        box.checked = !!recipe[name];
        box.onchange = () => {
            recipe[name] = box.checked;
            generate();
        };
        return row;
    };
    const slider = (name, label, min, max) => {
        const row = el(`<label class="slider"><span></span><input type="range" /><b></b></label>`);
        row.querySelector("span").textContent = label;
        const r = row.querySelector("input");
        Object.assign(r, {
            min: min,
            max: max,
            value: recipe[name]
        });
        row.querySelector("b").textContent = recipe[name];
        r.oninput = () => {
            recipe[name] = Number(r.value);
            row.querySelector("b").textContent = r.value;
            generate();
        };
        return row;
    };
    const paintOpts = () => {
        opts.textContent = "";
        if (recipe.kind === "random") {
            opts.append(slider("length", "Length", 8, 64), toggle("digits", "Digits"), toggle("symbols", "Symbols"), toggle("avoidAmbiguous", "Avoid look-alike characters"));
        } else if (recipe.kind === "passphrase") {
            opts.append(slider("words", "Words", 3, 12), toggle("capitalize", "Capitalize"), toggle("number", "Add a number"));
        } else {
            opts.append(slider("length", "Digits", 4, 12));
        }
    };
    for (const [ id, label ] of [ [ "random", "Random" ], [ "passphrase", "Passphrase" ], [ "pin", "PIN" ] ]) {
        const chip = el(`<div class="pchip" role="button" tabindex="0"><span></span></div>`);
        chip.querySelector("span").textContent = label;
        chip.dataset.kind = id;
        chip.onclick = () => {
            recipe.kind = id;
            if (id === "pin") recipe.length = 6; else if (recipe.length < 8) recipe.length = 24;
            [ ...kinds.children ].forEach(c => c.classList.toggle("sel", c.dataset.kind === id));
            paintOpts();
            generate();
        };
        kinds.appendChild(chip);
    }
    const body = () => recipe.kind === "random" ? {
        kind: "random",
        length: recipe.length,
        digits: recipe.digits,
        symbols: recipe.symbols,
        avoidAmbiguous: recipe.avoidAmbiguous
    } : recipe.kind === "passphrase" ? {
        kind: "passphrase",
        words: recipe.words,
        separator: recipe.separator,
        capitalize: recipe.capitalize,
        number: recipe.number
    } : {
        kind: "pin",
        length: recipe.length
    };
    let token = 0;
    async function generate() {
        const t = ++token;
        try {
            const r = await window.vault.generate(body());
            if (t !== token) return;
            value = r.value;
            out.textContent = r.value;
            bits.textContent = `${RATING[r.rating]} · about ${r.bits} bits of entropy`;
        } catch (e) {
            bits.textContent = cleanError(e);
        }
    }
    cancel.onclick = close;
    again.onclick = generate;
    use.onclick = () => {
        if (!value) return;
        target.value = value;
        target.dispatchEvent(new Event("input", {
            bubbles: true
        }));
        close();
        target.focus();
    };
    modal.addEventListener("keydown", e => {
        if (e.key === "Escape") close();
    });
    kinds.firstElementChild.classList.add("sel");
    paintOpts();
    document.body.appendChild(modal);
    use.focus();
    generate();
}

// A password input with Show, Generate and a strength meter.
function passwordRow(input) {
    const wrap = el(`<div></div>`);
    const row = concealedRow(input);
    const gen = el(`<button type="button" class="iconbtn">Generate</button>`);
    gen.onclick = () => openGenerator(input);
    row.appendChild(gen);
    wrap.append(row, strengthMeter(input));
    return wrap;
}

// Kind, tags, favorite and custom fields: the parts every item has.
function itemExtras(prov, current) {
    const kindBlock = fieldBlock("Type");
    const kind = selectOf(KINDS, current && current.kind || (prov.type === "password" ? "login" : "api_key"));
    kindBlock.appendChild(kind);
    const tagBlock = fieldBlock("Tags" + OPTIONAL);
    const tags = el(`<input type="text" placeholder="comma-separated, e.g. prod, billing" />`);
    tags.value = (current && current.tags || []).join(", ");
    tagBlock.appendChild(tags);
    const favRow = el(`<label class="chkrow field"><input type="checkbox" class="chk" /> <span>Favorite</span></label>`);
    const fav = favRow.querySelector("input");
    fav.checked = !!(current && current.favorite);
    const fieldsBlock = fieldBlock("Custom fields" + OPTIONAL);
    const rows = el(`<div class="cfields"></div>`);
    const secrets = new Map((current && current.secretFields || []).map(f => [ f.id, f.value ]));
    const addRow = f => {
        const row = el(`<div class="cfield"><input type="text" placeholder="Label" /><span class="kindsel"></span><span class="valslot"></span><button type="button" class="iconbtn danger" aria-label="Remove field">Remove</button></div>`);
        row.dataset.id = f.id || "";
        const label = row.querySelector("input");
        label.value = f.label || "";
        const k = selectOf(FIELD_KINDS, f.kind || "text");
        row.querySelector(".kindsel").appendChild(k);
        const slot = row.querySelector(".valslot");
        let input = null;
        const paint = () => {
            const prior = input ? input.value : isSecretField(f.kind) ? secrets.get(f.id) || "" : f.value || "";
            slot.textContent = "";
            input = el(`<input type="text" />`);
            input.placeholder = k.value === "otp" ? "otpauth:// link or setup key" : "Value";
            input.type = isSecretField(k.value) ? "password" : k.value === "date" ? "date" : "text";
            input.autocomplete = "off";
            input.value = prior;
            slot.appendChild(isSecretField(k.value) ? concealedRow(input) : input);
        };
        k.onchange = paint;
        paint();
        row.querySelector("button.danger").onclick = () => row.remove();
        row.read = () => ({
            id: row.dataset.id,
            label: label.value.trim(),
            kind: k.value,
            value: input.value
        });
        rows.appendChild(row);
        return label;
    };
    for (const f of current && current.fields || []) addRow(f);
    const add = el(`<button type="button" class="btn sm ghost">+ Add field</button>`);
    add.onclick = () => addRow({
        kind: "text"
    }).focus();
    fieldsBlock.append(rows, add);
    return {
        nodes: [ kindBlock, tagBlock, fieldsBlock, favRow ],
        get: () => ({
            kind: kind.value,
            tags: tags.value.split(",").map(t => t.trim()).filter(Boolean),
            favorite: fav.checked,
            fields: [ ...rows.children ].map(r => r.read()).filter(f => f.label || f.value)
        })
    };
}

const fmtBytes = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;

// Below the editor of a saved item: its attachments and its versions.
function itemTail(scroll, project, key, current) {
    const files = panel(scroll, "Attachments");
    const msg = el(`<div class="err"></div>`);
    const list = current.attachments || [];
    if (!list.length) files.appendChild(el(`<div class="note">No files. Attachments are encrypted on this device and are not synced.</div>`));
    for (const a of list) {
        const row = el(`<div class="filerow"><div class="grow"><div class="name"></div><div class="sub"></div></div></div>`);
        row.querySelector(".name").textContent = a.name;
        row.querySelector(".sub").textContent = `${fmtBytes(a.size)} · added ${String(a.addedAt || "").slice(0, 10)}`;
        const save = el(`<button class="iconbtn">Save…</button>`);
        save.onclick = async () => {
            msg.textContent = "";
            try {
                const r = await human("saveAttachment", project, key, a.id);
                if (r.ok) save.textContent = "Saved";
            } catch (e) {
                msg.textContent = cleanError(e);
            }
        };
        const remove = el(`<button class="iconbtn danger">Remove</button>`);
        let armed = false;
        remove.onclick = async () => {
            if (!armed) {
                armed = true;
                remove.textContent = "Remove for good?";
                setTimeout(() => {
                    armed = false;
                    remove.textContent = "Remove";
                }, 2500);
                return;
            }
            try {
                await window.vault.removeAttachment(project, key, a.id);
                render();
            } catch (e) {
                msg.textContent = cleanError(e);
            }
        };
        row.append(save, remove);
        files.appendChild(row);
    }
    const add = el(`<button class="btn sm ghost">Attach a file…</button>`);
    add.onclick = async () => {
        msg.textContent = "";
        try {
            const r = await window.vault.addAttachment(project, key);
            if (r.ok) render();
        } catch (e) {
            msg.textContent = cleanError(e);
        }
    };
    files.append(add, msg);
    const versions = el(`<button class="btn ghost" style="margin-top:12px">Versions…</button>`);
    versions.onclick = () => {
        view = {
            name: "versions",
            project: project,
            secret: key
        };
        render();
    };
    scroll.appendChild(versions);
}

// A one-time code on an item card. It counts down here and asks for the next code when the
// period ends, for three periods; asking more often would hold off auto-lock.
function otpButton(project, key, revision) {
    const wrap = el(`<span class="otp"></span>`);
    const btn = el(`<button class="iconbtn" title="Show the one-time code">Code</button>`);
    const code = el(`<span class="otpcode mono" hidden></span>`);
    let timer = null, digits = "", left = 0, periods = 0;
    const stop = () => {
        clearTimeout(timer);
        digits = "";
        code.hidden = true;
        code.textContent = "";
        btn.textContent = "Code";
    };
    const paint = () => {
        const half = Math.ceil(digits.length / 2);
        code.textContent = `${digits.slice(0, half)} ${digits.slice(half)} · ${left}s`;
    };
    const tick = () => {
        if (revision !== renderVersion || !document.body.contains(wrap)) return stop();
        if (--left > 0) {
            paint();
            timer = setTimeout(tick, 1000);
        } else if (periods < 3) fetchCode(); else stop();
    };
    const fetchCode = async () => {
        clearTimeout(timer);
        try {
            const r = await window.vault.otp(project, key);
            if (revision !== renderVersion) return;
            digits = String(r.code);
            left = r.remaining;
            periods++;
            paint();
            code.hidden = false;
            btn.textContent = "Copy code";
            timer = setTimeout(tick, 1000);
        } catch (e) {
            stop();
            code.hidden = false;
            code.textContent = cleanError(e);
        }
    };
    btn.onclick = async () => {
        if (!digits) {
            periods = 0;
            return fetchCode();
        }
        await window.vault.copyOtp(project, key);
        btn.textContent = "Copied";
        btn.classList.add("copied");
        setTimeout(() => {
            btn.classList.remove("copied");
            if (!code.hidden) btn.textContent = "Copy code";
        }, 1200);
    };
    wrap.append(btn, code);
    return wrap;
}

function backTo(label, next) {
    return {
        label: label,
        onClick: () => {
            view = next;
            render();
        }
    };
}

async function renderTrash() {
    const revision = renderVersion;
    $app.appendChild(topbar({
        crumb: backTo("Projects", {
            name: "projects"
        })
    }));
    const scroll = el(`<div class="scroll"></div>`);
    const items = await window.vault.trash();
    if (revision !== renderVersion) return;
    scroll.appendChild(el(`<div class="section"><span class="label">Trash</span><span class="label">${items.length}</span></div>`));
    scroll.appendChild(el(`<p class="note" style="margin:-4px 2px 12px">Agents cannot see items in the Trash. They are deleted for good after 30 days.</p>`));
    const err = el(`<div class="err"></div>`);
    if (items.length) {
        const empty = el(`<button class="btn danger outlined">Empty Trash</button>`);
        let armed = false;
        empty.onclick = async () => {
            if (!armed) {
                armed = true;
                empty.textContent = `Delete ${items.length} for good?`;
                setTimeout(() => {
                    armed = false;
                    empty.textContent = "Empty Trash";
                }, 2800);
                return;
            }
            try {
                await human("emptyTrash");
                render();
            } catch (e) {
                err.textContent = cleanError(e);
            }
        };
        scroll.append(empty, err);
    } else scroll.appendChild(el(`<div class="empty"><div class="big">The Trash is empty</div><p>Deleted items wait here before they go for good.</p></div>`));
    for (const {project: project, item: item} of items) {
        const card = el(`<div class="secret card"><div class="head"><span class="key mono"></span><span class="pname"></span></div><div class="note"></div><div class="actions"></div></div>`);
        card.querySelector(".key").textContent = item.key;
        card.querySelector(".pname").textContent = project;
        card.querySelector(".note").textContent = `Moved to the Trash ${String(item.trashedAt).slice(0, 10)}`;
        const restore = el(`<button class="iconbtn">Restore</button>`);
        restore.onclick = async () => {
            try {
                await window.vault.restoreSecret(project, item.key);
                render();
            } catch (e) {
                err.textContent = cleanError(e);
            }
        };
        const purge = el(`<button class="iconbtn danger">Delete for good</button>`);
        let armed = false;
        purge.onclick = async () => {
            if (!armed) {
                armed = true;
                purge.textContent = "Confirm?";
                setTimeout(() => {
                    armed = false;
                    purge.textContent = "Delete for good";
                }, 2500);
                return;
            }
            try {
                await human("purgeSecret", project, item.key);
                render();
            } catch (e) {
                err.textContent = cleanError(e);
            }
        };
        card.querySelector(".actions").append(restore, purge);
        scroll.appendChild(card);
    }
    $app.appendChild(scroll);
}

const PROBLEMS = {
    weak: [ "Weak passwords", "Easy to guess. Generate a new one." ],
    reused: [ "Reused passwords", "The same password on more than one item." ],
    old: [ "Not changed in a year", "Rotate these when you can." ],
    expiring: [ "Expiring soon", "These reach their expiry date soon." ],
    expired: [ "Expired", "Past their expiry date." ]
};

async function renderWatchtower() {
    const revision = renderVersion;
    $app.appendChild(topbar({
        crumb: backTo("Projects", {
            name: "projects"
        })
    }));
    const scroll = el(`<div class="scroll"></div>`);
    const findings = await window.vault.watchtower();
    if (revision !== renderVersion) return;
    scroll.appendChild(el(`<div class="section"><span class="label">Watchtower</span><span class="label">${findings.length} ${findings.length === 1 ? "issue" : "issues"}</span></div>`));
    const open = f => {
        view = {
            name: "secret",
            project: f.project,
            secret: f.key
        };
        render();
    };
    const row = (f, detail) => {
        const r = el(`<div class="row"><div class="grow"><div class="name mono"></div><div class="sub"></div></div><div class="chev">›</div></div>`);
        r.querySelector(".name").textContent = f.key;
        r.querySelector(".sub").textContent = [ f.project, detail ].filter(Boolean).join(" · ");
        r.onclick = () => open(f);
        return r;
    };
    if (!findings.length) scroll.appendChild(el(`<div class="empty"><div class="big">Nothing to fix</div><p>No weak, reused, old or expiring passwords.</p></div>`));
    for (const [ problem, [ title, about ] ] of Object.entries(PROBLEMS)) {
        const group = findings.filter(f => f.problem === problem);
        if (!group.length) continue;
        const body = panel(scroll, title, {
            tag: String(group.length)
        });
        body.appendChild(el(`<div class="note"></div>`)).textContent = about;
        for (const f of group) body.appendChild(row(f, f.detail));
    }
    const breach = panel(scroll, "Breached passwords");
    breach.appendChild(el(`<div class="note">Checks your passwords against Have I Been Pwned. Only the first 5 characters of each password's SHA-1 hash leave this device; nothing runs until you choose Check.</div>`));
    const check = el(`<button class="btn sm">Check now</button>`);
    const out = el(`<div></div>`);
    check.onclick = async () => {
        check.disabled = true;
        check.textContent = "Checking…";
        out.textContent = "";
        try {
            const r = await window.vault.breachCheck();
            if (revision !== renderVersion) return;
            if (!r.breached.length) out.appendChild(el(`<div class="note good">None of your passwords appear in known breaches.</div>`));
            for (const b of r.breached) out.appendChild(row(b, `seen ${b.count.toLocaleString()} times in breaches`));
        } catch (e) {
            out.appendChild(el(`<div class="err"></div>`)).textContent = cleanError(e);
        }
        check.disabled = false;
        check.textContent = "Check again";
    };
    breach.append(check, out);
    const leaks = panel(scroll, "Leaked values");
    leaks.appendChild(el(`<div class="note">Looks for your vault's values in a folder's files (.git and node_modules are skipped). Nothing leaves this device. For staged changes and Git history, use <span class="mono">vaultos scan --staged</span> or <span class="mono">--history</span> with a saved index.</div>`));
    const scanBtn = el(`<button class="btn sm">Scan a folder…</button>`);
    const saveIndex = el(`<button class="btn ghost sm">Save index for vaultos scan</button>`);
    const found = el(`<div></div>`);
    scanBtn.onclick = async () => {
        scanBtn.disabled = true;
        scanBtn.textContent = "Scanning…";
        found.textContent = "";
        try {
            const r = await window.vault.scanFolder();
            if (revision !== renderVersion) return;
            if (r.ok) {
                const summary = `${r.files.toLocaleString()} files in ${r.folder}${r.incomplete ? " (stopped at the limit)" : ""}`;
                if (!r.findings.length) found.appendChild(el(`<div class="note good"></div>`)).textContent = `No values from your vault in ${summary}.`;
                else found.appendChild(el(`<div class="note bad"></div>`)).textContent = `${r.findings.length} found in ${summary}. Rotate any value that was shared or committed.`;
                for (const f of r.findings) {
                    const item = f.items[0] || {};
                    found.appendChild(row({ project: item.project, key: item.item || "Unknown item" }, `${f.path}:${f.line}`));
                }
            }
        } catch (e) {
            found.appendChild(el(`<div class="err"></div>`)).textContent = cleanError(e);
        }
        scanBtn.disabled = false;
        scanBtn.textContent = "Scan a folder…";
    };
    saveIndex.onclick = async () => {
        found.textContent = "";
        try {
            const r = await human("saveLeakIndex");
            if (revision !== renderVersion) return;
            found.appendChild(el(`<div class="note good"></div>`)).textContent = `Saved an index of ${r.indexed} values (keyed hashes only). Save it again after adding secrets.`;
        } catch (e) {
            found.appendChild(el(`<div class="err"></div>`)).textContent = cleanError(e);
        }
    };
    leaks.append(scanBtn, saveIndex, found);
    $app.appendChild(scroll);
}

const ACTION_LABELS = {
    create_secret: "Created",
    update_secret: "Edited",
    update_meta: "Details changed",
    trash_secret: "Moved to the Trash",
    restore_secret: "Restored",
    add_attachment: "File attached",
    remove_attachment: "File removed",
    import_items: "Imported",
    move_secret: "Moved"
};

async function renderVersions() {
    const revision = renderVersion;
    const {project: project, secret: key} = view;
    $app.appendChild(topbar({
        crumb: backTo(key, {
            name: "secret",
            project: project,
            secret: key
        })
    }));
    const scroll = el(`<div class="scroll"></div>`);
    const entries = await window.vault.itemHistory(project, key);
    if (revision !== renderVersion) return;
    scroll.appendChild(el(`<div class="section"><span class="label mono"></span><span class="label">Versions</span></div>`)).querySelector(".label").textContent = key;
    scroll.appendChild(el(`<p class="note" style="margin:-4px 2px 12px">Restoring a version keeps the current owner, delegation and attachments, and can be undone.</p>`));
    const err = el(`<div class="err"></div>`);
    scroll.appendChild(err);
    if (!entries.length) scroll.appendChild(el(`<div class="empty"><div class="big">No versions yet</div></div>`));
    for (const e of entries) {
        const card = el(`<div class="secret card"><div class="key"></div><p class="note"></p></div>`);
        card.querySelector(".key").textContent = ACTION_LABELS[e.action] || e.action;
        card.querySelector(".note").textContent = `${e.ts} · ${agentLabel(e.actor)}${e.reverted ? " · undone" : ""}`;
        if (e.restorable) {
            const b = el(`<button class="btn ghost sm">Restore this version</button>`);
            b.onclick = async () => {
                try {
                    await window.vault.restoreVersion(e.id);
                    view = {
                        name: "project",
                        project: project,
                        focusKey: key
                    };
                    render();
                } catch (x) {
                    err.textContent = cleanError(x);
                }
            };
            card.appendChild(b);
        }
        scroll.appendChild(card);
    }
    $app.appendChild(scroll);
}

// Import from 1Password (.1pux), Bitwarden (.json) or a CSV into a project.
async function importInto(project, status) {
    status.className = "note";
    status.textContent = "";
    try {
        const r = await window.vault.importFile(project);
        if (!r.ok) return false;
        const {imported: imported, renamed: renamed, skipped: skipped} = r.result;
        status.textContent = [ `Imported ${imported} ${imported === 1 ? "item" : "items"}.`, renamed.length && `${renamed.length} saved under a new name because the name was taken.`, skipped.length && `Skipped ${skipped.length}: ${skipped.slice(0, 3).join("; ")}${skipped.length > 3 ? "…" : ""}` ].filter(Boolean).join(" ");
        return true;
    } catch (e) {
        status.className = "err";
        status.textContent = cleanError(e);
        return false;
    }
}
