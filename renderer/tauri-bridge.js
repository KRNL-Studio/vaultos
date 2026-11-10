"use strict";

// The desktop's bridge: the window.vault / window.quick surface the pages use, over two
// Tauri commands. The Rust process checks which window and page each call comes from, and
// whether the vault is unlocked. Outside Tauri this file does nothing.
(() => {
    const T = window.__TAURI__;
    if (!T || !T.core) return;
    const current = T.webviewWindow.getCurrentWebviewWindow();
    // Tauri rejects with a string; the pages expect Error objects.
    const invoke = (command, channel, args) => T.core.invoke(command, {
        channel: channel,
        args: args
    }).catch(e => {
        throw new Error(typeof e === "string" ? e : e && e.message || "The operation failed. Please retry.");
    });
    const on = name => fn => {
        let unlisten = null, stopped = false;
        current.listen(name, () => fn()).then(u => {
            if (stopped) u(); else unlisten = u;
        });
        return () => {
            stopped = true;
            if (unlisten) unlisten();
        };
    };
    const api = (command, names) => Object.fromEntries(names.map(n => [ n, (...args) => invoke(command, n, args) ]));

    // Elements styled as a title bar (-webkit-app-region: drag) move the window.
    document.addEventListener("mousedown", e => {
        if (e.button !== 0 || e.detail > 1) return;
        for (let n = e.target; n && n.nodeType === 1; n = n.parentElement) {
            const region = getComputedStyle(n).getPropertyValue("-webkit-app-region").trim();
            if (region === "no-drag" || n.matches("button, input, textarea, select, a, [contenteditable]")) return;
            if (region === "drag") {
                current.startDragging();
                return;
            }
        }
    });

    if (location.pathname.endsWith("/quick.html")) {
        window.quick = {
            ...api("quick", [ "state", "unlock", "unlockTouchId", "confirmHuman", "search", "copy", "copyOtp", "openUrl", "open", "openMain", "hide" ]),
            onShow: on("quick:show"),
            onLocked: on("quick:locked")
        };
        return;
    }
    const vault = api("vault", [ "state", "providers", "takeCommand", "search", "getDesktopPrefs", "setDesktopPrefs", "chooseFolder", "setAgentAccess", "copy", "init", "unlock", "unlockTouchId", "upgrade", "confirmHuman", "lock", "projects", "createProject", "deleteProject", "secrets", "setSecret", "deleteSecret", "reveal", "getSettings", "setSettings", "changePassword", "secretKeyState", "setSecretKey", "removeSecretKey", "saveEmergencyKit", "agents", "enrolAgent", "reissueAgent", "revokeAgent", "setAgentScopes", "setAgentRunCommands", "allScopes", "delegate", "adopt", "approveInject", "approveInjectAll", "pending", "history", "revert", "syncStatus", "syncPush", "syncPull", "syncInit", "syncIdentity", "syncTrust", "syncDevices", "syncUntrust", "trash", "restoreSecret", "purgeSecret", "emptyTrash", "generate", "generateSshKey", "browsers", "setUpBrowsers", "removeBrowserHelper", "unpairBrowser", "accessGrants", "endAccess", "strength", "otp", "copyOtp", "addAttachment", "saveAttachment", "removeAttachment", "itemHistory", "restoreVersion", "watchtower", "breachCheck", "scanFolder", "saveLeakIndex", "importFile", "quit" ]);
    vault.exportProject = project => invoke("vault", "export", [ project ]);
    vault.onLocked = on("vault:locked");
    vault.onUnlocked = on("vault:unlocked");
    vault.onCommand = on("vault:command");
    window.vault = vault;
})();
