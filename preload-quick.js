"use strict";

// The Quick Access panel's whole surface: unlock, search metadata, copy, open. Its calls use
// their own "quick:" channels, which the main process accepts only from the panel.
const {contextBridge: contextBridge, ipcRenderer: ipcRenderer} = require("electron");

const on = channel => fn => {
    const listener = () => fn();
    ipcRenderer.on(channel, listener);
    return () => ipcRenderer.removeListener(channel, listener);
};

contextBridge.exposeInMainWorld("quick", {
    state: () => ipcRenderer.invoke("quick:state"),
    unlock: pw => ipcRenderer.invoke("quick:unlock", pw),
    unlockTouchId: () => ipcRenderer.invoke("quick:unlockTouchId"),
    confirmHuman: pw => ipcRenderer.invoke("quick:confirmHuman", pw),
    search: q => ipcRenderer.invoke("quick:search", q),
    copy: (project, key, field) => ipcRenderer.invoke("quick:copy", project, key, field),
    openUrl: (project, key) => ipcRenderer.invoke("quick:openUrl", project, key),
    open: (project, key) => ipcRenderer.invoke("quick:open", project, key),
    openMain: () => ipcRenderer.invoke("quick:openMain"),
    hide: () => ipcRenderer.invoke("quick:hide"),
    onShow: on("quick:show"),
    onLocked: on("quick:locked")
});
