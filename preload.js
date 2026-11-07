"use strict";

const {contextBridge: contextBridge, ipcRenderer: ipcRenderer} = require("electron");

contextBridge.exposeInMainWorld("vault", {
    state: () => ipcRenderer.invoke("vault:state"),
    providers: () => ipcRenderer.invoke("vault:providers"),
    onLocked: fn => {
        const listener = () => fn();
        ipcRenderer.on("vault:locked", listener);
        return () => ipcRenderer.removeListener("vault:locked", listener);
    },
    onUnlocked: fn => {
        const listener = () => fn();
        ipcRenderer.on("vault:unlocked", listener);
        return () => ipcRenderer.removeListener("vault:unlocked", listener);
    },
    onCommand: fn => {
        const listener = () => fn();
        ipcRenderer.on("vault:command", listener);
        return () => ipcRenderer.removeListener("vault:command", listener);
    },
    takeCommand: () => ipcRenderer.invoke("vault:takeCommand"),
    search: q => ipcRenderer.invoke("vault:search", q),
    getDesktopPrefs: () => ipcRenderer.invoke("vault:getDesktopPrefs"),
    setDesktopPrefs: patch => ipcRenderer.invoke("vault:setDesktopPrefs", patch),
    chooseFolder: () => ipcRenderer.invoke("vault:chooseFolder"),
    setAgentAccess: (id, projects, roots, wildcards) => ipcRenderer.invoke("vault:setAgentAccess", id, projects, roots, wildcards),
    copy: (project, key) => ipcRenderer.invoke("vault:copy", project, key),
    init: pw => ipcRenderer.invoke("vault:init", pw),
    unlock: pw => ipcRenderer.invoke("vault:unlock", pw),
    unlockTouchId: () => ipcRenderer.invoke("vault:unlockTouchId"),
    confirmHuman: pw => ipcRenderer.invoke("vault:confirmHuman", pw),
    lock: () => ipcRenderer.invoke("vault:lock"),
    projects: () => ipcRenderer.invoke("vault:projects"),
    createProject: name => ipcRenderer.invoke("vault:createProject", name),
    deleteProject: id => ipcRenderer.invoke("vault:deleteProject", id),
    secrets: project => ipcRenderer.invoke("vault:secrets", project),
    setSecret: (project, secret) => ipcRenderer.invoke("vault:setSecret", project, secret),
    deleteSecret: (project, key) => ipcRenderer.invoke("vault:deleteSecret", project, key),
    reveal: (project, key) => ipcRenderer.invoke("vault:reveal", project, key),
    getSettings: () => ipcRenderer.invoke("vault:getSettings"),
    setSettings: patch => ipcRenderer.invoke("vault:setSettings", patch),
    exportProject: project => ipcRenderer.invoke("vault:export", project),
    changePassword: (oldPw, newPw) => ipcRenderer.invoke("vault:changePassword", oldPw, newPw),
    agents: () => ipcRenderer.invoke("vault:agents"),
    enrolAgent: (name, scopes, projects, roots, wildcards) => ipcRenderer.invoke("vault:enrolAgent", name, scopes, projects, roots, wildcards),
    reissueAgent: id => ipcRenderer.invoke("vault:reissueAgent", id),
    revokeAgent: id => ipcRenderer.invoke("vault:revokeAgent", id),
    setAgentScopes: (id, scopes) => ipcRenderer.invoke("vault:setAgentScopes", id, scopes),
    allScopes: () => ipcRenderer.invoke("vault:allScopes"),
    delegate: (project, key, agentRef, on) => ipcRenderer.invoke("vault:delegate", project, key, agentRef, on),
    adopt: (project, key) => ipcRenderer.invoke("vault:adopt", project, key),
    approveInject: (project, key, on) => ipcRenderer.invoke("vault:approveInject", project, key, on),
    approveInjectAll: items => ipcRenderer.invoke("vault:approveInjectAll", items),
    pending: () => ipcRenderer.invoke("vault:pending"),
    history: limit => ipcRenderer.invoke("vault:history", limit),
    revert: id => ipcRenderer.invoke("vault:revert", id),
    audit: limit => ipcRenderer.invoke("vault:audit", limit),
    syncStatus: () => ipcRenderer.invoke("vault:syncStatus"),
    syncPush: () => ipcRenderer.invoke("vault:syncPush"),
    syncPull: accept => ipcRenderer.invoke("vault:syncPull", accept),
    syncInit: label => ipcRenderer.invoke("vault:syncInit", label),
    syncIdentity: () => ipcRenderer.invoke("vault:syncIdentity"),
    syncTrust: identity => ipcRenderer.invoke("vault:syncTrust", identity),
    quit: () => ipcRenderer.invoke("vault:quit")
});
