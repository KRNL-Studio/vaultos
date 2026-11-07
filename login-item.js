"use strict";

// Optional "open at login": a per-user LaunchAgent on macOS or an XDG autostart entry on
// Linux that starts VaultOS with --hidden, so it waits locked in the menu bar. Written only
// when the human turns the preference on, rewritten on each start (the app may have moved)
// and removed when it is turned off.

const fs = require("node:fs");

const os = require("node:os");

const path = require("node:path");

const LABEL = "org.vaultos.preview.desktop";

function itemPath({platform: platform = process.platform, home: home = os.homedir(), env: env = process.env} = {}) {
    if (platform === "darwin") return path.join(home, "Library", "LaunchAgents", `${LABEL}.plist`);
    if (platform === "linux") return path.join(env.XDG_CONFIG_HOME && path.isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : path.join(home, ".config"), "autostart", `${LABEL}.desktop`);
    return null;
}

const xml = s => String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&apos;"
})[c]);

// Desktop Entry Exec quoting: every argument double-quoted, with \ " ` $ escaped.
const execArg = s => `"${String(s).replace(/[\\"`$]/g, c => "\\" + c).replace(/%/g, "%%")}"`;

function content(command, {platform: platform = process.platform, dataDir: dataDir = null} = {}) {
    if (platform === "darwin") {
        const env = dataDir ? `\n  <key>EnvironmentVariables</key>\n  <dict><key>VAULTOS_DATA_DIR</key><string>${xml(dataDir)}</string></dict>` : "";
        return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>${command.map(a => `<string>${xml(a)}</string>`).join("")}</array>
  <key>RunAtLoad</key><true/>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProcessType</key><string>Interactive</string>${env}
</dict>
</plist>
`;
    }
    const exec = (dataDir ? [ "env", `VAULTOS_DATA_DIR=${dataDir}`, ...command ] : command).map(execArg).join(" ");
    return `[Desktop Entry]\nType=Application\nName=VaultOS\nComment=Start VaultOS locked in the system tray\nExec=${exec}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n`;
}

// One login item label serves every data directory, so an item is removed only by the vault
// it starts: a test or second vault with the preference off leaves another vault's item alone.
function belongsTo(text, {platform: platform = process.platform, dataDir: dataDir = null} = {}) {
    if (!dataDir) return !text.includes("VAULTOS_DATA_DIR");
    return platform === "darwin" ? text.includes(`<string>${xml(dataDir)}</string>`) : text.includes(execArg(`VAULTOS_DATA_DIR=${dataDir}`));
}

const safeArg = a => typeof a === "string" && !/[\0\n\r]/.test(a);

function setEnabled(on, command, options = {}) {
    const file = itemPath(options);
    if (!file) throw new Error("Open at login is not supported on this platform");
    if (options.dataDir != null && (!safeArg(options.dataDir) || !path.isAbsolute(options.dataDir))) throw new Error("Invalid data directory for open at login");
    if (!on) {
        try {
            const st = fs.lstatSync(file);
            if (st.isFile() && !st.isSymbolicLink() && st.size < 65536 && belongsTo(fs.readFileSync(file, "utf8"), options)) fs.unlinkSync(file);
        } catch (e) {
            if (e.code !== "ENOENT") throw e;
        }
        return false;
    }
    if (!Array.isArray(command) || !command.length || !command.every(safeArg)) throw new Error("Invalid login command");
    fs.mkdirSync(path.dirname(file), {
        recursive: true
    });
    try {
        if (fs.lstatSync(file).isSymbolicLink()) throw new Error("Refusing to replace a symbolic link");
    } catch (e) {
        if (e.code !== "ENOENT") throw e;
    }
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, content(command, options), {
        mode: 420
    });
    fs.renameSync(tmp, file);
    return true;
}

module.exports = {
    LABEL: LABEL,
    belongsTo: belongsTo,
    itemPath: itemPath,
    content: content,
    setEnabled: setEnabled
};
