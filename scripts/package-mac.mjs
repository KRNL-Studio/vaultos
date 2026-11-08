// Packages VaultOS.app: the Tauri desktop app in Contents/MacOS, with vaultos, vaultos-agent,
// vaultos-mcp, vaultosd, vaultos-ssh-sign and vaultos-browser in Contents/Helpers (not beside
// it: on a case-insensitive volume `vaultos` would replace `VaultOS`), and the unpacked
// browser extension in Contents/Resources/extension, and the Safari app extension in
// Contents/PlugIns (the same web extension, with a Safari manifest, and a sandboxed handler that
// relays through its own copy of vaultos-browser). Writes a ZIP, its checksum and a CycloneDX inventory.
// The build is ad-hoc signed ("unsigned") unless VAULTOS_SIGN_IDENTITY names a Developer ID
// Application identity and notarization credentials are set, and signing and notarization
// pass. Notarization takes a notarytool Keychain profile (VAULTOS_NOTARY_PROFILE) or an App
// Store Connect API key: VAULTOS_NOTARY_KEY (absolute path of the .p8 file),
// VAULTOS_NOTARY_KEY_ID and VAULTOS_NOTARY_ISSUER.
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { budget, build, checksum, sbom, TOOLS, version } from "./rust-dist.mjs";

if (process.platform !== "darwin") throw new Error("Build macOS artifacts on macOS; use npm run dist:linux on Linux");
const arch = process.env.VAULTOS_ARCH || process.arch;
const triple = {
    arm64: "aarch64-apple-darwin",
    x64: "x86_64-apple-darwin"
}[arch];
if (!triple) throw new Error("Supported architectures: arm64, x64");
const identity = process.env.VAULTOS_SIGN_IDENTITY;
const env = process.env;
const notary = env.VAULTOS_NOTARY_PROFILE ? [ "--keychain-profile", env.VAULTOS_NOTARY_PROFILE ] : env.VAULTOS_NOTARY_KEY && env.VAULTOS_NOTARY_KEY_ID && env.VAULTOS_NOTARY_ISSUER ? [ "--key", env.VAULTOS_NOTARY_KEY, "--key-id", env.VAULTOS_NOTARY_KEY_ID, "--issuer", env.VAULTOS_NOTARY_ISSUER ] : null;
if (identity && !notary) throw new Error("A signed build must also be notarized: set VAULTOS_NOTARY_PROFILE, or VAULTOS_NOTARY_KEY, VAULTOS_NOTARY_KEY_ID and VAULTOS_NOTARY_ISSUER");
if (env.VAULTOS_NOTARY_KEY && !path.isAbsolute(env.VAULTOS_NOTARY_KEY)) throw new Error("VAULTOS_NOTARY_KEY must be an absolute path");

const v = version();
const release = build(triple);
const folder = path.resolve("dist", `VaultOS-darwin-${arch}`);
const app = path.join(folder, "VaultOS.app");
rmSync(folder, {
    recursive: true,
    force: true
});
const macos = path.join(app, "Contents", "MacOS");
const helpers = path.join(app, "Contents", "Helpers");
const resources = path.join(app, "Contents", "Resources");
for (const dir of [ macos, helpers, resources ]) mkdirSync(dir, {
    recursive: true
});
copyFileSync(path.join(release, "vaultos-desktop"), path.join(macos, "VaultOS"));
chmodSync(path.join(macos, "VaultOS"), 0o755);
for (const tool of TOOLS) {
    copyFileSync(path.join(release, tool), path.join(helpers, tool));
    chmodSync(path.join(helpers, tool), 0o755);
}
copyFileSync("build/AppIcon.icns", path.join(resources, "AppIcon.icns"));
for (const notice of [ "LICENSE", "THIRD_PARTY_NOTICES.md" ]) copyFileSync(notice, path.join(resources, notice));
cpSync("extension", path.join(resources, "extension"), {
    recursive: true
});

// Safari: VaultOS.app/Contents/PlugIns/VaultOS Safari.appex.
const appex = path.join(app, "Contents", "PlugIns", "VaultOS Safari.appex");
const appexMacos = path.join(appex, "Contents", "MacOS");
const appexResources = path.join(appex, "Contents", "Resources");
for (const dir of [ appexMacos, appexResources ]) mkdirSync(dir, {
    recursive: true
});
execFileSync("/usr/bin/xcrun", [ "swiftc", "-O", "-target", `${arch === "arm64" ? "arm64" : "x86_64"}-apple-macos13.0`, "-module-name", "VaultOSSafari", "-parse-as-library", "-application-extension", "-framework", "SafariServices", "-Xlinker", "-e", "-Xlinker", "_NSExtensionMain", "-o", path.join(appexMacos, "VaultOSSafari"), "safari/SafariWebExtensionHandler.swift" ], {
    stdio: "inherit"
});
copyFileSync(path.join(release, "vaultos-browser"), path.join(appexMacos, "vaultos-browser"));
chmodSync(path.join(appexMacos, "vaultos-browser"), 0o755);
cpSync("extension", appexResources, {
    recursive: true
});
// Safari ignores Chromium's key and version floor; it needs MV3 service workers and session storage.
const safariManifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
delete safariManifest.key;
delete safariManifest.minimum_chrome_version;
// Passkeys run in the page's own world, which has not been tried in Safari: leave them out there.
safariManifest.content_scripts = safariManifest.content_scripts.filter(c => c.world !== "MAIN");
rmSync(path.join(appexResources, "passkeys.js"));
rmSync(path.join(appexResources, "passkey.js"));
rmSync(path.join(appexResources, "passkey.html"));
safariManifest.browser_specific_settings = {
    safari: {
        strict_min_version: "16.4"
    }
};
writeFileSync(path.join(appexResources, "manifest.json"), JSON.stringify(safariManifest, null, 2) + "\n");
writeFileSync(path.join(appex, "Contents", "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>CFBundleDevelopmentRegion</key>
\t<string>en</string>
\t<key>CFBundleDisplayName</key>
\t<string>VaultOS</string>
\t<key>CFBundleExecutable</key>
\t<string>VaultOSSafari</string>
\t<key>CFBundleIdentifier</key>
\t<string>org.vaultos.preview.safari</string>
\t<key>CFBundleInfoDictionaryVersion</key>
\t<string>6.0</string>
\t<key>CFBundleName</key>
\t<string>VaultOS Safari</string>
\t<key>CFBundlePackageType</key>
\t<string>XPC!</string>
\t<key>CFBundleShortVersionString</key>
\t<string>${v.replace(/-.*$/, "")}</string>
\t<key>CFBundleVersion</key>
\t<string>1</string>
\t<key>LSMinimumSystemVersion</key>
\t<string>13.0</string>
\t<key>NSHumanReadableDescription</key>
\t<string>Fill and save website logins from the VaultOS app.</string>
\t<key>NSExtension</key>
\t<dict>
\t\t<key>NSExtensionPointIdentifier</key>
\t\t<string>com.apple.Safari.web-extension</string>
\t\t<key>NSExtensionPrincipalClass</key>
\t\t<string>VaultOSSafari.SafariWebExtensionHandler</string>
\t</dict>
</dict>
</plist>
`);

const plist = {
    CFBundleDevelopmentRegion: "en",
    CFBundleDisplayName: "VaultOS",
    CFBundleExecutable: "VaultOS",
    CFBundleIconFile: "AppIcon",
    CFBundleIdentifier: "org.vaultos.preview",
    CFBundleInfoDictionaryVersion: "6.0",
    CFBundleName: "VaultOS",
    CFBundlePackageType: "APPL",
    CFBundleShortVersionString: v.replace(/-.*$/, ""),
    CFBundleVersion: "1",
    LSApplicationCategoryType: "public.app-category.developer-tools",
    LSMinimumSystemVersion: "13.0",
    NSHighResolutionCapable: true,
    NSHumanReadableCopyright: "MIT licensed. Preview build."
};
const entry = ([ k, val ]) => `\t<key>${k}</key>\n\t${val === true ? "<true/>" : `<string>${val}</string>`}`;
writeFileSync(path.join(app, "Contents", "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
${Object.entries(plist).map(entry).join("\n")}
</dict>
</plist>
`);

// Inner programs first, then the bundles, each under its own identifier. The Safari app
// extension and its helper run sandboxed.
const sign = (target, id, entitlements) => execFileSync("/usr/bin/codesign", [ "--force", ...identity ? [ "--options", "runtime", "--timestamp", "--sign", identity ] : [ "--sign", "-" ], "--identifier", id, ...entitlements ? [ "--entitlements", entitlements ] : [], target ], {
    stdio: "inherit"
});
for (const tool of TOOLS) sign(path.join(helpers, tool), `org.vaultos.preview.${tool}`);
sign(path.join(appexMacos, "vaultos-browser"), "org.vaultos.preview.safari.vaultos-browser", "safari/helper.entitlements");
sign(appex, "org.vaultos.preview.safari", "safari/extension.entitlements");
sign(app, "org.vaultos.preview");
execFileSync("/usr/bin/codesign", [ "--verify", "--deep", "--strict", app ], {
    stdio: "inherit"
});

const kind = identity ? "notarized" : "unsigned";
const zip = path.resolve("dist", `VaultOS-${v}-macOS-${arch}-${kind}.zip`);
const archive = () => {
    rmSync(zip, {
        force: true
    });
    execFileSync("/usr/bin/ditto", [ "-c", "-k", "--sequesterRsrc", "--keepParent", app, zip ]);
};
archive();
// A ZIP is named "notarized" only once Apple accepted it and the ticket is stapled.
if (identity) try {
    const submitted = JSON.parse(execFileSync("/usr/bin/xcrun", [ "notarytool", "submit", zip, ...notary, "--wait", "--output-format", "json" ], {
        encoding: "utf8",
        stdio: [ "ignore", "pipe", "inherit" ]
    }));
    if (submitted.status !== "Accepted") throw new Error(`Notarization ${submitted.status} (submission ${submitted.id}); see: xcrun notarytool log ${submitted.id}`);
    execFileSync("/usr/bin/xcrun", [ "stapler", "staple", app ], {
        stdio: "inherit"
    });
    execFileSync("/usr/sbin/spctl", [ "--assess", "--type", "execute", "--verbose", app ], {
        stdio: "inherit"
    });
    archive();
} catch (e) {
    rmSync(zip, {
        force: true
    });
    throw e;
}
budget("VaultOS.app", app, 24);
budget(path.basename(zip), zip, 9);
checksum(zip);
sbom(triple, zip.replace(/\.zip$/, ".cdx.json"));
console.log("Built " + zip);
