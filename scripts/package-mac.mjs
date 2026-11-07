// Packages VaultOS.app: the Tauri desktop app in Contents/MacOS, with vaultos, vaultos-agent,
// vaultos-mcp, vaultosd, vaultos-ssh-sign and vaultos-browser in Contents/Helpers (not beside
// it: on a case-insensitive volume `vaultos` would replace `VaultOS`), and the unpacked
// browser extension in Contents/Resources/extension. Writes a ZIP, its checksum and a CycloneDX inventory.
// The build is ad-hoc signed ("unsigned") unless VAULTOS_SIGN_IDENTITY names a Developer ID
// Application identity and notarization credentials are set, and signing and notarization
// pass. Notarization takes a notarytool Keychain profile (VAULTOS_NOTARY_PROFILE) or an App
// Store Connect API key: VAULTOS_NOTARY_KEY (absolute path of the .p8 file),
// VAULTOS_NOTARY_KEY_ID and VAULTOS_NOTARY_ISSUER.
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
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

// Inner programs first, then the bundle, each under its own identifier.
const sign = (target, id) => execFileSync("/usr/bin/codesign", identity ? [ "--force", "--options", "runtime", "--timestamp", "--sign", identity, "--identifier", id, target ] : [ "--force", "--sign", "-", "--identifier", id, target ], {
    stdio: "inherit"
});
for (const tool of TOOLS) sign(path.join(helpers, tool), `org.vaultos.preview.${tool}`);
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
budget("VaultOS.app", app, 20);
budget(path.basename(zip), zip, 8);
checksum(zip);
sbom(triple, zip.replace(/\.zip$/, ".cdx.json"));
console.log("Built " + zip);
