import { cpSync, mkdirSync, readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";

import { tmpdir } from "node:os";

import path from "node:path";

import { execFileSync } from "node:child_process";

import { createHash } from "node:crypto";

import { packager } from "@electron/packager";

import { flipFuses, FuseVersion, FuseV1Options } from "@electron/fuses";

import { APP_FILES } from "./app-files.mjs";

if (process.platform !== "darwin") throw new Error("Build macOS artifacts on macOS; use npm run dist:linux for Linux");

const arch = process.env.VAULTOS_ARCH || process.arch;

if (![ "arm64", "x64" ].includes(arch)) throw new Error("Supported architectures: arm64, x64");

const pkg = JSON.parse(readFileSync("package.json"));

const stage = mkdtempSync(path.join(tmpdir(), "vaultos-package-"));

const files = [ ...APP_FILES, "build/AppIcon.icns" ];

try {
    for (const file of files) {
        mkdirSync(path.dirname(path.join(stage, file)), {
            recursive: true
        });
        cpSync(file, path.join(stage, file), {
            recursive: true
        });
    }
    execFileSync("npm", [ "ci", "--omit=dev", "--ignore-scripts" ], {
        cwd: stage,
        stdio: "inherit"
    });
    execFileSync(process.execPath, [ "scripts/build-native.mjs" ], {
        stdio: "inherit",
        env: {
            ...process.env,
            VAULTOS_ARCH: arch === "x64" ? "x86_64" : arch
        }
    });
    const [folder] = await packager({
        dir: stage,
        name: "VaultOS",
        platform: "darwin",
        arch: arch,
        electronVersion: pkg.devDependencies.electron,
        out: "dist",
        overwrite: true,
        asar: true,
        prune: false,
        appBundleId: "org.vaultos.preview",
        appVersion: pkg.version,
        buildVersion: "1",
        appCategoryType: "public.app-category.developer-tools",
        icon: "build/AppIcon.icns",
        darwinDarkModeSupport: true,
        extendInfo: {
            LSMinimumSystemVersion: "13.0"
        },
        extraResource: [ "build/native/vaultos-keychain", "build/native/vaultos-clipboard" ]
    });
    const bundle = path.join(folder, "VaultOS.app");
    cpSync(path.join(folder,'LICENSE'),path.join(bundle,'Contents','Resources','LICENSE.electron'));
    cpSync(path.join(folder,'LICENSES.chromium.html'),path.join(bundle,'Contents','Resources','LICENSES.chromium.html'));
    await flipFuses(bundle, {
        version: FuseVersion.V1,
        [FuseV1Options.RunAsNode]: false,
        [FuseV1Options.EnableCookieEncryption]: true,
        [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
        [FuseV1Options.EnableNodeCliInspectArguments]: false,
        [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
        [FuseV1Options.OnlyLoadAppFromAsar]: true
    });
    if (process.env.VAULTOS_SIGN_IDENTITY) {
        const {signAsync: signAsync} = await import("@electron/osx-sign");
        await signAsync({
            app: bundle,
            identity: process.env.VAULTOS_SIGN_IDENTITY,
            hardenedRuntime: true,
            optionsForFile: () => ({
                entitlements: "build/entitlements.plist"
            })
        });
        if (!process.env.VAULTOS_NOTARY_PROFILE) throw new Error("Signed public builds require a notarization profile");
        const {notarize: notarize} = await import("@electron/notarize");
        await notarize({
            appPath: bundle,
            keychainProfile: process.env.VAULTOS_NOTARY_PROFILE
        });
    } else {
        execFileSync("/usr/bin/codesign", [ "--force", "--deep", "--sign", "-", "--identifier", "org.vaultos.preview", bundle ], {
            stdio: "inherit"
        });
    }
    execFileSync("/usr/bin/codesign", [ "--verify", "--deep", "--strict", bundle ], {
        stdio: "inherit"
    });
    const kind = process.env.VAULTOS_SIGN_IDENTITY ? "notarized" : "unsigned";
    const zip = path.resolve("dist", `VaultOS-${pkg.version}-macOS-${arch}-${kind}.zip`);
    execFileSync("/usr/bin/ditto", [ "-c", "-k", "--sequesterRsrc", "--keepParent", bundle, zip ]);
    writeFileSync(zip + ".sha256", createHash("sha256").update(readFileSync(zip)).digest("hex") + "  " + path.basename(zip) + "\n");
    const sbom = execFileSync("npm", [ "sbom", "--package-lock-only", "--sbom-format=cyclonedx", "--omit=dev" ], {
        cwd: stage,
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024
    });
    writeFileSync(zip.replace(/\.zip$/, ".cdx.json"), sbom);
    console.log("Built " + zip);
} finally {
    rmSync(stage, {
        recursive: true,
        force: true
    });
}
