// Points the in-app updater at a published release: reads the release's signed update archives
// (VaultOS-<version>-macOS-<arch>-notarized.app.tar.gz and .sig), writes dist/latest.json and, with
// --publish, uploads it to the `updates` release, which the app reads at
// https://github.com/KRNL-Studio/vaultos/releases/download/updates/latest.json.
//
//   node scripts/update-feed.mjs v0.3.0-preview.5 [--publish] [--allow-unsigned]
//
// Only notarized archives are offered unless --allow-unsigned is given, so an update never
// replaces a notarized app with an ad hoc signed one by default. A Mac whose architecture has no
// archive in the release is simply not offered the update.
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const REPO = "KRNL-Studio/vaultos";
const FEED = "updates";
const PLATFORMS = {
    arm64: "darwin-aarch64",
    x64: "darwin-x86_64"
};

const args = process.argv.slice(2);
const tag = args.find(a => !a.startsWith("--"));
const publish = args.includes("--publish");
const allowUnsigned = args.includes("--allow-unsigned");
if (!tag || !/^v[0-9]+\.[0-9]+\.[0-9]+(-preview\.[0-9]+)?$/.test(tag)) throw new Error("Usage: node scripts/update-feed.mjs v<version> [--publish] [--allow-unsigned]");
const version = tag.slice(1);

const gh = (...a) => execFileSync("gh", a, {
    encoding: "utf8",
    stdio: [ "ignore", "pipe", "inherit" ]
});
const release = JSON.parse(gh("release", "view", tag, "-R", REPO, "--json", "assets,publishedAt,url,isDraft"));
if (release.isDraft) throw new Error(`${tag} is still a draft; publish it first`);
const assets = new Map(release.assets.map(a => [ a.name, a ]));

const platforms = {};
for (const [ arch, target ] of Object.entries(PLATFORMS)) {
    const kinds = allowUnsigned ? [ "notarized", "unsigned" ] : [ "notarized" ];
    const kind = kinds.find(k => assets.has(`VaultOS-${version}-macOS-${arch}-${k}.app.tar.gz`) && assets.has(`VaultOS-${version}-macOS-${arch}-${k}.app.tar.gz.sig`));
    if (!kind) {
        console.warn(`No signed ${kinds.join(" or ")} update archive for ${arch} in ${tag}; skipped`);
        continue;
    }
    const name = `VaultOS-${version}-macOS-${arch}-${kind}.app.tar.gz`;
    const signature = gh("release", "download", tag, "-R", REPO, "-p", `${name}.sig`, "-O", "-").trim();
    const signed = Buffer.from(signature, "base64").toString("utf8");
    if (!signed.includes(`\tversion:${version}`)) throw new Error(`${name}.sig is not bound to version ${version}`);
    platforms[target] = {
        signature: signature,
        url: assets.get(name).url
    };
    console.log(`${target}: ${name}`);
}
if (!Object.keys(platforms).length) throw new Error(`${tag} has no update archives to offer`);

const feed = {
    version: version,
    notes: `See ${release.url}`,
    pub_date: release.publishedAt,
    platforms: platforms
};
mkdirSync("dist", {
    recursive: true
});
const out = path.resolve("dist", "latest.json");
writeFileSync(out, JSON.stringify(feed, null, 2) + "\n");
console.log("Wrote " + out);

if (publish) {
    try {
        gh("release", "view", FEED, "-R", REPO, "--json", "tagName");
    } catch {
        gh("release", "create", FEED, "-R", REPO, "--prerelease", "--latest=false", "--title", "VaultOS update feed", "--notes", "The in-app updater reads latest.json from this release. It names the newest release and its signed update archives; download VaultOS itself from the versioned releases.");
    }
    gh("release", "upload", FEED, out, "-R", REPO, "--clobber");
    console.log(`Published the update feed for ${tag}`);
}
