import { mkdirSync } from "node:fs";

import { execFileSync } from "node:child_process";

if (process.platform !== "darwin") {
    console.log(`No native helper is needed on ${process.platform}; Linux uses secret-tool (libsecret) at run time.`);
    process.exit(0);
}

mkdirSync("build/native", {
    recursive: true
});

const arch = process.env.VAULTOS_ARCH || (process.arch === "arm64" ? "arm64" : "x86_64");

const helpers = [ [ "native/Keychain.swift", "vaultos-keychain" ], [ "native/Clipboard.swift", "vaultos-clipboard" ] ];

for (const [source, name] of helpers) {
    execFileSync("/usr/bin/swiftc", [ "-O", "-target", `${arch}-apple-macos13.0`, source, "-o", `build/native/${name}` ], {
        stdio: "inherit"
    });
    if (process.env.VAULTOS_BUILD_TEST_HELPER === "1") execFileSync("/usr/bin/swiftc", [ "-O", "-D", "VAULTOS_TEST", source, "-o", `build/native/${name}-test` ], {
        stdio: "inherit"
    });
}
