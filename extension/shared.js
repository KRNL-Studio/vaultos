// Helpers shared by the extension's scripts, kept free of the DOM so Node can test them.
// Loaded as a classic script (content scripts cannot be modules) and by `require` in tests.
"use strict";

(function (root) {
    // Letters and digits that are hard to confuse, as the owner checks them.
    const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

    /** A pairing code, `XXXX-XXXX`, from 8 random bytes. */
    function pairingCode(bytes) {
        const chars = Array.from(bytes.slice(0, 8), b => CODE_ALPHABET[b % CODE_ALPHABET.length]);
        return chars.slice(0, 4).join("") + "-" + chars.slice(4).join("");
    }

    /** What to call this browser when pairing. */
    function browserName(brands, isBrave) {
        if (isBrave) return "Brave";
        const names = (brands || []).map(b => b.brand);
        for (const n of [ "Microsoft Edge", "Opera", "Arc", "Helium", "Google Chrome", "Chromium" ]) {
            if (names.includes(n)) return n === "Google Chrome" ? "Chrome" : n === "Microsoft Edge" ? "Edge" : n;
        }
        return "Browser";
    }

    const OTP_WORDS = /(one.?time|otp|totp|2fa|mfa|verification.?code|security.?code|auth.?code)/i;
    const USER_WORDS = /(user|login|email|e-mail|account|identifier)/i;

    /** A field for a one-time code, from its attributes. */
    function isOtp(f) {
        if ((f.autocomplete || "").includes("one-time-code")) return true;
        if (![ "text", "tel", "number", "" ].includes(f.type || "")) return false;
        return OTP_WORDS.test(`${f.name || ""} ${f.id || ""} ${f.placeholder || ""} ${f.label || ""}`);
    }

    /** A username or email field, from its attributes. */
    function isUsername(f) {
        const ac = f.autocomplete || "";
        if (ac.includes("username") || ac === "email") return true;
        if (![ "text", "email", "tel", "" ].includes(f.type || "")) return false;
        if (f.type === "email") return true;
        return USER_WORDS.test(`${f.name || ""} ${f.id || ""} ${f.placeholder || ""} ${f.label || ""}`);
    }

    /** Whether a submitted login is the one just filled, so no save is offered. */
    function sameLogin(a, b) {
        return Boolean(a && b) && a.username === b.username && a.passwordHash === b.passwordHash;
    }

    const isNewPassword = f => (f.autocomplete || "").includes("new-password");

    /**
     * Which of a form's password fields (`{autocomplete}` each, in order) to fill or to save
     * from, or -1 when the form is not that simple. Filling needs the form's only password
     * field, for the current password; saving takes the last new password (after the current
     * one and before none), or the only field.
     */
    function passwordField(fields, purpose) {
        if (purpose === "fill") return fields.length === 1 && !isNewPassword(fields[0]) ? 0 : -1;
        const fresh = fields.map((f, i) => isNewPassword(f) ? i : -1).filter(i => i >= 0);
        if (fresh.length) return fresh[fresh.length - 1];
        return fields.length === 1 ? 0 : -1;
    }

    /** The second line of a login in a menu: its username and the host it was saved for. */
    function loginDetail(login) {
        return [ login.username, login.host ].filter(Boolean).join(" · ") || login.project || "";
    }

    const CSS = `
:host { all: initial; }
.vo { font: 13px/1.35 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #111; }
.button { position: absolute; width: 20px; height: 20px; border: 0; border-radius: 5px; padding: 0;
  background: #1f6feb; color: #fff; font-weight: 700; font-size: 11px; cursor: pointer; box-shadow: 0 1px 3px #0004; }
.menu, .banner { position: absolute; background: #fff; border: 1px solid #d0d7de; border-radius: 8px;
  box-shadow: 0 8px 24px #0003; padding: 4px; min-width: 220px; max-width: 320px; }
.banner { position: fixed; top: 12px; right: 12px; padding: 12px; }
.item { display: block; width: 100%; text-align: left; border: 0; background: none; padding: 6px 8px;
  border-radius: 6px; cursor: pointer; font: inherit; color: inherit; }
.item:hover, .item:focus { background: #eef3fb; outline: none; }
.name { font-weight: 600; display: block; }
.sub { color: #57606a; font-size: 12px; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.note { color: #57606a; padding: 6px 8px; }
.row { display: flex; gap: 8px; justify-content: flex-end; margin-top: 10px; }
.primary, .secondary { border-radius: 6px; padding: 5px 10px; font: inherit; cursor: pointer; }
.primary { background: #1f6feb; color: #fff; border: 1px solid #1f6feb; }
.secondary { background: #fff; color: #111; border: 1px solid #d0d7de; }
@media (prefers-color-scheme: dark) {
  .vo { color: #e6edf3; }
  .menu, .banner { background: #161b22; border-color: #30363d; }
  .item:hover, .item:focus { background: #1f2a37; }
  .sub, .note { color: #8b949e; }
  .secondary { background: #161b22; color: #e6edf3; border-color: #30363d; }
}`;

    const shared = { CODE_ALPHABET, pairingCode, browserName, isOtp, isUsername, sameLogin, isNewPassword, passwordField, loginDetail, CSS };
    if (typeof module !== "undefined" && module.exports) module.exports = shared;
    else root.VaultOSShared = shared;
})(globalThis);
