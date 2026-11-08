// Runs in the page's own world, before its scripts, in the top frame only. It routes the
// page's WebAuthn calls to VaultOS: the request goes to content.js, which asks the extension,
// which shows its own window where the human picks a passkey or saves a new one. The page
// can see and forge these messages, but it gains nothing: it can already make WebAuthn calls,
// and VaultOS answers only for the page's own site, which the browser (not the page) reports,
// and only after the human chooses in a window no page can draw on. When VaultOS has nothing
// to offer, or the human chooses another device, the browser's own WebAuthn runs instead.
(() => {
    "use strict";
    const creds = globalThis.navigator && navigator.credentials;
    if (!creds || typeof PublicKeyCredential !== "function" || window.top !== window) return;
    const nativeCreate = creds.create.bind(creds);
    const nativeGet = creds.get.bind(creds);
    const REQUEST = "vaultos-passkey-request";
    const REPLY = "vaultos-passkey-reply";
    const CANCEL = "vaultos-passkey-cancel";

    const bytes = v => {
        if (v instanceof ArrayBuffer) return new Uint8Array(v);
        if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
        throw new TypeError("Expected a BufferSource");
    };
    const b64url = v => btoa(String.fromCharCode(...bytes(v))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const buffer = s => {
        const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out.buffer;
    };
    const ids = list => Array.isArray(list) ? list.filter(c => c && c.type === "public-key").map(c => b64url(c.id)) : [];

    let next = 0;
    function ask(kind, request, signal) {
        const id = `${Date.now()}-${++next}`;
        return new Promise((resolve, reject) => {
            const done = () => {
                window.removeEventListener("message", onReply);
                signal?.removeEventListener("abort", onAbort);
            };
            const onReply = e => {
                if (e.source !== window || !e.data || e.data.type !== REPLY || e.data.id !== id) return;
                done();
                resolve(e.data.result || { ok: false, code: "fallback" });
            };
            const onAbort = () => {
                done();
                window.postMessage({ type: CANCEL, id }, window.location.origin);
                reject(signal.reason ?? new DOMException("The operation was aborted.", "AbortError"));
            };
            if (signal?.aborted) return onAbort();
            window.addEventListener("message", onReply);
            signal?.addEventListener("abort", onAbort);
            window.postMessage({ type: REQUEST, id, kind, request }, window.location.origin);
        });
    }

    const own = (proto, props) => {
        const o = Object.create(proto);
        for (const [k, v] of Object.entries(props)) Object.defineProperty(o, k, { value: v, enumerable: typeof v !== "function" });
        return o;
    };

    function credential(r, response, json, extensions) {
        const c = own(PublicKeyCredential.prototype, {
            id: r.credentialId,
            rawId: buffer(r.credentialId),
            type: "public-key",
            authenticatorAttachment: "platform",
            response,
            getClientExtensionResults: () => ({ ...extensions }),
            toJSON: () => ({
                id: r.credentialId,
                rawId: r.credentialId,
                type: "public-key",
                authenticatorAttachment: "platform",
                clientExtensionResults: { ...extensions },
                response: json
            })
        });
        return c;
    }

    function failure(r) {
        if (r.code === "exists") return new DOMException("The authenticator already has a passkey for this account.", "InvalidStateError");
        if (r.code === "cancel") return new DOMException("The operation either timed out or was not allowed.", "NotAllowedError");
        return new DOMException(r.error || "VaultOS could not complete the request.", "NotAllowedError");
    }

    creds.create = async function create(options) {
        const pk = options && options.publicKey;
        if (!pk) return nativeCreate(options);
        let request;
        try {
            request = {
                rpId: pk.rp && pk.rp.id || window.location.hostname,
                rpName: String(pk.rp && pk.rp.name || ""),
                user: { id: b64url(pk.user.id), name: String(pk.user.name || ""), displayName: String(pk.user.displayName || "") },
                challenge: b64url(pk.challenge),
                algorithms: Array.isArray(pk.pubKeyCredParams) ? pk.pubKeyCredParams.filter(p => p && p.type === "public-key").map(p => Number(p.alg)) : [],
                exclude: ids(pk.excludeCredentials)
            };
        } catch {
            return nativeCreate(options);
        }
        const r = await ask("create", request, options.signal);
        if (r.ok === false && r.code === "fallback") return nativeCreate(options);
        if (!r.ok) throw failure(r);
        const extensions = pk.extensions && pk.extensions.credProps ? { credProps: { rk: true } } : {};
        const response = own(AuthenticatorAttestationResponse.prototype, {
            clientDataJSON: buffer(r.clientDataJSON),
            attestationObject: buffer(r.attestationObject),
            getAuthenticatorData: () => buffer(r.authenticatorData),
            getPublicKey: () => buffer(r.publicKey),
            getPublicKeyAlgorithm: () => -7,
            getTransports: () => [ "hybrid", "internal" ]
        });
        return credential(r, response, {
            clientDataJSON: r.clientDataJSON,
            attestationObject: r.attestationObject,
            authenticatorData: r.authenticatorData,
            publicKey: r.publicKey,
            publicKeyAlgorithm: -7,
            transports: [ "hybrid", "internal" ]
        }, extensions);
    };

    creds.get = async function get(options) {
        const pk = options && options.publicKey;
        // Passkey autofill waits for a field to be focused; VaultOS offers no such list yet.
        if (!pk || options.mediation === "conditional") return nativeGet(options);
        let request;
        try {
            request = { rpId: pk.rpId || window.location.hostname, challenge: b64url(pk.challenge), allow: ids(pk.allowCredentials) };
        } catch {
            return nativeGet(options);
        }
        const r = await ask("get", request, options.signal);
        if (r.ok === false && r.code === "fallback") return nativeGet(options);
        if (!r.ok) throw failure(r);
        const response = own(AuthenticatorAssertionResponse.prototype, {
            clientDataJSON: buffer(r.clientDataJSON),
            authenticatorData: buffer(r.authenticatorData),
            signature: buffer(r.signature),
            userHandle: buffer(r.userHandle)
        });
        return credential(r, response, {
            clientDataJSON: r.clientDataJSON,
            authenticatorData: r.authenticatorData,
            signature: r.signature,
            userHandle: r.userHandle
        }, {});
    };
})();
