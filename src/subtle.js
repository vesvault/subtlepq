/***************************************************************************
 * subtlepq: spec-shaped ML-KEM / ML-DSA operations
 * per https://wicg.github.io/webcrypto-modern-algos/
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * These functions implement only the ML-* algorithms; routing between them
 * and the platform's native SubtleCrypto lives in index.js / install.js.
 * Shared secrets from encapsulateKey/decapsulateKey are imported through
 * the native SubtleCrypto, so the returned sharedKey is a genuine platform
 * CryptoKey and all downstream crypto is native.
 ***************************************************************************/

import { getEngine } from "./engine.js";
import {
    normalizeAlg, KEM_PUB_USAGES, KEM_PRIV_USAGES,
} from "./algorithms.js";
import { forgeKey, materialOf, isOurKey } from "./keystore.js";
import {
    encodeSpki, decodeSpki, encodePkcs8, decodePkcs8, b64u, unb64u,
} from "./formats.js";
import * as E from "./errors.js";

const rng = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export function toBytes(src, what) {
    if (ArrayBuffer.isView(src)) {
        return new Uint8Array(
            src.buffer.slice(src.byteOffset, src.byteOffset + src.byteLength));
    }
    if (src instanceof ArrayBuffer) return new Uint8Array(src.slice(0));
    throw E.dataError(what + " must be a BufferSource");
}

function requireAlg(alg, kind) {
    const a = normalizeAlg(alg);
    if (!a) throw E.notSupported("unrecognized algorithm");
    if (kind && a.kind !== kind) {
        throw E.notSupported(a.name + " does not support this operation");
    }
    return a;
}

function requireKey(key, a, type, usage) {
    if (!isOurKey(key)) {
        throw E.invalidAccess("key is not a " + a.name + " key from this polyfill");
    }
    if (key.algorithm.name !== a.name) {
        throw E.invalidAccess("key algorithm does not match " + a.name);
    }
    if (key.type !== type) throw E.invalidAccess("expected a " + type + " key");
    if (usage && !key.usages.includes(usage)) {
        throw E.invalidAccess("key does not permit " + usage);
    }
    return materialOf(key);
}

function checkUsages(usages, allowed) {
    for (const u of usages) {
        if (!allowed.includes(u)) throw E.syntaxError("unsupported key usage " + u);
    }
}

function signContext(a) {
    const ctx = a.context === undefined
        ? new Uint8Array(0) : toBytes(a.context, "context");
    if (ctx.length > 255) throw E.opError("context must be at most 255 bytes");
    return ctx;
}

export async function importSharedKey(ssBytes, sharedKeyAlgorithm, extractable, keyUsages) {
    const ns = globalThis.crypto && globalThis.crypto.subtle;
    if (!ns) throw E.notSupported("no native SubtleCrypto to hold the shared key");
    try {
        return await ns.importKey("raw", ssBytes, sharedKeyAlgorithm, extractable, keyUsages);
    } finally {
        ssBytes.fill(0);
    }
}

/* ---- key management ---- */

export async function generateKey(algorithm, extractable, keyUsages = []) {
    const a = requireAlg(algorithm);
    if (a.ops) return a.ops.generateKey(algorithm, extractable, keyUsages);
    const eng = await getEngine();
    if (a.kind === "kem") {
        checkUsages(keyUsages, [...KEM_PUB_USAGES, ...KEM_PRIV_USAGES]);
        const pubU = keyUsages.filter((u) => KEM_PUB_USAGES.includes(u));
        const privU = keyUsages.filter((u) => KEM_PRIV_USAGES.includes(u));
        if (!privU.length) throw E.syntaxError("private key usages must not be empty");
        const seed = rng(eng.kemLengths(a.name).seed);
        const { pub, sk } = eng.kemKeypairDerand(a.name, seed);
        return {
            publicKey: forgeKey("public", a.name, true, pubU, { pub }),
            privateKey: forgeKey("private", a.name, extractable, privU, { pub, seed, sk }),
        };
    }
    checkUsages(keyUsages, ["sign", "verify"]);
    if (!keyUsages.includes("sign")) {
        throw E.syntaxError("private key usages must not be empty");
    }
    const seed = rng(eng.sigLengths(a.name).seed);
    const { pub, sk } = eng.sigKeypairDerand(a.name, seed);
    return {
        publicKey: forgeKey("public", a.name, true,
            keyUsages.includes("verify") ? ["verify"] : [], { pub }),
        privateKey: forgeKey("private", a.name, extractable, ["sign"], { pub, seed, sk }),
    };
}

export async function importKey(format, keyData, algorithm, extractable, keyUsages = []) {
    const a = requireAlg(algorithm);
    if (a.ops) return a.ops.importKey(format, keyData, algorithm, extractable, keyUsages);
    const eng = await getEngine();
    const L = a.kind === "kem" ? eng.kemLengths(a.name) : eng.sigLengths(a.name);
    const pubUsages = a.kind === "kem" ? KEM_PUB_USAGES : ["verify"];
    const privUsages = a.kind === "kem" ? KEM_PRIV_USAGES : ["sign"];

    const importPub = (pub) => {
        checkUsages(keyUsages, pubUsages);
        if (pub.length !== L.pk) throw E.dataError("bad " + a.name + " public key length");
        return forgeKey("public", a.name, extractable, keyUsages, { pub });
    };
    /* expanded (pkcs8 "both" / jwk pub): must agree with the seed-derived value */
    const importSeed = (seed, expanded, expect) => {
        checkUsages(keyUsages, privUsages);
        if (!keyUsages.length) throw E.syntaxError("private key usages must not be empty");
        if (seed.length !== L.seed) throw E.dataError("bad " + a.name + " seed length");
        const { pub, sk } = a.kind === "kem"
            ? eng.kemKeypairDerand(a.name, seed)
            : eng.sigKeypairDerand(a.name, seed);
        if (expanded && !bytesEqual(expanded, expect === "pub" ? pub : sk)) {
            throw E.dataError(a.name + " seed and " +
                (expect === "pub" ? "public key" : "expandedKey") + " do not match");
        }
        return forgeKey("private", a.name, extractable, keyUsages, { pub, seed, sk });
    };

    if (format === "raw-public") return importPub(toBytes(keyData, "keyData"));
    if (format === "raw-seed") return importSeed(toBytes(keyData, "keyData"));
    if (format === "spki") {
        const { name, pub } = decodeSpki(toBytes(keyData, "keyData"));
        if (name !== a.name) throw E.dataError("SPKI algorithm is " + name + ", not " + a.name);
        return importPub(pub);
    }
    if (format === "pkcs8") {
        const { name, seed, expanded } = decodePkcs8(toBytes(keyData, "keyData"));
        if (name !== a.name) throw E.dataError("PKCS#8 algorithm is " + name + ", not " + a.name);
        return importSeed(seed, expanded, "sk");
    }
    if (format === "jwk") return importJwk(keyData, a, extractable, importPub, importSeed);
    throw E.notSupported("key format " + format + " is not supported");
}

function bytesEqual(x, y) {
    if (x.length !== y.length) return false;
    let d = 0;
    for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
    return d === 0;
}

function importJwk(jwk, a, extractable, importPub, importSeed) {
    if (!jwk || typeof jwk !== "object" || ArrayBuffer.isView(jwk) ||
            jwk instanceof ArrayBuffer) {
        throw E.dataError("jwk import expects a JsonWebKey object");
    }
    if (jwk.kty !== "AKP") throw E.dataError('JWK kty must be "AKP"');
    if (jwk.alg !== undefined && jwk.alg !== a.name) {
        throw E.dataError("JWK alg does not match " + a.name);
    }
    if (jwk.ext === false && extractable) {
        throw E.dataError("JWK ext forbids an extractable key");
    }
    const checkOps = (usages) => {
        if (jwk.key_ops === undefined) return;
        if (!Array.isArray(jwk.key_ops)) throw E.dataError("JWK key_ops must be an array");
        for (const u of usages) {
            if (!jwk.key_ops.includes(u)) {
                throw E.dataError("JWK key_ops does not permit " + u);
            }
        }
    };
    if (jwk.priv !== undefined) {
        const key = importSeed(unb64u(jwk.priv, "priv"),
            jwk.pub === undefined ? null : unb64u(jwk.pub, "pub"), "pub");
        checkOps(key.usages);
        return key;
    }
    if (jwk.pub === undefined) throw E.dataError("JWK has neither pub nor priv");
    const key = importPub(unb64u(jwk.pub, "pub"));
    checkOps(key.usages);
    return key;
}

export async function exportKey(format, key) {
    const a = requireAlg(key && key.algorithm && key.algorithm.name);
    const m = requireKey(key, a, key.type, null);
    if (!key.extractable) throw E.invalidAccess("key is not extractable");
    const pub = () => {
        if (key.type !== "public") throw E.invalidAccess(format + " exports public keys");
        return m.pub;
    };
    const seed = () => {
        if (key.type !== "private") throw E.invalidAccess(format + " exports private keys");
        return m.seed;
    };
    if (format === "raw-public") return pub().slice().buffer;
    if (format === "raw-seed") return seed().slice().buffer;
    if (format === "spki") return encodeSpki(a.name, pub()).buffer;
    if (format === "pkcs8") return encodePkcs8(a.name, seed()).buffer;
    if (format === "jwk") {
        const jwk = {
            kty: "AKP",
            alg: a.name,
            pub: b64u(m.pub),
            key_ops: [...key.usages],
            ext: key.extractable,
        };
        if (key.type === "private") jwk.priv = b64u(seed());
        return jwk;
    }
    throw E.notSupported("key format " + format + " is not supported");
}

export async function getPublicKey(key, keyUsages = []) {
    if (!isOurKey(key)) throw E.invalidAccess("key is not from this polyfill");
    const a = requireAlg(key.algorithm.name);
    if (key.type !== "private") throw E.invalidAccess("expected a private key");
    checkUsages(keyUsages, a.kind === "kem" ? KEM_PUB_USAGES : ["verify"]);
    return forgeKey("public", a.name, true, keyUsages, { pub: materialOf(key).pub });
}

/* ---- KEM operations ---- */

export async function encapsulateBits(algorithm, encapsulationKey) {
    const a = requireAlg(algorithm, "kem");
    if (a.ops) return a.ops.encapsulateBits(algorithm, encapsulationKey);
    const m = requireKey(encapsulationKey, a, "public", "encapsulateBits");
    const { ct, ss } = (await getEngine()).kemEncaps(a.name, m.pub);
    return { sharedKey: ss.buffer, ciphertext: ct.buffer };
}

export async function encapsulateKey(algorithm, encapsulationKey,
                                     sharedKeyAlgorithm, extractable, keyUsages) {
    const a = requireAlg(algorithm, "kem");
    if (a.ops) {
        return a.ops.encapsulateKey(algorithm, encapsulationKey,
            sharedKeyAlgorithm, extractable, keyUsages);
    }
    const m = requireKey(encapsulationKey, a, "public", "encapsulateKey");
    const { ct, ss } = (await getEngine()).kemEncaps(a.name, m.pub);
    const sharedKey = await importSharedKey(ss, sharedKeyAlgorithm, extractable, keyUsages);
    return { sharedKey, ciphertext: ct.buffer };
}

export async function decapsulateBits(algorithm, decapsulationKey, ciphertext) {
    const a = requireAlg(algorithm, "kem");
    if (a.ops) return a.ops.decapsulateBits(algorithm, decapsulationKey, ciphertext);
    const m = requireKey(decapsulationKey, a, "private", "decapsulateBits");
    const eng = await getEngine();
    const ct = toBytes(ciphertext, "ciphertext");
    if (ct.length !== eng.kemLengths(a.name).ct) {
        throw E.opError("bad " + a.name + " ciphertext length");
    }
    return eng.kemDecaps(a.name, m.sk, ct).buffer;
}

export async function decapsulateKey(algorithm, decapsulationKey, ciphertext,
                                     sharedKeyAlgorithm, extractable, keyUsages) {
    const a = requireAlg(algorithm, "kem");
    if (a.ops) {
        return a.ops.decapsulateKey(algorithm, decapsulationKey, ciphertext,
            sharedKeyAlgorithm, extractable, keyUsages);
    }
    const m = requireKey(decapsulationKey, a, "private", "decapsulateKey");
    const eng = await getEngine();
    const ct = toBytes(ciphertext, "ciphertext");
    if (ct.length !== eng.kemLengths(a.name).ct) {
        throw E.opError("bad " + a.name + " ciphertext length");
    }
    const ss = eng.kemDecaps(a.name, m.sk, ct);
    return importSharedKey(ss, sharedKeyAlgorithm, extractable, keyUsages);
}

/* ---- ML-DSA operations ---- */

export async function sign(algorithm, key, data) {
    const a = requireAlg(algorithm, "sig");
    const ctx = signContext(a);
    const m = requireKey(key, a, "private", "sign");
    return (await getEngine())
        .sigSign(a.name, m.sk, toBytes(data, "data"), ctx).buffer;
}

export async function verify(algorithm, key, signature, data) {
    const a = requireAlg(algorithm, "sig");
    const ctx = signContext(a);
    const m = requireKey(key, a, "public", "verify");
    return (await getEngine()).sigVerify(
        a.name, m.pub, toBytes(data, "data"), ctx, toBytes(signature, "signature"));
}

/* ---- wrapKey / unwrapKey: exportKey + native wrap composition ----
 *
 * The exported bytes ride through the native wrapKey/unwrapKey inside a
 * throwaway raw-imported HMAC key, so the wrap algorithm gets the native
 * spec-defined treatment (encrypt for AES-GCM/RSA-OAEP, key wrap for
 * AES-KW) and the wrapping key's own usages are enforced natively. */

function nativeSubtle() {
    const ns = globalThis.crypto && globalThis.crypto.subtle;
    if (!ns) throw E.notSupported("no native SubtleCrypto for key wrapping");
    return ns;
}

const CARRIER = { name: "HMAC", hash: "SHA-256" };

export async function wrapKey(format, key, wrappingKey, wrapAlgorithm) {
    if (isOurKey(wrappingKey)) {
        throw E.invalidAccess("ML-KEM/ML-DSA keys cannot wrap other keys");
    }
    if (!isOurKey(key)) {
        throw E.invalidAccess("key is not from this polyfill");
    }
    const exported = await exportKey(format, key);
    let bytes = format === "jwk"
        ? new TextEncoder().encode(JSON.stringify(exported))
        : new Uint8Array(exported);
    /* WebCrypto pads JWK JSON with spaces to the AES-KW 8-byte multiple */
    const wrapName = wrapAlgorithm && wrapAlgorithm.name || wrapAlgorithm;
    if (format === "jwk" && bytes.length % 8 &&
            String(wrapName).toUpperCase() === "AES-KW") {
        const padded = new Uint8Array(Math.ceil(bytes.length / 8) * 8).fill(0x20);
        padded.set(bytes);
        bytes.fill(0);
        bytes = padded;
    }
    const ns = nativeSubtle();
    try {
        const carrier = await ns.importKey("raw", bytes, CARRIER, true, ["sign"]);
        return await ns.wrapKey("raw", carrier, wrappingKey, wrapAlgorithm);
    } finally {
        bytes.fill(0);
    }
}

export async function unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm,
                                unwrappedKeyAlgorithm, extractable, keyUsages) {
    if (isOurKey(unwrappingKey)) {
        throw E.invalidAccess("ML-KEM/ML-DSA keys cannot unwrap other keys");
    }
    requireAlg(unwrappedKeyAlgorithm);
    const ns = nativeSubtle();
    const carrier = await ns.unwrapKey("raw", wrappedKey, unwrappingKey,
        unwrapAlgorithm, CARRIER, true, ["sign"]);
    const bytes = new Uint8Array(await ns.exportKey("raw", carrier));
    let keyData = bytes;
    if (format === "jwk") {
        try {
            keyData = JSON.parse(new TextDecoder().decode(bytes));
        } catch {
            throw E.dataError("unwrapped data is not JWK JSON");
        } finally {
            bytes.fill(0);
        }
    }
    try {
        return await importKey(format, keyData, unwrappedKeyAlgorithm, extractable, keyUsages);
    } finally {
        if (keyData instanceof Uint8Array) keyData.fill(0);
    }
}

/* ---- feature detection ---- */

const OPS = {
    kem: ["generateKey", "importKey", "exportKey", "getPublicKey",
        "encapsulateBits", "encapsulateKey", "decapsulateBits", "decapsulateKey"],
    sig: ["generateKey", "importKey", "exportKey", "getPublicKey", "sign", "verify"],
};

export function supports(operation, algorithm) {
    const a = normalizeAlg(algorithm);
    if (!a) return false;
    if (a.ops) return a.ops.supports(operation);
    return OPS[a.kind].includes(operation);
}
