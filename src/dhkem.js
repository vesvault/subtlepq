/***************************************************************************
 * subtlepq/dhkem: DHKEM over the platform's native ECDH -- RFC 9180 sec 4.1
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * KEM-shaped classical key agreement: ephemeral-static ECDH wrapped as
 * encapsulate/decapsulate, so classical and post-quantum share one calling
 * convention and migrating to ML-KEM is a name change. NOT part of the
 * WICG draft -- a subtlepq extension; if the WG ever adopts DHKEM
 * identifiers, those will be adopted here and these names aliased.
 *
 * Everything underneath is native WebCrypto (ECDH / X25519 + HKDF-SHA256);
 * no WASM is involved and all keys are genuine platform CryptoKeys --
 * structured-cloneable, native usage enforcement (surfaced as
 * "deriveBits", the underlying native usage).
 *
 * Decapsulation needs the recipient PUBLIC key bytes for the RFC 9180
 * kem_context. They are remembered automatically for private keys made by
 * generateKey()/importKey() of this module; for foreign or structured-
 * cloned private keys pass { name, publicKey } (CryptoKey or serialized
 * bytes) or use an extractable key.
 ***************************************************************************/

import { registerExtension, unregisterExtension } from "./algorithms.js";
import { importSharedKey, toBytes } from "./subtle.js";
import { unb64u } from "./formats.js";
import * as E from "./errors.js";

const te = new TextEncoder();

function cat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
}

/* suite_id = "KEM" || I2OSP(kem_id, 2); Nsecret = 32 for both suites.
 * The RFC serialized public key form is exactly WebCrypto "raw": 32 bytes
 * for X25519, the 65-byte uncompressed point for P-256. */
const SUITES = {
    "DHKEM-X25519-HKDF-SHA256": {
        nEnc: 32,
        native: { name: "X25519" },
        suiteId: cat(te.encode("KEM"), [0x00, 0x20]),
        jwkPub: (jwk) => (jwk.x === undefined ? null : unb64u(jwk.x, "x")),
    },
    "DHKEM-P256-HKDF-SHA256": {
        nEnc: 65,
        native: { name: "ECDH", namedCurve: "P-256" },
        suiteId: cat(te.encode("KEM"), [0x00, 0x10]),
        jwkPub: (jwk) => (jwk.x === undefined || jwk.y === undefined ? null
            : cat([0x04], unb64u(jwk.x, "x"), unb64u(jwk.y, "y"))),
    },
};

const PUB_USAGES = ["encapsulateBits", "encapsulateKey"];
const PRIV_USAGES = ["decapsulateBits", "decapsulateKey", "deriveBits", "deriveKey"];

/* key -> its serialized PUBLIC key bytes (for a private key, the public
 * half): encap serializes pkR and decap mixes it into the kem_context,
 * and neither can be exported off a non-extractable CryptoKey */
const pkmap = new WeakMap();

function nativeSubtle() {
    const ns = globalThis.crypto && globalThis.crypto.subtle;
    if (!ns) throw E.notSupported("no native SubtleCrypto for DHKEM");
    return ns;
}

function requireSuite(alg) {
    let name, obj;
    if (typeof alg === "string") {
        name = alg;
    } else if (alg && typeof alg.name === "string") {
        name = alg.name;
        obj = alg;
    }
    const canonical = name === undefined ? undefined :
        Object.keys(SUITES).find((n) => n.toLowerCase() === name.toLowerCase());
    if (!canonical) throw E.notSupported("unrecognized DHKEM algorithm");
    return { name: canonical, s: SUITES[canonical], alg: obj };
}

function requireKey(key, s, name, type) {
    const ka = key && key.algorithm;
    const match = ka && ka.name === s.native.name &&
        (s.native.namedCurve === undefined || ka.namedCurve === s.native.namedCurve);
    if (!match) {
        throw E.invalidAccess("key is not a native " + s.native.name +
            (s.native.namedCurve ? "/" + s.native.namedCurve : "") +
            " key usable with " + name);
    }
    if (key.type !== type) throw E.invalidAccess("expected a " + type + " key");
}

function checkUsages(usages, allowed) {
    for (const u of usages) {
        if (!allowed.includes(u)) throw E.syntaxError("unsupported key usage " + u);
    }
}

/* ExtractAndExpand (RFC 9180 sec 4.1) in one native HKDF deriveBits call:
 * LabeledExtract("", "eae_prk", dh) + LabeledExpand(prk, "shared_secret",
 * kem_context, 32) map exactly onto HKDF's extract-then-expand. */
async function extractAndExpand(ns, s, dh, kemContext) {
    const ikm = cat(te.encode("HPKE-v1"), s.suiteId, te.encode("eae_prk"), dh);
    const info = cat([0, 32], te.encode("HPKE-v1"), s.suiteId,
        te.encode("shared_secret"), kemContext);
    const k = await ns.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    ikm.fill(0);
    return new Uint8Array(await ns.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info }, k, 256));
}

const dhBits = async (ns, s, priv, pub) => new Uint8Array(
    await ns.deriveBits({ name: s.native.name, public: pub }, priv, 256));

async function publicBytesFor(ns, key, s, name, alg) {
    const given = alg && alg.publicKey;
    if (given !== undefined && given !== null) {
        if (typeof CryptoKey !== "undefined" && given instanceof CryptoKey) {
            requireKey(given, s, name, "public");
            return new Uint8Array(await ns.exportKey("raw", given));
        }
        const b = toBytes(given, "publicKey");
        if (b.length !== s.nEnc) throw E.dataError("bad " + name + " publicKey length");
        return b;
    }
    const known = pkmap.get(key);
    if (known) return known.slice();
    if (key.extractable) {
        const pub = s.jwkPub(await ns.exportKey("jwk", key));
        if (pub) return pub;
    }
    throw E.invalidAccess("cannot determine the recipient public key for " + name +
        " decapsulation; pass { name, publicKey } or use a key from this module");
}

/* ---- key management (thin translation onto native ECDH / X25519) ---- */

export async function generateKey(algorithm, extractable, keyUsages = []) {
    const { s } = requireSuite(algorithm);
    checkUsages(keyUsages, [...PUB_USAGES, ...PRIV_USAGES]);
    if (!keyUsages.some((u) => PRIV_USAGES.includes(u))) {
        throw E.syntaxError("private key usages must not be empty");
    }
    const ns = nativeSubtle();
    const pair = await ns.generateKey(s.native, extractable, ["deriveBits"]);
    const pub = new Uint8Array(await ns.exportKey("raw", pair.publicKey));
    pkmap.set(pair.publicKey, pub);
    pkmap.set(pair.privateKey, pub);
    return pair;
}

export async function importKey(format, keyData, algorithm, extractable, keyUsages = []) {
    const { s, name } = requireSuite(algorithm);
    const ns = nativeSubtle();
    const importPriv = async (fmt, data) => {
        checkUsages(keyUsages, PRIV_USAGES);
        if (!keyUsages.length) throw E.syntaxError("private key usages must not be empty");
        return ns.importKey(fmt, data, s.native, extractable, ["deriveBits"]);
    };
    if (format === "raw" || format === "raw-public" || format === "spki") {
        checkUsages(keyUsages, PUB_USAGES);
        const fmt = format === "raw-public" ? "raw" : format;
        const bytes = toBytes(keyData, "keyData");
        const key = await ns.importKey(fmt, bytes, s.native, extractable, []);
        if (fmt === "raw") {
            pkmap.set(key, bytes);
        } else {
            /* spki: recover the raw form via an extractable twin */
            try {
                const twin = extractable ? key
                    : await ns.importKey("spki", bytes, s.native, true, []);
                pkmap.set(key, new Uint8Array(await ns.exportKey("raw", twin)));
            } catch {}
        }
        return key;
    }
    if (format === "pkcs8") {
        const bytes = toBytes(keyData, "keyData");
        const key = await importPriv("pkcs8", bytes);
        /* recover the public half for decap: from the key if extractable,
         * else from a throwaway extractable import of the same bytes */
        try {
            const twin = extractable ? key
                : await ns.importKey("pkcs8", bytes, s.native, true, ["deriveBits"]);
            const pub = s.jwkPub(await ns.exportKey("jwk", twin));
            if (pub) pkmap.set(key, pub);
        } catch {}
        bytes.fill(0);
        return key;
    }
    if (format === "jwk") {
        if (!keyData || typeof keyData !== "object" || ArrayBuffer.isView(keyData) ||
                keyData instanceof ArrayBuffer) {
            throw E.dataError("jwk import expects a JsonWebKey object");
        }
        /* alg/key_ops carry DHKEM-level values the native import would
         * reject; the native usage set is supplied explicitly instead */
        const clean = { ...keyData };
        delete clean.alg;
        delete clean.key_ops;
        delete clean.use;
        if (keyData.d === undefined) {
            checkUsages(keyUsages, PUB_USAGES);
            const key = await ns.importKey("jwk", clean, s.native, extractable, []);
            const pub = s.jwkPub(keyData);
            if (pub) pkmap.set(key, pub);
            return key;
        }
        const key = await importPriv("jwk", clean);
        const pub = s.jwkPub(keyData);
        if (pub) pkmap.set(key, pub);
        return key;
    }
    throw E.notSupported("key format " + format + " is not supported");
}

/* ---- KEM operations (RFC 9180 sec 4.1 Encap / Decap, base mode) ---- */

async function encap(algorithm, encapsulationKey) {
    const { s, name } = requireSuite(algorithm);
    requireKey(encapsulationKey, s, name, "public");
    const ns = nativeSubtle();
    const eph = await ns.generateKey(s.native, false, ["deriveBits"]);
    const enc = new Uint8Array(await ns.exportKey("raw", eph.publicKey));
    const dh = await dhBits(ns, s, eph.privateKey, encapsulationKey);
    const known = pkmap.get(encapsulationKey);
    let pkRm;
    if (known) {
        pkRm = known;
    } else {
        try {
            pkRm = new Uint8Array(await ns.exportKey("raw", encapsulationKey));
        } catch {
            throw E.invalidAccess("cannot serialize the " + name +
                " encapsulation key: not extractable and not from this module");
        }
    }
    const ss = await extractAndExpand(ns, s, dh, cat(enc, pkRm));
    dh.fill(0);
    return { ss, enc };
}

async function decap(algorithm, decapsulationKey, ciphertext) {
    const { s, name, alg } = requireSuite(algorithm);
    requireKey(decapsulationKey, s, name, "private");
    const enc = toBytes(ciphertext, "ciphertext");
    if (enc.length !== s.nEnc) throw E.opError("bad " + name + " ciphertext length");
    const ns = nativeSubtle();
    let pkE;
    try {
        pkE = await ns.importKey("raw", enc, s.native, true, []);
    } catch {
        /* unlike ML-KEM implicit rejection, DHKEM decap MAY fail: an
         * invalid public key raises ValidationError per RFC 9180 */
        throw E.opError("invalid " + name + " ciphertext");
    }
    const dh = await dhBits(ns, s, decapsulationKey, pkE);
    const pkRm = await publicBytesFor(ns, decapsulationKey, s, name, alg);
    const ss = await extractAndExpand(ns, s, dh, cat(enc, pkRm));
    dh.fill(0);
    return ss;
}

export async function encapsulateBits(algorithm, encapsulationKey) {
    const { ss, enc } = await encap(algorithm, encapsulationKey);
    return { sharedKey: ss.buffer, ciphertext: enc.buffer };
}

export async function encapsulateKey(algorithm, encapsulationKey,
                                     sharedKeyAlgorithm, extractable, keyUsages) {
    const { ss, enc } = await encap(algorithm, encapsulationKey);
    const sharedKey = await importSharedKey(ss, sharedKeyAlgorithm, extractable, keyUsages);
    return { sharedKey, ciphertext: enc.buffer };
}

export async function decapsulateBits(algorithm, decapsulationKey, ciphertext) {
    return (await decap(algorithm, decapsulationKey, ciphertext)).buffer;
}

export async function decapsulateKey(algorithm, decapsulationKey, ciphertext,
                                     sharedKeyAlgorithm, extractable, keyUsages) {
    const ss = await decap(algorithm, decapsulationKey, ciphertext);
    return importSharedKey(ss, sharedKeyAlgorithm, extractable, keyUsages);
}

/* ---- feature detection / registration ---- */

const OPS = ["generateKey", "importKey", "exportKey",
    "encapsulateBits", "encapsulateKey", "decapsulateBits", "decapsulateKey"];

export function supports(operation, algorithm) {
    if (algorithm !== undefined) {
        try {
            requireSuite(algorithm);
        } catch {
            return false;
        }
    }
    return OPS.includes(operation);
}

const ops = {
    generateKey, importKey,
    encapsulateBits, encapsulateKey, decapsulateBits, decapsulateKey,
    supports: (operation) => OPS.includes(operation),
};

/* Makes the DHKEM-* names routable through the subtlepq ponyfill `subtle`
 * and, after install(), through crypto.subtle. True-polyfill users don't
 * need this: install(true) registers (and uninstall() unregisters). */
export function register() {
    for (const name of Object.keys(SUITES)) registerExtension(name, "kem", ops);
}

export function unregister() {
    for (const name of Object.keys(SUITES)) unregisterExtension(name);
}
