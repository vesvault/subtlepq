/***************************************************************************
 * subtlepq/dhkem test: RFC 9180 sec 4.1 DHKEM over native ECDH / X25519
 * Oracle: RFC 9180 Appendix A test vectors (base mode)
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/

import assert from "assert";
import { readFileSync } from "fs";
import { subtle, supports, install, uninstall } from "../src/index.js";
import * as dhkem from "../src/dhkem.js";

const { vectors } = JSON.parse(
    readFileSync(new URL("./vectors/rfc9180-subset.json", import.meta.url)));

let passed = 0;
const ok = (label, cond) => { assert(cond, label); passed++; };
const rejects = async (label, fn, errName) => {
    try {
        await fn();
    } catch (e) {
        ok(label + " [" + e.name + "]", e.name === errName);
        return;
    }
    assert(false, label + ": expected " + errName);
};
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const eq = (x, y) => Buffer.from(x).equals(Buffer.from(y));

const X = "DHKEM-X25519-HKDF-SHA256";
const P = "DHKEM-P256-HKDF-SHA256";
const kemUsages = ["encapsulateBits", "encapsulateKey", "decapsulateBits", "decapsulateKey"];

/* jwk private key for a vector: OKP for X25519, EC for P-256 */
function vecJwk(v) {
    if (v.alg === X) {
        return { kty: "OKP", crv: "X25519", d: b64u(hex(v.skRm)), x: b64u(hex(v.pkRm)) };
    }
    const pk = hex(v.pkRm);
    return { kty: "EC", crv: "P-256", d: b64u(hex(v.skRm)),
        x: b64u(pk.slice(1, 33)), y: b64u(pk.slice(33, 65)) };
}

/* ---- before register(): unknown to the router, falls through to native
 * (which reports the unknown name as TypeError or NotSupportedError) ---- */
ok("supports false before register", !supports("encapsulateBits", X));
try {
    await subtle.generateKey(X, false, kemUsages);
    assert(false, "ponyfill rejects before register: expected an error");
} catch (e) {
    ok("ponyfill rejects before register [" + e.name + "]",
        e.name === "NotSupportedError" || e.name === "TypeError");
}

dhkem.register();

/* ---- supports() after register ---- */
for (const alg of [X, P]) {
    ok("supports generateKey " + alg, supports("generateKey", alg));
    ok("supports encapsulateBits " + alg, supports("encapsulateBits", { name: alg.toLowerCase() }));
    ok("supports decapsulateKey " + alg, supports("decapsulateKey", alg));
}
ok("no sign for DHKEM", !supports("sign", X));
ok("dhkem.supports standalone", dhkem.supports("encapsulateBits", P) &&
    !dhkem.supports("encapsulateBits", "DHKEM-P384-HKDF-SHA384"));

/* ---- roundtrips via the ponyfill, both suites ---- */
for (const [alg, nEnc] of [[X, 32], [P, 65]]) {
    const kp = await subtle.generateKey(alg, false, kemUsages);
    ok(alg + " keys are native CryptoKeys", kp.publicKey instanceof CryptoKey &&
        kp.privateKey instanceof CryptoKey &&
        kp.privateKey.usages.includes("deriveBits"));
    const { sharedKey, ciphertext } = await subtle.encapsulateBits(alg, kp.publicKey);
    ok(alg + " encapsulateBits shapes", sharedKey instanceof ArrayBuffer &&
        sharedKey.byteLength === 32 && ciphertext.byteLength === nEnc);
    const ss2 = await subtle.decapsulateBits(alg, kp.privateKey, ciphertext);
    ok(alg + " roundtrip shared secret", eq(sharedKey, ss2));
    const ss3 = await subtle.decapsulateBits(alg, kp.privateKey, ciphertext);
    ok(alg + " decap deterministic", eq(ss2, ss3));
}

/* ---- RFC 9180 Appendix A vectors (base mode): decap oracle + cross ---- */
for (const v of vectors) {
    const skR = await subtle.importKey("jwk", vecJwk(v), v.alg, false, ["decapsulateBits"]);
    const ss = await subtle.decapsulateBits(v.alg, skR, hex(v.enc));
    ok(v.alg + " RFC 9180 shared_secret", eq(ss, hex(v.shared_secret)));

    /* encap to the vector public key, decap with the vector private key */
    const pkR = await subtle.importKey("raw", hex(v.pkRm), v.alg, false, ["encapsulateBits"]);
    const { sharedKey, ciphertext } = await subtle.encapsulateBits(v.alg, pkR);
    ok(v.alg + " encap vs vector key",
        eq(sharedKey, await subtle.decapsulateBits(v.alg, skR, ciphertext)));
}

/* ---- encapsulateKey -> genuine native AES-GCM key ---- */
const kpX = await subtle.generateKey(X, false, kemUsages);
const gcm = { name: "AES-GCM", length: 256 };
const encK = await subtle.encapsulateKey(X, kpX.publicKey, gcm, false, ["encrypt"]);
ok("sharedKey is a native AES-GCM CryptoKey", encK.sharedKey instanceof CryptoKey &&
    encK.sharedKey.algorithm.name === "AES-GCM");
const iv = crypto.getRandomValues(new Uint8Array(12));
const msg = Buffer.from("dhkem bridges classical ECDH to the KEM shape");
const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encK.sharedKey, msg);
const rxKey = await subtle.decapsulateKey(X, kpX.privateKey, encK.ciphertext,
    gcm, false, ["decrypt"]);
ok("decapsulateKey opens the seal",
    eq(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, rxKey, sealed), msg));

/* ---- pkcs8 import (non-extractable): public half recovered for decap ---- */
const kpP = await subtle.generateKey(P, true, kemUsages);
const pkcs8 = await crypto.subtle.exportKey("pkcs8", kpP.privateKey);
const skP = await subtle.importKey("pkcs8", pkcs8, P, false, ["decapsulateBits"]);
ok("pkcs8 import is non-extractable", !skP.extractable);
const encP = await subtle.encapsulateBits(P, kpP.publicKey);
ok("pkcs8-imported key decapsulates",
    eq(encP.sharedKey, await subtle.decapsulateBits(P, skP, encP.ciphertext)));

/* ---- foreign native keys (made outside this module) ---- */
const foreignX = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
const encF = await subtle.encapsulateBits(X, foreignX.publicKey);
ok("foreign extractable key decapsulates (jwk fallback)",
    eq(encF.sharedKey, await subtle.decapsulateBits(X, foreignX.privateKey, encF.ciphertext)));

const foreignLocked = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
const pubBytes = new Uint8Array(await crypto.subtle.exportKey("raw", foreignLocked.publicKey));
const encL = await subtle.encapsulateBits(X, foreignLocked.publicKey);
await rejects("foreign non-extractable key without publicKey",
    () => subtle.decapsulateBits(X, foreignLocked.privateKey, encL.ciphertext),
    "InvalidAccessError");
ok("... works with { publicKey: bytes }", eq(encL.sharedKey,
    await subtle.decapsulateBits({ name: X, publicKey: pubBytes },
        foreignLocked.privateKey, encL.ciphertext)));
ok("... works with { publicKey: CryptoKey }", eq(encL.sharedKey,
    await subtle.decapsulateBits({ name: X, publicKey: foreignLocked.publicKey },
        foreignLocked.privateKey, encL.ciphertext)));

/* ---- structured clone: DHKEM keys are REAL keys, clones survive ---- */
try {
    const clone = structuredClone(foreignLocked.privateKey);
    ok("structuredClone of a DHKEM key works", clone instanceof CryptoKey);
    ok("cloned key decapsulates with explicit publicKey", eq(encL.sharedKey,
        await subtle.decapsulateBits({ name: X, publicKey: pubBytes },
            clone, encL.ciphertext)));
} catch (e) {
    console.log("skip: structuredClone(CryptoKey) unsupported here:", e.message);
}

/* ---- error paths ---- */
await rejects("wrong-curve key", () => subtle.encapsulateBits(X, kpP.publicKey),
    "InvalidAccessError");
await rejects("private key to encapsulate", () => subtle.encapsulateBits(X, kpX.privateKey),
    "InvalidAccessError");
await rejects("bad ciphertext length",
    () => subtle.decapsulateBits(X, kpX.privateKey, new Uint8Array(31)), "OperationError");
await rejects("invalid P-256 point ciphertext",
    () => subtle.decapsulateBits(P, kpP.privateKey, new Uint8Array(65).fill(9)),
    "OperationError");
await rejects("sign with a DHKEM name", () => subtle.sign(X, kpX.privateKey, msg),
    "NotSupportedError");
await rejects("generateKey empty usages", () => subtle.generateKey(X, false, []),
    "SyntaxError");
await rejects("generateKey bogus usage", () => subtle.generateKey(X, false, ["sign"]),
    "SyntaxError");

/* ---- install(): DHKEM reachable through the patched crypto.subtle ---- */
install();
const kpG = await crypto.subtle.generateKey(X, false, kemUsages);
const encG = await crypto.subtle.encapsulateBits(X, kpG.publicKey);
ok("installed encapsulateBits", encG.ciphertext.byteLength === 32);
ok("installed decapsulateBits", eq(encG.sharedKey,
    await crypto.subtle.decapsulateBits(X, kpG.privateKey, encG.ciphertext)));
ok("installed supports", crypto.subtle.constructor.supports("encapsulateBits", X));
/* native ECDH is untouched: plain deriveBits still native */
const dh = await crypto.subtle.deriveBits(
    { name: "X25519", public: kpG.publicKey }, kpG.privateKey, 256);
ok("native deriveBits passthrough", dh.byteLength === 32);
uninstall();

/* ---- unregister ---- */
dhkem.unregister();
ok("supports false after unregister", !supports("encapsulateBits", X));
await rejects("ponyfill rejects after unregister",
    () => subtle.encapsulateBits(X, kpX.publicKey), "NotSupportedError");

console.log("PASS:", passed, "checks");
