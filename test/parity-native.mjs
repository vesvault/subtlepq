/***************************************************************************
 * subtlepq parity suite: polyfill vs the platform-native WebCrypto ML-KEM /
 * ML-DSA implementation (Node >= 24.7). The native implementation is the
 * oracle: same bytes, same behavior, same error names.
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * Run: node test/parity-native.mjs   (skips cleanly on older Node)
 ***************************************************************************/

import assert from "assert";
import { subtle as pq, supports as pqSupports } from "../src/index.js";

const native = globalThis.crypto.subtle;
const NSC = Object.getPrototypeOf(native).constructor;

let hasML = false;
try {
    hasML = NSC.supports("encapsulateBits", "ML-KEM-768") === true &&
        NSC.supports("sign", "ML-DSA-65") === true;
} catch {}
if (!hasML) {
    console.log("SKIP: native WebCrypto lacks ML-KEM/ML-DSA (need Node >= 24.7)");
    process.exit(0);
}

let passed = 0;
const ok = (label, cond) => { assert(cond, label); passed++; };
const hex = (b) => Buffer.from(b).toString("hex");
const beq = (a, b) => hex(a) === hex(b);
/* canonical JWK compare: sorted members, sorted key_ops */
const canon = (j) => JSON.stringify(Object.entries(j)
    .map(([k, v]) => [k, Array.isArray(v) ? [...v].sort() : v])
    .sort((a, b) => (a[0] < b[0] ? -1 : 1)));

async function errParity(label, mk) {
    let ep, en;
    try { await mk(pq); ep = "resolved"; } catch (e) { ep = e.name; }
    try { await mk(native); en = "resolved"; } catch (e) { en = e.name; }
    ok(label + " [pq=" + ep + " native=" + en + "]", ep === en && ep !== "resolved");
}

const KEMS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];
const DSAS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
const KEM_PRIV = ["decapsulateBits", "decapsulateKey"];
const KEM_PUB = ["encapsulateBits", "encapsulateKey"];

/* ---- supports() parity ----
 * Known oracle gap (Node 24.18): supports() returns false for the
 * encapsulateKey/decapsulateKey operations even though the methods work;
 * the WICG draft maps both *Key and *Bits to the "encapsulate"/
 * "decapsulate" check, so true (subtlepq's answer) is the spec answer. */
const ORACLE_SUPPORTS_GAPS = ["encapsulateKey", "decapsulateKey"];
let gaps = 0;
for (const alg of [...KEMS, ...DSAS]) {
    for (const op of ["generateKey", "importKey", "exportKey", "getPublicKey",
        "encapsulateBits", "encapsulateKey", "decapsulateBits", "decapsulateKey",
        "sign", "verify"]) {
        const n = NSC.supports(op, alg), p = pqSupports(op, alg);
        if (n !== p && ORACLE_SUPPORTS_GAPS.includes(op) && p && !n) { gaps++; continue; }
        ok("supports(" + op + ", " + alg + ") parity [pq=" + p + " native=" + n + "]", n === p);
    }
}
if (gaps) console.log("note: " + gaps + " supports() results differ where the oracle " +
    "contradicts the draft (" + ORACLE_SUPPORTS_GAPS.join(", ") + "): spec answer kept");

/* ---- ML-KEM: same seed => same bytes everywhere ---- */
for (const alg of KEMS) {
    const seed = crypto.getRandomValues(new Uint8Array(64));
    const pPriv = await pq.importKey("raw-seed", seed, alg, true, KEM_PRIV);
    const nPriv = await native.importKey("raw-seed", seed, alg, true, KEM_PRIV);
    const pPub = await pq.getPublicKey(pPriv, KEM_PUB);
    const nPub = await native.getPublicKey(nPriv, KEM_PUB);

    ok(alg + " raw-seed roundtrip parity", beq(
        await pq.exportKey("raw-seed", pPriv), await native.exportKey("raw-seed", nPriv)));
    ok(alg + " raw-public parity", beq(
        await pq.exportKey("raw-public", pPub), await native.exportKey("raw-public", nPub)));
    ok(alg + " spki bytes identical", beq(
        await pq.exportKey("spki", pPub), await native.exportKey("spki", nPub)));
    ok(alg + " pkcs8 bytes identical", beq(
        await pq.exportKey("pkcs8", pPriv), await native.exportKey("pkcs8", nPriv)));
    ok(alg + " private jwk identical", canon(await pq.exportKey("jwk", pPriv)) ===
        canon(await native.exportKey("jwk", nPriv)));
    ok(alg + " public jwk identical", canon(await pq.exportKey("jwk", pPub)) ===
        canon(await native.exportKey("jwk", nPub)));

    /* cross-import each other's serializations */
    const xNat = await native.importKey("pkcs8",
        await pq.exportKey("pkcs8", pPriv), alg, true, KEM_PRIV);
    const xPq = await pq.importKey("pkcs8",
        await native.exportKey("pkcs8", nPriv), alg, true, KEM_PRIV);
    ok(alg + " pkcs8 cross-import", beq(
        await native.exportKey("raw-seed", xNat), await pq.exportKey("raw-seed", xPq)));

    /* live interop: encapsulate on one stack, decapsulate on the other */
    const e1 = await pq.encapsulateBits(alg, pPub);
    const d1 = await native.decapsulateBits(alg, nPriv, e1.ciphertext);
    ok(alg + " pq encaps -> native decaps", beq(e1.sharedKey, d1));
    const e2 = await native.encapsulateBits(alg, nPub);
    const d2 = await pq.decapsulateBits(alg, pPriv, e2.ciphertext);
    ok(alg + " native encaps -> pq decaps", beq(e2.sharedKey, d2));
}

/* ---- ML-DSA: cross sign/verify (sigs are hedged, so no byte compare) ---- */
for (const alg of DSAS) {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const pPriv = await pq.importKey("raw-seed", seed, alg, true, ["sign"]);
    const nPriv = await native.importKey("raw-seed", seed, alg, true, ["sign"]);
    const pPub = await pq.getPublicKey(pPriv, ["verify"]);
    const nPub = await native.getPublicKey(nPriv, ["verify"]);

    ok(alg + " raw-public parity", beq(
        await pq.exportKey("raw-public", pPub), await native.exportKey("raw-public", nPub)));
    ok(alg + " spki bytes identical", beq(
        await pq.exportKey("spki", pPub), await native.exportKey("spki", nPub)));
    ok(alg + " pkcs8 bytes identical", beq(
        await pq.exportKey("pkcs8", pPriv), await native.exportKey("pkcs8", nPriv)));
    ok(alg + " private jwk identical", canon(await pq.exportKey("jwk", pPriv)) ===
        canon(await native.exportKey("jwk", nPriv)));

    const msg = crypto.getRandomValues(new Uint8Array(97));
    const ctx = { name: alg, context: new TextEncoder().encode("parity-ctx") };
    ok(alg + " pq sign -> native verify",
        await native.verify(alg, nPub, await pq.sign(alg, pPriv, msg), msg));
    ok(alg + " native sign -> pq verify",
        await pq.verify(alg, pPub, await native.sign(alg, nPriv, msg), msg));
    ok(alg + " pq sign(ctx) -> native verify(ctx)",
        await native.verify(ctx, nPub, await pq.sign(ctx, pPriv, msg), msg));
    ok(alg + " ctx mismatch rejects on both",
        !(await native.verify(alg, nPub, await pq.sign(ctx, pPriv, msg), msg)) &&
        !(await pq.verify(alg, pPub, await native.sign(ctx, nPriv, msg), msg)));
}

/* ---- wrapKey composition vs native wrapKey ---- */
{
    const seed = crypto.getRandomValues(new Uint8Array(64));
    const pPriv = await pq.importKey("raw-seed", seed, "ML-KEM-768", true, KEM_PRIV);
    const nPriv = await native.importKey("raw-seed", seed, "ML-KEM-768", true, KEM_PRIV);
    const kw = await native.generateKey({ name: "AES-KW", length: 256 }, false,
        ["wrapKey", "unwrapKey"]);
    /* AES-KW over raw-seed (64B, KW-aligned; KW is deterministic => bytes) */
    const w1 = await pq.wrapKey("raw-seed", pPriv, kw, "AES-KW");
    ok("AES-KW wrapped bytes identical",
        beq(w1, await native.wrapKey("raw-seed", nPriv, kw, "AES-KW")));
    const u1 = await native.unwrapKey("raw-seed", w1, kw, "AES-KW", "ML-KEM-768", true, KEM_PRIV);
    ok("pq wrap -> native unwrap", beq(await native.exportKey("raw-seed", u1), seed));
    /* AES-GCM over pkcs8 (86B is not KW-alignable; fixed IV => bytes comparable) */
    const gk = await native.generateKey({ name: "AES-GCM", length: 256 }, false,
        ["wrapKey", "unwrapKey"]);
    const gcm = { name: "AES-GCM", iv: new Uint8Array(12) };
    const w2 = await native.wrapKey("pkcs8", nPriv, gk, gcm);
    ok("AES-GCM wrapped pkcs8 bytes identical",
        beq(w2, await pq.wrapKey("pkcs8", pPriv, gk, gcm)));
    const u2 = await pq.unwrapKey("pkcs8", w2, gk, gcm, "ML-KEM-768", true, KEM_PRIV);
    ok("native wrap -> pq unwrap", beq(await pq.exportKey("raw-seed", u2), seed));
}

/* ---- error-name parity on malformed input ---- */
const jwkGood = await pq.exportKey("jwk",
    await pq.importKey("raw-seed", new Uint8Array(32), "ML-DSA-65", true, ["sign"]));
await errParity("bad seed length", (s) =>
    s.importKey("raw-seed", new Uint8Array(63), "ML-KEM-768", true, KEM_PRIV));
await errParity("spki truncated", (s) =>
    s.importKey("spki", new Uint8Array(40), "ML-KEM-768", true, KEM_PUB));
await errParity("pkcs8 garbage", (s) =>
    s.importKey("pkcs8", crypto.getRandomValues(new Uint8Array(90)), "ML-KEM-768", true, KEM_PRIV));
await errParity("jwk wrong kty", (s) =>
    s.importKey("jwk", { ...jwkGood, kty: "OKP" }, "ML-DSA-65", true, ["sign"]));
await errParity("jwk alg mismatch", (s) =>
    s.importKey("jwk", jwkGood, "ML-DSA-44", true, ["sign"]));
await errParity("jwk ext=false vs extractable", (s) =>
    s.importKey("jwk", { ...jwkGood, ext: false }, "ML-DSA-65", true, ["sign"]));
await errParity("jwk key_ops conflict", (s) =>
    s.importKey("jwk", { ...jwkGood, key_ops: ["verify"] }, "ML-DSA-65", true, ["sign"]));
await errParity("empty private usages", (s) =>
    s.importKey("raw-seed", new Uint8Array(64), "ML-KEM-768", true, []));
await errParity("bogus usage", (s) =>
    s.importKey("raw-seed", new Uint8Array(64), "ML-KEM-768", true, ["deriveBits"]));
await errParity("non-extractable export", async (s) => {
    const k = await s.importKey("raw-seed", new Uint8Array(64), "ML-KEM-768", false, KEM_PRIV);
    return s.exportKey("pkcs8", k);
});

console.log("PASS:", passed, "parity checks vs", process.version);
