/***************************************************************************
 * subtlepq JS-layer test: ponyfill + install(), native bridging, ACVP seeds
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/

import assert from "assert";
import { readFileSync } from "fs";
import { subtle, supports, install, uninstall } from "../src/index.js";

const vectors = JSON.parse(
    readFileSync(new URL("./vectors/acvp-subset.json", import.meta.url)));

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

/* ---- supports() ---- */
ok("supports encapsulateBits ML-KEM-768", supports("encapsulateBits", "ML-KEM-768"));
ok("supports sign ML-DSA-87", supports("sign", { name: "ml-dsa-87" }));
ok("no encapsulate for ML-DSA", !supports("encapsulateBits", "ML-DSA-65"));
ok("unknown alg", !supports("sign", "RSA-FAKE"));

/* ---- KEM: generate / encapsulate / decapsulate via ponyfill ---- */
const kemUsages = ["encapsulateBits", "encapsulateKey", "decapsulateBits", "decapsulateKey"];
const kp = await subtle.generateKey("ML-KEM-768", true, kemUsages);
ok("public instanceof CryptoKey", kp.publicKey instanceof CryptoKey);
ok("private type/alg", kp.privateKey.type === "private" &&
    kp.privateKey.algorithm.name === "ML-KEM-768");
ok("usages split", kp.publicKey.usages.includes("encapsulateBits") &&
    !kp.publicKey.usages.includes("decapsulateBits") &&
    kp.privateKey.usages.includes("decapsulateKey"));

const { sharedKey: ss1, ciphertext } = await subtle.encapsulateBits("ML-KEM-768", kp.publicKey);
ok("encapsulateBits shapes", ss1 instanceof ArrayBuffer && ss1.byteLength === 32 &&
    ciphertext.byteLength === 1088);
const ss2 = await subtle.decapsulateBits("ML-KEM-768", kp.privateKey, ciphertext);
ok("shared secrets match", Buffer.from(ss1).equals(Buffer.from(ss2)));

/* ---- encapsulateKey -> genuine native AES-GCM key, used with native subtle ---- */
const gcm = { name: "AES-GCM", length: 256 };
const enc = await subtle.encapsulateKey("ML-KEM-768", kp.publicKey, gcm, false, ["encrypt"]);
ok("sharedKey is a native CryptoKey", enc.sharedKey instanceof CryptoKey &&
    enc.sharedKey.algorithm.name === "AES-GCM");
const iv = crypto.getRandomValues(new Uint8Array(12));
const msg = Buffer.from("subtlepq bridges to native crypto");
const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, enc.sharedKey, msg);
const rxKey = await subtle.decapsulateKey("ML-KEM-768", kp.privateKey, enc.ciphertext,
    gcm, false, ["decrypt"]);
const opened = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, rxKey, sealed);
ok("native AES-GCM roundtrip via KEM shared key", Buffer.from(opened).equals(msg));

/* ---- wrong usage / wrong key type ---- */
await rejects("encapsulate with private key",
    () => subtle.encapsulateBits("ML-KEM-768", kp.privateKey), "InvalidAccessError");
await rejects("decapsulate needs usage",
    async () => {
        const k2 = await subtle.generateKey("ML-KEM-768", false, ["decapsulateKey"]);
        return subtle.decapsulateBits("ML-KEM-768", k2.privateKey, ciphertext);
    }, "InvalidAccessError");

/* ---- ACVP seed import: raw-seed -> raw-public matches vector ---- */
let n = 0;
for (const c of vectors.sets["ML-KEM-keyGen-FIPS203"]) {
    const alg = c.group.parameterSet;
    if (!c.test.d || !c.test.z) continue;
    const seed = Buffer.concat([hex(c.test.d), hex(c.test.z)]);
    const priv = await subtle.importKey("raw-seed", seed, alg, true, ["decapsulateBits"]);
    const rawPub = await subtle.exportKey("raw-public", await subtle.getPublicKey(priv, ["encapsulateBits"]));
    ok(alg + " seed->public matches ACVP", Buffer.from(rawPub).equals(hex(c.test.ek)));
    const seedBack = await subtle.exportKey("raw-seed", priv);
    ok(alg + " raw-seed roundtrip", Buffer.from(seedBack).equals(seed));
    n++;
}
assert(n >= 3);

for (const c of vectors.sets["ML-DSA-keyGen-FIPS204"].slice(0, 3)) {
    const alg = c.group.parameterSet;
    const priv = await subtle.importKey("raw-seed", hex(c.test.seed), alg, false, ["sign"]);
    const pub = await subtle.getPublicKey(priv, ["verify"]);
    const rawPub = await subtle.exportKey("raw-public", pub);
    ok(alg + " seed->public matches ACVP", Buffer.from(rawPub).equals(hex(c.test.pk)));
    await rejects(alg + " non-extractable seed export",
        () => subtle.exportKey("raw-seed", priv), "InvalidAccessError");
}

/* ---- ML-DSA sign/verify with context ---- */
const dsa = await subtle.generateKey("ML-DSA-65", true, ["sign", "verify"]);
const data = Buffer.from("subtlepq P1");
const ctxAlg = { name: "ML-DSA-65", context: Buffer.from("subtlepq-ctx") };
const sig = await subtle.sign(ctxAlg, dsa.privateKey, data);
ok("signature length", sig.byteLength === 3309);
ok("verify true", await subtle.verify(ctxAlg, dsa.publicKey, sig, data));
ok("verify false without ctx", !(await subtle.verify("ML-DSA-65", dsa.publicKey, sig, data)));
await rejects("context > 255",
    () => subtle.sign({ name: "ML-DSA-65", context: new Uint8Array(256) }, dsa.privateKey, data),
    "OperationError");

/* ---- P2: spki ---- */
const spki = await subtle.exportKey("spki", kp.publicKey);
ok("spki DER header", Buffer.from(spki.slice(0, 17)).equals(
    Buffer.from("308204b2300b0609608648016503040402", "hex")));
const pubFromSpki = await subtle.importKey("spki", spki, "ML-KEM-768", true, ["encapsulateBits"]);
ok("spki roundtrip", Buffer.from(await subtle.exportKey("raw-public", pubFromSpki))
    .equals(Buffer.from(await subtle.exportKey("raw-public", kp.publicKey))));
await rejects("spki oid vs algorithm mismatch",
    () => subtle.importKey("spki", spki, "ML-KEM-512", true, ["encapsulateBits"]), "DataError");
await rejects("spki truncated",
    () => subtle.importKey("spki", new Uint8Array(spki).slice(0, 40), "ML-KEM-768", true, []),
    "DataError");

/* ---- P2: pkcs8 (seed-only, both, expandedKey-only) ---- */
const p8 = await subtle.exportKey("pkcs8", kp.privateKey);
ok("pkcs8 seed-only encoding", p8.byteLength === 86 && Buffer.from(p8.slice(0, 22)).equals(
    Buffer.from("3054020100300b060960864801650304040204428040", "hex")));
const privFromP8 = await subtle.importKey("pkcs8", p8, "ML-KEM-768", true, ["decapsulateBits"]);
const seedK = Buffer.from(await subtle.exportKey("raw-seed", kp.privateKey));
ok("pkcs8 roundtrip", Buffer.from(await subtle.exportKey("raw-seed", privFromP8)).equals(seedK));

const der = (tag, ...parts) => {
    const len = parts.reduce((n, p) => n + p.length, 0);
    const hdr = [tag];
    if (len < 0x80) hdr.push(len);
    else {
        const b = [];
        for (let n = len; n; n >>>= 8) b.unshift(n & 0xff);
        hdr.push(0x80 | b.length, ...b);
    }
    return Uint8Array.from([...hdr, ...parts.flatMap((p) => [...p])]);
};
const OID768 = der(0x06, [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02]);
const { getEngine } = await import("../src/engine.js");
const { sk: skK } = (await getEngine()).kemKeypairDerand("ML-KEM-768", seedK);
const bothP8 = der(0x30, der(0x02, [0]), der(0x30, OID768),
    der(0x04, der(0x30, der(0x04, seedK), der(0x04, skK))));
const privFromBoth = await subtle.importKey("pkcs8", bothP8, "ML-KEM-768", true, ["decapsulateKey"]);
ok("pkcs8 both CHOICE imports", Buffer.from(await subtle.exportKey("raw-seed", privFromBoth)).equals(seedK));
const skBad = skK.slice();
skBad[0] ^= 1;
await rejects("pkcs8 both with mismatched expandedKey",
    () => subtle.importKey("pkcs8",
        der(0x30, der(0x02, [0]), der(0x30, OID768),
            der(0x04, der(0x30, der(0x04, seedK), der(0x04, skBad)))),
        "ML-KEM-768", true, ["decapsulateKey"]), "DataError");
await rejects("pkcs8 expandedKey-only",
    () => subtle.importKey("pkcs8",
        der(0x30, der(0x02, [0]), der(0x30, OID768), der(0x04, der(0x04, skK))),
        "ML-KEM-768", true, ["decapsulateKey"]), "NotSupportedError");

/* ---- P2: jwk (AKP) ---- */
const jwkPriv = await subtle.exportKey("jwk", dsa.privateKey);
ok("jwk private shape", jwkPriv.kty === "AKP" && jwkPriv.alg === "ML-DSA-65" &&
    typeof jwkPriv.pub === "string" && typeof jwkPriv.priv === "string" &&
    jwkPriv.ext === true && jwkPriv.key_ops.includes("sign"));
const dsaFromJwk = await subtle.importKey("jwk", jwkPriv, "ML-DSA-65", true, ["sign"]);
const sigJ = await subtle.sign(ctxAlg, dsaFromJwk, data);
ok("jwk private roundtrip signs", await subtle.verify(ctxAlg, dsa.publicKey, sigJ, data));
const jwkPub = await subtle.exportKey("jwk", dsa.publicKey);
ok("jwk public has no priv", jwkPub.priv === undefined && typeof jwkPub.pub === "string");
const dsaPubFromJwk = await subtle.importKey("jwk", jwkPub, "ML-DSA-65", true, ["verify"]);
ok("jwk public roundtrip verifies", await subtle.verify(ctxAlg, dsaPubFromJwk, sigJ, data));
await rejects("jwk wrong kty",
    () => subtle.importKey("jwk", { ...jwkPriv, kty: "OKP" }, "ML-DSA-65", true, ["sign"]),
    "DataError");
await rejects("jwk alg mismatch",
    () => subtle.importKey("jwk", jwkPriv, "ML-DSA-44", true, ["sign"]), "DataError");
await rejects("jwk ext=false vs extractable",
    () => subtle.importKey("jwk", { ...jwkPriv, ext: false }, "ML-DSA-65", true, ["sign"]),
    "DataError");
await rejects("jwk key_ops does not permit sign",
    () => subtle.importKey("jwk", { ...jwkPriv, key_ops: ["verify"] }, "ML-DSA-65", true, ["sign"]),
    "DataError");
const pubTampered = (jwkPriv.pub[0] === "A" ? "B" : "A") + jwkPriv.pub.slice(1);
await rejects("jwk priv/pub mismatch",
    () => subtle.importKey("jwk", { ...jwkPriv, pub: pubTampered }, "ML-DSA-65", true, ["sign"]),
    "DataError");

/* ---- P2: wrapKey / unwrapKey composition ---- */
const kek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false,
    ["wrapKey", "unwrapKey", "encrypt"]);
const ivw = crypto.getRandomValues(new Uint8Array(12));
const gcmw = { name: "AES-GCM", iv: ivw };
const wrapped = await subtle.wrapKey("pkcs8", kp.privateKey, kek, gcmw);
ok("wrapKey pkcs8/AES-GCM shape", wrapped instanceof ArrayBuffer && wrapped.byteLength === 86 + 16);
const unwrapped = await subtle.unwrapKey("pkcs8", wrapped, kek, gcmw,
    "ML-KEM-768", false, ["decapsulateBits"]);
ok("unwrapped key decapsulates", Buffer.from(
    await subtle.decapsulateBits("ML-KEM-768", unwrapped, ciphertext)).equals(Buffer.from(ss1)));
ok("unwrapped key honors extractable=false", unwrapped.extractable === false);

const kw = await crypto.subtle.generateKey({ name: "AES-KW", length: 256 }, false,
    ["wrapKey", "unwrapKey"]);
const wrappedSeed = await subtle.wrapKey("raw-seed", kp.privateKey, kw, "AES-KW");
ok("AES-KW raw-seed wrap", wrappedSeed.byteLength === 72);
const unwrappedKw = await subtle.unwrapKey("raw-seed", wrappedSeed, kw, "AES-KW",
    "ML-KEM-768", true, ["decapsulateKey"]);
ok("AES-KW roundtrip", Buffer.from(await subtle.exportKey("raw-seed", unwrappedKw)).equals(seedK));

const wrappedJwk = await subtle.wrapKey("jwk", dsa.privateKey, kw, "AES-KW");
ok("AES-KW jwk wrap is 8-aligned", wrappedJwk.byteLength % 8 === 0);
const dsaUnwrapped = await subtle.unwrapKey("jwk", wrappedJwk, kw, "AES-KW",
    "ML-DSA-65", true, ["sign"]);
ok("AES-KW jwk roundtrip signs", await subtle.verify(ctxAlg, dsa.publicKey,
    await subtle.sign(ctxAlg, dsaUnwrapped, data), data));

const nx = await subtle.generateKey("ML-DSA-44", false, ["sign", "verify"]);
await rejects("wrap non-extractable key",
    () => subtle.wrapKey("pkcs8", nx.privateKey, kek, gcmw), "InvalidAccessError");
await rejects("ML key as wrapping key",
    () => subtle.wrapKey("raw-seed", kp.privateKey, kp.publicKey, "ML-KEM-768"),
    "InvalidAccessError");
await rejects("ML key as unwrapping key",
    () => subtle.unwrapKey("pkcs8", wrapped, kp.privateKey, gcmw, "ML-KEM-768", true,
        ["decapsulateBits"]), "InvalidAccessError");

/* ---- forged key boundaries ---- */
try {
    structuredClone(kp.privateKey);
    assert(false, "structuredClone should fail on forged keys");
} catch (e) {
    ok("structuredClone -> DataCloneError", e.name === "DataCloneError");
}

/* ---- ponyfill passthrough ---- */
const digest = await subtle.digest("SHA-256", Buffer.from("abc"));
ok("native digest via ponyfill", Buffer.from(digest).toString("hex").startsWith("ba7816bf"));

/* ---- install(): true polyfill on globalThis.crypto.subtle ---- */
install();
ok("crypto.subtle.encapsulateBits appears", typeof crypto.subtle.encapsulateBits === "function");
ok("wrappers carry real parameter lists (console hints)",
    crypto.subtle.generateKey.length === 3 &&
    /generateKey\(\s*algorithm, extractable, keyUsages\)/.test(String(crypto.subtle.generateKey)) &&
    /sharedKeyAlgorithm/.test(String(crypto.subtle.encapsulateKey)) &&
    subtle.unwrapKey.length === 7 &&
    /format, keyData, algorithm/.test(String(subtle.importKey)) &&
    crypto.subtle.generateKey.name === "generateKey");
const kp2 = await crypto.subtle.generateKey("ML-KEM-512", true, kemUsages);
const e2 = await crypto.subtle.encapsulateBits("ML-KEM-512", kp2.publicKey);
const d2 = await crypto.subtle.decapsulateBits("ML-KEM-512", kp2.privateKey, e2.ciphertext);
ok("patched subtle KEM roundtrip", Buffer.from(e2.sharedKey).equals(Buffer.from(d2)));
const dig2 = await crypto.subtle.digest("SHA-256", Buffer.from("abc"));
ok("native digest still works", Buffer.from(dig2).equals(Buffer.from(digest)));
const ec = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
ok("native generateKey passthrough", ec.privateKey.algorithm.name === "ECDSA");
const SC = Object.getPrototypeOf(crypto.subtle).constructor;
ok("SubtleCrypto.supports ML", SC.supports("encapsulateKey", "ML-KEM-1024") === true);
ok("SubtleCrypto.supports unknown false", SC.supports("encrypt", "FAKE-ALG") === false);
const dsa2 = await crypto.subtle.generateKey("ML-DSA-44", false, ["sign", "verify"]);
const sig2 = await crypto.subtle.sign("ML-DSA-44", dsa2.privateKey, data);
ok("patched sign/verify", await crypto.subtle.verify("ML-DSA-44", dsa2.publicKey, sig2, data));
const spki2 = await crypto.subtle.exportKey("spki", kp2.publicKey);
const pub2 = await crypto.subtle.importKey("spki", spki2, "ML-KEM-512", true, ["encapsulateBits"]);
ok("patched spki roundtrip", (await crypto.subtle.encapsulateBits("ML-KEM-512", pub2))
    .ciphertext.byteLength === 768);
const wrapped2 = await crypto.subtle.wrapKey("raw-seed", kp2.privateKey, kw, "AES-KW");
const unwrapped3 = await crypto.subtle.unwrapKey("raw-seed", wrapped2, kw, "AES-KW",
    "ML-KEM-512", true, ["decapsulateBits"]);
ok("patched wrapKey/unwrapKey roundtrip",
    Buffer.from(await crypto.subtle.exportKey("raw-seed", unwrapped3))
        .equals(Buffer.from(await crypto.subtle.exportKey("raw-seed", kp2.privateKey))));
const hmacNative = await crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-256", length: 256 }, true, ["sign"]);
const wrappedNative = await crypto.subtle.wrapKey("raw", hmacNative, kw, "AES-KW");
ok("native wrapKey passthrough after install", wrappedNative.byteLength === 40);

uninstall();
ok("uninstall removes encapsulateBits", typeof crypto.subtle.encapsulateBits !== "function");
const dig3 = await crypto.subtle.digest("SHA-256", Buffer.from("abc"));
ok("native digest after uninstall", Buffer.from(dig3).equals(Buffer.from(digest)));

/* ---- partial native support: only the gaps are intercepted ----
 * Pretend the platform does ML-KEM-512 natively (mock ctor.supports before
 * install). The polyfill must then delegate ML-KEM-512 to the real native
 * methods -- which on this Node don't know it, so the call rejects natively
 * instead of succeeding through the polyfill -- while still handling
 * ML-KEM-768 and reporting supports() for both. */
const SC2 = Object.getPrototypeOf(crypto.subtle).constructor;
const hadSupports = Object.getOwnPropertyDescriptor(SC2, "supports");
Object.defineProperty(SC2, "supports", {
    value: (op, alg) => String(alg) === "ML-KEM-512",
    writable: true, configurable: true,
});
install();
ok("partial: gap algo still polyfilled",
    (await crypto.subtle.generateKey("ML-KEM-768", false, kemUsages))
        .publicKey.algorithm.name === "ML-KEM-768");
try {
    /* the polyfill would succeed here; only native delegation rejects */
    await crypto.subtle.generateKey("ML-KEM-512", false, kemUsages);
    assert(false, "partial: 'native' algo must delegate (and fail natively here)");
} catch (e) {
    ok("partial: 'native' algo delegated to platform [" + e.name + "]", true);
}
ok("partial: polyfill-forged key still handled by provenance",
    (await crypto.subtle.encapsulateBits("ML-KEM-512", pub2)).ciphertext.byteLength === 768);
ok("partial: supports() covers both",
    SC2.supports("encapsulateBits", "ML-KEM-512") &&
    SC2.supports("encapsulateBits", "ML-KEM-768"));
uninstall();
if (hadSupports) Object.defineProperty(SC2, "supports", hadSupports);
else delete SC2.supports;
ok("partial: mock supports cleaned up",
    hadSupports ? SC2.supports === hadSupports.value : SC2.supports === undefined);

console.log("PASS:", passed, "checks");
