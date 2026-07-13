/***************************************************************************
 * subtlepq wasm engine test: roundtrips + NIST ACVP known-answer vectors
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * Runs under Node >= 18. Vectors: test/vectors/acvp-subset.json
 * (extracted from usnistgov/ACVP-Server, see "source" field within).
 ***************************************************************************/

import assert from "assert";
import { readFileSync } from "fs";
import SubtlePQEngine from "../wasm/dist/subtlepq-engine.mjs";

const vectors = JSON.parse(
    readFileSync(new URL("./vectors/acvp-subset.json", import.meta.url)));

const KEM_ALGS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];
const SIG_ALGS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
const ZEROS32 = Buffer.alloc(32);

let passed = 0;
function ok(label, cond) {
    assert(cond, label);
    passed++;
}

const M = await SubtlePQEngine();

const put = (bytes) => {
    const p = M._malloc(bytes.length);
    M.HEAPU8.set(bytes, p);
    return p;
};
const putStr = (s) => put(Buffer.from(s + "\0", "utf8"));
const get = (p, n) => Buffer.from(M.HEAPU8.slice(p, p + n));
const free = (...ps) => ps.forEach((p) => M._free(p));
const cstr = (p) => {
    let e = p;
    while (M.HEAPU8[e]) e++;
    return Buffer.from(M.HEAPU8.slice(p, e)).toString();
};
const u32s = (p, n) => {
    const r = [];
    for (let i = 0; i < n; i++)
        r.push(new DataView(M.HEAPU8.buffer, p + 4 * i, 4).getUint32(0, true));
    return r;
};
const hex = (s) => Buffer.from(s, "hex");

console.log("liboqs:", cstr(M._pqf_liboqs_version()));

const kemLen = {}, sigLen = {};
for (const alg of KEM_ALGS) {
    const a = putStr(alg), o = M._malloc(20);
    ok(alg + " lengths", M._pqf_kem_lengths(a, o) === 0);
    const [pk, sk, ct, ss, seed] = u32s(o, 5);
    kemLen[alg] = { pk, sk, ct, ss, seed };
    free(a, o);
}
ok("ML-KEM-768 sizes", kemLen["ML-KEM-768"].pk === 1184 &&
    kemLen["ML-KEM-768"].ct === 1088 && kemLen["ML-KEM-768"].ss === 32 &&
    kemLen["ML-KEM-768"].seed === 64);
for (const alg of SIG_ALGS) {
    const a = putStr(alg), o = M._malloc(12);
    ok(alg + " lengths", M._pqf_sig_lengths(a, o) === 0);
    const [pk, sk, sig] = u32s(o, 3);
    sigLen[alg] = { pk, sk, sig };
    free(a, o);
}
ok("ML-DSA-65 sizes", sigLen["ML-DSA-65"].pk === 1952 && sigLen["ML-DSA-65"].sig === 3309);

/* ---- KEM roundtrips + implicit rejection ---- */
for (const alg of KEM_ALGS) {
    const L = kemLen[alg];
    const a = putStr(alg);
    const pk = M._malloc(L.pk), sk = M._malloc(L.sk);
    const ct = M._malloc(L.ct), ss1 = M._malloc(L.ss), ss2 = M._malloc(L.ss);
    ok(alg + " keypair", M._pqf_kem_keypair(a, pk, sk) === 0);
    ok(alg + " encaps", M._pqf_kem_encaps(a, pk, ct, ss1) === 0);
    ok(alg + " decaps", M._pqf_kem_decaps(a, sk, ct, ss2) === 0);
    ok(alg + " ss match", get(ss1, L.ss).equals(get(ss2, L.ss)));
    M.HEAPU8[ct] ^= 0xff; /* corrupt */
    ok(alg + " implicit rejection rc", M._pqf_kem_decaps(a, sk, ct, ss2) === 0);
    ok(alg + " implicit rejection ss differs", !get(ss1, L.ss).equals(get(ss2, L.ss)));
    free(a, pk, sk, ct, ss1, ss2);
}

/* ---- SIG roundtrips incl. context ---- */
for (const alg of SIG_ALGS) {
    const L = sigLen[alg];
    const a = putStr(alg);
    const pk = M._malloc(L.pk), sk = M._malloc(L.sk);
    ok(alg + " keypair", M._pqf_sig_keypair(a, pk, sk) === 0);
    const msg = Buffer.from("subtlepq P0 message");
    const ctx = Buffer.from("subtlepq-ctx");
    const mp = put(msg), cp = put(ctx);
    const sig = M._malloc(L.sig), slp = M._malloc(4);
    new DataView(M.HEAPU8.buffer, slp, 4).setUint32(0, L.sig, true);
    ok(alg + " sign", M._pqf_sig_sign(a, sk, mp, msg.length, cp, ctx.length, sig, slp) === 0);
    const slen = u32s(slp, 1)[0];
    ok(alg + " verify", M._pqf_sig_verify(a, pk, mp, msg.length, cp, ctx.length, sig, slen) === 0);
    ok(alg + " verify wrong ctx", M._pqf_sig_verify(a, pk, mp, msg.length, cp, ctx.length - 1, sig, slen) === 1);
    M.HEAPU8[mp] ^= 1;
    ok(alg + " verify tampered", M._pqf_sig_verify(a, pk, mp, msg.length, cp, ctx.length, sig, slen) === 1);
    free(a, pk, sk, mp, cp, sig, slp);
}

/* ---- ACVP ML-KEM keyGen ---- */
let n = 0;
for (const c of vectors.sets["ML-KEM-keyGen-FIPS203"]) {
    const alg = c.group.parameterSet, L = kemLen[alg];
    if (!L || !c.test.d || !c.test.z) continue;
    const a = putStr(alg), seed = put(Buffer.concat([hex(c.test.d), hex(c.test.z)]));
    const pk = M._malloc(L.pk), sk = M._malloc(L.sk);
    ok(alg + " ACVP keyGen rc", M._pqf_kem_keypair_derand(a, seed, pk, sk) === 0);
    ok(alg + " ACVP keyGen ek", get(pk, L.pk).equals(hex(c.test.ek)));
    ok(alg + " ACVP keyGen dk", get(sk, L.sk).equals(hex(c.test.dk)));
    free(a, seed, pk, sk);
    n++;
}
console.log("ACVP ML-KEM keyGen cases:", n);
assert(n >= 3);

/* ---- ACVP ML-KEM encapDecap ---- */
let ne = 0, nd = 0;
for (const c of vectors.sets["ML-KEM-encapDecap-FIPS203"]) {
    const alg = c.group.parameterSet, L = kemLen[alg];
    if (!L) continue;
    const a = putStr(alg);
    if (c.group.function === "encapsulation" && c.test.ek && c.test.m) {
        const pk = put(hex(c.test.ek)), m = put(hex(c.test.m));
        const ct = M._malloc(L.ct), ss = M._malloc(L.ss);
        ok(alg + " ACVP encaps rc", M._pqf_kem_encaps_derand(a, pk, m, hex(c.test.m).length, ct, ss) === 0);
        ok(alg + " ACVP encaps c", get(ct, L.ct).equals(hex(c.test.c)));
        ok(alg + " ACVP encaps k", get(ss, L.ss).equals(hex(c.test.k)));
        free(pk, m, ct, ss);
        ne++;
    } else if (c.group.function === "decapsulation" && c.test.dk && c.test.c && c.test.k) {
        const sk = put(hex(c.test.dk)), ct = put(hex(c.test.c)), ss = M._malloc(L.ss);
        ok(alg + " ACVP decaps rc", M._pqf_kem_decaps(a, sk, ct, ss) === 0);
        ok(alg + " ACVP decaps k", get(ss, L.ss).equals(hex(c.test.k)));
        free(sk, ct, ss);
        nd++;
    }
    free(a);
}
console.log("ACVP ML-KEM encaps/decaps cases:", ne, "/", nd);
assert(ne >= 3 && nd >= 3);

/* ---- ACVP ML-DSA keyGen ---- */
n = 0;
for (const c of vectors.sets["ML-DSA-keyGen-FIPS204"]) {
    const alg = c.group.parameterSet, L = sigLen[alg];
    if (!L || !c.test.seed) continue;
    const a = putStr(alg), seed = put(hex(c.test.seed));
    const pk = M._malloc(L.pk), sk = M._malloc(L.sk);
    ok(alg + " ACVP keyGen rc", M._pqf_sig_keypair_derand(a, seed, hex(c.test.seed).length, pk, sk) === 0);
    ok(alg + " ACVP keyGen pk", get(pk, L.pk).equals(hex(c.test.pk)));
    ok(alg + " ACVP keyGen sk", get(sk, L.sk).equals(hex(c.test.sk)));
    free(a, seed, pk, sk);
    n++;
}
console.log("ACVP ML-DSA keyGen cases:", n);
assert(n >= 3);

/* ---- ACVP ML-DSA sigGen (external interface, pure ML-DSA) ---- */
n = 0;
for (const c of vectors.sets["ML-DSA-sigGen-FIPS204"]) {
    const alg = c.group.parameterSet, L = sigLen[alg];
    /* pure ML-DSA only: skip HashML-DSA (pre-hash) and externalMu cases */
    if (!L || c.group.externalMu === true || !c.test.message || !c.test.sk) continue;
    if (c.test.hashAlg && c.test.hashAlg !== "none") continue;
    const msg = hex(c.test.message);
    const ctx = c.test.context ? hex(c.test.context) : Buffer.alloc(0);
    const rnd = c.group.deterministic ? ZEROS32 : (c.test.rnd ? hex(c.test.rnd) : null);
    if (!rnd) continue;
    const a = putStr(alg), sk = put(hex(c.test.sk));
    const mp = put(msg), cp = put(ctx.length ? ctx : Buffer.alloc(1)), rp = put(rnd);
    const sig = M._malloc(L.sig), slp = M._malloc(4);
    new DataView(M.HEAPU8.buffer, slp, 4).setUint32(0, L.sig, true);
    ok(alg + " ACVP sigGen rc", M._pqf_sig_sign_derand(a, sk, mp, msg.length, cp, ctx.length, rp, rnd.length, sig, slp) === 0);
    const slen = u32s(slp, 1)[0];
    ok(alg + " ACVP sigGen sig", get(sig, slen).equals(hex(c.test.signature)));
    free(a, sk, mp, cp, rp, sig, slp);
    n++;
}
console.log("ACVP ML-DSA sigGen cases:", n);
assert(n >= 3);

console.log("PASS:", passed, "checks");
