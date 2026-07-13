/***************************************************************************
 * subtlepq cross-check vs libVES ML-KEM (WasmOQS + libVES.Algo.OQS.MLKEM):
 * an independent liboqs build and an independent ASN.1 layer.
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * Interop contract verified here:
 *  - same 64-byte seed => identical keypairs on both stacks
 *  - SPKI bytes identical
 *  - subtlepq seed-only pkcs8 imports into libVES (PEM)
 *  - libVES expandedKey-only export is rejected by subtlepq with
 *    NotSupportedError (WICG behavior), the "both" CHOICE imports fine
 *  - encapsulate on either stack decapsulates on the other
 *
 * Run: LIBVES_DIR=/usr/src/libVES node test/parity-libves.mjs
 * (skips cleanly when LIBVES_DIR is absent)
 ***************************************************************************/

import assert from "assert";
import vm from "node:vm";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { createRequire } from "module";
import { subtle as pq } from "../src/index.js";

const DIR = process.env.LIBVES_DIR || "/usr/src/libVES";
if (!existsSync(join(DIR, "libVES.Algo.OQS.js"))) {
    console.log("SKIP: no libVES checkout at " + DIR + " (set LIBVES_DIR)");
    process.exit(0);
}

let passed = 0;
const ok = (label, cond) => { assert(cond, label); passed++; };
const hex = (b) => Buffer.from(b).toString("hex");
const beq = (a, b) => hex(new Uint8Array(a)) === hex(new Uint8Array(b));
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
const OID_ARC = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04];
const OIDS = { "ML-KEM-512": 1, "ML-KEM-768": 2, "ML-KEM-1024": 3 };

/* ---- libVES bootstrap, mirroring libVES/wasm_test.js ---- */
const g = globalThis;
g.libVES = function () {};
libVES.Error = function (code, msg, optns) {
    this.code = code; this.message = msg;
    if (optns) for (const k in optns) this[k] = optns[k];
};
libVES.Error.prototype.toString = function () { return this.message || this.code; };
libVES.Cipher = {};
libVES.Algo = { all: [] };
libVES.maxKeyLen = 48896;
libVES.getModule = function (sectn, mods) {
    const arr = mods instanceof Array ? mods : [mods];
    if (sectn[arr[0]]) {
        return arr.length > 1 ? libVES.getModule(sectn[arr[0]], arr.slice(1))
            : Promise.resolve(sectn[arr[0]]);
    }
    return Promise.reject(new libVES.Error("Internal", "no module " + arr[0]));
};
libVES.getModuleFunc = function (sectn, mod) {
    return function () { return libVES.getModule(sectn, mod); };
};
/* sloppy-mode eval so the libVES scripts' top-level vars become globals */
const load = (f) => vm.runInThisContext(readFileSync(join(DIR, f), "utf8"), { filename: f });
load("libVES.Util.js");
load("libVES.Algo.OQS.js");
/* WasmOQSinit is the config OBJECT declared by libVES.Algo.OQS.js; only the
 * factory function comes from the emscripten module */
const require2 = createRequire(import.meta.url);
g.WasmOQS = require2(join(DIR, "WasmOQS", "WasmOQS.js"));
g.WasmOQSinit.locateFile = (f) => join(DIR, "WasmOQS", f);

const wasm = await libVES.Algo.OQS.wasm();
const MLKEM = libVES.Algo.OQS.MLKEM;

for (const alg of ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]) {
    const spec = MLKEM.findSpec(alg);
    const seed = crypto.getRandomValues(new Uint8Array(64));

    /* same seed => same keypair */
    const pqPriv = await pq.importKey("raw-seed", seed, alg, true,
        ["decapsulateBits", "decapsulateKey"]);
    const pqPub = await pq.getPublicKey(pqPriv, ["encapsulateBits", "encapsulateKey"]);
    const lk = wasm.init(alg, true);
    ok(alg + " libVES generateFromSeed", wasm.generateFromSeed(lk, seed));
    ok(alg + " same seed -> same public key",
        beq(await pq.exportKey("raw-public", pqPub), lk.pub));

    /* SPKI byte parity between the two ASN.1 layers */
    ok(alg + " spki bytes identical",
        beq(await pq.exportKey("spki", pqPub), MLKEM.exportPub(spec, lk.pub)));

    /* subtlepq seed-only pkcs8 -> libVES PEM import */
    const pem = libVES.Util.PEM.encode(await pq.exportKey("pkcs8", pqPriv), "PRIVATE KEY");
    const li = await libVES.Util.PEM.import(pem);
    ok(alg + " subtlepq pkcs8 imports into libVES",
        li.algo === alg && beq(li.pub, lk.pub) && beq(li.priv, lk.priv));

    /* libVES expandedKey-only export -> subtlepq: NotSupportedError by design */
    const libDer = MLKEM.exportPriv(spec, lk.pub, lk.priv);
    let name = "resolved";
    try {
        await pq.importKey("pkcs8", libDer, alg, true, ["decapsulateBits"]);
    } catch (e) { name = e.name; }
    ok(alg + " libVES expandedKey-only export rejected [" + name + "]",
        name === "NotSupportedError");

    /* "both" CHOICE (seed + libVES's expanded bytes) -> subtlepq import */
    const oid = OID_ARC.concat(OIDS[alg]);
    const both = der(0x30, der(0x02, [0]),
        der(0x30, Uint8Array.from(oid)),
        der(0x04, der(0x30, der(0x04, seed), der(0x04, new Uint8Array(lk.priv)))));
    const pqBoth = await pq.importKey("pkcs8", both, alg, true, ["decapsulateBits"]);
    ok(alg + " both CHOICE (libVES expanded bytes) imports",
        beq(await pq.exportKey("raw-seed", pqBoth), seed));

    /* live interop, both directions */
    const e1 = await pq.encapsulateBits(alg, pqPub);
    ok(alg + " pq encaps -> libVES decaps",
        beq(e1.sharedKey, wasm.decaps(lk, new Uint8Array(e1.ciphertext))));
    const pubOnly = await libVES.Util.PEM.import(
        libVES.Util.PEM.encode(MLKEM.exportPub(spec, lk.pub), "PUBLIC KEY"));
    const ct2 = wasm.encaps(pubOnly);
    const ss2 = wasm.decaps(pubOnly);
    ok(alg + " libVES encaps -> pq decaps",
        beq(await pq.decapsulateBits(alg, pqPriv, new Uint8Array(ct2)), ss2));
}

console.log("PASS:", passed, "libVES cross-checks");
process.exit(0);
