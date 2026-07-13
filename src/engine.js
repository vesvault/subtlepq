/***************************************************************************
 * subtlepq: lazy wasm engine loader + typed wrappers over subtlepq_engine.c
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * All byte outputs are fresh Uint8Array copies; secret material in wasm
 * linear memory is zeroed before the temporary allocations are freed.
 ***************************************************************************/

import * as E from "./errors.js";

let enginePromise = null;

export function getEngine() {
    if (!enginePromise) enginePromise = load();
    return enginePromise;
}

async function load() {
    const { default: init } = await import("../wasm/dist/subtlepq-engine.mjs");
    return new Engine(await init());
}

class Engine {
    constructor(M) {
        this.M = M;
        this.lens = new Map();
    }

    put(bytes) {
        const p = this.M._malloc(bytes.length);
        this.M.HEAPU8.set(bytes, p);
        return p;
    }
    str(s) {
        return this.put(new TextEncoder().encode(s + "\0"));
    }
    take(p, n) {
        return this.M.HEAPU8.slice(p, p + n);
    }
    wipe(p, n) {
        this.M.HEAPU8.fill(0, p, p + n);
    }
    drop(...ps) {
        for (const p of ps) this.M._free(p);
    }
    u32(p) {
        return new DataView(this.M.HEAPU8.buffer, p, 4).getUint32(0, true);
    }
    setU32(p, v) {
        new DataView(this.M.HEAPU8.buffer, p, 4).setUint32(0, v, true);
    }

    kemLengths(name) {
        let L = this.lens.get(name);
        if (!L) {
            const a = this.str(name), o = this.M._malloc(20);
            const rc = this.M._pqf_kem_lengths(a, o);
            if (rc === 0) {
                L = { pk: this.u32(o), sk: this.u32(o + 4), ct: this.u32(o + 8),
                      ss: this.u32(o + 12), seed: this.u32(o + 16) };
                this.lens.set(name, L);
            }
            this.drop(a, o);
            if (!L) throw E.notSupported("unknown KEM algorithm " + name);
        }
        return L;
    }

    sigLengths(name) {
        let L = this.lens.get(name);
        if (!L) {
            const a = this.str(name), o = this.M._malloc(12);
            const rc = this.M._pqf_sig_lengths(a, o);
            if (rc === 0) {
                L = { pk: this.u32(o), sk: this.u32(o + 4), sig: this.u32(o + 8), seed: 32 };
                this.lens.set(name, L);
            }
            this.drop(a, o);
            if (!L) throw E.notSupported("unknown signature algorithm " + name);
        }
        return L;
    }

    kemKeypairDerand(name, seed) {
        const L = this.kemLengths(name);
        const a = this.str(name), s = this.put(seed);
        const pk = this.M._malloc(L.pk), sk = this.M._malloc(L.sk);
        const rc = this.M._pqf_kem_keypair_derand(a, s, pk, sk);
        const out = rc === 0 ? { pub: this.take(pk, L.pk), sk: this.take(sk, L.sk) } : null;
        this.wipe(s, seed.length);
        this.wipe(sk, L.sk);
        this.drop(a, s, pk, sk);
        if (!out) throw E.opError(name + " key generation failed");
        return out;
    }

    kemEncaps(name, pub) {
        const L = this.kemLengths(name);
        const a = this.str(name), p = this.put(pub);
        const ct = this.M._malloc(L.ct), ss = this.M._malloc(L.ss);
        const rc = this.M._pqf_kem_encaps(a, p, ct, ss);
        const out = rc === 0 ? { ct: this.take(ct, L.ct), ss: this.take(ss, L.ss) } : null;
        this.wipe(ss, L.ss);
        this.drop(a, p, ct, ss);
        if (!out) throw E.opError(name + " encapsulation failed");
        return out;
    }

    kemDecaps(name, sk, ct) {
        const L = this.kemLengths(name);
        const a = this.str(name), k = this.put(sk), c = this.put(ct);
        const ss = this.M._malloc(L.ss);
        const rc = this.M._pqf_kem_decaps(a, k, c, ss);
        const out = rc === 0 ? this.take(ss, L.ss) : null;
        this.wipe(k, sk.length);
        this.wipe(ss, L.ss);
        this.drop(a, k, c, ss);
        if (!out) throw E.opError(name + " decapsulation failed");
        return out;
    }

    sigKeypairDerand(name, seed) {
        const L = this.sigLengths(name);
        const a = this.str(name), s = this.put(seed);
        const pk = this.M._malloc(L.pk), sk = this.M._malloc(L.sk);
        const rc = this.M._pqf_sig_keypair_derand(a, s, seed.length, pk, sk);
        const out = rc === 0 ? { pub: this.take(pk, L.pk), sk: this.take(sk, L.sk) } : null;
        this.wipe(s, seed.length);
        this.wipe(sk, L.sk);
        this.drop(a, s, pk, sk);
        if (!out) throw E.opError(name + " key generation failed");
        return out;
    }

    sigSign(name, sk, msg, ctx) {
        const L = this.sigLengths(name);
        const a = this.str(name), k = this.put(sk);
        const m = this.put(msg), c = this.put(ctx.length ? ctx : new Uint8Array(1));
        const sig = this.M._malloc(L.sig), slp = this.M._malloc(4);
        this.setU32(slp, L.sig);
        const rc = this.M._pqf_sig_sign(a, k, m, msg.length, c, ctx.length, sig, slp);
        const out = rc === 0 ? this.take(sig, this.u32(slp)) : null;
        this.wipe(k, sk.length);
        this.drop(a, k, m, c, sig, slp);
        if (!out) throw E.opError(name + " signing failed");
        return out;
    }

    sigVerify(name, pub, msg, ctx, sig) {
        const a = this.str(name), p = this.put(pub);
        const m = this.put(msg), c = this.put(ctx.length ? ctx : new Uint8Array(1));
        const s = this.put(sig);
        const rc = this.M._pqf_sig_verify(a, p, m, msg.length, c, ctx.length, s, sig.length);
        this.drop(a, p, m, c, s);
        if (rc < 0) throw E.opError(name + " verification failed");
        return rc === 0;
    }
}
