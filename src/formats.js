/***************************************************************************
 * subtlepq: spki / pkcs8 / jwk codecs (fixed ASN.1 templates)
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * DER shapes per draft-ietf-lamps-kyber/dilithium-certificates as adopted
 * by the WICG draft: SPKI AlgorithmIdentifier has NO parameters; PKCS#8
 * privateKey is the seed-only CHOICE, an implicit [0] primitive holding
 * the seed. Import also accepts the "both" CHOICE (seed + expandedKey,
 * verified against each other); expandedKey-only is NotSupportedError.
 ***************************************************************************/

import * as E from "./errors.js";

/* NIST algorithm arc: 2.16.840.1.101.3.4.{4=kem,3=sig}.n */
const OIDS = {
    "ML-KEM-512":  [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01],
    "ML-KEM-768":  [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02],
    "ML-KEM-1024": [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03],
    "ML-DSA-44":   [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11],
    "ML-DSA-65":   [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12],
    "ML-DSA-87":   [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13],
};

function oidToName(body) {
    for (const [name, oid] of Object.entries(OIDS)) {
        if (oid.length === body.length && oid.every((b, i) => b === body[i])) return name;
    }
    return null;
}

/* ---- DER write ---- */

function tlv(tag, ...parts) {
    const len = parts.reduce((n, p) => n + p.length, 0);
    const hdr = [tag];
    if (len < 0x80) {
        hdr.push(len);
    } else {
        const b = [];
        for (let n = len; n; n >>>= 8) b.unshift(n & 0xff);
        hdr.push(0x80 | b.length, ...b);
    }
    const out = new Uint8Array(hdr.length + len);
    out.set(hdr);
    let p = hdr.length;
    for (const part of parts) { out.set(part, p); p += part.length; }
    return out;
}

function algorithmIdentifier(name) {
    return tlv(0x30, tlv(0x06, OIDS[name]));
}

/* ---- DER read ---- */

class Reader {
    constructor(u8, what) { this.u8 = u8; this.p = 0; this.what = what; }
    bad(m) { return E.dataError("malformed " + this.what + ": " + m); }
    tlv() {
        if (this.p + 2 > this.u8.length) throw this.bad("truncated");
        const tag = this.u8[this.p++];
        let len = this.u8[this.p++];
        if (len & 0x80) {
            const n = len & 0x7f;
            if (n < 1 || n > 4) throw this.bad("bad length encoding");
            len = 0;
            for (let i = 0; i < n; i++) {
                if (this.p >= this.u8.length) throw this.bad("truncated");
                len = len * 256 + this.u8[this.p++];
            }
        }
        if (this.p + len > this.u8.length) throw this.bad("truncated");
        const val = this.u8.subarray(this.p, this.p + len);
        this.p += len;
        return { tag, val };
    }
    expect(tag, m) {
        const t = this.tlv();
        if (t.tag !== tag) throw this.bad("expected " + m);
        return t.val;
    }
    get done() { return this.p >= this.u8.length; }
}

function readAlgorithm(r, what) {
    const seq = new Reader(r.expect(0x30, "AlgorithmIdentifier"), what);
    const name = oidToName(seq.expect(0x06, "algorithm OID"));
    if (!name) throw E.dataError(what + " algorithm OID is not an ML-KEM/ML-DSA algorithm");
    if (!seq.done) throw E.dataError(what + " AlgorithmIdentifier parameters must be absent");
    return name;
}

/* ---- SubjectPublicKeyInfo ---- */

export function encodeSpki(name, pub) {
    const bits = new Uint8Array(pub.length + 1);
    bits.set(pub, 1);
    return tlv(0x30, algorithmIdentifier(name), tlv(0x03, bits));
}

export function decodeSpki(bytes) {
    const outer = new Reader(bytes, "SPKI");
    const r = new Reader(outer.expect(0x30, "SubjectPublicKeyInfo"), "SPKI");
    if (!outer.done) throw outer.bad("trailing bytes");
    const name = readAlgorithm(r, "SPKI");
    const bits = r.expect(0x03, "subjectPublicKey BIT STRING");
    if (!r.done) throw r.bad("trailing bytes");
    if (bits.length < 1 || bits[0] !== 0) throw r.bad("subjectPublicKey unused bits");
    return { name, pub: bits.slice(1) };
}

/* ---- PrivateKeyInfo (seed-only CHOICE) ---- */

export function encodePkcs8(name, seed) {
    return tlv(0x30,
        tlv(0x02, [0]),
        algorithmIdentifier(name),
        tlv(0x04, tlv(0x80, seed)));
}

/* Returns { name, seed, expanded? }; expanded (from the "both" CHOICE) is
 * the caller's to verify against the seed-derived key. */
export function decodePkcs8(bytes) {
    const outer = new Reader(bytes, "PKCS#8");
    const r = new Reader(outer.expect(0x30, "PrivateKeyInfo"), "PKCS#8");
    if (!outer.done) throw outer.bad("trailing bytes");
    const ver = r.expect(0x02, "version INTEGER");
    if (ver.length !== 1 || ver[0] > 1) throw r.bad("unsupported version");
    const name = readAlgorithm(r, "PKCS#8");
    const inner = new Reader(r.expect(0x04, "privateKey OCTET STRING"), "PKCS#8");
    /* anything after privateKey (attributes, [1] publicKey) is ignored */
    const t = inner.tlv();
    if (t.tag === 0x80) {                             /* seed [0] */
        if (!inner.done) throw inner.bad("trailing bytes after seed");
        return { name, seed: t.val.slice() };
    }
    if (t.tag === 0x04) {                             /* expandedKey */
        throw E.notSupported(
            "expandedKey-only ML private keys are not supported; provide the seed");
    }
    if (t.tag === 0x30) {                             /* both */
        const b = new Reader(t.val, "PKCS#8");
        const seed = b.expect(0x04, "seed OCTET STRING");
        const expanded = b.expect(0x04, "expandedKey OCTET STRING");
        if (!b.done || !inner.done) throw b.bad("trailing bytes");
        return { name, seed: seed.slice(), expanded: expanded.slice() };
    }
    throw inner.bad("unrecognized private key CHOICE");
}

/* ---- JWK base64url ---- */

export function b64u(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64u(s, what) {
    if (typeof s !== "string" || /[^A-Za-z0-9_-]/.test(s)) {
        throw E.dataError("JWK " + what + " is not base64url");
    }
    let bin;
    try {
        bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    } catch {
        throw E.dataError("JWK " + what + " is not base64url");
    }
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}
