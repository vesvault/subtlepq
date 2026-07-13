/***************************************************************************
 * subtlepq: algorithm registry and AlgorithmIdentifier normalization
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/

const NAMES = [
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
];

export const KEM_PUB_USAGES = ["encapsulateBits", "encapsulateKey"];
export const KEM_PRIV_USAGES = ["decapsulateBits", "decapsulateKey"];

/* Extension algorithms (subtlepq/dhkem): registered at runtime, carrying
 * their own ops table; the core ML-* set above stays engine-backed. */
const EXTENSIONS = new Map();

export function registerExtension(name, kind, ops) {
    EXTENSIONS.set(name.toLowerCase(), { name, kind, ops });
}

export function unregisterExtension(name) {
    EXTENSIONS.delete(name.toLowerCase());
}

export function hasExtensions() {
    return EXTENSIONS.size > 0;
}

/* WebCrypto algorithm names are matched case-insensitively.
 * Returns { name, kind, context?, ops? } with the canonical name, or null;
 * `ops` marks an extension algorithm handled outside subtle.js. */
export function normalizeAlg(alg) {
    let name, context;
    if (typeof alg === "string") {
        name = alg;
    } else if (alg && typeof alg.name === "string") {
        name = alg.name;
        context = alg.context;
    } else {
        return null;
    }
    const canonical = NAMES.find((n) => n.toLowerCase() === name.toLowerCase());
    if (canonical) {
        return {
            name: canonical,
            kind: canonical.startsWith("ML-KEM") ? "kem" : "sig",
            context,
        };
    }
    const ext = EXTENSIONS.get(name.toLowerCase());
    if (!ext) return null;
    return { name: ext.name, kind: ext.kind, ops: ext.ops, context };
}
