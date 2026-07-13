/***************************************************************************
 * subtlepq: dispatch rules shared by the ponyfill (index.js) and the
 * polyfill installer (install.js)
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * Key provenance beats algorithm name: a key forged by this polyfill is
 * always handled here; otherwise an ML-* algorithm name routes here and
 * everything else goes to the platform untouched.
 ***************************************************************************/

import { normalizeAlg } from "./algorithms.js";
import { isOurKey } from "./keystore.js";

const oursAlg = (alg) => !!normalizeAlg(alg);

/* args => should subtlepq handle this call? -- keyed by SubtleCrypto method.
 * `ours` is the algorithm-name predicate: the ponyfill claims every
 * registered name (default); install() narrows it to exclude algorithms the
 * platform supports natively. Key-provenance checks are not narrowed --
 * a polyfill-forged key can only be operated on here. */
export function makeRoutes(ours = oursAlg) {
    return {
        /* wrapped existing methods */
        generateKey: (args) => ours(args[0]),
        importKey: (args) => ours(args[2]),
        exportKey: (args) => isOurKey(args[1]),
        sign: (args) => isOurKey(args[1]) || ours(args[0]),
        verify: (args) => isOurKey(args[1]) || ours(args[0]),
        /* wrap/unwrap: ours when the wrapped key or either key handle is ours;
         * (format, key, wrappingKey, ...) / (format, data, unwrappingKey, wrapAlg, keyAlg, ...) */
        wrapKey: (args) => isOurKey(args[1]) || isOurKey(args[2]),
        unwrapKey: (args) => ours(args[4]) || isOurKey(args[2]),
        /* methods added by the WICG draft */
        encapsulateBits: (args) => ours(args[0]) || isOurKey(args[1]),
        encapsulateKey: (args) => ours(args[0]) || isOurKey(args[1]),
        decapsulateBits: (args) => ours(args[0]) || isOurKey(args[1]),
        decapsulateKey: (args) => ours(args[0]) || isOurKey(args[1]),
        getPublicKey: (args) => isOurKey(args[0]),
    };
}

export const ROUTES = makeRoutes();

/* Wrapper factories carrying the spec parameter lists, so consoles show real
 * argument hints (and fn.length matches native) instead of (...args). Written
 * out statically -- Function() codegen would break under strict CSP. Each
 * forwards (arguments, this) to the routing handler; the async wrapper turns
 * sync throws into rejections, as native SubtleCrypto does. */
export const shape = (op, h) => SHAPES[op](h);

const SHAPES = {
    generateKey: (h) => async function generateKey(
        algorithm, extractable, keyUsages) { return h(arguments, this); },
    importKey: (h) => async function importKey(
        format, keyData, algorithm, extractable, keyUsages) { return h(arguments, this); },
    exportKey: (h) => async function exportKey(
        format, key) { return h(arguments, this); },
    sign: (h) => async function sign(
        algorithm, key, data) { return h(arguments, this); },
    verify: (h) => async function verify(
        algorithm, key, signature, data) { return h(arguments, this); },
    encapsulateBits: (h) => async function encapsulateBits(
        algorithm, encapsulationKey) { return h(arguments, this); },
    encapsulateKey: (h) => async function encapsulateKey(
        algorithm, encapsulationKey, sharedKeyAlgorithm, extractable, keyUsages) {
        return h(arguments, this); },
    decapsulateBits: (h) => async function decapsulateBits(
        algorithm, decapsulationKey, ciphertext) { return h(arguments, this); },
    decapsulateKey: (h) => async function decapsulateKey(
        algorithm, decapsulationKey, ciphertext, sharedKeyAlgorithm, extractable, keyUsages) {
        return h(arguments, this); },
    getPublicKey: (h) => async function getPublicKey(
        key, keyUsages) { return h(arguments, this); },
    wrapKey: (h) => async function wrapKey(
        format, key, wrappingKey, wrapAlgorithm) { return h(arguments, this); },
    unwrapKey: (h) => async function unwrapKey(
        format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm,
        extractable, keyUsages) { return h(arguments, this); },
};
