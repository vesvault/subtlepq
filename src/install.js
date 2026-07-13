/***************************************************************************
 * subtlepq: true-polyfill installer -- patches globalThis.crypto.subtle
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * install() wraps SubtleCrypto.prototype methods so ML-* algorithms and
 * subtlepq keys are handled here while every other call reaches the saved
 * native original with untouched arguments. Native support is probed per
 * algorithm at install time: algorithms the platform already does natively
 * are delegated to it (their keys stay genuine platform keys), only the
 * gaps are polyfilled, and when there are no gaps install() is a no-op
 * (self-retiring). install(true) also registers the subtlepq/dhkem
 * extension names. uninstall() restores the originals and unregisters
 * what install(true) registered.
 ***************************************************************************/

import * as ours from "./subtle.js";
import { makeRoutes, shape } from "./router.js";
import { allAlgorithms, normalizeAlg } from "./algorithms.js";
import * as dhkem from "./dhkem.js";
import * as E from "./errors.js";

let saved = null;

function nativeSupports(ctor, operation, algorithm) {
    try {
        return typeof ctor.supports === "function" &&
            ctor.supports(operation, algorithm) === true;
    } catch {
        return false;
    }
}

/* the operation that proves native end-to-end support for an algorithm kind */
const PROBE = { kem: "encapsulateBits", sig: "sign" };

export function install(withDhkem) {
    if (saved) return;
    const subtle = globalThis.crypto && globalThis.crypto.subtle;
    if (!subtle) {
        throw new Error("subtlepq: crypto.subtle is unavailable (insecure context?)");
    }
    const proto = Object.getPrototypeOf(subtle);
    const ctor = subtle.constructor;
    saved = { proto, ctor, methods: {}, supports: Object.getOwnPropertyDescriptor(ctor, "supports") };

    if (withDhkem) {
        dhkem.register();
        saved.dhkem = true;
    }

    /* per-algorithm native delegation, probed once at install time: names
     * the platform already supports natively (extension names included,
     * should an implementation ever adopt them) route to the native
     * original -- their keys stay genuine platform keys -- and only the
     * gaps are polyfilled. No gaps at all: nothing to patch, self-retire.
     * Polyfill-forged keys always stay here (provenance beats name). */
    const native = new Set();
    const algs = allAlgorithms();
    for (const { name, kind } of algs) {
        if (nativeSupports(ctor, PROBE[kind], name)) native.add(name);
    }
    if (native.size === algs.length) return;
    const oursAlg = (alg) => {
        const a = normalizeAlg(alg);
        return !!a && !native.has(a.name);
    };

    for (const [op, isOurs] of Object.entries(makeRoutes(oursAlg))) {
        const orig = proto[op];
        saved.methods[op] = Object.getOwnPropertyDescriptor(proto, op);
        const wrapped = shape(op, (args, self) => {
            if (isOurs(args)) return ours[op](...args);
            if (typeof orig === "function") return orig.apply(self, args);
            throw E.notSupported(op + " is not supported");
        });
        Object.defineProperty(proto, op, {
            value: wrapped, writable: true, configurable: true,
        });
    }

    const origSupports = ctor.supports;
    const supports = function (operation, algorithm, ...rest) {
        if (ours.supports(operation, algorithm)) return true;
        if (typeof origSupports === "function") {
            return origSupports.call(this, operation, algorithm, ...rest);
        }
        return false;
    };
    Object.defineProperty(ctor, "supports", {
        value: supports, writable: true, configurable: true,
    });
}

export function uninstall() {
    if (!saved) return;
    for (const [op, desc] of Object.entries(saved.methods)) {
        if (desc) Object.defineProperty(saved.proto, op, desc);
        else delete saved.proto[op];
    }
    if (saved.supports) Object.defineProperty(saved.ctor, "supports", saved.supports);
    else delete saved.ctor.supports;
    if (saved.dhkem) dhkem.unregister();
    saved = null;
}
