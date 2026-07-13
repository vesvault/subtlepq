/***************************************************************************
 * subtlepq: true-polyfill installer -- patches globalThis.crypto.subtle
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * install() wraps SubtleCrypto.prototype methods so ML-* algorithms and
 * subtlepq keys are handled here while every other call reaches the saved
 * native original with untouched arguments. Methods and algorithms the
 * platform already supports natively are left alone (self-retiring).
 * uninstall() restores the originals.
 ***************************************************************************/

import * as ours from "./subtle.js";
import { ROUTES, shape } from "./router.js";
import { hasExtensions } from "./algorithms.js";
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

export function install() {
    if (saved) return;
    const subtle = globalThis.crypto && globalThis.crypto.subtle;
    if (!subtle) {
        throw new Error("subtlepq: crypto.subtle is unavailable (insecure context?)");
    }
    const proto = Object.getPrototypeOf(subtle);
    const ctor = subtle.constructor;
    saved = { proto, ctor, methods: {}, supports: Object.getOwnPropertyDescriptor(ctor, "supports") };

    /* nothing to do on platforms that already do ML-KEM + ML-DSA natively --
     * unless extension algorithms (subtlepq/dhkem) are registered, which no
     * native implementation covers; register() before install() */
    if (!hasExtensions() &&
        nativeSupports(ctor, "encapsulateBits", "ML-KEM-768") &&
        nativeSupports(ctor, "sign", "ML-DSA-65")) {
        return;
    }

    for (const [op, isOurs] of Object.entries(ROUTES)) {
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
    saved = null;
}
