/***************************************************************************
 * subtlepq: post-quantum polyfill for the Web Cryptography API
 * ML-KEM (FIPS 203) + ML-DSA (FIPS 204) per the WICG Modern Algorithms
 * draft, with native delegation.
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * Default import is a ponyfill: `subtle` mirrors crypto.subtle plus the
 * WICG methods, handling ML-* here and delegating everything else to the
 * platform. No globals are touched unless install() is called.
 ***************************************************************************/

import * as ours from "./subtle.js";
import { ROUTES, shape } from "./router.js";
import * as E from "./errors.js";

export { install, uninstall } from "./install.js";
export { supports } from "./subtle.js";

const routedFns = {};
function routed(op) {
    if (!routedFns[op]) {
        routedFns[op] = shape(op, (args) => {
            if (ROUTES[op](args)) return ours[op](...args);
            const ns = globalThis.crypto && globalThis.crypto.subtle;
            if (ns && typeof ns[op] === "function") return ns[op](...args);
            throw E.notSupported(op + " is not supported");
        });
    }
    return routedFns[op];
}

export const subtle = new Proxy(Object.create(null), {
    get(_, prop) {
        if (typeof prop === "string" && ROUTES[prop]) return routed(prop);
        const ns = globalThis.crypto && globalThis.crypto.subtle;
        const v = ns && ns[prop];
        return typeof v === "function" ? v.bind(ns) : v;
    },
    has(_, prop) {
        const ns = globalThis.crypto && globalThis.crypto.subtle;
        return (typeof prop === "string" && !!ROUTES[prop]) || (ns ? prop in ns : false);
    },
});
