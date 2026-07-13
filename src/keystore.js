/***************************************************************************
 * subtlepq: forged CryptoKey factory + private key-material store
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * Keys are Object.create(CryptoKey.prototype) with own data properties, so
 * they pass instanceof and structural checks. Key material never lives on
 * the key object: it is held in a closure-scoped WeakMap, which doubles as
 * the "is this key ours" dispatch test.
 *
 * Forged keys cannot survive structured clone (postMessage/IndexedDB) --
 * the material would not travel. Left alone they would clone SILENTLY
 * into a dead plain object, so each key carries an enumerable
 * symbol-valued marker property: symbols are not serializable, making
 * every clone attempt fail loudly with DataCloneError instead.
 ***************************************************************************/

const store = new WeakMap();

const KeyProto =
    typeof CryptoKey !== "undefined" ? CryptoKey.prototype : Object.prototype;

/* material: { pub: Uint8Array, seed?: Uint8Array, sk?: Uint8Array } */
export function forgeKey(type, algName, extractable, usages, material) {
    const key = Object.create(KeyProto);
    Object.defineProperties(key, {
        type: { value: type, enumerable: true },
        extractable: { value: !!extractable, enumerable: true },
        algorithm: { value: Object.freeze({ name: algName }), enumerable: true },
        usages: { value: Object.freeze([...usages]), enumerable: true },
        __subtlepq: {
            value: Symbol("subtlepq key: not structured-cloneable; export and re-import instead"),
            enumerable: true,
        },
    });
    store.set(key, material);
    return key;
}

export function materialOf(key) {
    return store.get(key);
}

export function isOurKey(key) {
    return typeof key === "object" && key !== null && store.has(key);
}
