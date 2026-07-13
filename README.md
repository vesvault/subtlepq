# subtlepq

Post-quantum polyfill for the Web Cryptography API: ML-KEM (FIPS 203) and ML-DSA (FIPS 204) per the [WICG Modern Algorithms draft](https://wicg.github.io/webcrypto-modern-algos/), with native delegation where the platform already supports it.

**Status: P4 — engine, core JS layer, all key formats, key wrapping, native-parity suites, DHKEM extension.**

Key formats: `raw-public`, `raw-seed`, `spki`, `pkcs8` (seed-only encoding per the LAMPS
drafts; the `both` CHOICE is accepted on import and cross-checked), and `jwk` (kty `"AKP"`,
`pub`/`priv` with `priv` = seed). `wrapKey`/`unwrapKey` compose export/import with the native
wrapping algorithm, so AES-GCM, AES-KW, and RSA-OAEP wrapping of ML-* keys just work.

## Use

Ponyfill (no globals touched):

```js
import { subtle } from "subtlepq";

const { publicKey, privateKey } = await subtle.generateKey("ML-KEM-768", false,
    ["encapsulateKey", "decapsulateKey"]);
const { sharedKey, ciphertext } = await subtle.encapsulateKey("ML-KEM-768", publicKey,
    { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
// sharedKey is a genuine native CryptoKey; all downstream crypto is native
```

True polyfill (patches `crypto.subtle`, delegates everything non-ML to the platform, self-retires where native support exists):

```js
import { install } from "subtlepq";
install();
const kp = await crypto.subtle.generateKey("ML-DSA-65", false, ["sign", "verify"]);
const sig = await crypto.subtle.sign({ name: "ML-DSA-65", context: ctx }, kp.privateKey, data);
```

Known limits (inherent to a script polyfill, made loud rather than silent): ML-* keys are not structured-cloneable — `postMessage`/IndexedDB throws `DataCloneError`; export the 32–64-byte seed and re-import instead. Key material lives in wasm linear memory: `extractable: false` is API-level enforcement, not platform isolation.

## DHKEM: classical ECDH in the same KEM shape

`subtlepq/dhkem` wraps ephemeral-static ECDH as a KEM per [RFC 9180 §4.1](https://www.rfc-editor.org/rfc/rfc9180#section-4.1) — `DHKEM-X25519-HKDF-SHA256` and `DHKEM-P256-HKDF-SHA256` — so classical and post-quantum key agreement share one calling convention, and migrating to ML-KEM is a name change:

```js
import * as dhkem from "subtlepq/dhkem";
dhkem.register();       // before install(), if you use the true polyfill
import { subtle } from "subtlepq";

const kp = await subtle.generateKey("DHKEM-X25519-HKDF-SHA256", false,
    ["encapsulateKey", "decapsulateKey"]);
const { sharedKey, ciphertext } = await subtle.encapsulateKey(
    "DHKEM-X25519-HKDF-SHA256", kp.publicKey,          // -> "ML-KEM-768" later
    { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
```

These names are **not** in the WICG draft — this is a subtlepq extension (if the WG adopts DHKEM identifiers, those will be adopted and these aliased). Underneath it is 100% native WebCrypto (ECDH/X25519 + HKDF): no wasm is involved, and the keys are genuine platform CryptoKeys — structured-cloneable, native usage enforcement (surfaced as `deriveBits`). The ciphertext is the serialized ephemeral public key (32 bytes X25519 / 65 bytes P-256), interoperable with any RFC 9180 DHKEM implementation, and validated against the RFC 9180 Appendix A test vectors.

One asymmetry vs a true KEM: RFC 9180 decapsulation mixes the recipient *public* key into the KDF. subtlepq remembers the public half for keys created through `subtlepq/dhkem`; for private keys from elsewhere (or structured-cloned into another realm) pass it explicitly — `decapsulateBits({ name: "DHKEM-X25519-HKDF-SHA256", publicKey }, key, ct)` — or use an extractable key.

## Engine

`wasm/` builds a minimal [liboqs](https://github.com/open-quantum-safe/liboqs) (pinned submodule, ML-KEM + ML-DSA only) plus a thin shim (`subtlepq_engine.c`) to WebAssembly:

```
git submodule update --init
wasm/build.sh          # needs emsdk; override location with EMSDK=...
npm test
```

Outputs `wasm/dist/subtlepq-engine.mjs` (+ `.wasm` sidecar, CSP-clean) and `subtlepq-engine.single.mjs` (self-contained, requires `'wasm-unsafe-eval'` under strict CSP). 75 KB wasm covers all six parameter sets.

Seeded operations liboqs does not expose publicly (ML-DSA keygen from seed, KAT-deterministic encapsulation/signing) use a bracketed RNG-playback override — the same technique liboqs' own ACVP tests use.

Tests run NIST ACVP known-answer vectors (subset, see `test/vectors/acvp-subset.json`) for all six parameter sets, plus roundtrip, implicit-rejection, context, and polyfill-routing checks. `test/dhkem-test.mjs` validates the DHKEM extension against the RFC 9180 Appendix A vectors (`test/vectors/rfc9180-subset.json`).

`npm run test:parity` (Node >= 24.7) runs the polyfill side-by-side against the
platform-native ML-KEM/ML-DSA WebCrypto implementation as an oracle: identical
spki/pkcs8/jwk bytes, cross-stack encapsulate/decapsulate and sign/verify, identical
AES-KW/AES-GCM wrapKey output, and matching DOMException names on malformed input.
`npm run test:libves` cross-checks ML-KEM against [libVES](https://github.com/vesvault/libVES)
(an independent liboqs build and ASN.1 layer): same-seed keypair equality, SPKI byte
parity, and mutual key import and encapsulation.

## Built by the libVES team

subtlepq comes from [VESvault](https://vesvault.com), the team behind [libVES](https://github.com/vesvault/libVES) — end-to-end encryption between users with post-quantum vaults (ML-KEM via liboqs) and VESrecovery™ key recovery. subtlepq gives you the primitives; if you need what goes on top — user-to-user key exchange, shared vaults, recovery from a lost key — that's libVES.

## License

Apache-2.0, (c) 2026 VESvault Corp.
