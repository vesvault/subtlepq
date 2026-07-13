/***************************************************************************
 * subtlepq wasm engine: ML-KEM (FIPS 203) + ML-DSA (FIPS 204) via liboqs
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 *
 * Seeded and KAT-deterministic operations that liboqs does not expose
 * through its public API (ML-DSA keygen from seed xi, deterministic
 * encapsulation and signing) temporarily replace the liboqs RNG with a
 * playback buffer -- the same technique liboqs' own ACVP vector tests
 * use.  The wasm module is single-threaded, so the global RNG swap is
 * safe; every playback is bracketed and restores the system RNG.
 *
 * Return codes: 0 = ok, 1 = verify failed, -1 = unknown algorithm,
 * -2 = operation failed, -3 = RNG playback under/overrun.
 ***************************************************************************/

#include <string.h>
#include <stdint.h>
#include <emscripten.h>
#include <oqs/oqs.h>

static int initialized = 0;
static void ensure_init(void) {
    if (!initialized) {
        OQS_init();
        initialized = 1;
    }
}

/* ---- RNG playback ---- */

static const uint8_t *rng_pb_buf;
static size_t rng_pb_len, rng_pb_pos;
static int rng_pb_fault;

static void rng_playback(uint8_t *out, size_t n) {
    if (rng_pb_buf && rng_pb_pos + n <= rng_pb_len) {
        memcpy(out, rng_pb_buf + rng_pb_pos, n);
        rng_pb_pos += n;
    } else {
        memset(out, 0, n);
        rng_pb_fault = 1;
    }
}

static void rng_begin(const uint8_t *buf, size_t len) {
    rng_pb_buf = buf;
    rng_pb_len = len;
    rng_pb_pos = 0;
    rng_pb_fault = 0;
    OQS_randombytes_custom_algorithm(rng_playback);
}

/* fault if the operation consumed less or more than the whole buffer */
static int rng_end(void) {
    int fault = rng_pb_fault || rng_pb_pos != rng_pb_len;
    rng_pb_buf = NULL;
    OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
    return fault;
}

/* ---- ML-KEM ---- */

EMSCRIPTEN_KEEPALIVE
int pqf_kem_lengths(const char *alg, uint32_t *out5 /* pk sk ct ss seed */) {
    ensure_init();
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return -1;
    out5[0] = kem->length_public_key;
    out5[1] = kem->length_secret_key;
    out5[2] = kem->length_ciphertext;
    out5[3] = kem->length_shared_secret;
    out5[4] = kem->length_keypair_seed;
    OQS_KEM_free(kem);
    return 0;
}

EMSCRIPTEN_KEEPALIVE
int pqf_kem_keypair(const char *alg, uint8_t *pk, uint8_t *sk) {
    ensure_init();
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return -1;
    OQS_STATUS s = OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_free(kem);
    return s == OQS_SUCCESS ? 0 : -2;
}

/* seed = d || z per FIPS 203 (length_keypair_seed bytes) */
EMSCRIPTEN_KEEPALIVE
int pqf_kem_keypair_derand(const char *alg, const uint8_t *seed, uint8_t *pk, uint8_t *sk) {
    ensure_init();
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return -1;
    OQS_STATUS s = OQS_KEM_keypair_derand(kem, pk, sk, seed);
    OQS_KEM_free(kem);
    return s == OQS_SUCCESS ? 0 : -2;
}

EMSCRIPTEN_KEEPALIVE
int pqf_kem_encaps(const char *alg, const uint8_t *pk, uint8_t *ct, uint8_t *ss) {
    ensure_init();
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return -1;
    OQS_STATUS s = OQS_KEM_encaps(kem, ct, ss, pk);
    OQS_KEM_free(kem);
    return s == OQS_SUCCESS ? 0 : -2;
}

/* KAT only: m (32 bytes) supplied instead of drawn from the RNG */
EMSCRIPTEN_KEEPALIVE
int pqf_kem_encaps_derand(const char *alg, const uint8_t *pk,
                          const uint8_t *m, uint32_t mlen,
                          uint8_t *ct, uint8_t *ss) {
    ensure_init();
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return -1;
    rng_begin(m, mlen);
    OQS_STATUS s = OQS_KEM_encaps(kem, ct, ss, pk);
    int fault = rng_end();
    OQS_KEM_free(kem);
    if (s != OQS_SUCCESS) return -2;
    return fault ? -3 : 0;
}

EMSCRIPTEN_KEEPALIVE
int pqf_kem_decaps(const char *alg, const uint8_t *sk, const uint8_t *ct, uint8_t *ss) {
    ensure_init();
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return -1;
    OQS_STATUS s = OQS_KEM_decaps(kem, ss, ct, sk);
    OQS_KEM_free(kem);
    return s == OQS_SUCCESS ? 0 : -2;
}

/* ---- ML-DSA ---- */

EMSCRIPTEN_KEEPALIVE
int pqf_sig_lengths(const char *alg, uint32_t *out3 /* pk sk sig_max */) {
    ensure_init();
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) return -1;
    out3[0] = sig->length_public_key;
    out3[1] = sig->length_secret_key;
    out3[2] = sig->length_signature;
    OQS_SIG_free(sig);
    return 0;
}

EMSCRIPTEN_KEEPALIVE
int pqf_sig_keypair(const char *alg, uint8_t *pk, uint8_t *sk) {
    ensure_init();
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) return -1;
    OQS_STATUS s = OQS_SIG_keypair(sig, pk, sk);
    OQS_SIG_free(sig);
    return s == OQS_SUCCESS ? 0 : -2;
}

/* seed = xi (32 bytes) per FIPS 204, played back through the RNG */
EMSCRIPTEN_KEEPALIVE
int pqf_sig_keypair_derand(const char *alg, const uint8_t *seed, uint32_t seedlen,
                           uint8_t *pk, uint8_t *sk) {
    ensure_init();
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) return -1;
    rng_begin(seed, seedlen);
    OQS_STATUS s = OQS_SIG_keypair(sig, pk, sk);
    int fault = rng_end();
    OQS_SIG_free(sig);
    if (s != OQS_SUCCESS) return -2;
    return fault ? -3 : 0;
}

/* hedged (FIPS 204 default); ctx may be NULL/0 */
EMSCRIPTEN_KEEPALIVE
int pqf_sig_sign(const char *alg, const uint8_t *sk,
                 const uint8_t *msg, uint32_t msglen,
                 const uint8_t *ctx, uint32_t ctxlen,
                 uint8_t *sigout, uint32_t *siglen) {
    ensure_init();
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) return -1;
    size_t sl = *siglen;
    OQS_STATUS s = OQS_SIG_sign_with_ctx_str(sig, sigout, &sl, msg, msglen, ctx, ctxlen, sk);
    OQS_SIG_free(sig);
    if (s != OQS_SUCCESS) return -2;
    *siglen = (uint32_t)sl;
    return 0;
}

/* KAT only: rnd (32 bytes) supplied instead of drawn from the RNG;
 * pass 32 zero bytes for the FIPS 204 deterministic variant */
EMSCRIPTEN_KEEPALIVE
int pqf_sig_sign_derand(const char *alg, const uint8_t *sk,
                        const uint8_t *msg, uint32_t msglen,
                        const uint8_t *ctx, uint32_t ctxlen,
                        const uint8_t *rnd, uint32_t rndlen,
                        uint8_t *sigout, uint32_t *siglen) {
    ensure_init();
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) return -1;
    size_t sl = *siglen;
    rng_begin(rnd, rndlen);
    OQS_STATUS s = OQS_SIG_sign_with_ctx_str(sig, sigout, &sl, msg, msglen, ctx, ctxlen, sk);
    int fault = rng_end();
    OQS_SIG_free(sig);
    if (s != OQS_SUCCESS) return -2;
    if (fault) return -3;
    *siglen = (uint32_t)sl;
    return 0;
}

EMSCRIPTEN_KEEPALIVE
int pqf_sig_verify(const char *alg, const uint8_t *pk,
                   const uint8_t *msg, uint32_t msglen,
                   const uint8_t *ctx, uint32_t ctxlen,
                   const uint8_t *sigin, uint32_t siglen) {
    ensure_init();
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) return -1;
    OQS_STATUS s = OQS_SIG_verify_with_ctx_str(sig, msg, msglen, sigin, siglen, ctx, ctxlen, pk);
    OQS_SIG_free(sig);
    return s == OQS_SUCCESS ? 0 : 1;
}

/* ---- misc ---- */

EMSCRIPTEN_KEEPALIVE
const char *pqf_liboqs_version(void) {
    return OQS_version();
}
