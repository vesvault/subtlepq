#!/bin/bash
#
# subtlepq wasm engine build: liboqs (dedicated minimal config) + shim
#
# (c) 2026 VESvault Corp
# SPDX-License-Identifier: Apache-2.0
#
# Reproducible given the pinned liboqs submodule and emsdk version below.
# Outputs:
#   dist/subtlepq-engine.mjs + dist/subtlepq-engine.wasm   (sidecar, CSP-clean)
#   dist/subtlepq-engine.single.mjs                      (wasm embedded base64)

set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
EMSDK="${EMSDK:-/usr/src/emsdk}"
cd "$EMSDK" && EMSDK_QUIET=1 source ./emsdk_env.sh >/dev/null 2>&1 && cd - >/dev/null

ALGS="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
BUILD="$ROOT/build-liboqs"

emcmake cmake -S "$ROOT/liboqs" -B "$BUILD" \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DOQS_MINIMAL_BUILD="$ALGS" \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_USE_OPENSSL=OFF \
    -DOQS_DIST_BUILD=OFF \
    -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON
cmake --build "$BUILD" -j"$(nproc)"

mkdir -p "$ROOT/dist"

CFLAGS="-Os -I$BUILD/include"
LDFLAGS="-Os -L$BUILD/lib -loqs \
    -sMODULARIZE -sEXPORT_ES6=1 -sEXPORT_NAME=SubtlePQEngine \
    -sEXPORTED_RUNTIME_METHODS=HEAPU8 \
    -sEXPORTED_FUNCTIONS=_malloc,_free \
    -sALLOW_MEMORY_GROWTH=1 -sSTACK_SIZE=1048576 \
    -sFILESYSTEM=0"

emcc $CFLAGS -c "$ROOT/subtlepq_engine.c" -o "$BUILD/subtlepq_engine.o"
emcc $LDFLAGS "$BUILD/subtlepq_engine.o" -o "$ROOT/dist/subtlepq-engine.mjs"
emcc $LDFLAGS -sSINGLE_FILE=1 "$BUILD/subtlepq_engine.o" -o "$ROOT/dist/subtlepq-engine.single.mjs"

ls -l "$ROOT/dist"
