#!/usr/bin/env bash
# Compile and run all QAT benchmarks:
#   CY: RSA-2048 encrypt, RSA-2048 decrypt, AES-128-CBC cipher,
#       SHA-256 hash, DH-1024 Phase 1, 512-bit primality test
#   DC: Deflate compress + decompress
#   JNI: RSA-2048 encrypt via Java JNI
#
# Must be run from any directory; paths are resolved relative to this script.
# QAT requires root, so the run steps use sudo.

set -euo pipefail

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- helpers ----------------------------------------------------------------

log()  { echo "[bench] $*"; }
die()  { echo "[bench] ERROR: $*" >&2; exit 1; }

compile_c() {
    local src="$1" out="$2" extra_libs="${3:-}"
    log "Compiling $(basename "$src") ..."
    gcc -O2 \
        -o "$out" \
        "$src" \
        -I/usr/include/qat \
        -lqat -lusdm -lpthread $extra_libs \
        || die "gcc failed for $src"
    log "  -> $out"
}

run_bench() {
    local bin="$1" label="$2"
    log ""
    log "========================================================="
    log " $label"
    log "========================================================="
    sudo "$bin"
}

# ---- 1. CY benchmarks -------------------------------------------------------

compile_c "$BENCH_DIR/bench_rsa_native.c"   "$BENCH_DIR/bench_rsa_native"
compile_c "$BENCH_DIR/bench_rsa_decrypt.c"  "$BENCH_DIR/bench_rsa_decrypt"
compile_c "$BENCH_DIR/bench_sym_cipher.c"   "$BENCH_DIR/bench_sym_cipher"
compile_c "$BENCH_DIR/bench_sym_hash.c"     "$BENCH_DIR/bench_sym_hash"
compile_c "$BENCH_DIR/bench_dh.c"           "$BENCH_DIR/bench_dh"
compile_c "$BENCH_DIR/bench_prime.c"        "$BENCH_DIR/bench_prime"

# ---- 2. DC benchmark --------------------------------------------------------

compile_c "$BENCH_DIR/bench_dc_deflate.c"   "$BENCH_DIR/bench_dc_deflate"

# ---- 3. Java JNI benchmark --------------------------------------------------

# javac requires the source file to live under a directory tree that matches
# the package (com/lehigh/qat/).  We copy it there, compile against the
# QatRsa.class already built in the parent directory, then output classes
# back into the bench directory.

PKG_SRC="$BENCH_DIR/com/lehigh/qat"
mkdir -p "$PKG_SRC"
cp "$BENCH_DIR/RsaJniBenchmark.java" "$PKG_SRC/RsaJniBenchmark.java"

log "Compiling RsaJniBenchmark.java ..."
javac \
    -cp "$BENCH_DIR" \
    -d  "$BENCH_DIR" \
    "$PKG_SRC/RsaJniBenchmark.java" \
    || die "javac failed"
log "  -> $BENCH_DIR/com/lehigh/qat/RsaJniBenchmark.class"

# ---- 4. Run all benchmarks --------------------------------------------------

run_bench "$BENCH_DIR/bench_rsa_native"   "RSA-2048 encrypt (CY, pure C)"
run_bench "$BENCH_DIR/bench_rsa_decrypt"  "RSA-2048 decrypt (CY, pure C)"
run_bench "$BENCH_DIR/bench_sym_cipher"   "AES-128-CBC encrypt (CY, pure C)"
run_bench "$BENCH_DIR/bench_sym_hash"     "SHA-256 hash (CY, pure C)"
run_bench "$BENCH_DIR/bench_dh"           "DH-1024 Phase 1 (CY, pure C)"
run_bench "$BENCH_DIR/bench_prime"        "512-bit primality test (CY, pure C)"
run_bench "$BENCH_DIR/bench_dc_deflate"   "Deflate compress+decompress (DC, pure C)"

log ""
log "========================================================="
log " RSA-2048 encrypt (JNI benchmark)"
log "========================================================="
# library path points to the parent dir where libqatrsa.so lives;
# classpath includes both the parent (QatRsa.class) and bench dir
# (RsaJniBenchmark.class).
sudo java \
    -Djava.library.path="$BENCH_DIR" \
    -cp "$BENCH_DIR" \
    com.lehigh.qat.RsaJniBenchmark
