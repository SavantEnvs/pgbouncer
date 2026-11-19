#!/usr/bin/env bash
#
# mayhem/build.sh — build pgbouncer's fuzz harnesses and its C test (hba_test).
#
# Runs inside the commit image as `mayhem` in /mayhem (re-runnable, offline). The project is built
# with upstream's own autotools/antimake build: `make pgbouncer` compiles every src/ and vendored
# lib/usual object with $SANITIZER_FLAGS $DEBUG_FLAGS and SanitizerCoverage (-fsanitize=fuzzer-no-link).
# Each libFuzzer harness in mayhem/harnesses/ #includes src/main.c (main renamed) and links against
# those objects (minus main.o), once with $LIB_FUZZING_ENGINE and once with $STANDALONE_FUZZ_MAIN.
# fuzz_config is a raw file-input program over a plain sanitized (no SanCov) build of the same sources.
# The test oracle is upstream's own: test/hba_test (built by upstream's test/Makefile with its normal
# flags) and the pytest suite, which runs a separate normal-flags pgbouncer (mayhem/.work/test/pgbouncer).
# Everything is configured with --enable-cassert, as upstream CI does, so pgbouncer's Assert() is live.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"

# 1) configure once (generated files are gitignored upstream; a cleaned tree re-runs this).
#    Configure with the project's normal CFLAGS: those are what test/hba_test gets.
if [ ! -f config.mak ] || [ ! -x configure ]; then
  ./autogen.sh
  CFLAGS="-O2 -g $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" ./configure \
    --enable-cassert --without-cares --without-pam --without-ldap --without-systemd
fi

# 1b) the normal-flags pgbouncer the pytest suite runs (BOUNCER_EXE in mayhem/test.sh). Antimake does
#     not track CFLAGS, so .objs/pgbouncer is cleared before and after: this build and the fuzz build
#     below each compile every object fresh.
TEST_BIN_DIR="$SRC/mayhem/.work/test"
rm -rf .objs/pgbouncer pgbouncer
make -j"$MAYHEM_JOBS" pgbouncer
mkdir -p "$TEST_BIN_DIR"
cp pgbouncer "$TEST_BIN_DIR/pgbouncer"
rm -rf .objs/pgbouncer pgbouncer

# 2) the sanitized + coverage-instrumented pgbouncer (all objects under .objs/pgbouncer/)
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
make -j"$MAYHEM_JOBS" pgbouncer CFLAGS="$FUZZ_CFLAGS" LDFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"

mapfile -t OBJS < <(find .objs/pgbouncer -name '*.o' ! -path '.objs/pgbouncer/src/main.o' | LC_ALL=C sort)
LIBS="-levent -lssl -lcrypto -lm"
WORK="$SRC/mayhem/.work"
mkdir -p "$WORK"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$WORK/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$WORK/standalone_main.o"

# libFuzzer targets (in-process; see mayhem/harnesses/pgb_fuzz.h)
TARGETS="client_login client_session server_login admin hba auth_file"
for t in $TARGETS; do
  $CC $FUZZ_CFLAGS -DHAVE_CONFIG_H -Iinclude -Ilib -Wno-unused-function \
      -c "$SRC/mayhem/harnesses/fuzz_$t.c" -o "$WORK/fuzz_$t.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$WORK/fuzz_$t.o" "${OBJS[@]}" \
      "$WORK/lsan_off.o" $LIBS -o "$SRC/fuzz_$t"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$WORK/standalone_main.o" "$WORK/fuzz_$t.o" "${OBJS[@]}" \
      "$WORK/lsan_off.o" $LIBS -o "$SRC/fuzz_$t-standalone"
done

# 2b) the config target is a raw file-input program (pgbouncer exits on a config it cannot load,
#     like the daemon does). It gets its own plain sanitized build of the same sources, with NO
#     compile-time AFL/SanCov instrumentation: Mayhem instruments a raw ELF itself, and an
#     afl-clang-fast build of this target recorded 0 edges in Mayhem.
RAW_DIR="$WORK/raw"
mkdir -p "$RAW_DIR"
RAW_OBJS=()
for o in "${OBJS[@]}"; do
  rel="${o#.objs/pgbouncer/}"
  RAW_OBJS+=("$RAW_DIR/${rel//\//_}")
done
printf '%s\n' "${OBJS[@]}" | CC="$CC" xargs -P "$MAYHEM_JOBS" -I{} sh -c '
  o="{}"; rel="${o#.objs/pgbouncer/}"; src="${rel%.o}.c"; out="$0/$(echo "$rel" | tr / _)"
  exec $CC $SANITIZER_FLAGS $DEBUG_FLAGS -DHAVE_CONFIG_H -Iinclude -Ilib -w -c "$src" -o "$out"
' "$RAW_DIR"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -DHAVE_CONFIG_H -Iinclude -Ilib -Wno-unused-function \
    -c "$SRC/mayhem/harnesses/fuzz_config.c" -o "$RAW_DIR/fuzz_config.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$RAW_DIR/fuzz_config.o" "${RAW_OBJS[@]}" \
    "$WORK/lsan_off.o" $LIBS -o "$SRC/fuzz_config"

# 3) upstream's C test (test/Makefile: hba_test from test/hba_test.c + src/hba.c + src/util.c),
#    normal flags, own object dir (test/.objs).
make -C test -j"$MAYHEM_JOBS" hba_test
