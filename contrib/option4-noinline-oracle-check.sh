#!/bin/bash
# Precondition for pruning: with nh6m fixed, does the -fno-inline build now pass the gate?
# If it does not, it cannot serve as a reachability oracle and pruning must not proceed.
set -uo pipefail
EX=/opt/lazer-extract; HEXL=/opt/lazer-pinned/third_party/hexl-development/build-v3/hexl/lib
KAT=/opt/lazer-evidence/task1-2026-08-17/src; OUT=/opt/lazer-evidence/option4-2026-08-17
cp -a "$EX" /opt/lazer-extract.preprune 2>/dev/null && echo "backup: /opt/lazer-extract.preprune"
NOINL="-fno-inline -fno-inline-functions -fno-inline-small-functions -fno-inline-functions-called-once -fno-ipa-cp-clone"
CF="-Wall -Wextra -O2 -g -march=x86-64-v3 -maes -mtune=generic -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -ffunction-sections -fdata-sections $NOINL"
cd "$EX"; rm -f src/*.o liblazer.a liblazer.so lazer.h
make lib-static CFLAGS="$CF" -j4 > "$OUT/ni2-build.log" 2>&1 || { grep error: "$OUT/ni2-build.log"|head; exit 1; }
echo "liblazer (no-inline): $(stat -c%s liblazer.a)"
cd /tmp/o4x
LINKF="-O2 -std=c11 -g -static -I$EX -I. -L$EX -L$HEXL -llazer -lhexl -lmpfr -lgmp -lm -lstdc++"
gcc -fno-inline -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -Wl,--print-gc-sections -o kat_ni2 kat_verify.c soq_lbpp_wire.c $LINKF 2> /tmp/gc-noinline2.log
echo "=== GATE on the no-inline build (must pass, or pruning is off):"
./kat_ni2 /opt/lazer-work/corpus/out 2>&1 | tail -6
echo "=== discard list size:"
echo "  lazer_static.o .text sections discarded: $(grep 'removing unused section' /tmp/gc-noinline2.log | grep lazer_static.o | grep -c '\.text\.')"
echo "  (compare: the WRONG -O3 list had 244)"
