#!/bin/bash
# Root-cause nh6m. The divergence is NON-MONOTONIC (-O1 ok, -O2 wrong, -O3 ok), which is the
# signature of undefined behaviour rather than a deliberate opt-dependent path. Each flag below
# disables one UB-exploiting assumption. If adding it to -O2 restores the -O3 digest
# d5b417375955cb07, that names the UB class.
set -uo pipefail
EX=/opt/lazer-extract; HEXL=/opt/lazer-pinned/third_party/hexl-development/build-v3/hexl/lib
KAT=/opt/lazer-evidence/task1-2026-08-17/src; OUT=/opt/lazer-evidence/option4-2026-08-17
BASE="-Wall -march=x86-64-v3 -maes -mtune=generic -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -ffunction-sections -fdata-sections -g"
GOOD=d5b417375955cb07
probe () {
  local tag="$1"; shift; local flags="$*"
  cd "$EX"; rm -f src/*.o liblazer.a liblazer.so lazer.h
  make lib-static CFLAGS="$BASE $flags" -j4 > "$OUT/ub-$tag.log" 2>&1 || { printf "%-34s BUILD FAILED\n" "$tag"; return; }
  cd "$KAT"
  gcc -O2 -std=c11 -g -static -ffunction-sections -fdata-sections -Wl,--gc-sections -I"$EX" -I. \
      -o /tmp/o4x/ub_$tag matstage.c soq_lbpp_wire.c -L"$EX" -L"$HEXL" -llazer -lhexl -lmpfr -lgmp -lm -lstdc++ 2>/dev/null \
      || { printf "%-34s LINK FAILED\n" "$tag"; return; }
  local d; d=$(/tmp/o4x/ub_$tag | head -1 | awk '{print $NF}' | sed 's/raw=//')
  local v="DIVERGENT"; [ "$d" = "$GOOD" ] && v="matches -O3  <-- IMPLICATED"
  printf "%-34s %s  %s\n" "$tag" "$d" "$v"
}
echo "=== baselines"
probe O3_reference            -O3
probe O2_reference            -O2
echo "=== UB-class probes, each added to -O2"
probe O2_no_strict_aliasing   -O2 -fno-strict-aliasing
probe O2_fwrapv               -O2 -fwrapv
probe O2_no_strict_overflow   -O2 -fno-strict-overflow
probe O2_no_vectorize         -O2 -fno-tree-vectorize -fno-tree-slp-vectorize
probe O2_no_ipa               -O2 -fno-ipa-cp -fno-ipa-sra -fno-ipa-modref
probe O2_no_loop_distribute   -O2 -fno-tree-loop-distribute-patterns
probe O2_no_gcse              -O2 -fno-gcse -fno-gcse-after-reload
probe O2_all_conservative     -O2 -fno-strict-aliasing -fwrapv -fno-strict-overflow
