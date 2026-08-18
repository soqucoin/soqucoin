#!/bin/bash
set -uo pipefail
EX=/opt/lazer-extract; HEXL=/opt/lazer-pinned/third_party/hexl-development/build-v3/hexl/lib
KAT=/opt/lazer-evidence/task1-2026-08-17/src; OUT=/opt/lazer-evidence/option4-2026-08-17
BASE="-Wall -march=x86-64-v3 -maes -mtune=generic -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -ffunction-sections -fdata-sections -g"
run () {
  local tag="$1" cc="$2" opt="$3"
  command -v "$cc" >/dev/null || { printf "%-22s (compiler absent)\n" "$tag"; return; }
  cd "$EX"; rm -f src/*.o liblazer.a liblazer.so lazer.h
  make lib-static CC="$cc" CFLAGS="$BASE $opt" -j4 > "$OUT/cc-$tag.log" 2>&1 || { printf "%-22s BUILD FAILED\n" "$tag"; return; }
  cd "$KAT"
  $cc -O2 -std=c11 -g -static -ffunction-sections -fdata-sections -Wl,--gc-sections -I"$EX" -I. \
      -o /tmp/o4x/cc_$tag matstage.c soq_lbpp_wire.c -L"$EX" -L"$HEXL" -llazer -lhexl -lmpfr -lgmp -lm -lstdc++ 2>/dev/null \
      || { printf "%-22s LINK FAILED\n" "$tag"; return; }
  printf "%-22s %s\n" "$tag" "$(/tmp/o4x/cc_$tag | head -1 | awk '{print $NF}')"
}
run gcc13_O3   gcc-13   -O3
run gcc13_O2   gcc-13   -O2
run gcc14_O3   gcc-14   -O3
run gcc14_O2   gcc-14   -O2
run clang18_O3 clang-18 -O3
run clang18_O2 clang-18 -O2
