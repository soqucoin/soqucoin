#!/bin/bash
set -uo pipefail
EX=/opt/lazer-extract; HEXL=/opt/lazer-pinned/third_party/hexl-development/build-v3/hexl/lib
KAT=/opt/lazer-evidence/task1-2026-08-17/src; OUT=/opt/lazer-evidence/option4-2026-08-17
BASE="-Wall -Wextra -march=x86-64-v3 -maes -mtune=generic -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -ffunction-sections -fdata-sections -g"
run () {
  local tag="$1"; shift; local flags="$*"
  cd "$EX"; rm -f src/*.o liblazer.a liblazer.so lazer.h
  make lib-static CFLAGS="$BASE $flags" -j4 > "$OUT/cf-$tag.log" 2>&1 || { printf "%-26s BUILD FAILED\n" "$tag"; return; }
  cd "$KAT"
  gcc -O2 -std=c11 -g -static -ffunction-sections -fdata-sections -Wl,--gc-sections \
      -I"$EX" -I. -o /tmp/o4x/c_$tag matstage.c soq_lbpp_wire.c \
      -L"$EX" -L"$HEXL" -llazer -lhexl -lmpfr -lgmp -lm -lstdc++ 2>/dev/null
  gcc -O2 -std=c11 -g -static -ffunction-sections -fdata-sections -Wl,--gc-sections \
      -I"$EX" -I. -o /tmp/o4x/k_$tag kat_verify.c soq_lbpp_wire.c \
      -L"$EX" -L"$HEXL" -llazer -lhexl -lmpfr -lgmp -lm -lstdc++ 2>/dev/null
  local d g
  d=$(/tmp/o4x/c_$tag | head -1 | awk '{print $NF}')
  g=$(/tmp/o4x/k_$tag /opt/lazer-work/corpus/out 2>&1 | grep -cE "^  MISMATCH")
  printf "%-26s stage1=%s  mismatches=%s\n" "$tag" "$d" "$g"
}
echo "=== isolating the variable: -O level vs -fomit-frame-pointer ==="
run O3_fomit   -O3 -fomit-frame-pointer
run O3_nofomit -O3
run O2_fomit   -O2 -fomit-frame-pointer
run O2_nofomit -O2
run O1         -O1
run Os         -Os
