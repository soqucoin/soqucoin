#!/bin/bash
# Which FILE's -O2 codegen causes the divergence? The unity TU is compiled at -O2, but one
# file at a time is wrapped in #pragma GCC optimize("O3"). Whichever file restores the oracle
# digest owns the bug. This is mechanical and does not require guessing at the code.
set -uo pipefail
EX=/opt/lazer-extract; HEXL=/opt/lazer-pinned/third_party/hexl-development/build-v3/hexl/lib
KAT=/opt/lazer-evidence/task1-2026-08-17/src; OUT=/opt/lazer-evidence/option4-2026-08-17
BASE="-Wall -march=x86-64-v3 -maes -mtune=generic -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -ffunction-sections -fdata-sections -g -O2"
GOOD=d5b417375955cb07
CANDS="urandom.c rng.c aes256ctr-amd64.c aes256ctr.c shake128.c intvec.c int.c poly.c polymat.c coder.c"
cp -a "$EX/src" /tmp/src-pristine
for f in $CANDS; do
  cp -a /tmp/src-pristine/. "$EX/src/"
  python3 - "$f" <<'PY'
import sys
f = sys.argv[1]
p = "/opt/lazer-extract/src/" + f
s = open(p).read()
s = '#pragma GCC push_options\n#pragma GCC optimize ("O3")\n' + s + '\n#pragma GCC pop_options\n'
open(p, "w").write(s)
PY
  cd "$EX"; rm -f src/*.o liblazer.a liblazer.so lazer.h
  if ! make lib-static CFLAGS="$BASE" -j4 > "$OUT/fb-$f.log" 2>&1; then printf "%-22s BUILD FAILED\n" "$f"; continue; fi
  cd "$KAT"
  gcc -O2 -std=c11 -g -static -ffunction-sections -fdata-sections -Wl,--gc-sections -I"$EX" -I. \
      -o /tmp/o4x/fb_x matstage.c soq_lbpp_wire.c -L"$EX" -L"$HEXL" -llazer -lhexl -lmpfr -lgmp -lm -lstdc++ 2>/dev/null \
      || { printf "%-22s LINK FAILED\n" "$f"; continue; }
  d=$(/tmp/o4x/fb_x | head -1 | awk '{print $NF}' | sed 's/raw=//')
  v="still divergent"; [ "$d" = "$GOOD" ] && v="*** RESTORES ORACLE - THIS FILE OWNS IT ***"
  printf "%-22s %s  %s\n" "$f" "$d" "$v"
done
cp -a /tmp/src-pristine/. "$EX/src/"
