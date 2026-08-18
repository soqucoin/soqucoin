#!/bin/bash
# Iterate pruning to a fixpoint. Each round: rebuild no-inline, VERIFY THE GATE on that build
# (it is the reachability oracle, so it must be sound), regenerate the discard list, prune,
# rebuild at the shipping flags, and re-verify gate + degenerate soundness.
set -uo pipefail
EX=/opt/lazer-extract; HEXL=/opt/lazer-pinned/third_party/hexl-development/build-v3/hexl/lib
KAT=/opt/lazer-evidence/task1-2026-08-17/src; OUT=/opt/lazer-evidence/option4-2026-08-17
NOINL="-fno-inline -fno-inline-functions -fno-inline-small-functions -fno-inline-functions-called-once -fno-ipa-cp-clone"
NIF="-Wall -Wextra -O2 -g -march=x86-64-v3 -maes -mtune=generic -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -ffunction-sections -fdata-sections $NOINL"
SHIP="-Wall -Wextra -O3 -g -march=x86-64-v3 -maes -mtune=generic -fomit-frame-pointer -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -ffunction-sections -fdata-sections"
LINKF="-O2 -std=c11 -g -static -I$EX -I. -L$EX -L$HEXL -llazer -lhexl -lmpfr -lgmp -lm -lstdc++"

for R in 2 3 4; do
  echo "================ ROUND $R"
  cp -a "$EX" "/opt/lazer-extract.r$R" 2>/dev/null
  cd "$EX"; rm -f src/*.o liblazer.a liblazer.so lazer.h
  make lib-static CFLAGS="$NIF" -j4 > "$OUT/it$R-ni.log" 2>&1 || { echo "no-inline build failed"; grep error: "$OUT/it$R-ni.log"|head -5; exit 1; }
  cd /tmp/o4x
  gcc -fno-inline -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--print-gc-sections \
      -o kat_it$R kat_verify.c soq_lbpp_wire.c $LINKF 2> /tmp/gc-it$R.log || { echo "no-inline link failed"; exit 1; }
  g=$(./kat_it$R /opt/lazer-work/corpus/out 2>&1 | tail -1)
  echo "  oracle build gate: $g"
  [ "$g" = "KAT-GATE-PASSED" ] || { echo "  !! oracle build does not pass; stopping"; exit 1; }
  n=$(grep 'removing unused section' /tmp/gc-it$R.log | grep lazer_static.o | grep -c '\.text\.')
  echo "  discard list: $n"
  python3 /root/prune_ni.py /tmp/gc-it$R.log "$EX" "$OUT/prune-ni-round$R.json" 2>&1 | tail -4
  removed=$(python3 -c "import json;print(json.load(open('$OUT/prune-ni-round$R.json'))['total'])")
  if [ "$removed" -eq 0 ]; then echo "  FIXPOINT REACHED (nothing left to prune)"; break; fi
  cd "$EX"; rm -f src/*.o liblazer.a liblazer.so lazer.h
  make lib-static CFLAGS="$SHIP" -j4 > "$OUT/it$R-ship.log" 2>&1 || { echo "  !! ship build failed"; grep error: "$OUT/it$R-ship.log"|head -8; exit 2; }
  cd /tmp/o4x
  gcc -ffunction-sections -fdata-sections -Wl,--gc-sections -o kat_s$R kat_verify.c soq_lbpp_wire.c $LINKF 2> "$OUT/it$R-link.log" || { echo "  !! ship link failed"; grep "undefined reference" "$OUT/it$R-link.log"|head -8; exit 3; }
  echo "  ship gate: $(./kat_s$R /opt/lazer-work/corpus/out 2>&1 | tail -1)"
  cd "$EX/src"; echo "  LOC now: $(wc -l $(grep -E '^#include "' lazer.c | grep -oE '"[A-Za-z0-9._/-]+\.c"' | tr -d '"') | tail -1 | awk '{print $1}')"
done
