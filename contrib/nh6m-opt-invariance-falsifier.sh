#!/bin/bash
# FALSIFIER for bead statement-matrix-opt-level-divergence-nh6m.
#
# Asserts that the statement matrix derived from PUBSEED is IDENTICAL across optimisation
# levels and compilers. Red before the fix (three distinct digests, two configs rejecting every
# honest proof); green after.
#
# Root cause: aes256ctr-amd64.c _aes256ctr_init punned 64-bit loads/stores over uint8_t[16],
# a strict-aliasing violation. GCC at -O2/-Os exploited it, corrupting the AES-CTR nonce and
# therefore every byte of seed-derived public data.
set -uo pipefail
EX=${1:-/opt/lazer-extract}
HEXL=/opt/lazer-pinned/third_party/hexl-development/build-v3/hexl/lib
KAT=/opt/lazer-evidence/task1-2026-08-17/src
BASE="-Wall -march=x86-64-v3 -maes -mtune=generic -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -ffunction-sections -fdata-sections -g"
declare -a DIGESTS=()
fail=0
for cfg in "gcc-13:-O1" "gcc-13:-O2" "gcc-13:-O3" "gcc-13:-Os" "gcc-14:-O2" "gcc-14:-O3" "clang-18:-O2" "clang-18:-O3"; do
  cc="${cfg%%:*}"; opt="${cfg##*:}"
  command -v "$cc" >/dev/null || { printf "%-18s SKIP (compiler absent)\n" "$cc $opt"; continue; }
  cd "$EX"; rm -f src/*.o liblazer.a liblazer.so lazer.h
  make lib-static CC="$cc" CFLAGS="$BASE $opt" -j4 > /tmp/nh6m-$cc$opt.log 2>&1 \
    || { printf "%-18s BUILD FAILED\n" "$cc $opt"; fail=1; continue; }
  cd "$KAT"
  "$cc" -O2 -std=c11 -g -static -ffunction-sections -fdata-sections -Wl,--gc-sections -I"$EX" -I. \
      -o /tmp/nh6m_probe matstage.c soq_lbpp_wire.c -L"$EX" -L"$HEXL" -llazer -lhexl -lmpfr -lgmp -lm -lstdc++ 2>/dev/null \
    || { printf "%-18s LINK FAILED\n" "$cc $opt"; fail=1; continue; }
  d=$(/tmp/nh6m_probe | head -1 | awk '{print $NF}' | sed 's/raw=//')
  DIGESTS+=("$d")
  printf "%-18s %s\n" "$cc $opt" "$d"
done
uniq_count=$(printf "%s\n" "${DIGESTS[@]}" | sort -u | wc -l)
echo
if [ "$uniq_count" -eq 1 ] && [ "$fail" -eq 0 ]; then
  echo "PASS: one digest across every configuration ($uniq_count distinct)"
  exit 0
fi
echo "FAIL: $uniq_count distinct digests across configurations - public-data derivation is not"
echo "      optimisation-invariant, which is a chain-split class defect."
printf "%s\n" "${DIGESTS[@]}" | sort | uniq -c
exit 1
