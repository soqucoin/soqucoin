#!/bin/bash
# Option 4 costing measurement: what is the TRUE reachable subset of liblazer on the
# SoquObscura verify path, measured at FUNCTION granularity rather than archive-member
# granularity, and how many source lines does it correspond to?
#
# Why this exists: DL-SOQUOBSCURA-P5-PORT-BRIEF.md records that liblazer.a is 12 coarse
# object files and all 12 are pulled in, therefore "no archive-level trim is available."
# True, but it is the wrong granularity. src/lazer.c is an 83-line unity file that
# #includes 33 separate .c files, so the real question is which of those 33 files, and
# which functions inside them, actually execute. -ffunction-sections + --gc-sections
# answers it by construction: the linker discards whatever nothing reaches.
#
# The gate is non-negotiable: a trimmed build that does not still return 64/64 pinned
# verdicts has measured nothing.
#
# ⛔ DO NOT ADD `make clean` TO THIS SCRIPT. The LaZer clean target recursively deletes
#    third_party/hexl-development, the next build re-unzips pristine upstream, and BOTH
#    HEXL portability patches are silently lost -> 107,960 %zmm instructions and a binary
#    that SIGILLs on 6 of 8 fleet nodes. Bead: hexl-patches-lost-on-clean-6joj.
set -euo pipefail

SRC=/opt/lazer-pinned
GC=/opt/lazer-gc
# The patched, verified-portable HEXL. Taken from the PINNED tree and never rebuilt here,
# precisely because rebuilding it is how the patches get lost.
HEXL=$SRC/third_party/hexl-development/build-v3/hexl/lib
KAT=/opt/lazer-evidence/task1-2026-08-17/src
CORPUS=/opt/lazer-work/corpus/out
OUT=/opt/lazer-evidence/option4-2026-08-17
mkdir -p "$OUT"

echo "############ STEP 0: guard - is the libhexl we are about to link actually portable?"
ZMM=$(objdump -d "$HEXL/libhexl.a" 2>/dev/null | grep -cE '%zmm' || true)
echo "libhexl: $HEXL/libhexl.a"
echo "%zmm instructions (MUST be 0): $ZMM"
if [ "$ZMM" != "0" ]; then echo "FATAL: unpatched HEXL, refusing to proceed"; exit 1; fi

echo "############ STEP 1: fresh copy so the working build is untouched"
rm -rf "$GC"
cp -a "$SRC" "$GC"
cd "$GC"

echo "############ STEP 2: rebuild ONLY liblazer, with per-function sections"
# Targeted object removal instead of `make clean` - see the banner above.
rm -f src/*.o liblazer.a liblazer.so lazer.h
# CFLAGS is overridden wholesale on the command line, so it must reproduce
# CFLAGS_DEFAULT + CFLAGS_FALCON_AMD64 exactly, plus the two section flags.
CF="-Wall -Wextra -O3 -g -march=x86-64-v3 -maes -mtune=generic -fomit-frame-pointer"
CF="$CF -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA"
CF="$CF -ffunction-sections -fdata-sections"
make lib-static CFLAGS="$CF" -j4 > "$OUT/build.log" 2>&1 || { tail -40 "$OUT/build.log"; exit 1; }
echo "liblazer.a: $(stat -c%s liblazer.a) bytes, $(ar t liblazer.a | wc -l) members"

echo "############ STEP 3: link twice, with and without --gc-sections"
rm -rf /tmp/o4 && mkdir -p /tmp/o4 && cd /tmp/o4
cp "$KAT"/kat_verify.c "$KAT"/soq_lbpp_wire.c "$KAT"/soq_lbpp_wire.h \
   "$KAT"/soq_lbpp_static_asserts.h .
cp -r "$KAT"/params . 2>/dev/null || true

LINKF="-O2 -std=c11 -g -static -I$GC -I. -L$GC -L$HEXL -llazer -lhexl -lmpfr -lgmp -lm -lstdc++"
# shellcheck disable=SC2086
gcc -o kat_nogc  kat_verify.c soq_lbpp_wire.c $LINKF
# shellcheck disable=SC2086
gcc -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -Wl,-Map="$OUT/gc.map" -Wl,--print-gc-sections \
    -o kat_gcsec kat_verify.c soq_lbpp_wire.c $LINKF 2> "$OUT/gc-discarded.log"
stat -c "%n %s bytes" kat_nogc kat_gcsec
echo "sections the linker DISCARDED: $(grep -c 'removing unused section' "$OUT/gc-discarded.log" || true)"

echo "############ STEP 4: THE GATE. A trim that breaks this has measured nothing."
./kat_gcsec "$CORPUS" 2>&1 | tail -8 | tee "$OUT/gate-gcsec.txt"

echo "############ STEP 5: dump symbols + DWARF line tables for attribution"
for b in kat_nogc kat_gcsec; do
  nm -S --defined-only "$b" 2>/dev/null | awk '$4=="" {next} {print}' > "$OUT/$b.nm" || true
  nm -S --defined-only "$b" 2>/dev/null > "$OUT/$b.nm"
  objdump --dwarf=decodedline "$b" > "$OUT/$b.lines" 2>/dev/null
  cp "$b" "$OUT/$b"
done
wc -l "$OUT"/kat_nogc.nm "$OUT"/kat_gcsec.nm

echo "############ STEP 6: baseline LOC of the 33 unity-included files"
cd "$GC"
grep -oE '"[A-Za-z0-9._/-]+\.c"' src/lazer.c | tr -d '"' > "$OUT/unity-files.txt"
( cd src && wc -l $(cat "$OUT/unity-files.txt") ) > "$OUT/unity-loc.txt" 2>&1 || true
tail -4 "$OUT/unity-loc.txt"
echo "DONE. Artifacts in $OUT"
