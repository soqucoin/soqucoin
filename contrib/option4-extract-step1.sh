#!/bin/bash
# STEP 3 of the option-4 plan, first subtraction: remove the ENTIRELY DEAD files.
#
# Measured by --gc-sections + DWARF attribution (contrib/option4-analyze.py): these 11 of
# the 33 files that src/lazer.c #includes contribute ZERO reachable function bodies on the
# verify path, totalling 7,920 LOC. 10 of the 11 are removable as pure subtraction; the
# 11th (stopwatch.c) is not, see below. No soundness judgement is involved either way,
# which is exactly why this is the right first step.
#
# The mechanism that makes it possible: prover entry points live in the same unity object
# and reference the removed prover files, but --gc-sections discards unreferenced sections
# BEFORE their relocations need resolving, so the link succeeds without them.
#
# ⭐ THE GATE IS THE WHOLE POINT. 64/64 after subtraction, or the subtraction is wrong.
#
# ⛔ DO NOT ADD `make clean` - bead hexl-patches-lost-on-clean-6joj.
set -euo pipefail

SRC=/opt/lazer-pinned
EX=/opt/lazer-extract
HEXL=$SRC/third_party/hexl-development/build-v3/hexl/lib
KAT=/opt/lazer-evidence/task1-2026-08-17/src
CORPUS=/opt/lazer-work/corpus/out
OUT=/opt/lazer-evidence/option4-2026-08-17

# stopwatch.c is DELIBERATELY RETAINED. It has zero reachable function bodies, but
# lin-proofs.c references its stopwatch_* globals through the STOPWATCH_START/STOP macros
# at COMPILE time, so removing the source breaks the build even though the linker discards
# all of its code. Unreachable at link time is NOT the same as removable at source level.
# Removing it needs the macros neutered first, which is a behaviour change, not subtraction.
DEAD="blindsig.c bytes.c dump.c grandom.c lnp-quad-eval.c lnp-tbox.c lnp.c polyring.c rejection.c version.c"

echo "############ guard: portable HEXL"
ZMM=$(objdump -d "$HEXL/libhexl.a" 2>/dev/null | grep -cE '%zmm' || true)
[ "$ZMM" = "0" ] || { echo "FATAL: unpatched HEXL ($ZMM zmm)"; exit 1; }
echo "ok, 0 %zmm"

echo "############ copy"
rm -rf "$EX"
cp -a "$SRC" "$EX"
cd "$EX"

echo "############ baseline LOC"
BEFORE=$(cd src && wc -l $(grep -oE '"[A-Za-z0-9._/-]+\.c"' lazer.c | tr -d '"') | tail -1 | awk '{print $1}')
echo "unity LOC before: $BEFORE"

echo "############ drop the 11 dead #includes from src/lazer.c"
python3 - <<PY
dead = "$DEAD".split()
p = "src/lazer.c"
src = open(p).read().split("\n")
out, dropped = [], []
for line in src:
    s = line.strip()
    if s.startswith('#include "') and s.endswith('"'):
        name = s[len('#include "'):-1]
        if name in dead:
            dropped.append(name)
            out.append("/* REMOVED by option-4 extraction: zero reachable function bodies")
            out.append(" * on the verify path, proven by --gc-sections. was: " + s + " */")
            continue
    out.append(line)
missing = set(dead) - set(dropped)
if missing:
    raise SystemExit("FATAL: these dead files were not found in lazer.c: " + ", ".join(sorted(missing)))
open(p, "w").write("\n".join(out))
print("dropped %d includes: %s" % (len(dropped), " ".join(dropped)))
PY

echo "############ drop them from the Makefile's LIBSOURCES too"
# They are prerequisites of src/lazer_static.o, so deleting the files without editing
# LIBSOURCES fails with "No rule to make target 'src/blindsig.c'".
python3 - <<PY
dead = set("$DEAD".split())
p = "Makefile"
out, dropped = [], []
for line in open(p).read().split("\n"):
    s = line.strip()
    # LIBSOURCES entries look like: " src/blindsig.c \\"
    if s.startswith("src/") and s.rstrip(" \\\\").split("/")[-1] in dead:
        dropped.append(s.rstrip(" \\\\"))
        continue
    out.append(line)
open(p, "w").write("\n".join(out))
print("dropped %d Makefile prerequisites" % len(dropped))
for d in dropped:
    print("   " + d)
PY

echo "############ add the includes the unity build was hiding"
# ⭐ A REAL FINDING, not a workaround. lin-proofs.c uses stopwatch_* symbols but never
# includes stopwatch.h - it relied on blindsig.c, included 10 lines earlier in the unity
# file, to declare them. Remove blindsig.c and lin-proofs.c stops compiling. A unity build
# hides missing includes, so any extraction has to restore them. Mechanical, but real work,
# and invisible until you try it.
python3 - <<'PY2'
p = "src/lin-proofs.c"
s = open(p).read()
if '#include "stopwatch.h"' in s:
    print("  lin-proofs.c already includes stopwatch.h")
else:
    anchor = '#include "memory.h"'
    if anchor not in s:
        raise SystemExit("FATAL: cannot find an include anchor in lin-proofs.c")
    s = s.replace(anchor, anchor + '\n#include "stopwatch.h" /* option-4: was arriving via blindsig.c in the unity build */', 1)
    open(p, "w").write(s)
    print("  added stopwatch.h to lin-proofs.c")
PY2

echo "############ physically delete the dropped sources so nothing can silently use them"
cd src && rm -f $DEAD && cd ..
echo "remaining unity sources: $(grep -cE '^#include "' src/lazer.c)"

echo "############ rebuild with per-function sections"
rm -f src/*.o liblazer.a liblazer.so lazer.h
CF="-Wall -Wextra -O3 -g -march=x86-64-v3 -maes -mtune=generic -fomit-frame-pointer"
CF="$CF -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -ffunction-sections -fdata-sections"
if ! make lib-static CFLAGS="$CF" -j4 > "$OUT/extract-build.log" 2>&1; then
  echo "=== BUILD FAILED. First errors:"
  grep -E "error:|undefined reference" "$OUT/extract-build.log" | head -25
  echo "=== (full log: $OUT/extract-build.log)"
  exit 1
fi
echo "liblazer.a: $(stat -c%s liblazer.a) bytes, $(ar t liblazer.a | wc -l) members"

echo "############ link the KAT harness with --gc-sections"
rm -rf /tmp/o4x && mkdir -p /tmp/o4x && cd /tmp/o4x
cp "$KAT"/kat_verify.c "$KAT"/soq_lbpp_wire.c "$KAT"/soq_lbpp_wire.h \
   "$KAT"/soq_lbpp_static_asserts.h "$KAT"/degen-witness-vs-lazer.c .
cp -r "$KAT"/params . 2>/dev/null || true
LINKF="-O2 -std=c11 -g -static -I$EX -I. -L$EX -L$HEXL -llazer -lhexl -lmpfr -lgmp -lm -lstdc++"
# shellcheck disable=SC2086
if ! gcc -ffunction-sections -fdata-sections -Wl,--gc-sections \
     -o kat_x kat_verify.c soq_lbpp_wire.c $LINKF 2> "$OUT/extract-link.log"; then
  echo "=== LINK FAILED:"; grep -E "undefined reference" "$OUT/extract-link.log" | head -25; exit 1
fi
echo "kat_x: $(stat -c%s kat_x) bytes"

echo "############ ⭐ THE GATE"
./kat_x "$CORPUS" 2>&1 | tail -7 | tee "$OUT/gate-extract.txt"

echo "############ and the degenerate-witness probe must still reject everything"
# shellcheck disable=SC2086
gcc -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -o degen_x degen-witness-vs-lazer.c soq_lbpp_wire.c $LINKF
./degen_x "$CORPUS" 2>/dev/null | tail -5 | tee "$OUT/degen-extract.txt"

echo "############ LOC accounting"
AFTER=$(cd "$EX/src" && wc -l $(grep -oE '"[A-Za-z0-9._/-]+\.c"' lazer.c | tr -d '"') | tail -1 | awk '{print $1}')
echo "unity LOC before: $BEFORE"
echo "unity LOC after:  $AFTER"
echo "removed:          $((BEFORE - AFTER))"
echo "DONE. tree at $EX"
