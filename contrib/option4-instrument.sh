#!/bin/bash
# STEP 1 of the option-4 plan: establish WHICH check rejects each degenerate mutant.
#
# The previous probe proved LaZer rejects every degenerate witness tested, but not where.
# That distinction matters: if the mutants die at lnp_tbox_decproof on canonicality, the
# probe never exercised the soundness path and says nothing about poly_eq(c, c2).
#
# Upstream left diagnostics at every reject site, commented out. Instrumenting is therefore
# uncommenting them, not inventing anything - which keeps the instrumented build faithful.
#
# ⛔ DO NOT ADD `make clean`. It recursively deletes third_party/hexl-development, the next
#    build re-unzips pristine upstream, and both portability patches are silently lost
#    (0 -> 107,960 %zmm). Bead hexl-patches-lost-on-clean-6joj.
set -euo pipefail

SRC=/opt/lazer-pinned
INSTR=/opt/lazer-instr
HEXL=$SRC/third_party/hexl-development/build-v3/hexl/lib
OUT=/opt/lazer-evidence/option4-2026-08-17

echo "############ guard: portable HEXL"
ZMM=$(objdump -d "$HEXL/libhexl.a" 2>/dev/null | grep -cE '%zmm' || true)
echo "%zmm in libhexl.a (MUST be 0): $ZMM"
[ "$ZMM" = "0" ] || { echo "FATAL: unpatched HEXL"; exit 1; }

echo "############ copy"
rm -rf "$INSTR"
cp -a "$SRC" "$INSTR"
cd "$INSTR"

echo "############ uncomment the reject-site diagnostics"
python3 - <<'PY'
import re

# (file, anchor substring, label) - the anchor is upstream's own commented diagnostic.
SITES = [
    ("src/lin-proofs.c", "lnp_tbox_decproof failed",        "DECPROOF"),
    ("src/lin-proofs.c", "_lnp_tbox_verify failed",         "TBOX_VERIFY"),
    ("src/lin-proofs.c", "z3, z4 norm bound check failed",  "Z34_NORM"),
    ("src/lnp-quad.c",   "recovering challenge failed",     "CHALLENGE_POLY_EQ"),
    ("src/lnp-quad.c",   "z1 norm bound check failed",      "Z1_NORM"),
    ("src/lnp-quad.c",   "h norm bound check failed",       "H_LINF"),
]

# handled separately: lnp-quad.c has a bare "norm bound check failed." for the w1 bound,
# which is a substring of the z1 one, so it must be matched by exact line.
patched = {}
for path, anchor, label in SITES:
    src = patched.get(path) or open(path).read()
    out_lines = []
    hits = 0
    for line in src.split("\n"):
        s = line.strip()
        if s.startswith("//printf") and anchor in line:
            indent = line[:len(line) - len(line.lstrip())]
            out_lines.append(f'{indent}fprintf(stderr, "SOQ_REJECT_SITE={label}\\n");')
            hits += 1
        else:
            out_lines.append(line)
    if hits == 0:
        raise SystemExit(f"FATAL: anchor not found: {path} :: {anchor}")
    patched[path] = "\n".join(out_lines)
    print(f"  {label:<20} {path}  ({hits} site)")

# the w1 bound: the remaining commented printf in lnp-quad.c whose text is exactly
# "norm bound check failed." with no qualifier
p = "src/lnp-quad.c"
src = patched[p]
out_lines, hits = [], 0
for line in src.split("\n"):
    s = line.strip()
    if s.startswith("//printf") and "norm bound check failed" in line and "z1" not in line and "h " not in line:
        indent = line[:len(line) - len(line.lstrip())]
        out_lines.append(f'{indent}fprintf(stderr, "SOQ_REJECT_SITE=W1_BOUND\\n");')
        hits += 1
    else:
        out_lines.append(line)
if hits != 1:
    raise SystemExit(f"FATAL: expected exactly 1 W1_BOUND site, found {hits}")
patched[p] = "\n".join(out_lines)
print(f"  {'W1_BOUND':<20} {p}  ({hits} site)")

for path, text in patched.items():
    if "stdio.h" not in text.split("\n")[0:40] and "#include <stdio.h>" not in text:
        text = "#include <stdio.h>\n" + text
    open(path, "w").write(text)
print("patched OK")
PY

echo "############ rebuild liblazer only (targeted object removal, NOT make clean)"
rm -f src/*.o liblazer.a liblazer.so lazer.h
CF="-Wall -Wextra -O3 -g -march=x86-64-v3 -maes -mtune=generic -fomit-frame-pointer"
CF="$CF -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA"
make lib-static CFLAGS="$CF" -j4 > "$OUT/instr-build.log" 2>&1 \
  || { tail -30 "$OUT/instr-build.log"; exit 1; }
echo "liblazer.a: $(stat -c%s liblazer.a) bytes"

echo "############ build the degenerate probe against the instrumented lib"
cd /opt/lazer-evidence/task1-2026-08-17/src
gcc -O2 -std=c11 -g -static -I"$INSTR" -I. -o /tmp/o4/degen_instr \
    degen-witness-vs-lazer.c soq_lbpp_wire.c \
    -L"$INSTR" -L"$HEXL" -llazer -lhexl -lmpfr -lgmp -lm -lstdc++
echo "built /tmp/o4/degen_instr"

echo "############ sanity: the instrumented lib must STILL pass the real gate 64/64"
gcc -O2 -std=c11 -g -static -I"$INSTR" -I. -o /tmp/o4/kat_instr \
    kat_verify.c soq_lbpp_wire.c \
    -L"$INSTR" -L"$HEXL" -llazer -lhexl -lmpfr -lgmp -lm -lstdc++
/tmp/o4/kat_instr /opt/lazer-work/corpus/out 2>/dev/null | tail -6
echo "DONE"
