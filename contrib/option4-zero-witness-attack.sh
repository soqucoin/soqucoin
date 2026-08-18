#!/bin/bash
# STEP 1b: the REAL zero-witness soundness test.
#
# The byte-level probe was VACUOUS and the instrumented run proved it: all 90 mutants were
# rejected at DECPROOF, i.e. by the decoder's range/canonicality checks. Not one reached
# poly_eq(c, c2). So "LaZer rejects degenerate witnesses" had no soundness content.
#
# To reach the soundness path a degenerate witness must be RE-ENCODED so it decodes cleanly.
# lnp_tbox_encproof is `static void`, so this patches the LaZer tree (which we control) to
# export a wrapper, and captures the recomputed challenge seed so the Fiat-Shamir FIXED POINT
# can be attacked directly rather than argued about.
#
# Two experiments:
#   A. zero witness, ORIGINAL c        -> which check rejects? expect CHALLENGE_POLY_EQ
#   B. zero witness, c := F(cseed)     -> iterate the fixed point; expect no convergence
#
# ⛔ DO NOT ADD `make clean` - bead hexl-patches-lost-on-clean-6joj.
set -euo pipefail

INSTR=/opt/lazer-instr
HEXL=/opt/lazer-pinned/third_party/hexl-development/build-v3/hexl/lib
KAT=/opt/lazer-evidence/task1-2026-08-17/src
OUT=/opt/lazer-evidence/option4-2026-08-17
cd "$INSTR"

echo "############ patch: capture cseed + export a re-encode wrapper"
python3 - <<'PY'
# 1. capture the recomputed challenge seed inside lnp_quad_verify.
#    NOTE there are TWO cseed squeezes in this file - the prover has one too. Only the
#    VERIFIER's must be instrumented, so anchor inside lnp_quad_verify by offset.
p = "src/lnp-quad.c"
s = open(p).read()
anchor = "shake128_squeeze (hstate, cseed, 32);"
n = s.count(anchor)
if n != 2:
    raise SystemExit(f"FATAL: expected 2 cseed squeezes in {p}, found {n}")
fstart = s.find("\nlnp_quad_verify (uint8_t hash")
if fstart < 0:
    raise SystemExit("FATAL: cannot locate lnp_quad_verify")
at = s.find(anchor, fstart)
if at < 0:
    raise SystemExit("FATAL: no cseed squeeze inside lnp_quad_verify")
inject = anchor + """
  { extern unsigned char soq_x_last_cseed[32];
    extern int soq_x_cseed_valid;
    memcpy (soq_x_last_cseed, cseed, 32); soq_x_cseed_valid = 1; }"""
s = s[:at] + inject + s[at + len(anchor):]
open(p, "w").write(s)
print(f"  captured cseed in lnp_quad_verify (offset {at}, prover's copy untouched)")

# 2. globals + exported wrapper in the unity file
p = "src/lazer.c"
s = open(p).read()
if "soq_x_last_cseed" in s:
    raise SystemExit("already patched")
s = ("#include <string.h>\n"
     "unsigned char soq_x_last_cseed[32];\n"
     "int soq_x_cseed_valid = 0;\n") + s
s += r'''

/* ===================== SoquObscura option-4 soundness probe =====================
 * Re-encode a DEGENERATE witness so that it decodes cleanly, in order to reach the
 * soundness checks. Declarations mirror _lin_verifier_verify exactly.
 *   zero_all  : zero every prover-supplied field
 *   newc_seed : if non-NULL, replace c with poly_urandom_autostable(newc_seed),
 *               which is how the Fiat-Shamir fixed point is attacked.
 * Returns 1 on success, 0 if the input proof did not decode. */
int
soq_x_reencode_degenerate (lin_verifier_state_t state__, const uint8_t *in,
                           uint8_t *out, size_t *outlen,
                           const unsigned char *newc_seed, int zero_all)
{
  _lnp_verifier_state_ptr state_ = state__->lnp_state;
  __lnp_state_ptr state = state_->state;
  lnp_tbox_params_srcptr params = state->params;
  size_t prooflen;
  int b;

  b = lnp_tbox_decproof (&prooflen, in, state->tA1, state->tB, state->h,
                         state->c, state->z1, state->z21, state->hint,
                         state->z3, state->z4, params);
  if (b != 1)
    return 0;

  if (zero_all)
    {
      polyvec_set_zero (state->z1);
      polyvec_set_zero (state->z21);
      polyvec_set_zero (state->hint);
      polyvec_set_zero (state->z3);
      polyvec_set_zero (state->z4);
      polyvec_set_zero (state->tA1);
      polyvec_set_zero (state->tB);
      polyvec_set_zero (state->h);
    }

  if (newc_seed != NULL)
    poly_urandom_autostable (state->c, params->quad_eval->quad_many->omega,
                             params->quad_eval->quad_many->log2omega,
                             newc_seed, 0);

  lnp_tbox_encproof (out, outlen, state->tA1, state->tB, state->h, state->c,
                     state->z1, state->z21, state->hint, state->z3, state->z4,
                     params);
  return 1;
}
'''
open(p, "w").write(s)
print("  added soq_x_reencode_degenerate to lazer.c")
PY

echo "############ rebuild (targeted removal, NOT make clean)"
rm -f src/*.o liblazer.a liblazer.so lazer.h
CF="-Wall -Wextra -O3 -g -march=x86-64-v3 -maes -mtune=generic -fomit-frame-pointer"
CF="$CF -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA"
make lib-static CFLAGS="$CF" -j4 > "$OUT/attack-build.log" 2>&1 \
  || { grep -E "error:" "$OUT/attack-build.log" | head -20; exit 1; }
echo "liblazer.a: $(stat -c%s liblazer.a) bytes"
nm --defined-only liblazer.a | grep -c "T soq_x_reencode_degenerate" || {
  echo "FATAL: wrapper not exported"; exit 1; }

echo "############ sanity: still 64/64 with the probe compiled in"
cd "$KAT"
gcc -O2 -std=c11 -g -static -I"$INSTR" -I. -o /tmp/o4/kat_atk kat_verify.c soq_lbpp_wire.c \
    -L"$INSTR" -L"$HEXL" -llazer -lhexl -lmpfr -lgmp -lm -lstdc++
/tmp/o4/kat_atk /opt/lazer-work/corpus/out 2>/dev/null | tail -3

echo "############ build + run the attack harness"
gcc -O2 -std=c11 -g -static -I"$INSTR" -I. -o /tmp/o4/attack \
    zero-witness-attack.c soq_lbpp_wire.c \
    -L"$INSTR" -L"$HEXL" -llazer -lhexl -lmpfr -lgmp -lm -lstdc++
/tmp/o4/attack /opt/lazer-work/corpus/out
