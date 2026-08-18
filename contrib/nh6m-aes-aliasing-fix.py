#!/usr/bin/env python3
"""Fix bead nh6m: strict-aliasing violation in the AES-CTR nonce setup.

_aes256ctr_init read `const uint8_t nonce[16]` and wrote `state->n2` (uint8_t[16]) through
`unsigned long long *`. Accessing a uint8_t object through an incompatible lvalue type is a
strict-aliasing violation, so GCC may assume those 64-bit stores do not alias later byte reads
of n2 and reorder or elide them. The result is a corrupted AES-CTR nonce, a wrong keystream,
and therefore different seed-derived public data at some optimisation levels.

memcpy is the correct idiom and compiles to the same moves on any modern compiler.
"""
import sys
p = "/opt/lazer-extract/src/aes256ctr-amd64.c"
s = open(p).read()
old = """  (*(unsigned long long *)&state->n2[8])
      = BSWAP64 ((*(unsigned long long *)&nonce[8]));
  (*(unsigned long long *)&state->n2[0])
      = BSWAP64 ((*(unsigned long long *)&nonce[0]));"""
new = """  /* option-4 nh6m: the original code punned 64-bit loads/stores over uint8_t[16], which is
   * a strict-aliasing violation. GCC at -O2/-Os exploited it and corrupted the nonce, so the
   * seed-derived statement matrix differed by optimisation level. memcpy is the correct
   * idiom and lowers to the same instructions. */
  {
    uint64_t _n_lo, _n_hi;
    __builtin_memcpy (&_n_lo, &nonce[0], 8);
    __builtin_memcpy (&_n_hi, &nonce[8], 8);
    _n_lo = BSWAP64 (_n_lo);
    _n_hi = BSWAP64 (_n_hi);
    __builtin_memcpy (&state->n2[0], &_n_lo, 8);
    __builtin_memcpy (&state->n2[8], &_n_hi, 8);
  }"""
if old not in s:
    sys.exit("FATAL: the punned block was not found verbatim")
open(p, "w").write(s.replace(old, new, 1))
print("patched _aes256ctr_init: 4 punned accesses -> memcpy")
