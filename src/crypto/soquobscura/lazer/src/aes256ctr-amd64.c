/* Modified implementation from supercop-20221122 */
#include "aes256ctr.h"
#include "lazer.h"

#if RNG == RNG_AES256CTR
#if TARGET == TARGET_AMD64
/*
  aesenc-int.c version $Date: 2016/04/01 17:05:23 $
  AES-CTR
  Romain Dolbeau
  Public Domain
  2018.02.23 djb: __m128i* for loadu
*/
#include "aes256ctr.h"
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline void
aesni_key256_expand (const unsigned char *key, __m128i rkeys[16])
{
  __m128i key0 = _mm_loadu_si128 ((const __m128i *)(key + 0));
  __m128i key1 = _mm_loadu_si128 ((const __m128i *)(key + 16));
  __m128i temp0, temp1, temp2, temp4;
  int idx = 0;

  rkeys[idx++] = key0;
  temp0 = key0;
  temp2 = key1;

  /* blockshift-based block by Cedric Bourrasset & Romain Dolbeau */
#define BLOCK1(IMM)                                                           \
  temp1 = _mm_aeskeygenassist_si128 (temp2, IMM);                             \
  rkeys[idx++] = temp2;                                                       \
  temp4 = _mm_slli_si128 (temp0, 4);                                          \
  temp0 = _mm_xor_si128 (temp0, temp4);                                       \
  temp4 = _mm_slli_si128 (temp0, 8);                                          \
  temp0 = _mm_xor_si128 (temp0, temp4);                                       \
  temp1 = _mm_shuffle_epi32 (temp1, 0xff);                                    \
  temp0 = _mm_xor_si128 (temp0, temp1)

#define BLOCK2(IMM)                                                           \
  temp1 = _mm_aeskeygenassist_si128 (temp0, IMM);                             \
  rkeys[idx++] = temp0;                                                       \
  temp4 = _mm_slli_si128 (temp2, 4);                                          \
  temp2 = _mm_xor_si128 (temp2, temp4);                                       \
  temp4 = _mm_slli_si128 (temp2, 8);                                          \
  temp2 = _mm_xor_si128 (temp2, temp4);                                       \
  temp1 = _mm_shuffle_epi32 (temp1, 0xaa);                                    \
  temp2 = _mm_xor_si128 (temp2, temp1)

  BLOCK1 (0x01);
  BLOCK2 (0x01);

  BLOCK1 (0x02);
  BLOCK2 (0x02);

  BLOCK1 (0x04);
  BLOCK2 (0x04);

  BLOCK1 (0x08);
  BLOCK2 (0x08);

  BLOCK1 (0x10);
  BLOCK2 (0x10);

  BLOCK1 (0x20);
  BLOCK2 (0x20);

  BLOCK1 (0x40);
  rkeys[idx++] = temp0;
}

/** single, by-the-book AES encryption with AES-NI */
static inline void
aesni_encrypt1 (unsigned char *out, unsigned char *n, __m128i rkeys[16])
{
  __m128i nv = _mm_load_si128 ((const __m128i *)n);
  int i;
  __m128i temp = _mm_xor_si128 (nv, rkeys[0]);
  for (i = 1; i < 14; i++)
    {
      temp = _mm_aesenc_si128 (temp, rkeys[i]);
    }
  temp = _mm_aesenclast_si128 (temp, rkeys[14]);
  _mm_store_si128 ((__m128i *)(out), temp);
}

/** increment the 16-bytes nonce ;
    this really should be improved somehow...
    but it's not yet time-critical, because we
    use the vector variant anyway  */
static inline void
incle (unsigned char n[16])
{
  /*   unsigned long long out; */
  /*   unsigned char carry; */
  unsigned long long *n_ = (unsigned long long *)n;
  n_[1]++;
  if (n_[1] == 0)
    n_[0]++;
  /* perhaps this will be efficient on broadwell ? */
  /*   carry = _addcarry_u64(0, n_[1], 1ULL, &out); */
  /*   carry = _addcarry_u64(carry, n_[0], 0ULL, &out); */
}

/** multiple-blocks-at-once AES encryption with AES-NI ;
    on Haswell, aesenc as a latency of 7 and a througput of 1
    so the sequence of aesenc should be bubble-free, if you
    have at least 8 blocks. Let's build an arbitratry-sized
    function */
/* Step 1 : loading the nonce */
/* load & increment the n vector (non-vectorized, unused for now) */
#define NVx(a)                                                                \
  __m128i nv##a = _mm_shuffle_epi8 (                                          \
      _mm_load_si128 ((const __m128i *)n),                                    \
      _mm_set_epi8 (8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7));   \
  incle (n)
/* load the incremented n vector (vectorized, probably buggy) */
#define NVxV_DEC(a) __m128i nv##a;
#define NVxV_NOWRAP(a)                                                        \
  nv##a = _mm_shuffle_epi8 (                                                  \
      _mm_add_epi64 (nv0i, _mm_set_epi64x (a, 0)),                            \
      _mm_set_epi8 (8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7))
#define NVxV_WRAP(a)                                                          \
  __m128i ad##a                                                               \
      = _mm_add_epi64 (nv0i, _mm_set_epi64x (a, a >= wrapnumber ? 1 : 0));    \
  nv##a = _mm_shuffle_epi8 (ad##a, _mm_set_epi8 (8, 9, 10, 11, 12, 13, 14,    \
                                                 15, 0, 1, 2, 3, 4, 5, 6, 7))

/* Step 2 : define value in round one (xor with subkey #0, aka key) */
#define TEMPx(a) __m128i temp##a = _mm_xor_si128 (nv##a, rkeys[0])

/* Step 3: one round of AES */
#define AESENCx(a) temp##a = _mm_aesenc_si128 (temp##a, rkeys[i]);

/* Step 4: last round of AES */
#define AESENCLASTx(a) temp##a = _mm_aesenclast_si128 (temp##a, rkeys[14]);

/* Step 5: store result */
#define STOREx(a) _mm_store_si128 ((__m128i *)(out + (a * 16)), temp##a);

/* all the MAKE* macros are for automatic explicit unrolling */
#define MAKE4(X)                                                              \
  X (0);                                                                      \
  X (1);                                                                      \
  X (2);                                                                      \
  X (3)

#define MAKE6(X)                                                              \
  X (0);                                                                      \
  X (1);                                                                      \
  X (2);                                                                      \
  X (3);                                                                      \
  X (4);                                                                      \
  X (5)

#define MAKE7(X)                                                              \
  X (0);                                                                      \
  X (1);                                                                      \
  X (2);                                                                      \
  X (3);                                                                      \
  X (4);                                                                      \
  X (5);                                                                      \
  X (6)

#define MAKE8(X)                                                              \
  X (0);                                                                      \
  X (1);                                                                      \
  X (2);                                                                      \
  X (3);                                                                      \
  X (4);                                                                      \
  X (5);                                                                      \
  X (6);                                                                      \
  X (7)

#define MAKE10(X)                                                             \
  X (0);                                                                      \
  X (1);                                                                      \
  X (2);                                                                      \
  X (3);                                                                      \
  X (4);                                                                      \
  X (5);                                                                      \
  X (6);                                                                      \
  X (7);                                                                      \
  X (8);                                                                      \
  X (9)

#define MAKE12(X)                                                             \
  X (0);                                                                      \
  X (1);                                                                      \
  X (2);                                                                      \
  X (3);                                                                      \
  X (4);                                                                      \
  X (5);                                                                      \
  X (6);                                                                      \
  X (7);                                                                      \
  X (8);                                                                      \
  X (9);                                                                      \
  X (10);                                                                     \
  X (11)

/* create a function of unrolling N ; the MAKEN is the unrolling
   macro, defined above. The N in MAKEN must match N, obviously. */
#define FUNC(N, MAKEN)                                                        \
  static inline void aesni_encrypt##N (unsigned char *out, unsigned char *n,  \
                                       __m128i rkeys[16])                     \
  {                                                                           \
    __m128i nv0i = _mm_load_si128 ((const __m128i *)n);                       \
    long long nl = *(long long *)&n[8];                                       \
    MAKEN (NVxV_DEC);                                                         \
    /* check for nonce wraparound */                                          \
    if ((nl < 0) && (nl + N) >= 0)                                            \
      {                                                                       \
        int wrapnumber = (int)(N - (nl + N));                                 \
        MAKEN (NVxV_WRAP);                                                    \
        _mm_storeu_si128 ((__m128i *)n,                                       \
                          _mm_add_epi64 (nv0i, _mm_set_epi64x (N, 1)));       \
      }                                                                       \
    else                                                                      \
      {                                                                       \
        MAKEN (NVxV_NOWRAP);                                                  \
        _mm_storeu_si128 ((__m128i *)n,                                       \
                          _mm_add_epi64 (nv0i, _mm_set_epi64x (N, 0)));       \
      }                                                                       \
    int i;                                                                    \
    MAKEN (TEMPx);                                                            \
    for (i = 1; i < 14; i++)                                                  \
      {                                                                       \
        MAKEN (AESENCx);                                                      \
      }                                                                       \
    MAKEN (AESENCLASTx);                                                      \
    MAKEN (STOREx);                                                           \
  }

/* and now building our unrolled function is trivial */
FUNC (4, MAKE4)
FUNC (6, MAKE6)
FUNC (7, MAKE7)
FUNC (8, MAKE8)
FUNC (10, MAKE10)
FUNC (12, MAKE12)

static void
_aes256ctr_init (aes256ctr_state_t state, const uint8_t key[32],
                 const uint8_t nonce[16])
{
  state->cache_ptr = NULL;
  state->nbytes = 0;

  aesni_key256_expand (key, state->rkeys);
  /* n2 is in byte-reversed (i.e., native little endian)
     order to make increment/testing easier */
  /* option-4 nh6m: the original code punned 64-bit loads/stores over uint8_t[16], which is
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
  }
}

static void
_aes256ctr_stream (aes256ctr_state_t state, uint8_t *out, size_t outlen)
{
  unsigned long long i, j, mj;
  size_t len;

  len = MIN (outlen, state->nbytes);
  for (i = 0; i < len; i++)
    out[i] = state->cache_ptr[i];

  state->cache_ptr += len;
  state->nbytes -= len;

  out += len;
  outlen -= len;

#define LOOP(iter)                                                            \
  int lb = iter * 16;                                                         \
  for (i = 0; i < outlen; i += lb)                                            \
    {                                                                         \
      aesni_encrypt##iter (state->cache, state->n2, state->rkeys);            \
      mj = lb;                                                                \
      if ((i + mj) >= outlen)                                                 \
        {                                                                     \
          mj = outlen - i;                                                    \
          state->nbytes = 8 * 16 - mj;                                        \
          state->cache_ptr = state->cache + mj;                               \
        }                                                                     \
      for (j = 0; j < mj; j++)                                                \
        out[i + j] = state->cache[j];                                         \
    }
  LOOP (8);
#undef LOOP
}

#endif
#endif
