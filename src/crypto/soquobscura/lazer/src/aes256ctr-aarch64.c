/* AES-256-CTR using the ARMv8 cryptographic extensions.
 *
 * Soqucoin-original. Written because the portable C implementation in aes256ctr.c is correct but
 * 50-300x slower than AES-NI on the verify path, and AES-CTR is the RNG behind every
 * seed-derived value, so that gap is a denial-of-service surface rather than a benchmark
 * curiosity. Bead portable-aes-verify-path-too-slow-s6e8.
 *
 * DESIGN CHOICE, deliberately conservative: only the KEY SCHEDULE and the BLOCK CIPHER are
 * implemented here. The counter-mode logic - the big-endian increment, the 16-byte cache, the
 * partial-block bookkeeping - is a byte-for-byte copy of the generic implementation, which has
 * already been proven to produce the correct keystream. Reimplementing CTR mode would put the
 * counter semantics at risk for no benefit; AES is AES, so replacing the block function cannot
 * change the output, and the statement-matrix digest test proves that rather than assuming it.
 */
#include "aes256ctr.h"
#include "lazer.h"

#if RNG == RNG_AES256CTR
#if TARGET == TARGET_AARCH64

#include <arm_neon.h>
#include <string.h>

/* Big-endian counter increment. Identical to incbe() in aes256ctr.c. */
static inline void
incbe_arm (uint8_t n[16])
{
  unsigned int i = 16;

  do
    {
      i--;
      n[i]++;
    }
  while (n[i] == 0 && i > 0);
}

/* SubWord for the key schedule, via the crypto unit rather than a lookup table.
 *
 * vaeseq_u8 (v, key) computes AddRoundKey then SubBytes then ShiftRows. With a zero key it is
 * SubBytes followed by ShiftRows. ShiftRows shifts row i left by i columns, so on a state whose
 * four columns are IDENTICAL it is the identity. Replicating the word into all four lanes
 * therefore yields plain SubBytes, and lane 0 is SubWord(w).
 *
 * Using the crypto unit keeps this free of a data-dependent table lookup. */
static inline void
subword_arm (uint8_t w[4])
{
  uint8_t buf[16];
  uint8x16_t v;

  memcpy (buf + 0, w, 4);
  memcpy (buf + 4, w, 4);
  memcpy (buf + 8, w, 4);
  memcpy (buf + 12, w, 4);

  v = vaeseq_u8 (vld1q_u8 (buf), vdupq_n_u8 (0));
  vst1q_u8 (buf, v);
  memcpy (w, buf, 4);
}

/* AES-256 key schedule: 32-byte key -> 15 round keys. Standard FIPS-197 expansion, done
 * bytewise so there is no word-endianness to get wrong. */
static void
expand_key_arm (uint8_t rkeys[15][16], const uint8_t key[32])
{
  /* Nk = 8 words, Nr = 14 rounds, 4 * (Nr + 1) = 60 words total. */
  uint8_t w[60][4];
  unsigned int i;
  uint8_t rcon = 1;

  for (i = 0; i < 8; i++)
    memcpy (w[i], key + 4 * i, 4);

  for (i = 8; i < 60; i++)
    {
      uint8_t t[4];

      memcpy (t, w[i - 1], 4);

      if (i % 8 == 0)
        {
          /* RotWord */
          uint8_t tmp = t[0];
          t[0] = t[1];
          t[1] = t[2];
          t[2] = t[3];
          t[3] = tmp;

          subword_arm (t);
          t[0] ^= rcon;
          /* xtime in GF(2^8) for the next Rcon */
          rcon = (uint8_t)((rcon << 1) ^ ((rcon & 0x80) ? 0x1b : 0x00));
        }
      else if (i % 8 == 4)
        {
          subword_arm (t);
        }

      w[i][0] = w[i - 8][0] ^ t[0];
      w[i][1] = w[i - 8][1] ^ t[1];
      w[i][2] = w[i - 8][2] ^ t[2];
      w[i][3] = w[i - 8][3] ^ t[3];
    }

  for (i = 0; i < 15; i++)
    {
      memcpy (rkeys[i] + 0, w[4 * i + 0], 4);
      memcpy (rkeys[i] + 4, w[4 * i + 1], 4);
      memcpy (rkeys[i] + 8, w[4 * i + 2], 4);
      memcpy (rkeys[i] + 12, w[4 * i + 3], 4);
    }
}

/* One AES-256 block. vaeseq_u8 folds AddRoundKey into SubBytes+ShiftRows, so the canonical
 * form is 13 rounds of aese+aesmc, a final aese without MixColumns, then the last round key. */
static inline void
aes256_block_arm (const uint8_t rkeys[15][16], uint8_t out[16],
                  const uint8_t in[16])
{
  uint8x16_t st = vld1q_u8 (in);
  unsigned int i;

  for (i = 0; i < 13; i++)
    st = vaesmcq_u8 (vaeseq_u8 (st, vld1q_u8 (rkeys[i])));

  st = vaeseq_u8 (st, vld1q_u8 (rkeys[13]));
  st = veorq_u8 (st, vld1q_u8 (rkeys[14]));

  vst1q_u8 (out, st);
}

static void
_aes256ctr_init (aes256ctr_state_t state, const uint8_t key[32],
                 const uint8_t nonce[16])
{
  state->cache_ptr = NULL;
  state->nbytes = 0;

  expand_key_arm (state->rkeys, key);
  memcpy (state->nonce, nonce, 16);
}

/* Byte-for-byte the generic _aes256ctr_stream, with the block call swapped. */
static void
_aes256ctr_stream (aes256ctr_state_t state, uint8_t *out, size_t outlen)
{
  size_t len;

  len = MIN (outlen, state->nbytes);
  memcpy (out, state->cache_ptr, len);

  state->cache_ptr += len;
  state->nbytes -= len;

  out += len;
  outlen -= len;

  while (outlen >= 16)
    {
      aes256_block_arm (state->rkeys, out, state->nonce);
      incbe_arm (state->nonce);

      out += 16;
      outlen -= 16;
    }
  if (outlen > 0)
    {
      aes256_block_arm (state->rkeys, state->cache, state->nonce);
      incbe_arm (state->nonce);

      memcpy (out, state->cache, outlen);

      state->cache_ptr = state->cache + outlen;
      state->nbytes = 16 - outlen;
    }
}

/* NOTE: _aes256ctr_clear is deliberately NOT defined here. aes256ctr.c defines it for every
 * target, outside its TARGET_GENERIC guard, which is why the amd64 implementation does not
 * define one either. Defining it here is a redefinition error. */

#endif /* TARGET == TARGET_AARCH64 */
#endif /* RNG == RNG_AES256CTR */
