#include "lazer.h"
#include "rng.h"

static void
_urandom (intvec_t r, const int_t mod, unsigned int log2mod,
          const uint8_t seed[32], uint64_t dom)
{
  if (LIKELY (log2mod < 60))
    { // XXX
      int64_t vec[r->nelems];

      _urandom_i64 (vec, r->nelems, int_get_i64 (mod), log2mod, seed, dom);
      intvec_set_i64 (r, vec);
    }
  else
    {
      INT_T (lo, r->nlimbs);
      INT_T (hi, r->nlimbs);
      INT_T (one, r->nlimbs);

      int_set_i64 (lo, 0);
      int_set_i64 (one, 1);

      int_set (hi, mod);
      int_sub (hi, hi, one);
      int_rshift (hi, hi, 1);

      _urandom_bnd (r, lo, hi, seed, dom);
    }
}

static void
_urandom_bnd (intvec_t r, const int_t lo, const int_t hi,
              const uint8_t seed[32], uint64_t dom)
{
  unsigned int i;
  const unsigned int nlimbs = r->nlimbs;
  unsigned int top = nlimbs - 1;
  unsigned int nbits_top = NBITS_LIMB;
  limb_t mask = mask = ~(limb_t)0;
  int_ptr _r;
  INT_T (tmp, nlimbs);
  INT_T (l, nlimbs);
  INT_T (h, nlimbs);
  rng_state_t state;
  uint8_t *ptr;

  ASSERT_ERR (r->nlimbs >= lo->nlimbs);
  ASSERT_ERR (r->nlimbs >= hi->nlimbs);

  int_set (l, lo);
  int_set (h, hi);

  int_sub (tmp, h, l);

  for (; tmp->limbs[top] == 0 && top > 0; top--)
    ;
  for (; ((mask >> 1) & tmp->limbs[top]) == tmp->limbs[top]; mask >>= 1)
    nbits_top--;

  _rng_init (state, seed, dom);

  _VEC_FOREACH_ELEM (r, i)
  {
    _r = intvec_get_elem (r, i);
    ptr = (uint8_t *)_r->limbs;

    int_set_i64 (_r, 0);

    do
      {
        _rng_urandom (state, ptr,
                      (NBITS_LIMB / 8) * top + CEIL (nbits_top, 8));
        _r->limbs[top] &= mask;
      }
    while (limbs_gt_ct (_r->limbs, tmp->limbs, nlimbs));

    int_add (_r, _r, l);
  }

  _rng_clear (state);
}

static void
_urandom_i64 (int64_t *vec, unsigned int nelems, int64_t mod,
              unsigned int log2mod, const uint8_t seed[32], uint64_t dom)
{
  rng_state_t state;
  unsigned int i, j, k;
  int64_t tmp;

  ASSERT_ERR (mod >= ((int64_t)1 << (log2mod - 1)));
  ASSERT_ERR (mod < ((int64_t)1 << log2mod));

  _rng_init (state, seed, dom);

  k = 0;
  while (k < nelems)
    {
      unsigned int l = nelems - k;
      unsigned int outlen = CEIL (log2mod * l, 8);
      uint8_t out[outlen];

      _rng_urandom (state, out, outlen);

      for (i = 0; i < l; i++)
        {
          tmp = 0;
          for (j = 0; j < log2mod; j++)
            {
              const unsigned int q = (i * log2mod + j) >> 3;
              const unsigned int r = (i * log2mod + j) - (q << 3);

              ASSERT_ERR (q < outlen);

              tmp |= (((int64_t)((out[q] & (1 << r)) >> r)) << j);
            }
          if (((((mod - 1) - tmp) >> 63) & 1) == 0)
            {
              ASSERT_ERR (tmp < mod);
              ASSERT_ERR (tmp >= 0);
              vec[k] = tmp;
              k++;
            }
        }
    }

  _rng_clear (state);
}

#if 0
static void
_urandom_i64 (int64_t *vec, unsigned int nelems, int64_t mod,
              unsigned int log2mod, const uint8_t seed[32], uint64_t dom)
{
  rng_state_t state;
  unsigned int j, k;
  unsigned int outlen = CEIL (log2mod * nelems, 8);
  uint8_t out[outlen];

  ASSERT_ERR (mod >= ((int64_t)1 << (log2mod - 1)));
  ASSERT_ERR (mod < ((int64_t)1 << log2mod));

  _rng_init (state, seed, dom);
  _rng_urandom (state, out, outlen);

  for (k = 0; k < nelems; k++)
    {
      vec[k] = 0;

      for (j = 0; j < log2mod; j++)
        {
          const unsigned int q = (k * log2mod + j) >> 3;
          const unsigned int r = (k * log2mod + j) - (q << 3);

          ASSERT_ERR (q < outlen);

          vec[k] |= (((int64_t)((out[q] & (1 << r)) >> r)) << j);
        }
    }

  _rng_clear (state);
}
#endif
