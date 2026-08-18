#include "lazer.h"
#include "rng.h"

static void
_brandom (int8_t *vec, unsigned int nelems, unsigned int k,
          const uint8_t seed[32], uint64_t dom)
{
  rng_state_t state;
  unsigned int i, j;
  unsigned int outlen = CEIL (2 * k * nelems, 8);
  uint8_t out[outlen];

  _rng_init (state, seed, dom);
  _rng_urandom (state, out, outlen);
  _rng_clear (state);

  for (i = 0; i < nelems; i++)
    {
      vec[i] = 0;
      for (j = 0; j < k; j++)
        {
          const unsigned int q = (i * k + j) >> 3;
          const unsigned int r = (i * k + j) - (q << 3);

          vec[i] += ((out[q] & (1 << r)) >> r);
        }
    }
  for (i = 0; i < nelems; i++)
    {
      for (j = 0; j < k; j++)
        {
          const unsigned int q = (k * nelems + i * k + j) >> 3;
          const unsigned int r = (k * nelems + i * k + j) - (q << 3);

          vec[i] -= ((out[q] & (1 << r)) >> r);
        }
    }
}
