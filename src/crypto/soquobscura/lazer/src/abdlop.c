#include "lazer.h"

/*
 * A1 uniform in Rq^(kmsis x m1)
 *
 * A2 = (A2prime, 1)
 * A2prime uniform in Rq^(kmsis x (m2-kmsis))
 * 1 in Rq^(kmsis x kmsis)
 *
 * B = (Bprime, 0)
 * Bprime uniform in Rq^(l x (m2-kmsis))
 * 0 in Rq^(l x kmsis)
 */

/*
 * Compute public key (A1,A2prime,Bprime) from seed.
 *
 * Expand uniformly random A1,A2prime,Bprime
 * from seed||0, seed||1, seed||2 respectively:
 * A1 uniform in Rq^(kmsis x m1),
 * A2prime uniform in Rq^(kmsis x (m2-kmsis))
 * Bprime = (B,Bext) uniform in Rq^((l+lext) x (m2-kmsis))
 *
 * Caller must allocate A1,A2prime,Bprime with dimensions and ring Rq
 * given by params.
 */
void
abdlop_keygen (polymat_t A1, polymat_t A2prime, polymat_t Bprime,
               const uint8_t seed[32], const abdlop_params_t params)
{
#if ASSERT == ASSERT_ENABLED
  const unsigned int kmsis = params->kmsis;
  const unsigned int m2 = params->m2;
#endif
  polyring_srcptr Rq = params->ring;
  int_srcptr q = polyring_get_mod (Rq);
  const unsigned int log2q = polyring_get_log2q (Rq);
  const unsigned int m1 = params->m1;
  const unsigned int l = params->l;
  const unsigned int lext = params->lext;
  const unsigned int l_ = l + lext;

  ASSERT_ERR (polymat_get_ring (A1) == Rq);
  ASSERT_ERR (polymat_get_nrows (A1) == kmsis);
  ASSERT_ERR (polymat_get_ncols (A1) == m1);
  ASSERT_ERR (polymat_get_ring (A2prime) == Rq);
  ASSERT_ERR (polymat_get_nrows (A2prime) == kmsis);
  ASSERT_ERR (polymat_get_ncols (A2prime) == m2 - kmsis);
  ASSERT_ERR (l_ == 0 || polymat_get_ring (Bprime) == Rq);
  ASSERT_ERR (l_ == 0 || polymat_get_nrows (Bprime) == l + lext);
  ASSERT_ERR (l_ == 0 || polymat_get_ncols (Bprime) == m2 - kmsis);

  if (m1 > 0)
    {
      polymat_urandom (A1, q, log2q, seed, 0);
      polymat_urandom (A2prime, q, log2q, seed, 1);
    }

  if (l_ > 0)
    polymat_urandom (Bprime, q, log2q, seed, 2);
}

/* option-4 prune (no-inline reachability): ld discarded .text.abdlop_commit */

void
abdlop_enccomm (uint8_t *buf, size_t *buflen, polyvec_t tA1, polyvec_t tB,
                const abdlop_params_t params)
{
  polyring_srcptr Rq = params->ring;
  int_srcptr q = Rq->q;
  const unsigned int log2q = Rq->log2q;
  const unsigned int d = Rq->d;
  const unsigned int D = params->dcompress->D;
  const unsigned int kmsis = params->kmsis;
  const unsigned int m1 = params->m1;
  const unsigned int l = params->l;
#if ASSERT == ASSERT_ENABLED
  size_t outlen;
#endif
  coder_state_t cstate;
  polyvec_t tB_;
  const unsigned int len
      = CEIL (kmsis * d * (log2q - D) + l * d * log2q, 8) + 1;

  if (buflen != NULL)
    *buflen = len;

  if (buf == NULL)
    return;

  coder_enc_begin (cstate, buf);
  if (m1 > 0)
    {
      INT_T (mod, q->nlimbs);

      int_set_one (mod);
      int_lshift (mod, mod, log2q - D);

      polyvec_redp (tA1, tA1);
      coder_enc_urandom3 (cstate, tA1, mod, log2q - D);
    }
  if (l > 0)
    {
      polyvec_get_subvec (tB_, tB, 0, l, 1);
      polyvec_redp (tB_, tB_);
      coder_enc_urandom3 (cstate, tB_, q, log2q);
    }
  coder_enc_end (cstate);

#if ASSERT == ASSERT_ENABLED
  outlen =
#endif
      coder_get_offset (cstate);
  ASSERT_ERR (outlen % 8 == 0);
  ASSERT_ERR (outlen / 8 <= len);
}

/*
 * hash = H(hash||tA1||tB).
 * Input hash is usually the seed for the public parameters
 * used by abdlop_keygen.
 */
void
abdlop_hashcomm (uint8_t hash[32], polyvec_t tA1, polyvec_t tB,
                 const abdlop_params_t params)
{
  polyring_srcptr Rq = params->ring;
  const unsigned int log2q = Rq->log2q;
  const unsigned int d = Rq->d;
  const unsigned int D = params->dcompress->D;
  const unsigned int kmsis = params->kmsis;
  const unsigned int l = params->l;
  shake128_state_t hstate;
  const size_t outlen = CEIL (kmsis * d * (log2q - D) + l * d * log2q, 8) + 1;
  uint8_t out[outlen];

  abdlop_enccomm (out, NULL, tA1, tB, params);

  shake128_init (hstate);
  shake128_absorb (hstate, hash, 32);
  shake128_absorb (hstate, out, outlen);
  shake128_squeeze (hstate, hash, 32);
  shake128_clear (hstate);
}

/*
 * Compute compressed opening proof (c,z1,z21,h) from hash of transcript,
 * "short" message s1 and randomness s2, tA2, the public key
 * parts (A1,A2prime) and a seed.
 * Also update hash of transcript by hashing c into it.
 *
 * tA2 = Rq^kmsis
 * s1 in Rq^m1, l2(s1) <= alpha
 * s2 = (s21,s22) in uniform in [-nu,nu]^(m2-kmsis) x [-nu,nu]^kmsis
 * A1 uniform in Rq^(kmsis x m1),
 * A2prime uniform in Rq^(kmsis x (m2-kmsis))

/* option-4 prune (no-inline reachability): ld discarded .text.abdlop_prove */

/* option-4 prune (no-inline reachability): ld discarded .text.abdlop_verify */
