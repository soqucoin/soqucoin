#include "lazer.h"
#include "stopwatch.h"
/* Soqucoin: mpfr include REMOVED. After function-level pruning there are zero mpfr_ calls
 * anywhere in the vendored sources, so this was a compile-time dependency on a library whose
 * code is never linked - and a hard build blocker on any host without mpfr headers. Verified
 * by grep across all vendored .c and by the absence of undefined mpfr_ symbols at link. */

static void
_schwartz_zippel_poly (spolymat_t R2, spolyvec_t r1, poly_t r0,
                       uint8_t hash[32], spolymat_ptr R2i[],
                       spolyvec_ptr r1i[], poly_ptr r0i[], unsigned int N,
                       const abdlop_params_t params)
{
  polyring_srcptr Rq = params->ring;
  int_srcptr q = polyring_get_mod (Rq);
  const unsigned int log2q = polyring_get_log2q (Rq);
  const unsigned int m1 = params->m1;
  const unsigned int l = params->l;
  spolyvec_t r1tmp, r1tmp2;
  spolymat_t R2tmp, R2tmp2;
  const unsigned int nelems = 2 * (m1 + l);
  poly_ptr mui;
  polyvec_t mu;
  unsigned int i;

  polyvec_alloc (mu, Rq, N);
  spolyvec_alloc (r1tmp, Rq, nelems, nelems);
  spolyvec_alloc (r1tmp2, Rq, nelems, nelems);
  spolymat_alloc (R2tmp, Rq, nelems, nelems,
                  (nelems * nelems - nelems) / 2 + nelems);
  spolymat_alloc (R2tmp2, Rq, nelems, nelems,
                  (nelems * nelems - nelems) / 2 + nelems);

  if (r0 != NULL)
    poly_set_zero (r0);

  polyvec_urandom (mu, q, log2q, hash, 0);

  _VEC_FOREACH_ELEM (mu, i)
  {
    mui = polyvec_get_elem (mu, i);

    if (R2i[i] != NULL)
      {
        spolymat_scale2 (R2tmp2, mui, R2i[i]);
        spolymat_add (R2tmp, R2, R2tmp2, 0);
        spolymat_set (R2, R2tmp);
      }
    if (r1i[i] != NULL)
      {
        spolyvec_scale2 (r1tmp2, mui, r1i[i]);
        spolyvec_add (r1tmp, r1, r1tmp2, 0);
        spolyvec_set (r1, r1tmp);
      }

    if (r0 == NULL)
      continue;

    if (!(r0i[i] == NULL))
      poly_addmul (r0, mui, r0i[i], 0);
  }
  spolymat_fromcrt (R2);
  spolyvec_fromcrt (r1);
  if (r0 != NULL)
    poly_fromcrt (r0);

  spolyvec_free (r1tmp);
  spolyvec_free (r1tmp2);
  spolymat_free (R2tmp);
  spolymat_free (R2tmp2);
  polyvec_free (mu);

  ASSERT_ERR (spolymat_is_upperdiag (R2));
}

/* option-4 prune (no-inline reachability): ld discarded .text.lnp_quad_many_prove */

int
lnp_quad_many_verify (uint8_t hash[32], poly_t c, polyvec_t z1, polyvec_t z21,
                      polyvec_t h, polyvec_t tA1, polyvec_t tB, polymat_t A1,
                      polymat_t A2prime, polymat_t Bprime, spolymat_ptr R2i[],
                      spolyvec_ptr r1i[], poly_ptr r0i[], unsigned int N,
                      const abdlop_params_t params)
{
#if ASSERT == ASSERT_ENABLED
  unsigned int i;
#endif
  polyring_srcptr Rq = params->ring;
  const unsigned int m1 = params->m1;
  const unsigned int l = params->l;
  const unsigned int nelems = 2 * (m1 + l);
  spolymat_t R2;
  spolyvec_t r1;
  poly_t r0;
  int b;

  STOPWATCH_START (stopwatch_lnp_quad_many_verify, "lnp_quad_many_verify");

  ASSERT_ERR (params->lext == 1);
  ASSERT_ERR (poly_get_ring (c) == Rq);
  ASSERT_ERR (polyvec_get_ring (z1) == Rq);
  ASSERT_ERR (polyvec_get_nelems (z1) == m1);
  ASSERT_ERR (polyvec_get_ring (z21) == Rq);
  ASSERT_ERR (polyvec_get_nelems (z21) == params->m2 - params->kmsis);
  ASSERT_ERR (polyvec_get_ring (h) == Rq);
  ASSERT_ERR (polyvec_get_nelems (h) == params->kmsis);
  ASSERT_ERR (polyvec_get_ring (tA1) == Rq);
  ASSERT_ERR (polyvec_get_nelems (tA1) == params->kmsis);
  ASSERT_ERR (polyvec_get_ring (tB) == Rq);
  ASSERT_ERR (polyvec_get_nelems (tB) == l + params->lext);
  ASSERT_ERR (polymat_get_ring (A1) == Rq);
  ASSERT_ERR (polymat_get_nrows (A1) == params->kmsis);
  ASSERT_ERR (polymat_get_ncols (A1) == m1);
  ASSERT_ERR (polymat_get_ring (A2prime) == Rq);
  ASSERT_ERR (polymat_get_nrows (A2prime) == params->kmsis);
  ASSERT_ERR (polymat_get_ncols (A2prime) == params->m2 - params->kmsis);
  ASSERT_ERR (polymat_get_ring (Bprime) == Rq);
  ASSERT_ERR (polymat_get_nrows (Bprime) == l + params->lext);
  ASSERT_ERR (polymat_get_ncols (Bprime) == params->m2 - params->kmsis);
#if ASSERT == ASSERT_ENABLED
  for (i = 0; i < N; i++)
    {
      ASSERT_ERR (spolymat_is_upperdiag (R2i[i]));
      ASSERT_ERR (R2i[i] == NULL
                  || spolymat_get_nrows (R2i[i]) == 2 * (m1 + l));
      ASSERT_ERR (R2i[i] == NULL
                  || spolymat_get_ncols (R2i[i]) == 2 * (m1 + l));
      ASSERT_ERR (r1i[i] == NULL || r1i[i]->nelems_max == 2 * (m1 + l));
    }
#endif

  spolymat_alloc (R2, Rq, nelems, nelems,
                  (nelems * nelems - nelems) / 2 + nelems);
  spolyvec_alloc (r1, Rq, 2 * (m1 + l), 2 * (m1 + l));
  poly_alloc (r0, Rq);

  _schwartz_zippel_poly (R2, r1, r0, hash, R2i, r1i, r0i, N, params);

  b = lnp_quad_verify (hash, c, z1, z21, h, tA1, tB, A1, A2prime, Bprime, R2,
                       r1, r0, params);

  spolymat_free (R2);
  spolyvec_free (r1);
  poly_free (r0);

  STOPWATCH_STOP (stopwatch_lnp_quad_many_verify);
  return b;
}
