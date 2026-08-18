#include "lazer.h"

/*
 * not ctime, r in (-q,q)
 */
void
dcompress_decompose (intvec_t r1, intvec_t r0, const intvec_t r,
                     const dcompress_params_t params)
{
  int_ptr r1i, r0i;
  unsigned int i;
  unsigned int nlimbs = params->gamma->nlimbs;

  for (; params->gamma->limbs[nlimbs - 1] == 0; nlimbs--)
    ;

  INT_T (rq, r1->nlimbs - nlimbs + 1);
  INT_T (rr, nlimbs);
  INT_T (gamma_, nlimbs); /* gamma w/o zero padding */
  INT_T (one, r0->nlimbs);
  INTVEC_T (tmp, r0->nelems, nlimbs);

  ASSERT_ERR (r->nelems == r1->nelems);
  ASSERT_ERR (r->nlimbs == r1->nlimbs);
  ASSERT_ERR (r->nelems == r0->nelems);
  ASSERT_ERR (r->nlimbs == r0->nlimbs);
  ASSERT_ERR (r->nlimbs == params->qminus1->nlimbs);
  ASSERT_ERR (r->nlimbs == params->q->nlimbs);

  int_set (gamma_, params->gamma);
  int_set_i64 (one, 1);
  intvec_redp (r1, r, params->q);

  intvec_mod (tmp, r1, gamma_); /* in (-gamma,gamma) */
  intvec_set (r0, tmp);
  /* to (-gamma/2,gamma/2] */
  _VEC_FOREACH_ELEM (r0, i)
  {
    r0i = intvec_get_elem (r0, i);

    if (int_sgn (r0i) == -1)
      {
        if (int_absle (r0i, params->gammaby2))
          int_add (r0i, r0i, params->gamma);
      }
    else
      {
        if (int_absgt (r0i, params->gammaby2))
          int_sub (r0i, r0i, params->gamma);
      }
  }

  intvec_sub (r1, r1, r0);
  _VEC_FOREACH_ELEM (r1, i)
  {
    r1i = intvec_get_elem (r1, i);
    r0i = intvec_get_elem (r0, i);
    if (int_eq (r1i, params->qminus1))
      {
        int_set_i64 (r1i, 0);
        int_sub (r0i, r0i, one);
      }
    else
      {
        int_div (rq, rr, r1i, gamma_);
        int_set (r1i, rq);
      }
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.dcompress_power2round */

/*
 * r in (-q,q), y in (-m/2,m/2], not ctime
 */
void
dcompress_use_ghint (intvec_t ret, const intvec_t y, const intvec_t r,
                     const dcompress_params_t params)
{
  INTVEC_T (r0, ret->nelems, ret->nlimbs);
  int_ptr reti;
  unsigned int i;

  ASSERT_ERR (ret->nlimbs == y->nlimbs);
  ASSERT_ERR (ret->nelems == y->nelems);
  ASSERT_ERR (ret->nlimbs == r->nlimbs);
  ASSERT_ERR (ret->nelems == r->nelems);

  dcompress_decompose (ret, r0, r, params);
  intvec_add (ret, ret, y);
  intvec_mod (ret, ret, params->m); /* in (-m,m) */
  /* to [0,m) */
  _VEC_FOREACH_ELEM (r0, i)
  {
    reti = intvec_get_elem (ret, i);

    if (int_sgn (reti) == -1)
      int_add (reti, reti, params->m);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.dcompress_make_ghint */
