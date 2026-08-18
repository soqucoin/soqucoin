#include "brandom.h"
#include "grandom.h"
#include "lazer.h"
#include "memory.h"
#include "urandom.h"

#include <gmp.h>
#include <string.h>

/* option-4 prune (no-inline reachability): ld discarded .text.int_alloc */

/* option-4 prune (no-inline reachability): ld discarded .text.int_free */

void
int_mul (int_t r, const int_t a, const int_t b)
{
  limb_t scratch[mpn_sec_mul_itch (a->nlimbs, b->nlimbs)];

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == 2 * a->nlimbs);

  mpn_sec_mul (r->limbs, a->limbs, a->nlimbs, b->limbs, b->nlimbs, scratch);
  r->neg = a->neg ^ b->neg;
}

void
int_sqr (int_t r, const int_t a)
{
  limb_t scratch[mpn_sec_sqr_itch (a->nlimbs)];

  ASSERT_ERR (r->nlimbs == 2 * a->nlimbs);

  mpn_sec_sqr (r->limbs, a->limbs, a->nlimbs, scratch);
  r->neg = 0;
}

void
int_addmul (int_t r, const int_t a, const int_t b)
{
  INT_T (tmp, r->nlimbs);

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == 2 * a->nlimbs);

  int_mul (tmp, a, b);
  int_add (r, r, tmp);
}

/* option-4 prune (no-inline reachability): ld discarded .text.int_submul */

void
int_addsqr (int_t r, const int_t a)
{
  INT_T (tmp, r->nlimbs);

  ASSERT_ERR (r->nlimbs == 2 * a->nlimbs);

  int_sqr (tmp, a);
  int_add (r, r, tmp);
}

/* option-4 prune (no-inline reachability): ld discarded .text.int_subsqr */

/* divisor non-secret */
void
int_div (int_t rq, int_t rr, const int_t a, const int_t b)
{
  limb_t _a[a->nlimbs], r;
  unsigned int bnlimbs;

  for (bnlimbs = b->nlimbs; b->limbs[bnlimbs - 1] == 0; bnlimbs--)
    ;

  ASSERT_ERR (bnlimbs >= 1);
  ASSERT_ERR (a->nlimbs >= bnlimbs);
  ASSERT_ERR (rr->nlimbs == bnlimbs);
  ASSERT_ERR (rq->nlimbs == a->nlimbs - bnlimbs + 1);

  limbs_cpy (_a, a->limbs, a->nlimbs);
  {
    limb_t scratch[mpn_sec_div_qr_itch (a->nlimbs, bnlimbs)];

    r = mpn_sec_div_qr (rq->limbs, _a, a->nlimbs, b->limbs, bnlimbs, scratch);
  }
  rq->limbs[rq->nlimbs - 1] = r;
  limbs_cpy (rr->limbs, _a, bnlimbs);

  rq->neg = a->neg ^ b->neg;
  rr->neg = rq->neg;
}

/* [-(m-1),...,(m-1)] -> [0,...,m-1] */
void
int_redp (int_t r, const int_t a, const int_t m)
{
  limb_t tmp[a->nlimbs];
  limb_t b;

  ASSERT_ERR (a->nlimbs == m->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  limbs_cpy (r->limbs, a->limbs, a->nlimbs);
  limbs_sub (tmp, m->limbs, a->limbs, 0, a->nlimbs);

  b = a->neg & (1 ^ limbs_eq_zero_ct (a->limbs, a->nlimbs)); /* neg.zero! */
  limbs_cnd_select (r->limbs, r->limbs, tmp, r->nlimbs, b);
  r->neg = 0;
}

/* result in [-(m-1),...,m-1] */
void
int_mod (int_t r, const int_t a, const int_t m)
{
  ASSERT_ERR (r->nlimbs == m->nlimbs);
  ASSERT_ERR (m->limbs);

  if (m->nlimbs == 1)
    {
      const crtcoeff_t mod = (crtcoeff_t)m->limbs[0];
      crtcoeff_t x = int_mod_XXX (a, mod);
      int_set_i64 (r, x);
    }
  else
    {
      limb_t scratch[mpn_sec_div_r_itch (a->nlimbs, m->nlimbs)];
      limb_t tmp[a->nlimbs];

      limbs_cpy (tmp, a->limbs, a->nlimbs);
      mpn_sec_div_r (tmp, a->nlimbs, m->limbs, m->nlimbs, scratch);
      limbs_cpy (r->limbs, tmp, r->nlimbs);
      r->neg = a->neg;
    }
}

/* option-4 prune (no-inline reachability): ld discarded .text.int_invmod */

/* option-4 prune (no-inline reachability): ld discarded .text.int_brandom */

/* option-4 prune (no-inline reachability): ld discarded .text.int_grandom */

/* option-4 prune (no-inline reachability): ld discarded .text.int_urandom */

/* option-4 prune (no-inline reachability): ld discarded .text.int_urandom_bnd */

void
int_binexp (poly_t upsilon, poly_t powB, int_srcptr B)
{
  polyring_srcptr Rq;

  ASSERT_ERR (upsilon != NULL || powB != NULL);

  if (upsilon != NULL)
    Rq = upsilon->ring;
  else
    Rq = powB->ring;

  INT_T (pow2, Rq->q->nlimbs);
  INT_T (B_, Rq->q->nlimbs);
  int i;

  int_set (B_, B);
  if (upsilon != NULL)
    poly_set_zero (upsilon);
  if (powB != NULL)
    poly_set_zero (powB);

  for (i = Rq->log2q - 1; i >= 0; i--)
    {
      int_set_one (pow2);
      int_lshift (pow2, pow2, i);

      if (powB != NULL && int_le (pow2, B))
        int_set (poly_get_coeff (powB, i), pow2);

      if (upsilon != NULL && int_ge (B_, pow2))
        {
          int_sub (B_, B_, pow2);
          int_set_one (poly_get_coeff (upsilon, i));
        }
    }
}

/* option-4 prune (no-inline reachability): ld discarded .text.int_clear */

/* option-4 prune (no-inline reachability): ld discarded .text.int_out_str */

/* option-4 prune (no-inline reachability): ld discarded .text.int_dump */

/* option-4 prune (no-inline reachability): ld discarded .text.int_inp_str */

/* option-4 prune (no-inline reachability): ld discarded .text.int_import */

/* option-4 prune (no-inline reachability): ld discarded .text.int_export */
