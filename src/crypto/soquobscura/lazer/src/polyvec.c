#include "brandom.h"
#include "dom.h"
#include "grandom.h"
#include "lazer.h"
#include "memory.h"
#include "poly.h"
#include "urandom.h"

#include <string.h>

void
polyvec_alloc (polyvec_ptr r, const polyring_t ring, unsigned int nelems)
{
  void *mem;

  mem = _alloc (_sizeof_polyvec_data (ring, nelems));

  _polyvec_init (r, ring, nelems, mem);
  r->mem = mem;
}

void
polyvec_free (polyvec_ptr r)
{
  poly_ptr poly;
  unsigned int i;

  if (r == NULL)
    return;

  _VEC_FOREACH_ELEM (r, i)
  {
    poly = polyvec_get_elem (r, i);
    _free (poly->crtrep, _sizeof_crtrep_data (poly->ring));
  }

  _free (r->mem, _sizeof_polyvec_data (r->ring, r->nelems));
}

void
polyvec_get_subvec (polyvec_t subvec, const polyvec_t vec, unsigned int elem,
                    unsigned int nelems, unsigned int stride)
{
  ASSERT_ERR (1 + FLOOR (vec->nelems - elem, stride) >= nelems);

  subvec->elems = polyvec_get_elem (vec, elem);

  subvec->nelems = nelems;
  subvec->stride_elems = stride * vec->stride_elems;
  subvec->ring = vec->ring;
  subvec->mem = NULL;
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_eq */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_rshift */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_lshift */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_rrot */

void
polyvec_lrot (polyvec_t r, polyvec_t a, unsigned int n)
{
  poly_ptr ap, rp;
  unsigned int i;

  ASSERT_ERR (r->nelems == a->nelems);
  ASSERT_ERR (n < r->ring->d);

  _VEC_FOREACH_ELEM (r, i)
  {
    rp = polyvec_get_elem (r, i);
    ap = polyvec_get_elem (a, i);
    poly_lrot (rp, ap, n);
  }
}

void
polyvec_add (polyvec_t r, polyvec_t a, polyvec_t b, int crt)
{
  unsigned int i;

  ASSERT_ERR (a->nelems == b->nelems);
  ASSERT_ERR (r->nelems == a->nelems);

  _VEC_FOREACH_ELEM (r, i)
  {
    poly_add (polyvec_get_elem (r, i), polyvec_get_elem (a, i),
              polyvec_get_elem (b, i), crt);
  }
}

void
polyvec_sub (polyvec_t r, polyvec_t a, polyvec_t b, int crt)
{
  unsigned int i;

  ASSERT_ERR (a->nelems == b->nelems);
  ASSERT_ERR (r->nelems == a->nelems);

  _VEC_FOREACH_ELEM (r, i)
  {
    poly_sub (polyvec_get_elem (r, i), polyvec_get_elem (a, i),
              polyvec_get_elem (b, i), crt);
  }
}

void
polyvec_mul (polyvec_t r, polymat_t a, polyvec_t b)
{
  polyvec_t rowi;
  poly_ptr ri;
  unsigned int i;

  ASSERT_ERR (polyvec_get_ring (r) == polyvec_get_ring (b));
  ASSERT_ERR (polyvec_get_ring (r) == polymat_get_ring (a));
  ASSERT_ERR (polyvec_get_nelems (r) == polymat_get_nrows (a));
  ASSERT_ERR (polyvec_get_nelems (b) == polymat_get_ncols (a));

  _MAT_FOREACH_ROW (a, i)
  {
    ri = polyvec_get_elem (r, i);

    polymat_get_row (rowi, a, i);
    polyvec_dot (ri, rowi, b);
  }
}

void
polyvec_mulsparse (polyvec_t r, spolymat_t a, polyvec_t b)
{
  poly_ptr rp, ap, bp;
  unsigned int i, row, col;

  ASSERT_ERR (polyvec_get_ring (r) == polyvec_get_ring (b));
  ASSERT_ERR (polyvec_get_ring (r) == spolymat_get_ring (a));

  _VEC_FOREACH_ELEM (r, i)
  {
    rp = polyvec_get_elem (r, i);

    if (rp->crtrep == NULL)
      {
        ASSERT_ERR (rp->crt == 0);
        rp->crtrep = _alloc (_sizeof_crtrep_data (rp->ring));
      }
    rp->crt = 1;
    memset (rp->crtrep, 0, _sizeof_crtrep_data (rp->ring));
  }

  _SMAT_FOREACH_ELEM (a, i)
  {
    ap = spolymat_get_elem (a, i);
    row = spolymat_get_row (a, i);
    col = spolymat_get_col (a, i);

    bp = polyvec_get_elem (b, col);
    rp = polyvec_get_elem (r, row);

    poly_addmul (rp, ap, bp, 1);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_muldiag */

void
polyvec_mul2 (polyvec_t r, polyvec_t a, polymat_t b)
{
  polyvec_t coli;
  poly_ptr ri;
  unsigned int i;

  ASSERT_ERR (polyvec_get_ring (r) == polyvec_get_ring (a));
  ASSERT_ERR (polyvec_get_ring (r) == polymat_get_ring (b));
  ASSERT_ERR (polyvec_get_nelems (r) == polymat_get_ncols (b));
  ASSERT_ERR (polyvec_get_nelems (a) == polymat_get_nrows (b));

  _MAT_FOREACH_COL (b, i)
  {
    ri = polyvec_get_elem (r, i);

    polymat_get_col (coli, b, i);
    polyvec_dot (ri, a, coli);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_muldiag2 */

void
polyvec_addmul (polyvec_t r, polymat_t a, polyvec_t b, int crt)
{
  polyring_srcptr ring = polyvec_get_ring (r);
  const unsigned int nelems = polyvec_get_nelems (r);
  polyvec_t tmp;

  polyvec_alloc (tmp, ring, nelems);

  polyvec_mul (tmp, a, b);
  polyvec_add (r, r, tmp, crt);

  polyvec_free (tmp);
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_addmul2 */

void
polyvec_submul (polyvec_t r, polymat_t a, polyvec_t b, int crt)
{
  polyring_srcptr ring = polyvec_get_ring (r);
  const unsigned int nelems = polyvec_get_nelems (r);
  polyvec_t tmp;

  polyvec_alloc (tmp, ring, nelems);

  polyvec_mul (tmp, a, b);
  polyvec_sub (r, r, tmp, crt);

  polyvec_free (tmp);
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_submul2 */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_addrshift */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_subrshift */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_addlshift */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_sublshift */

void
polyvec_scale (polyvec_t r, const int_t a, polyvec_t b)
{
  unsigned int i;

  _VEC_FOREACH_ELEM (r, i)
  {
    poly_scale (polyvec_get_elem (r, i), a, polyvec_get_elem (b, i));
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_addscale */

void
polyvec_subscale (polyvec_t r, const int_t a, polyvec_t b, int crt)
{
  polyring_srcptr ring = polyvec_get_ring (r);
  const unsigned int nelems = polyvec_get_nelems (r);
  polyvec_t tmp;

  polyvec_alloc (tmp, ring, nelems);

  polyvec_scale (tmp, a, b);
  polyvec_sub (r, r, tmp, crt);

  polyvec_free (tmp);
}

void
polyvec_scale2 (polyvec_t r, poly_t a, polyvec_t b)
{
  poly_ptr ri, bi;
  unsigned int i;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = polyvec_get_elem (r, i);
    bi = polyvec_get_elem (b, i);
    poly_mul (ri, a, bi);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_addscale2 */

void
polyvec_subscale2 (polyvec_t r, poly_t a, polyvec_t b, int crt)
{
  polyring_srcptr ring = polyvec_get_ring (r);
  const unsigned int nelems = polyvec_get_nelems (r);
  polyvec_t tmp;

  polyvec_alloc (tmp, ring, nelems);

  polyvec_scale2 (tmp, a, b);
  polyvec_sub (r, r, tmp, crt);

  polyvec_free (tmp);
}

void
polyvec_mod (polyvec_t r, polyvec_t a)
{
  unsigned int i;

  _VEC_FOREACH_ELEM (r, i)
  {
    poly_mod (polyvec_get_elem (r, i), polyvec_get_elem (a, i));
  }
}

void
polyvec_redc (polyvec_t r, polyvec_t a)
{
  unsigned int i;

  _VEC_FOREACH_ELEM (r, i)
  {
    poly_redc (polyvec_get_elem (r, i), polyvec_get_elem (a, i));
  }
}

void
polyvec_redp (polyvec_t r, polyvec_t a)
{
  unsigned int i;

  _VEC_FOREACH_ELEM (r, i)
  {
    poly_redp (polyvec_get_elem (r, i), polyvec_get_elem (a, i));
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_tocrt */

void
polyvec_fromcrt (polyvec_t r)
{
  unsigned int i;
  poly_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = polyvec_get_elem (r, i);
#if DEBUGINFO == DEBUGINFO_ENABLED
    if (ri->crt == 1)
      DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt polvec_fromcrt");
#endif
    poly_fromcrt (ri);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_toisoring */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_fromisoring */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_auto_self */

void
polyvec_auto (polyvec_t r, polyvec_t a)
{
  unsigned int i;

  _VEC_FOREACH_ELEM (r, i)
  {
    poly_auto (polyvec_get_elem (r, i), polyvec_get_elem (a, i));
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_urandom_autostable */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_elem_mul */

void
polyvec_dot (poly_t r, polyvec_t a, polyvec_t b)
{
  poly_ptr ap, bp;
  unsigned int i;
  poly_t prod;

  poly_alloc (prod, a->ring);

  ASSERT_ERR (a->ring == b->ring);

  if (r->crtrep == NULL)
    {
      ASSERT_ERR (r->crt == 0);
      r->crtrep = _alloc (_sizeof_crtrep_data (r->ring));
    }
  r->crt = 1;
  memset (r->crtrep, 0, _sizeof_crtrep_data (r->ring));

  _VEC_FOREACH_ELEM (a, i)
  {
    ap = polyvec_get_elem (a, i);
    bp = polyvec_get_elem (b, i);
    poly_mul (prod, ap, bp);
    poly_add (r, r, prod, 1);
  }

  poly_free (prod);
}

void
polyvec_dot2 (poly_t r, spolyvec_t a, polyvec_t b)
{
  poly_ptr ap, bp;
  unsigned int i, elem;
  poly_t prod;

  poly_alloc (prod, a->ring);

  ASSERT_ERR (a->ring == b->ring);

  if (r->crtrep == NULL)
    {
      ASSERT_ERR (r->crt == 0);
      r->crtrep = _alloc (_sizeof_crtrep_data (r->ring));
    }
  r->crt = 1;
  memset (r->crtrep, 0, _sizeof_crtrep_data (r->ring));

  _SVEC_FOREACH_ELEM (a, i)
  {
    ap = spolyvec_get_elem (a, i);
    elem = spolyvec_get_elem_ (a, i);
    bp = polyvec_get_elem (b, elem);
    poly_mul (prod, ap, bp);
    poly_add (r, r, prod, 1);
  }

  poly_free (prod);
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_dcompress_power2round */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_dcompress_decompose */

void
polyvec_dcompress_use_ghint (polyvec_t ret, polyvec_t y, polyvec_t r,
                             const dcompress_params_t params)
{
  unsigned int i;
  poly_ptr retp, yp, rp;

  ASSERT_ERR (ret->ring == y->ring);
  ASSERT_ERR (ret->ring == r->ring);

  _VEC_FOREACH_ELEM (ret, i)
  {
    retp = polyvec_get_elem (ret, i);
    yp = polyvec_get_elem (y, i);
    rp = polyvec_get_elem (r, i);
    poly_dcompress_use_ghint (retp, yp, rp, params);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_dcompress_make_ghint */

/*
 * not ctime.
 */
void
polyvec_linf (int_t r, polyvec_t a)
{
  INT_T (tmp, r->nlimbs);
  poly_ptr ap;
  unsigned int i;

  ASSERT_ERR (r->nlimbs == a->ring->q->nlimbs);

  int_set_i64 (r, 0);

  _VEC_FOREACH_ELEM (a, i)
  {
    ap = polyvec_get_elem (a, i);
    poly_linf (tmp, ap);
    if (int_absgt (tmp, r))
      int_set (r, tmp);
  }
}

void
polyvec_l2sqr (int_t r, polyvec_t a)
{
  INT_T (tmp, r->nlimbs);
  poly_ptr ap;
  unsigned int i;

  ASSERT_ERR (r->nlimbs == 2 * a->ring->q->nlimbs);

  int_set_i64 (r, 0);

  _VEC_FOREACH_ELEM (a, i)
  {
    ap = polyvec_get_elem (a, i);
    poly_l2sqr (tmp, ap);
    int_add (r, r, tmp);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_grandom */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_brandom */

void
polyvec_urandom (polyvec_t r, const int_t mod, unsigned int log2mod,
                 const uint8_t seed[32], uint32_t dom)
{
  union dom _dom = { { 0, dom } };
  unsigned int i;

  _VEC_FOREACH_ELEM (r, i)
  {
    _dom.d32[0]++;
    _poly_urandom (polyvec_get_elem (r, i), mod, log2mod, seed, _dom.d64);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_urandom_bnd */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_out_str */

/* option-4 prune (no-inline reachability): ld discarded .text.polyvec_dump */
