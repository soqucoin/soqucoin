#include "brandom.h"
#include "dom.h"
#include "grandom.h"
#include "lazer.h"
#include "memory.h"
#include "poly.h"
#include "urandom.h"

#include <string.h>

void
polymat_alloc (polymat_ptr r, const polyring_t ring, unsigned int nrows,
               unsigned int ncols)
{
  void *mem;

  mem = _alloc (_sizeof_polymat_data (ring, nrows, ncols));

  _polymat_init (r, ring, nrows, ncols, mem);
  r->mem = mem;
}

void
polymat_free (polymat_ptr r)
{
  unsigned int i, j;
  poly_ptr poly;

  if (r == NULL)
    return;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    poly = polymat_get_elem (r, i, j);
    _free (poly->crtrep, _sizeof_crtrep_data (poly->ring));
  }

  _free (r->mem, _sizeof_polymat_data (r->ring, r->nrows, r->ncols));
}

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_is_upperdiag */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_subdiags_set_zero */

void
polymat_auto (polymat_t r, polymat_t a)
{
  unsigned int i, j;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    poly_auto (polymat_get_elem (r, i, j), polymat_get_elem (a, i, j));
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_tocrt */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_tocrtdiag */

void
polymat_fromcrt (polymat_t r)
{
  unsigned int i, j;
  poly_ptr ri;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    ri = polymat_get_elem (r, i, j);
    poly_fromcrt (ri);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_fromcrtdiag */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_add */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_adddiag */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_sub */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_subdiag */

void
polymat_scale (polymat_t r, const int_t a, polymat_t b)
{
  unsigned int i, j;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    poly_scale (polymat_get_elem (r, i, j), a, polymat_get_elem (b, i, j));
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_scalediag */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_addscale */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_addscalediag */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_subscale */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_subscalediag */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_scale2 */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_scalediag2 */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_addscale2 */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_addscalediag2 */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_subscale2 */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_subscalediag2 */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_rrot */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_rrotdiag */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_lrot */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_lrotdiag */

void
polymat_urandom (polymat_t r, const int_t mod, unsigned int log2mod,
                 const uint8_t seed[32], uint32_t dom)
{
  union dom _dom = { { 0, dom } };
  poly_ptr ptr;
  unsigned int i, j;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    ptr = polymat_get_elem (r, i, j);
    _dom.d32[0] = i * r->ncols + j;
    _poly_urandom (ptr, mod, log2mod, seed, _dom.d64);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_brandom */

void
polymat_mod (polymat_t r, polymat_t a)
{
  unsigned int i, j;
  poly_ptr ri, ai;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    ri = polymat_get_elem (r, i, j);
    ai = polymat_get_elem (a, i, j);
    poly_mod (ri, ai);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_moddiag */

void
polymat_redp (polymat_t r, polymat_t a)
{
  unsigned int i, j;
  poly_ptr ri, ai;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    ri = polymat_get_elem (r, i, j);
    ai = polymat_get_elem (a, i, j);
    poly_redp (ri, ai);
  }
}

void
polymat_redc (polymat_t r, polymat_t a)
{
  unsigned int i, j;
  poly_ptr ri, ai;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    ri = polymat_get_elem (r, i, j);
    ai = polymat_get_elem (a, i, j);
    poly_redc (ri, ai);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_out_str */

/* option-4 prune (no-inline reachability): ld discarded .text.polymat_dump */
