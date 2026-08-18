#include "brandom.h"
#include "dom.h"
#include "lazer.h"
#include "memory.h"
#include "rng.h"
#include "urandom.h"

#include <string.h>

void
intmat_alloc (intmat_ptr r, unsigned int nrows, unsigned int ncols,
              unsigned int nlimbs)
{
  void *mem;

  mem = _alloc (_sizeof_intmat_data (nrows, ncols, nlimbs));

  _intmat_init (r, nrows, ncols, nlimbs, mem);
}

void
intmat_free (intmat_ptr r)
{
  if (r == NULL)
    return;

  _free (r->bytes, _sizeof_intmat_data (r->nrows, r->ncols, r->nlimbs));
}

/* option-4 prune (no-inline reachability): ld discarded .text.intmat_eq */

/* option-4 prune (no-inline reachability): ld discarded .text.intmat_mul_sgn_self */

/* option-4 prune (no-inline reachability): ld discarded .text.intmat_brandom */

void
intmat_urandom (intmat_t r, const int_t mod, unsigned int log2mod,
                const uint8_t seed[32], uint32_t dom)
{
  union dom _dom = { { 0, dom } };
  intvec_t rowi;
  unsigned int i;

  _MAT_FOREACH_ROW (r, i)
  {
    intmat_get_row (rowi, r, i);
    _dom.d32[0] = i * r->ncols;

    _urandom (rowi, mod, log2mod, seed, _dom.d64);
  }
}

/* option-4 prune (no-inline reachability): ld discarded .text.intmat_out_str */

/* option-4 prune (no-inline reachability): ld discarded .text.intmat_dump */

/* option-4 prune (no-inline reachability): ld discarded .text.intmat_clear */
