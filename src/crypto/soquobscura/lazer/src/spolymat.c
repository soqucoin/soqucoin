#include "brandom.h"
#include "dom.h"
#include "grandom.h"
#include "lazer.h"
#include "memory.h"
#include "poly.h"
#include "urandom.h"

#include <stdlib.h>
#include <string.h>

static int
_cmp_polymat (const void *a_, const void *b_)
{
  _spolymat_srcptr a = (_spolymat_srcptr)a_;
  _spolymat_srcptr b = (_spolymat_srcptr)b_;
  const uint16_t arow = a->row;
  const uint16_t acol = a->col;
  const uint16_t brow = b->row;
  const uint16_t bcol = b->col;

  /* dont insert same element twice */
  ASSERT_ERR (!(arow == brow && acol == bcol));

  if (arow < brow)
    return -1;
  if (arow == brow && acol < bcol)
    return -1;
  return 1;
}

static poly_ptr
_poly_alloc_polymat (polyring_srcptr ring)
{
  poly_ptr poly;

  poly = _alloc (_sizeof_poly (ring));
  _poly_init (poly, ring, ((uint8_t *)poly) + sizeof (poly_t));
  return poly;
}

void
spolymat_sort (spolymat_ptr r)
{
  ASSERT_ERR (r->sorted == 0);

  qsort (r->elems, r->nelems, sizeof (_spolymat_struct), _cmp_polymat);
  r->sorted = 1;
}

void
spolymat_alloc (spolymat_ptr r, const polyring_t ring, unsigned int nrows,
                unsigned int ncols, unsigned int nelems_max)
{
  r->ring = ring;
  r->nrows = nrows;
  r->ncols = ncols;
  r->nelems_max = nelems_max;
  r->sorted = 1; /* the empty matrix is sorted */

  r->nelems = 0;
  r->elems = _alloc (nelems_max * sizeof (_spolymat_t));
  memset (r->elems, 0, nelems_max * sizeof (_spolymat_t));
}

void
spolymat_set (spolymat_ptr r, spolymat_ptr a)
{
  poly_ptr poly, poly2;
  unsigned int i, row, col;

  ASSERT_ERR (r->nelems_max >= a->nelems);
  ASSERT_ERR (r->ring == a->ring);
  ASSERT_ERR (r->nrows == a->nrows);
  ASSERT_ERR (r->ncols == a->ncols);
  ASSERT_ERR (a->sorted);

  r->nelems = 0;
  _SMAT_FOREACH_ELEM (a, i)
  {
    poly = spolymat_get_elem (a, i);
    row = spolymat_get_row (a, i);
    col = spolymat_get_col (a, i);

    poly2 = spolymat_insert_elem (r, row, col);
    poly_set (poly2, poly);
  }
  r->sorted = 1;
  r->nelems = a->nelems;
}

/* option-4 prune (no-inline reachability): ld discarded .text.spolymat_redc */

/* option-4 prune (no-inline reachability): ld discarded .text.spolymat_redp */

/* option-4 prune (no-inline reachability): ld discarded .text.spolymat_is_upperdiag */

/* r != a, r != b*/
void
spolymat_add (spolymat_t r, spolymat_t a, spolymat_t b, int crt)
{
  poly_ptr pr, pa, pb;
  unsigned int arow, acol, brow, bcol;
  unsigned int i = 0, j = 0, k = 0;

  ASSERT_ERR (a->sorted && b->sorted);

  r->nelems = 0;
  while (i < a->nelems && j < b->nelems)
    {
      ASSERT_ERR (k < r->nelems_max);

      pa = spolymat_get_elem (a, i);
      arow = spolymat_get_row (a, i);
      acol = spolymat_get_col (a, i);

      pb = spolymat_get_elem (b, j);
      brow = spolymat_get_row (b, j);
      bcol = spolymat_get_col (b, j);

      if (arow < brow || (arow == brow && acol < bcol))
        {
          pr = spolymat_insert_elem (r, arow, acol);
          poly_set (pr, pa);
          i++;
        }
      else if (brow < arow || (brow == arow && bcol < acol))
        {
          pr = spolymat_insert_elem (r, brow, bcol);
          poly_set (pr, pb);
          j++;
        }
      else
        {
          ASSERT_ERR (arow == brow && acol == bcol);
          pr = spolymat_insert_elem (r, arow, acol);
          poly_add (pr, pa, pb, crt);
          i++;
          j++;
        }
      k++;
    }
  while (i < a->nelems)
    {
      ASSERT_ERR (j == b->nelems);
      ASSERT_ERR (k < r->nelems_max);

      pa = spolymat_get_elem (a, i);
      arow = spolymat_get_row (a, i);
      acol = spolymat_get_col (a, i);

      pr = spolymat_insert_elem (r, arow, acol);
      poly_set (pr, pa);
      i++;
      k++;
    }
  while (j < b->nelems)
    {
      ASSERT_ERR (i == a->nelems);
      ASSERT_ERR (k < r->nelems_max);

      pb = spolymat_get_elem (b, j);
      brow = spolymat_get_row (b, j);
      bcol = spolymat_get_col (b, j);

      pr = spolymat_insert_elem (r, brow, bcol);
      poly_set (pr, pb);
      j++;
      k++;
    }
  r->nelems = k;
  r->sorted = 1;
}

void
spolymat_fromcrt (spolymat_t r)
{
  unsigned int i;
  poly_ptr ri;

  _SMAT_FOREACH_ELEM (r, i)
  {
    ri = spolymat_get_elem (r, i);
    poly_fromcrt (ri);
  }
}

/* r != b */
void
spolymat_lrot (spolymat_t r, spolymat_t b, unsigned int n)
{
  poly_ptr ri, bi;
  unsigned int brow, bcol, i;

  ASSERT_ERR (r->nelems_max >= b->nelems_max);

  r->nelems = 0;
  _SMAT_FOREACH_ELEM (b, i)
  {
    bi = spolymat_get_elem (b, i);
    brow = spolymat_get_row (b, i);
    bcol = spolymat_get_col (b, i);

    ri = spolymat_insert_elem (r, brow, bcol);
    poly_lrot (ri, bi, n);
  }
  r->nelems = b->nelems;
  r->sorted = b->sorted;
}

/* r != b */
void
spolymat_mod (spolymat_ptr r, spolymat_ptr b)
{
  poly_ptr ri, bi;
  unsigned int brow, bcol, i;

  ASSERT_ERR (r->nelems_max >= b->nelems_max);

  r->nelems = 0;
  _SMAT_FOREACH_ELEM (b, i)
  {
    bi = spolymat_get_elem (b, i);
    brow = spolymat_get_row (b, i);
    bcol = spolymat_get_col (b, i);

    ri = spolymat_insert_elem (r, brow, bcol);
    poly_mod (ri, bi);
  }
  r->nelems = b->nelems;
  r->sorted = b->sorted;
}

/* r != b */
void
spolymat_scale (spolymat_t r, const int_t a, spolymat_t b)
{
  poly_ptr ri, bi;
  unsigned int brow, bcol, i;

  ASSERT_ERR (r->nelems_max >= b->nelems_max);

  r->nelems = 0;
  _SMAT_FOREACH_ELEM (b, i)
  {
    bi = spolymat_get_elem (b, i);
    brow = spolymat_get_row (b, i);
    bcol = spolymat_get_col (b, i);

    ri = spolymat_insert_elem (r, brow, bcol);
    poly_scale (ri, a, bi);
  }
  r->nelems = b->nelems;
  r->sorted = b->sorted;
}

/* r != b */
void
spolymat_scale2 (spolymat_t r, poly_t a, spolymat_t b)
{
  poly_ptr ri, bi;
  unsigned int brow, bcol, i;

  ASSERT_ERR (r->nelems_max >= b->nelems_max);

  r->nelems = 0;
  _SMAT_FOREACH_ELEM (b, i)
  {
    bi = spolymat_get_elem (b, i);
    brow = spolymat_get_row (b, i);
    bcol = spolymat_get_col (b, i);

    ri = spolymat_insert_elem (r, brow, bcol);
    poly_mul (ri, a, bi);
  }
  r->nelems = b->nelems;
  r->sorted = b->sorted;
}

/* option-4 prune (no-inline reachability): ld discarded .text.spolymat_urandom */

/* option-4 prune (no-inline reachability): ld discarded .text.spolymat_brandom */

poly_ptr
spolymat_insert_elem (spolymat_ptr r, unsigned int row, unsigned int col)
{
  polyring_srcptr Rq = r->ring;
  const unsigned int nelems = r->nelems;

  ASSERT_ERR (r->nelems < r->nelems_max);

  if (r->elems[nelems].poly == NULL)
    r->elems[nelems].poly = _poly_alloc_polymat (Rq);
  r->elems[nelems].row = row;
  r->elems[nelems].col = col;

  r->nelems++;
  r->sorted = 0;
  return r->elems[nelems].poly;
}

void
spolymat_free (spolymat_ptr r)
{
  unsigned int i;

  if (r == NULL)
    return;

  for (i = 0; i < r->nelems_max; i++)
    {
      if (r->elems[i].poly != NULL)
        {
          _free (r->elems[i].poly->crtrep,
                 _sizeof_crtrep_data (r->elems[i].poly->ring));
          _free (r->elems[i].poly, _sizeof_poly (r->ring));
        }
    }

  _free (r->elems, r->nelems_max * sizeof (_spolymat_t));
}

poly_ptr
spolymat_get_elem2 (spolymat_ptr a, unsigned int row, unsigned int col)
{
  unsigned int i, arow, acol;

  _SMAT_FOREACH_ELEM (a, i)
  {
    arow = spolymat_get_row (a, i);
    acol = spolymat_get_col (a, i);

    if (arow == row && acol == col)
      return spolymat_get_elem (a, i);
  }
  return NULL;
}

/* option-4 prune (no-inline reachability): ld discarded .text.spolymat_out_str */

/* option-4 prune (no-inline reachability): ld discarded .text.spolymat_dump */
