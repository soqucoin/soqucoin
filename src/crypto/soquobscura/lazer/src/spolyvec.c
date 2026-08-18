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
_cmp_spolyvec (const void *a_, const void *b_)
{
  _spolyvec_srcptr a = (_spolyvec_srcptr)a_;
  _spolyvec_srcptr b = (_spolyvec_srcptr)b_;
  const uint16_t aelem = a->elem;
  const uint16_t belem = b->elem;

  /* dont insert same element twice */
  ASSERT_ERR (!(aelem == belem));

  if (aelem < belem)
    return -1;
  return 1;
}

static poly_ptr
_poly_alloc_polyvec (polyring_srcptr ring)
{
  poly_ptr poly;

  poly = _alloc (_sizeof_poly (ring));
  _poly_init (poly, ring, ((uint8_t *)poly) + sizeof (poly_t));
  return poly;
}

void
spolyvec_sort (spolyvec_ptr r)
{
  ASSERT_ERR (r->sorted == 0);

  qsort (r->elems, r->nelems, sizeof (_spolyvec_struct), _cmp_spolyvec);
  r->sorted = 1;
}

void
spolyvec_alloc (spolyvec_ptr r, const polyring_t ring, unsigned int nelems,
                unsigned int nelems_max)
{
  r->ring = ring;
  r->nelems = nelems;
  r->nelems_max = nelems_max;
  r->sorted = 1; /* the empty matrix is sorted */

  r->nelems = 0;
  r->elems = _alloc (nelems_max * sizeof (_spolyvec_t));
  memset (r->elems, 0, nelems_max * sizeof (_spolyvec_t));
}

void
spolyvec_set (spolyvec_ptr r, spolyvec_ptr a)
{
  poly_ptr poly, poly2;
  unsigned int i, elem;

  ASSERT_ERR (r->nelems_max >= a->nelems);
  ASSERT_ERR (r->ring == a->ring);
  ASSERT_ERR (a->sorted);

  r->nelems = 0;
  _SVEC_FOREACH_ELEM (a, i)
  {
    poly = spolyvec_get_elem (a, i);
    elem = spolyvec_get_elem_ (a, i);

    poly2 = spolyvec_insert_elem (r, elem);
    poly_set (poly2, poly);
  }
  r->sorted = 1;
  r->nelems = a->nelems;
}

/* option-4 prune (no-inline reachability): ld discarded .text.spolyvec_redc */

/* option-4 prune (no-inline reachability): ld discarded .text.spolyvec_redp */

/* r != a, r != b*/
void
spolyvec_add (spolyvec_t r, spolyvec_t a, spolyvec_t b, int crt)
{
  poly_ptr pr, pa, pb;
  unsigned int aelem, belem;
  unsigned int i = 0, j = 0, k = 0;

  ASSERT_ERR (a->sorted && b->sorted);

  r->nelems = 0;
  while (i < a->nelems && j < b->nelems)
    {
      ASSERT_ERR (k < r->nelems_max);

      pa = spolyvec_get_elem (a, i);
      aelem = spolyvec_get_elem_ (a, i);

      pb = spolyvec_get_elem (b, j);
      belem = spolyvec_get_elem_ (b, j);

      if (aelem < belem)
        {
          pr = spolyvec_insert_elem (r, aelem);
          poly_set (pr, pa);
          i++;
        }
      else if (belem < aelem)
        {
          pr = spolyvec_insert_elem (r, belem);
          poly_set (pr, pb);
          j++;
        }
      else
        {
          ASSERT_ERR (aelem == belem);
          pr = spolyvec_insert_elem (r, aelem);
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

      pa = spolyvec_get_elem (a, i);
      aelem = spolyvec_get_elem_ (a, i);

      pr = spolyvec_insert_elem (r, aelem);
      poly_set (pr, pa);
      i++;
      k++;
    }
  while (j < b->nelems)
    {
      ASSERT_ERR (i == a->nelems);
      ASSERT_ERR (k < r->nelems_max);

      pb = spolyvec_get_elem (b, j);
      belem = spolyvec_get_elem_ (b, j);

      pr = spolyvec_insert_elem (r, belem);
      poly_set (pr, pb);
      j++;
      k++;
    }
  r->nelems = k;
  r->sorted = 1;
}

void
spolyvec_fromcrt (spolyvec_t r)
{
  unsigned int i;
  poly_ptr ri;

  _SVEC_FOREACH_ELEM (r, i)
  {
    ri = spolyvec_get_elem (r, i);
    poly_fromcrt (ri);
  }
}

/* r != b */
void
spolyvec_lrot (spolyvec_t r, spolyvec_t b, unsigned int n)
{
  poly_ptr ri, bi;
  unsigned int belem, i;

  ASSERT_ERR (r->nelems_max >= b->nelems_max);

  r->nelems = 0;
  _SVEC_FOREACH_ELEM (b, i)
  {
    bi = spolyvec_get_elem (b, i);
    belem = spolyvec_get_elem_ (b, i);

    ri = spolyvec_insert_elem (r, belem);
    poly_lrot (ri, bi, n);
  }
  r->nelems = b->nelems;
  r->sorted = b->sorted;
}

/* r != b */
void
spolyvec_mod (spolyvec_ptr r, spolyvec_ptr b)
{
  poly_ptr ri, bi;
  unsigned int belem, i;

  ASSERT_ERR (r->nelems_max >= b->nelems_max);

  r->nelems = 0;
  _SVEC_FOREACH_ELEM (b, i)
  {
    bi = spolyvec_get_elem (b, i);
    belem = spolyvec_get_elem_ (b, i);

    ri = spolyvec_insert_elem (r, belem);
    poly_mod (ri, bi);
  }
  r->nelems = b->nelems;
  r->sorted = b->sorted;
}

/* r != b */
void
spolyvec_scale (spolyvec_t r, const int_t a, spolyvec_t b)
{
  poly_ptr ri, bi;
  unsigned int belem, i;

  ASSERT_ERR (r->nelems_max >= b->nelems_max);

  r->nelems = 0;
  _SVEC_FOREACH_ELEM (b, i)
  {
    bi = spolyvec_get_elem (b, i);
    belem = spolyvec_get_elem_ (b, i);

    ri = spolyvec_insert_elem (r, belem);
    poly_scale (ri, a, bi);
  }
  r->nelems = b->nelems;
  r->sorted = b->sorted;
}

/* r != b */
void
spolyvec_scale2 (spolyvec_t r, poly_t a, spolyvec_t b)
{
  poly_ptr ri, bi;
  unsigned int belem, i;

  ASSERT_ERR (r->nelems_max >= b->nelems_max);

  r->nelems = 0;
  _SVEC_FOREACH_ELEM (b, i)
  {
    bi = spolyvec_get_elem (b, i);
    belem = spolyvec_get_elem_ (b, i);

    ri = spolyvec_insert_elem (r, belem);
    poly_mul (ri, a, bi);
  }
  r->nelems = b->nelems;
  r->sorted = b->sorted;
}

/* option-4 prune (no-inline reachability): ld discarded .text.spolyvec_urandom */

/* option-4 prune (no-inline reachability): ld discarded .text.spolyvec_brandom */

poly_ptr
spolyvec_insert_elem (spolyvec_ptr r, unsigned int elem)
{
  polyring_srcptr Rq = r->ring;
  const unsigned int nelems = r->nelems;

  ASSERT_ERR (r->nelems < r->nelems_max);

  if (r->elems[nelems].poly == NULL)
    r->elems[nelems].poly = _poly_alloc_polyvec (Rq);
  r->elems[nelems].elem = elem;

  r->nelems++;
  r->sorted = 0;
  return r->elems[nelems].poly;
}

void
spolyvec_free (spolyvec_ptr r)
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

  _free (r->elems, r->nelems_max * sizeof (_spolyvec_t));
}

/* option-4 prune (no-inline reachability): ld discarded .text.spolyvec_get_elem2 */

/* option-4 prune (no-inline reachability): ld discarded .text.spolyvec_out_str */

/* option-4 prune (no-inline reachability): ld discarded .text.spolyvec_dump */
