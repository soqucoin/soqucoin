#include "poly.h"
#include "brandom.h"
#include "grandom.h"
#include "intvec.h"
#include "lazer.h"
#include "memory.h"
// #include "ntt.h"
#include "urandom.h"
#include <math.h>

void
poly_alloc (poly_ptr r, const polyring_t ring)
{
  void *mem;

  mem = _alloc (_sizeof_poly_data (ring));

  _poly_init (r, ring, mem);
  r->mem = mem;
}

void
poly_free (poly_ptr r)
{
  if (r == NULL)
    return;

  if (r->crt)
    _free (r->crtrep, _sizeof_crtrep_data (r->ring));
  _free (r->mem, _sizeof_poly_data (r->ring));
}

void
poly_set (poly_t r, const poly_t a)
{
  polyring_srcptr ring = a->ring;
  intvec_srcptr acoeffs;

  // XXXASSERT_ERR (r->ring == a->ring);

  r->crt = a->crt;
  if (r->crt)
    {
      if (r->crtrep == NULL)
        r->crtrep = _alloc (_sizeof_crtrep_data (ring));

      memcpy (r->crtrep, a->crtrep,
              sizeof (crtcoeff_t) * ring->d * ring->nmoduli);
    }
  else
    {
      acoeffs = _get_coeffvec_src (a);
      poly_set_coeffvec (r, acoeffs);
    }
}

void
poly_add (poly_t r, poly_t a, poly_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  const unsigned int deg = polyring_get_deg (ring);
  crtcoeff_t *ca, *cb, *cr;
  unsigned int i;

  ASSERT_ERR (ring == poly_get_ring (a));
  ASSERT_ERR (ring == poly_get_ring (b));

  r->crt = _to_same_dom (a, b, crt);
  if (r->crt)
    {
      if (r->crtrep == NULL)
        r->crtrep = _alloc (_sizeof_crtrep_data (ring));

      _POLYRING_FOREACH_P (ring, i)
      {
#ifdef XXX
        crtcoeff_t tmp;
        unsigned int j;

        for (j = 0; j < ring->d; j++)
          {
            ca = _get_crtcoeff (a->crtrep, i, j, deg);
            cb = _get_crtcoeff (b->crtrep, i, j, deg);
            cr = _get_crtcoeff (r->crtrep, i, j, deg);

            tmp = (crtcoeff_t)(*ca) + (*cb);
            *cr = _mont_rsum (tmp, ring->moduli[i]->p);
          }
#else
        ca = _get_crtcoeff (a->crtrep, i, 0, deg);
        cb = _get_crtcoeff (b->crtrep, i, 0, deg);
        cr = _get_crtcoeff (r->crtrep, i, 0, deg);
        hexl_ntt_add (cr, ca, cb, deg, ring->moduli[i]->p);
#endif
      }
    }
  else
    {
      intvec_add (r->coeffs, a->coeffs, b->coeffs);
      intvec_redc (r->coeffs, r->coeffs, ring->q);
    }
}

void
poly_sub (poly_t r, poly_t a, poly_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  const unsigned int deg = polyring_get_deg (ring);
  crtcoeff_t *ca, *cb, *cr;
  unsigned int i;

  ASSERT_ERR (ring == poly_get_ring (a));
  ASSERT_ERR (ring == poly_get_ring (b));

  r->crt = _to_same_dom (a, b, crt);
  if (r->crt)
    {
      if (r->crtrep == NULL)
        r->crtrep = _alloc (_sizeof_crtrep_data (ring));

      _POLYRING_FOREACH_P (ring, i)
      {
#ifdef XXX
        crtcoeff_t tmp;
        unsigned int j;

        for (j = 0; j < ring->d; j++)
          {
            ca = _get_crtcoeff (a->crtrep, i, j, deg);
            cb = _get_crtcoeff (b->crtrep, i, j, deg);
            cr = _get_crtcoeff (r->crtrep, i, j, deg);

            tmp = (crtcoeff_t)(*ca) - (*cb);
            *cr = _mont_rsum (tmp, ring->moduli[i]->p);
          }
#else
        ca = _get_crtcoeff (a->crtrep, i, 0, deg);
        cb = _get_crtcoeff (b->crtrep, i, 0, deg);
        cr = _get_crtcoeff (r->crtrep, i, 0, deg);
        hexl_ntt_sub (cr, ca, cb, deg, ring->moduli[i]->p);
#endif
      }
    }
  else
    {
      intvec_sub (r->coeffs, a->coeffs, b->coeffs);
      intvec_redc (r->coeffs, r->coeffs, ring->q);
    }
}

void
poly_neg (poly_t r, poly_t b)
{
#if ASSERT == ASSERT_ENABLED
  polyring_srcptr ring = poly_get_ring (r);
#endif
  ASSERT_ERR (ring == poly_get_ring (b));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (b->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt neg");
#endif
  _fromcrt (b); // XXX can also do this in crt dom

  r->crt = 0;
  intvec_neg (r->coeffs, b->coeffs);
}

void
poly_scale (poly_t r, const int_t a, poly_t b)
{
  polyring_srcptr ring = poly_get_ring (r);

  ASSERT_ERR (ring == poly_get_ring (b));
  ASSERT_ERR (a->nlimbs == b->coeffs->nlimbs);

#if 0
  crtcoeff_t _a;
  crtcoeff_t *cb, *cr;
  unsigned int i;

  if (b->crt == 1)
    {
      const unsigned int deg = polyring_get_deg (ring);

      if (r->crtrep == NULL)
        {
          ASSERT_ERR (r->crt == 0);
          r->crtrep = _alloc (_sizeof_crtrep_data (ring));
        }
      r->crt = 1;

      _POLYRING_FOREACH_P (ring, i)
      {
        _a = int_mod_XXX_hexl (a, ring->moduli[i]->p);

        cb = _get_crtcoeff (b->crtrep, i, 0, deg);
        cr = _get_crtcoeff (r->crtrep, i, 0, deg);
        hexl_ntt_scale (cr, _a, cb, deg, ring->moduli[i]->p, 1);
      }
    }
  else
    {
#endif
  INTVEC_T (tmp, polyring_get_deg (ring), 2 * a->nlimbs);

  _fromcrt (b); // XXX can also do this in crt dom

  r->crt = 0;
  intvec_scale (tmp, a, _get_coeffvec_src (b));
  intvec_mod (r->coeffs, tmp, ring->q);
  intvec_redc (r->coeffs, r->coeffs, ring->q);
  //}
}

/* option-4 prune (no-inline reachability): ld discarded .text.poly_rshift */

void
poly_lshift (poly_t r, poly_t a, unsigned int n)
{
  ASSERT_ERR (poly_get_ring (r) == poly_get_ring (a));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt lshift");
#endif
  _fromcrt (a);

  r->crt = 0;
  intvec_lshift (r->coeffs, a->coeffs, n);
}

/* option-4 prune (no-inline reachability): ld discarded .text.poly_rrot */

void
poly_lrot (poly_t r, poly_t a, unsigned int n)
{
  ASSERT_ERR (poly_get_ring (r) == poly_get_ring (a));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt lrot");
#endif
  _fromcrt (a);

  r->crt = 0;
  intvec_lrot (r->coeffs, a->coeffs, n);
}

void
poly_mod (poly_t r, poly_t a)
{
  polyring_srcptr ring = poly_get_ring (r);

  ASSERT_ERR (poly_get_ring (r) == poly_get_ring (a));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt mod");
#endif
  _fromcrt (a);

  r->crt = 0;
  intvec_mod (r->coeffs, a->coeffs, ring->q);
}

void
poly_redc (poly_t r, poly_t a)
{
  polyring_srcptr ring = poly_get_ring (r);

  ASSERT_ERR (poly_get_ring (r) == poly_get_ring (a));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt redc");
#endif
  _fromcrt (a);

  r->crt = 0;
  intvec_redc (r->coeffs, a->coeffs, ring->q);
}

void
poly_redp (poly_t r, poly_t a)
{
  polyring_srcptr ring = poly_get_ring (r);

  ASSERT_ERR (poly_get_ring (r) == poly_get_ring (a));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt redp");
#endif
  _fromcrt (a);

  r->crt = 0;
  intvec_redp (r->coeffs, a->coeffs, ring->q);
}

int
poly_eq (poly_t a, poly_t b)
{
  ASSERT_ERR (poly_get_ring (a) == poly_get_ring (b));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt eq");
#endif
  _fromcrt (a);
#if DEBUGINFO == DEBUGINFO_ENABLED
  if (b->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt eq");
#endif
  _fromcrt (b);

  return intvec_eq (_get_coeffvec_src (a), _get_coeffvec_src (b));
}

void
poly_toisoring (polyvec_t vec, poly_t a)
{
  polyring_srcptr Rprime = poly_get_ring (a);
  polyring_srcptr R = polyvec_get_ring (vec);
  const unsigned int dprime = polyring_get_deg (Rprime);
  const unsigned int d = polyring_get_deg (R);
  const unsigned int k = dprime / d;
  unsigned int i, j, l;
  poly_ptr poly;
  int_ptr coeffprime, coeff;

  ASSERT_ERR (!a->crt);
  ASSERT_ERR (d * k == dprime);
  ASSERT_ERR (polyvec_get_nelems (vec) == k);
  // XXXASSERT_ERR (int_eq (polyring_get_mod (Rprime), polyring_get_mod (R)) ==
  // 1);

  for (i = 0; i < k; i++)
    {
      poly = polyvec_get_elem (vec, i);
      poly->crt = 0;
      for (j = 0; j < d; j++)
        {
          l = k * j + i;

          coeffprime = poly_get_coeff (a, l);
          coeff = poly_get_coeff (poly, j);
          int_set (coeff, coeffprime);
        }
    }
}

/* option-4 prune (no-inline reachability): ld discarded .text.poly_fromisoring */

void
poly_mul (poly_t r, poly_t a, poly_t b)
{
  polyring_srcptr ring = r->ring;
  const unsigned int deg = polyring_get_deg (ring);
  unsigned int i;
  crtcoeff_t *ca, *cb, *cr;

  ASSERT_ERR (r->ring == a->ring);
  ASSERT_ERR (r->ring == b->ring);

  _tocrt (a);
  _tocrt (b);

  if (r->crtrep == NULL)
    {
      ASSERT_ERR (r->crt == 0);
      r->crtrep = _alloc (_sizeof_crtrep_data (ring));
    }
  r->crt = 1;

  _POLYRING_FOREACH_P (ring, i)
  {
#ifdef XXX
    crtcoeff_t p = ring->moduli[i]->p;
    crtcoeff_t pinv = ring->moduli[i]->mont_pinv;
    unsigned int j;
    crtcoeff_dbl_t tmp;

    for (j = 0; j < deg; j++)
      {
        ca = _get_crtcoeff (a->crtrep, i, j, deg);
        cb = _get_crtcoeff (b->crtrep, i, j, deg);
        cr = _get_crtcoeff (r->crtrep, i, j, deg);

        tmp = (crtcoeff_dbl_t)(*ca) * (*cb);
        *cr = _mont_rprod (tmp, p, pinv);
      }
#else
    ca = _get_crtcoeff (a->crtrep, i, 0, deg);
    cb = _get_crtcoeff (b->crtrep, i, 0, deg);
    cr = _get_crtcoeff (r->crtrep, i, 0, deg);
    hexl_ntt_mul (cr, ca, cb, 1, deg, ring->moduli[i]->p);
#endif
  }
}

void
poly_addmul (poly_t r, poly_t a, poly_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  poly_t tmp;

  poly_alloc (tmp, ring);

  poly_mul (tmp, a, b);
  poly_add (r, r, tmp, crt);

  poly_free (tmp);
}

/* option-4 prune (no-inline reachability): ld discarded .text.poly_submul */

/* option-4 prune (no-inline reachability): ld discarded .text.poly_addmul2 */

/* option-4 prune (no-inline reachability): ld discarded .text.poly_submul2 */

void
poly_adddot (poly_t r, polyvec_t a, polyvec_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  poly_t tmp;

  poly_alloc (tmp, ring);

  polyvec_dot (tmp, a, b);
  poly_add (r, r, tmp, crt);

  poly_free (tmp);
}

void
poly_adddot2 (poly_t r, spolyvec_t a, polyvec_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  poly_t tmp;

  poly_alloc (tmp, ring);

  polyvec_dot2 (tmp, a, b);
  poly_add (r, r, tmp, crt);

  poly_free (tmp);
}

/* option-4 prune (no-inline reachability): ld discarded .text.poly_subdot */

void
poly_addscale (poly_t r, int_t a, poly_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  poly_t tmp;

  poly_alloc (tmp, ring);

  poly_scale (tmp, a, b);
  poly_add (r, r, tmp, crt);

  poly_free (tmp);
}

/* option-4 prune (no-inline reachability): ld discarded .text.poly_subscale */

void
poly_tocrt (poly_t r)
{
  if (r->crt == 1)
    return;

  polyring_srcptr ring = poly_get_ring (r);
  const unsigned int deg = polyring_get_deg (ring);
  intvec_srcptr coeffs = r->coeffs;
  crtcoeff_t *crtrep;
  unsigned int i;
  void **hexl_ntts;
  // intvec_t tmp1;
  // INT_T (p, 1);
  crtcoeff_t *crtcoeff;

  DEBUG_PRINTF (DEBUG_PRINT_TOCRT, "crt %p", (void *)r);

  // intvec_alloc (tmp1, deg, 1); // XXX costs more than NTTs ...

  if (r->crtrep == NULL)
    r->crtrep = _alloc (_sizeof_crtrep_data (ring));
  r->crt = 1;

  hexl_ntts = (deg == 64 ? hexl_ntt_d64 : hexl_ntt_d128);

  crtrep = r->crtrep;
  _POLYRING_FOREACH_P (ring, i)
  {
#if 0
    int_set_i64 (p, ring->moduli[i]->p);

    intvec_mod (tmp1, coeffs, p); /* reduce to (-p,p) */
    // not needed, ntt input can be in (-p,p)
    // intvec_redc (tmp1, tmp1, p); /* reduce to (-(p-1)/2,(p-1)/2) */

    crtcoeff = _get_crtcoeff (crtrep, i, 0, deg);
#if CRTCOEFF_NBITS == 32
    intvec_get_i32 (crtcoeff, tmp1);
#else
#error "not implemented"
#endif
#else
    // XXX
    unsigned int j;
    for (j = 0; j < deg; j++)
      {
        crtcoeff = _get_crtcoeff (crtrep, i, j, deg);
        int_ptr coeff = intvec_get_elem (coeffs, j);
        *crtcoeff = int_mod_XXX_hexl (coeff, ring->moduli[i]->p);
      }
    crtcoeff = _get_crtcoeff (crtrep, i, 0, deg);
    // XXX
    //_ntt (crtcoeff, ring->moduli[i], deg);

    void *hexl_ntt = hexl_ntts[i];

    crtcoeff = _get_crtcoeff (crtrep, i, 0, deg);
    hexl_ntt_fwd (hexl_ntt, crtcoeff, 1, crtcoeff, 1);
#endif
  }
  // XXXintvec_free (tmp1);
}

void
poly_fromcrt (poly_t r)
{
  if (r->crt == 0)
    return;

  polyring_srcptr ring = poly_get_ring (r);
  const unsigned int deg = polyring_get_deg (ring);
  int_srcptr mod = polyring_get_mod (ring);
  intvec_ptr coeffs = _get_coeffvec (r);
  const unsigned int s = ring->nmoduli;
  crtcoeff_t *crtrep = r->crtrep;
  modulus_srcptr crtmod = ring->moduli[s - 1];
  crtcoeff_t *crtcoeff, x;
  crtcoeff_t p;
  int_ptr coeff;
  void **hexl_ntts;
  unsigned int i, j;
  float z;
  long round_z;

  if (ring->Ppmodq != NULL)
    {
#define ECRT 0
#if ECRT == 1
      INT_T (Pz, crtmod->P->nlimbs * 2);
      INT_T (tmp2, crtmod->P->nlimbs * 2);
      INT_T (tmp1, crtmod->P->nlimbs);
#else
      INT_T (Pz, ring->q->nlimbs + 1);
      INT_T (tmp2, ring->q->nlimbs + 1);
      INT_T (tmp1, ring->q->nlimbs * 2);
#endif

      DEBUG_PRINTF (DEBUG_PRINT_FROMCRT, "icrt %p", (void *)r);

      crtmod = ring->moduli[s - 1];
      hexl_ntts = (deg == 64 ? hexl_ntt_d64 : hexl_ntt_d128);

      _POLYRING_FOREACH_P (ring, i)
      {
        crtcoeff = _get_crtcoeff (crtrep, i, 0, deg);
        // XXX_intt (crtcoeff, ring->moduli[i], deg);

        void *hexl_ntt = hexl_ntts[i];

        crtcoeff = _get_crtcoeff (crtrep, i, 0, deg);
        hexl_ntt_inv (hexl_ntt, crtcoeff, 1, crtcoeff, 1);
        for (j = 0; j < deg; j++)
          {
            crtcoeff = _get_crtcoeff (crtrep, i, j, deg);
            // if (*crtcoeff > (ring->moduli[i]->p - 1) / 2)
            // XXX  *crtcoeff = *crtcoeff - ring->moduli[i]->p;
          }
      }

      _VEC_FOREACH_ELEM (coeffs, j)
      {
        coeff = intvec_get_elem (coeffs, j);
        int_set_i64 (Pz, 0);
        z = 0;

        _POLYRING_FOREACH_P (ring, i)
        {
          p = ring->moduli[i]->p;

          crtcoeff = _get_crtcoeff (crtrep, i, j, deg);
          // if (*crtcoeff > (p - 1) / 2)
          //   *crtcoeff -= p;
          // else if (*crtcoeff < -(p - 1) / 2)
          //   *crtcoeff += p;
          //  XXX

          x = ((crtcoeff_dbl_t)crtmod->k[i] * (*crtcoeff))
              % p; // XXX in (-p,p)
                   // XXX
                   // if (x > (p - 1) / 2)
                   //  x -= p;
                   // else if (x < -(p - 1) / 2)
                   //  x += p;
                   // XXX

#if ECRT == 1
          int_set_i64 (tmp1, x);
          int_mul (tmp2, crtmod->Pp[i], tmp1);
#else
          int_mul1 (tmp2, ring->Ppmodq[i], x);
#endif
          int_add (Pz, Pz, tmp2);

          z += (float)x / p;
        }

        round_z = lroundf (z);

#if ECRT == 1
        int_set_i64 (tmp1, round_z);
        int_mul (tmp2, crtmod->P, tmp1);
#else
        int_mul1 (tmp2, ring->Pmodq, round_z);
#endif

        int_sub (Pz, Pz, tmp2);

#if ECRT == 1
        int_mod (coeff, Pz, mod);
        int_redc (coeff, coeff, mod);
#else
        int_set (tmp1, Pz);
        int_mod (coeff, tmp1, mod);
        int_redc (coeff, coeff, mod);
#endif
      }

      _free (r->crtrep, _sizeof_crtrep_data (ring));
      r->crtrep = NULL;
      r->crt = 0;
    }
  else
    {
#undef ECRT
#define ECRT 1
#if ECRT == 1
      INT_T (Pz, crtmod->P->nlimbs * 2);
      INT_T (tmp2, crtmod->P->nlimbs * 2);
      INT_T (tmp1, crtmod->P->nlimbs);
#else
      INT_T (Pz, ring->q->nlimbs + 1);
      INT_T (tmp2, ring->q->nlimbs + 1);
      INT_T (tmp1, ring->q->nlimbs * 2);
#endif

      DEBUG_PRINTF (DEBUG_PRINT_FROMCRT, "icrt %p", (void *)r);

      crtmod = ring->moduli[s - 1];
      hexl_ntts = (deg == 64 ? hexl_ntt_d64 : hexl_ntt_d128);

      _POLYRING_FOREACH_P (ring, i)
      {
        crtcoeff = _get_crtcoeff (crtrep, i, 0, deg);
        // XXX_intt (crtcoeff, ring->moduli[i], deg);

        void *hexl_ntt = hexl_ntts[i];

        crtcoeff = _get_crtcoeff (crtrep, i, 0, deg);
        hexl_ntt_inv (hexl_ntt, crtcoeff, 1, crtcoeff, 1);
        for (j = 0; j < deg; j++)
          {
            crtcoeff = _get_crtcoeff (crtrep, i, j, deg);
            // if (*crtcoeff > (ring->moduli[i]->p - 1) / 2)
            // XXX  *crtcoeff = *crtcoeff - ring->moduli[i]->p;
          }
      }

      _VEC_FOREACH_ELEM (coeffs, j)
      {
        coeff = intvec_get_elem (coeffs, j);
        int_set_i64 (Pz, 0);
        z = 0;

        _POLYRING_FOREACH_P (ring, i)
        {
          p = ring->moduli[i]->p;

          crtcoeff = _get_crtcoeff (crtrep, i, j, deg);
          // if (*crtcoeff > (p - 1) / 2)
          //   *crtcoeff -= p;
          // else if (*crtcoeff < -(p - 1) / 2)
          //   *crtcoeff += p;
          //  XXX

          x = ((crtcoeff_dbl_t)crtmod->k[i] * (*crtcoeff))
              % p; // XXX in (-p,p)
                   // XXX
                   // if (x > (p - 1) / 2)
                   //  x -= p;
                   // else if (x < -(p - 1) / 2)
                   //  x += p;
                   // XXX

#if ECRT == 1
          int_set_i64 (tmp1, x);
          int_mul (tmp2, crtmod->Pp[i], tmp1);
#else
          int_mul1 (tmp2, ring->Ppmodq[i], x);
#endif
          int_add (Pz, Pz, tmp2);

          z += (float)x / p;
        }

        round_z = lroundf (z);

#if ECRT == 1
        int_set_i64 (tmp1, round_z);
        int_mul (tmp2, crtmod->P, tmp1);
#else
        int_mul1 (tmp2, ring->Pmodq, round_z);
#endif

        int_sub (Pz, Pz, tmp2);

#if ECRT == 1
        int_mod (coeff, Pz, mod);
        int_redc (coeff, coeff, mod);
#else
        int_set (tmp1, Pz);
        int_mod (coeff, tmp1, mod);
        int_redc (coeff, coeff, mod);
#endif
      }

      _free (r->crtrep, _sizeof_crtrep_data (ring));
      r->crtrep = NULL;
      r->crt = 0;
    }
}

/* option-4 prune (no-inline reachability): ld discarded .text.poly_grandom */

/* option-4 prune (no-inline reachability): ld discarded .text.poly_urandom */

void
poly_urandom_autostable (poly_t r, int64_t bnd, unsigned int log2,
                         const uint8_t seed[32], uint32_t dom)
{
  _poly_urandom_autostable (r, bnd, log2, seed, dom);
}

/* option-4 prune (no-inline reachability): ld discarded .text.poly_urandom_bnd */

/* option-4 prune (no-inline reachability): ld discarded .text.poly_brandom */

/* option-4 prune (no-inline reachability): ld discarded .text.poly_tracemap */

void
poly_auto (poly_t r, poly_t a)
{
  ASSERT_ERR (r != a);

#ifdef XXX
  /* o-1 auto in crt form reverses crt coeffs */
  if (a->crt == 1)
    {
      crtcoeff_t *ca, *cr;
      polyring_srcptr ring = poly_get_ring (a);
      const unsigned int deg = polyring_get_deg (ring);
      unsigned int i, j;

      if (r->crtrep == NULL)
        r->crtrep = _alloc (_sizeof_crtrep_data (ring));
      r->crt = 1;

      _POLYRING_FOREACH_P (ring, i)
      {
        for (j = 0; j < deg; j++)
          {
            cr = _get_crtcoeff (r->crtrep, i, j, deg);
            ca = _get_crtcoeff (a->crtrep, i, deg - j - 1, deg);

            *cr = *ca;
          }
      }
    }
  else
    {
      intvec_ptr rcoeffvec = _get_coeffvec (r);
      intvec_ptr acoeffvec = _get_coeffvec (a);

      intvec_auto (rcoeffvec, acoeffvec);
    }

  /* o-1 auto in crt form reverses crt coeffs */
  if (a->crt == 1)
    {
      crtcoeff_t *ca, *cb, tmp;
      polyring_srcptr ring = poly_get_ring (a);
      const unsigned int deg = polyring_get_deg (ring);
      unsigned int i, j;

      _POLYRING_FOREACH_P (ring, i)
      {
        for (j = 0; j < deg / 2; j++)
          {
            ca = _get_crtcoeff (a->crtrep, i, j, deg);
            cb = _get_crtcoeff (a->crtrep, i, deg - j - 1, deg);

            tmp = *cb;
            *cb = *ca;
            *ca = tmp;
          }
      }
    }
  else
    {
      intvec_ptr rcoeffvec = _get_coeffvec (r);
      intvec_ptr acoeffvec = _get_coeffvec (a);

      intvec_auto (rcoeffvec, acoeffvec);
    }
#endif

  intvec_ptr rcoeffvec = _get_coeffvec (r);
  intvec_ptr acoeffvec = _get_coeffvec (a);

  ASSERT_ERR (r->ring == a->ring);

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt auto");
#endif
  _fromcrt (a);

  intvec_auto (rcoeffvec, acoeffvec);
  r->crt = 0;
}

void
poly_auto_self (poly_t r)
{
  /* o-1 auto in crt form reverses crt coeffs */
  if (r->crt == 1)
    {
      crtcoeff_t *crb, *cre, tmp;
      polyring_srcptr ring = poly_get_ring (r);
      const unsigned int deg = polyring_get_deg (ring);
      unsigned int i, j;

      _POLYRING_FOREACH_P (ring, i)
      {
        for (j = 0; j < deg / 2; j++)
          {
            crb = _get_crtcoeff (r->crtrep, i, j, deg);
            cre = _get_crtcoeff (r->crtrep, i, deg - j - 1, deg);

            tmp = *crb;
            *crb = *cre;
            *cre = tmp;
          }
      }
    }
  else
    {
      intvec_ptr rcoeffvec = _get_coeffvec (r);

      intvec_auto_self (rcoeffvec);
    }
}

/* option-4 prune (no-inline reachability): ld discarded .text.poly_dcompress_power2round */

/* option-4 prune (no-inline reachability): ld discarded .text.poly_dcompress_decompose */

void
poly_dcompress_use_ghint (poly_t ret, poly_t y, poly_t r,
                          const dcompress_params_t params)
{
  intvec_ptr retcoeffvec = _get_coeffvec (ret);
  intvec_ptr ycoeffvec = _get_coeffvec (y);
  intvec_ptr rcoeffvec = _get_coeffvec (r);

  ASSERT_ERR (ret->ring == y->ring);
  ASSERT_ERR (ret->ring == r->ring);

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (y->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt dcompress use ghint");
#endif
  _fromcrt (y);
#if DEBUGINFO == DEBUGINFO_ENABLED
  if (r->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt dcompress use ghint");
#endif
  _fromcrt (r);

  dcompress_use_ghint (retcoeffvec, ycoeffvec, rcoeffvec, params);
  ret->crt = 0;
}

/* option-4 prune (no-inline reachability): ld discarded .text.poly_dcompress_make_ghint */

void
poly_l2sqr (int_t r, poly_t a)
{
  _fromcrt (a);

  intvec_l2sqr (r, poly_get_coeffvec (a));
}

void
poly_linf (int_t r, poly_t a)
{
  _fromcrt (a);

  intvec_linf (r, poly_get_coeffvec (a));
}

/* option-4 prune (no-inline reachability): ld discarded .text.poly_out_str */

/* option-4 prune (no-inline reachability): ld discarded .text.poly_dump */

static void
_poly_urandom (poly_t r, const int_t mod, unsigned int log2mod,
               const uint8_t seed[32], uint64_t dom)
{
  intvec_ptr coeffvec = _get_coeffvec (r);

  r->crt = 0;
  _intvec_urandom (coeffvec, mod, log2mod, seed, dom);
}

/* option-4 prune (no-inline reachability): ld discarded .text._poly_brandom */

/* option-4 prune (no-inline reachability): ld discarded .text._poly_grandom */

static void
_poly_urandom_autostable (poly_t r, int64_t bnd, unsigned int log2,
                          const uint8_t seed[32], uint64_t dom)
{
  _intvec_urandom_autostable (r->coeffs, bnd, log2, seed, dom);
  r->crt = 0;
}

/* option-4 prune (no-inline reachability): ld discarded .text._poly_urandom_bnd */
