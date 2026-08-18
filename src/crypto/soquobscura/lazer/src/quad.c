#include "lazer.h"

/*
 * nrows(r1) linear eqs in n vars over Rprime
 * to k*(nrows(r1)) linear eqs in n*k vars over R.
 * k = dprime/d.
 */
void
lin_toisoring (polymat_t r1, polyvec_t r0, polymat_t r1prime,
               polyvec_t r0prime)
{
  polyring_srcptr Rprime = NULL;
  polyring_srcptr R = NULL;
  polyvec_t r1prime_;
  poly_ptr r0prime_, poly;
  unsigned int i, j, cnst, lin, neqs_cnst = 0, neqs_lin = 0;
#if ASSERT == ASSERT_ENABLED
  unsigned int n = 0;
#endif

  cnst = (r0prime != NULL ? 1 : 0);
  lin = (r1prime != NULL ? 1 : 0);

  ASSERT_ERR (cnst || lin);

  if (cnst)
    {
      ASSERT_ERR (r0 != NULL);

      Rprime = polyvec_get_ring (r0prime);
      R = polyvec_get_ring (r0);
      neqs_cnst = polyvec_get_nelems (r0prime);
    }
  if (lin)
    {
      ASSERT_ERR (r1 != NULL);

      Rprime = polymat_get_ring (r1prime);
      R = polymat_get_ring (r1);
#if ASSERT == ASSERT_ENABLED
      n = polymat_get_ncols (r1prime);
#endif
      neqs_lin = polymat_get_nrows (r1prime);
    }

  const unsigned int dprime = polyring_get_deg (Rprime);
  const unsigned int d = polyring_get_deg (R);
  const unsigned int k = dprime / d;

  ASSERT_ERR (d * k == dprime);
  ASSERT_ERR (!lin || polymat_get_nrows (r1) == k * neqs_lin);
  ASSERT_ERR (!lin || polymat_get_ncols (r1) == k * n);
  ASSERT_ERR (!cnst || polyvec_get_nelems (r0) == k * neqs_cnst);

  if (cnst)
    {
      for (i = 0; i < neqs_cnst; i++)
        {
          poly_ptr r0_[k];

          r0prime_ = polyvec_get_elem (r0prime, i);

          for (j = 0; j < k; j++)
            {
              poly = polyvec_get_elem (r0, i * k + j);
              r0_[j] = poly;
            }
          quad_toisoring (NULL, NULL, r0_, NULL, NULL, r0prime_);
        }
    }
  if (lin)
    {
      for (i = 0; i < neqs_lin; i++)
        {
          polyvec_ptr r1__[k];
          polyvec_t r1_[k];

          polymat_get_row (r1prime_, r1prime, i);

          for (j = 0; j < k; j++)
            {
              polymat_get_row (r1_[j], r1, i * k + j);
              r1__[j] = r1_[j];
            }
          quad_toisoring (NULL, r1__, NULL, NULL, r1prime_, NULL);
        }
    }
}

/*
 * 1 quadratic eq. in n vars over Rprime
 * to k quadratic eqs in n*k vars over R,
 * k = dprime/d
 */
void
quad_toisoring (polymat_ptr R2[], polyvec_ptr r1[], poly_ptr r0[],
                polymat_ptr R2prime, polyvec_ptr r1prime, poly_ptr r0prime)
{
  unsigned int n = 0;
  unsigned int d, dprime, k, i, j, l, m;
  int quad, lin, cnst, idx;
  polyring_srcptr Rprime = NULL;
  polyring_srcptr R = NULL;
  polyvec_t subv, subv2, tmp, tmp2;
  polymat_t subm;
  poly_t tmp3;
  poly_ptr poly;

  cnst = (r0prime != NULL ? 1 : 0);
  lin = (r1prime != NULL ? 1 : 0);
  quad = (R2prime != NULL ? 1 : 0);

  ASSERT_ERR (cnst || lin || quad);

  if (cnst)
    {
      ASSERT_ERR (r0 != NULL);

      Rprime = poly_get_ring (r0prime);
      R = poly_get_ring (r0[0]);
    }
  if (lin)
    {
      ASSERT_ERR (r1 != NULL);

      Rprime = polyvec_get_ring (r1prime);
      R = polyvec_get_ring (r1[0]);
      n = polyvec_get_nelems (r1prime);
    }
  if (quad)
    {
      ASSERT_ERR (R2 != NULL);

      Rprime = polymat_get_ring (R2prime);
      R = polymat_get_ring (R2[0]);
      n = polymat_get_nrows (R2prime);
    }

  dprime = polyring_get_deg (Rprime);
  d = polyring_get_deg (R);
  k = dprime / d;

  polyvec_alloc (tmp, R, k);
  polyvec_alloc (tmp2, R, k);
  poly_alloc (tmp3, R);

  ASSERT_ERR (d * k == dprime);
  //XXXASSERT_ERR (int_eq (polyring_get_mod (Rprime), polyring_get_mod (R)) == 1);
  ASSERT_ERR (!quad || polymat_get_nrows (R2prime) == n);
  ASSERT_ERR (!quad || polymat_get_ncols (R2prime) == n);
  ASSERT_ERR (!quad || polymat_is_upperdiag (R2prime));
  ASSERT_ERR (!lin || polyvec_get_nelems (r1prime) == n);
  for (i = 0; i < k; i++)
    {
      ASSERT_ERR (!quad || polymat_get_nrows (R2[i]) == n * k);
      ASSERT_ERR (!quad || polymat_get_ncols (R2[i]) == n * k);
      ASSERT_ERR (!lin || polyvec_get_nelems (r1[i]) == n * k);
    }

  if (cnst)
    {
      poly_toisoring (tmp, r0prime);

      for (i = 0; i < k; i++)
        poly_set (r0[i], polyvec_get_elem (tmp, i));
    }
  if (lin)
    {
      for (j = 0; j < n; j++)
        {
          poly = polyvec_get_elem (r1prime, j);
          poly_toisoring (tmp, poly);
          polyvec_lrot (tmp2, tmp, 1);

          for (i = 0; i < k; i++)
            {
              polyvec_get_subvec (subv, r1[i], j * k, k, 1);
              for (l = 0; l < k; l++)
                {
                  poly = polyvec_get_elem (subv, l);

                  idx = (int)i - l;
                  if (idx >= 0)
                    poly_set (poly, polyvec_get_elem (tmp, idx));
                  else
                    poly_set (poly, polyvec_get_elem (tmp2, k + idx));
                }
            }
        }
    }
  if (quad && 0) // XXX
    {
      for (l = 0; l < k; l++)
        {
          printf ("==========\n");
          polymat_set_zero (R2[l]);

          for (i = 0; i < n; i++)
            {
              for (j = i; j < n; j++)
                {
                  polymat_get_submat (subm, R2[l], i * k, j * k, k, k, 1, 1);

                  poly = polymat_get_elem (R2prime, i, j);
                  poly_toisoring (tmp, poly);

                  printf ("-- (%u,%u) --\n", i, j);
                  for (m = 0; m < 2 * k - 1; m++)
                    {
                      printf ("%d\n", (int)m - ((int)k - 1));
                      polymat_get_antidiag (subv, subm, (int)m - ((int)k - 1));

                      idx = (int)l - (int)m;
                      if (idx >= 0)
                        {
                          printf ("idx0  %d\n", idx);
                          poly = polyvec_get_elem (tmp, idx);
                          polyvec_fill (subv, poly);
                        }
                      else if (idx + (int)k >= 0)
                        {
                          printf ("idx1  %d\n", (int)idx + (int)k);
                          poly = polyvec_get_elem (tmp, (int)idx + (int)k);
                          poly_lrot (tmp3, poly, 1);
                          polyvec_fill (subv, tmp3);
                        }
                      else
                        {
                          printf ("idx2  %d\n", (int)idx + 2 * (int)k);
                          ASSERT_ERR (idx + 2 * (int)k >= 0);
                          poly = polyvec_get_elem (tmp, idx + 2 * (int)k);
                          poly_lrot (tmp3, poly, 2);
                          polyvec_fill (subv, tmp3);
                        }
                    }
                }
            }

          /* diagonalize */
          for (i = 1; i < k; i++)
            {
              polymat_get_diag (subv, R2[l], -(int)i);
              polymat_get_diag (subv2, R2[l], i);
              polyvec_add (subv2, subv2, subv, 0);
              polyvec_redc (subv2, subv2);
              polyvec_set_zero (subv);
            }
          ASSERT_ERR (polymat_is_upperdiag (R2[l]));
        }
    }

  polyvec_free (tmp);
  polyvec_free (tmp2);
  poly_free (tmp3);
}
