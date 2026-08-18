#include "lazer.h"
#include "stopwatch.h"

/* option-4 prune (no-inline reachability): ld discarded .text.lnp_quad_prove */

int
lnp_quad_verify (uint8_t hash[32], poly_t c, polyvec_t z1, polyvec_t z21,
                 polyvec_t h, polyvec_t tA1, polyvec_t tB, polymat_t A1,
                 polymat_t A2prime, polymat_t Bprime, spolymat_t R2,
                 spolyvec_t r1, poly_t r0, const abdlop_params_t params)
{
  polyring_srcptr Rq = params->ring;
  const unsigned int kmsis = params->kmsis;
  const unsigned int m1 = params->m1;
  const unsigned int m2 = params->m2;
  const unsigned int l = params->l;
  const unsigned int lext = params->lext;
  const unsigned int log2q = polyring_get_log2q (Rq);
  const unsigned int d = polyring_get_deg (Rq);
  int_srcptr q = polyring_get_mod (Rq);
  const unsigned int nlimbs = int_get_nlimbs (q);
  dcompress_params_srcptr dcomp_param = params->dcompress;
  int_srcptr gamma = dcompress_get_gamma (dcomp_param);
  int_srcptr m = dcompress_get_m (dcomp_param);
  const unsigned int D = dcompress_get_d (dcomp_param);
  const unsigned int log2m = dcompress_get_log2m (dcomp_param);
  int_srcptr m_ = dcompress_get_m (dcomp_param);
  INT_T (l2sqr, nlimbs * 2);
  INT_T (bnd, nlimbs * 2);
  INT_T (linf, nlimbs);
  INT_T (tmp, 1);
  unsigned int outlen;
  shake128_state_t hstate;
  polyvec_t suba, suba_auto, subb, subb_auto, tB_, t, z, tmp3, w1, tmp1, f;
  polymat_t Bprime_, bextprime;
  poly_t tmp2, c2, v;
  coder_state_t cstate;
  /* buff for encoding of t,v,w1 */
  uint8_t out[CEIL (2 * log2q * d + log2m * d * kmsis, 8) + 1];
  uint8_t cseed[32];
  int b, accept = 0;

  STOPWATCH_START (stopwatch_lnp_quad_verify, "lnp_quad_verify");

  ASSERT_ERR (lext == 1);
  ASSERT_ERR (poly_get_ring (c) == Rq);
  ASSERT_ERR (polyvec_get_ring (z1) == Rq);
  ASSERT_ERR (polyvec_get_nelems (z1) == m1);
  ASSERT_ERR (polyvec_get_ring (z21) == Rq);
  ASSERT_ERR (polyvec_get_nelems (z21) == m2 - kmsis);
  ASSERT_ERR (polyvec_get_ring (h) == Rq);
  ASSERT_ERR (polyvec_get_nelems (h) == kmsis);
  ASSERT_ERR (polyvec_get_ring (tA1) == Rq);
  ASSERT_ERR (polyvec_get_nelems (tA1) == kmsis);
  ASSERT_ERR (polyvec_get_ring (tB) == Rq);
  ASSERT_ERR (polyvec_get_nelems (tB) == l + lext);
  ASSERT_ERR (polymat_get_ring (A1) == Rq);
  ASSERT_ERR (polymat_get_nrows (A1) == kmsis);
  ASSERT_ERR (polymat_get_ncols (A1) == m1);
  ASSERT_ERR (polymat_get_ring (A2prime) == Rq);
  ASSERT_ERR (polymat_get_nrows (A2prime) == kmsis);
  ASSERT_ERR (polymat_get_ncols (A2prime) == m2 - kmsis);
  ASSERT_ERR (polymat_get_ring (Bprime) == Rq);
  ASSERT_ERR (polymat_get_nrows (Bprime) == l + lext);
  ASSERT_ERR (polymat_get_ncols (Bprime) == m2 - kmsis);
  ASSERT_ERR (spolymat_is_upperdiag (R2));
  ASSERT_ERR (spolymat_get_ring (R2) == Rq);
  ASSERT_ERR (spolymat_get_nrows (R2) == 2 * (m1 + l));
  ASSERT_ERR (spolymat_get_ncols (R2) == 2 * (m1 + l));
  ASSERT_ERR (spolyvec_get_ring (r1) == Rq);
  ASSERT_ERR (r1->nelems_max == 2 * (m1 + l));

  polyvec_alloc (z, Rq, 2 * (m1 + l));
  polyvec_alloc (tmp3, Rq, 2 * (m1 + l));
  polyvec_alloc (w1, Rq, kmsis);
  polyvec_alloc (tmp1, Rq, kmsis);
  polyvec_alloc (f, Rq, 1);
  poly_alloc (tmp2, Rq);
  poly_alloc (c2, Rq);
  poly_alloc (v, Rq);

  polyvec_get_subvec (t, tB, l, lext, 1);
  polymat_get_submat (bextprime, Bprime, l, 0, lext, m2 - kmsis, 1, 1);
  if (l > 0)
    {
      polyvec_get_subvec (tB_, tB, 0, l, 1);
      polymat_get_submat (Bprime_, Bprime, 0, 0, l, m2 - kmsis, 1, 1);
    }

  /* recover w1 */

  polyvec_mul (tmp1, A1, z1);
  polyvec_addmul (tmp1, A2prime, z21, 0);
  poly_lshift (tmp2, c, D);
  polyvec_subscale2 (tmp1, tmp2, tA1, 0);

  polyvec_mod (tmp1, tmp1); // XXX
  polyvec_dcompress_use_ghint (w1, h, tmp1, dcomp_param);

  /* recover v */

  polyvec_scale2 (f, c, t);
  polyvec_submul (f, bextprime, z21, 0);

  polyvec_get_subvec (suba, z, 0, m1, 2);
  polyvec_get_subvec (suba_auto, z, 1, m1, 2);
  polyvec_set (suba, z1);
  polyvec_auto (suba_auto, z1);

  if (l > 0)
    {
      polyvec_get_subvec (subb, z, 2 * m1, l, 2);
      polyvec_get_subvec (subb_auto, z, 2 * m1 + 1, l, 2);
      polyvec_scale2 (subb, c, tB_);
      polyvec_submul (subb, Bprime_, z21, 0);
      polyvec_auto (subb_auto, subb);
    }

  poly_set (v, r0);                            /* r0 */
  poly_mul (v, c, v);                          /* c * r0 */
  poly_adddot2 (v, r1, z, 0);                  /* r1*z + c*r0*/
  poly_fromcrt (v);                            // XXX reduce
  poly_mul (v, c, v);                          /* c*r1*z + c^2*r0 */
  poly_sub (v, v, polyvec_get_elem (f, 0), 0); /* c*r1*z + c^2*r0 - f */
  polyvec_mulsparse (tmp3, R2, z);             /* R2*z */
  polyvec_fromcrt (tmp3);                      // XXX reduce
  poly_adddot (v, z, tmp3, 0); /* z*R2*z + c*r1*z + c^2*r0 - f*/
  poly_fromcrt (v);

  /* recover challenge from t, w1, v */
  polyvec_mod (t, t);
  polyvec_redp (t, t);
  poly_mod (v, v);
  poly_redp (v, v);

  coder_enc_begin (cstate, out);
  coder_enc_urandom3 (cstate, t, q, log2q);
  coder_enc_urandom2 (cstate, v, q, log2q);
  coder_enc_urandom3 (cstate, w1, m_, log2m);
  coder_enc_end (cstate);

  outlen = coder_get_offset (cstate);
  ASSERT_ERR (outlen % 8 == 0);
  ASSERT_ERR (outlen / 8 <= CEIL (2 * log2q * d + log2m * d * kmsis, 8) + 1);
  outlen >>= 3; /* nbits to nbytes */

  shake128_init (hstate);
  shake128_absorb (hstate, hash, 32);
  shake128_absorb (hstate, out, outlen);
  shake128_squeeze (hstate, cseed, 32);

  poly_urandom_autostable (c2, params->omega, params->log2omega, cseed, 0);
  b = poly_eq (c, c2);
  if (!b) {
    //printf("XXX recovering challenge failed.\n");
    goto ret;
  }

  /* check bounds */

  /*
   * l2(z1)^2 <= sigma1^2 * 2 * m1 *d = 1.55^2 * 2^(log2sigma1*2) * 2 * m1 * d
   * 1.55^2=2.4025, scale by 400: 1.55^2*400=962
   */
  int_set_i64 (tmp, 400);
  int_set_i64 (bnd, 2 * m1 * d * 962);
  int_lshift (bnd, bnd, 2 * params->log2stdev1);
  int_div (bnd, tmp, bnd, tmp); /* div by 400, overlap ok ? XXX */

  polyvec_l2sqr (l2sqr, z1);
  b = int_le (l2sqr, bnd);
  if (!b) {
    //printf("z1 norm bound check failed.");
    goto ret;
  }

  polyvec_subscale (tmp1, gamma, w1, 0);
  polyvec_l2sqr (l2sqr, tmp1);
  b = int_le (l2sqr, params->Bsqr);
  if (!b) {
    //printf("norm bound check failed.");
    goto ret;
  }

  /* 2*linf(h) <= m */
  polyvec_linf (linf, h);
  b = int_le (linf, m);
  if (!b) {
    //printf("h norm bound check failed.");
    goto ret;
  }

  /* update fiat-shamir hash */
  memcpy (hash, cseed, 32);
  accept = 1;
ret:
  /* cleanup */
  shake128_clear (hstate);
  polyvec_free (z);
  polyvec_free (tmp3);
  polyvec_free (w1);
  polyvec_free (tmp1);
  polyvec_free (f);
  poly_free (tmp2);
  poly_free (c2);
  poly_free (v);

  STOPWATCH_STOP (stopwatch_lnp_quad_verify);
  return accept;
}
