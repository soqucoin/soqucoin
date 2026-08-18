/* Localise the optimisation-dependent statement matrix: is it polymat_urandom (seed-derived,
 * would be a LaZer determinism bug) or the post-product in-place side effect (would be our
 * Tier A harness depending on an implementation detail)?
 * Also prints a CRT-NORMALISED digest, to separate "different values" from "different
 * internal representation". */
#define main kat_verify_main_unused
#include "kat_verify.c"
#undef main

static unsigned long long fnv(const unsigned char *p, size_t n, unsigned long long h)
{ for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; } return h; }

static unsigned long long dig(polymat_t A, unsigned r, unsigned c, int normalise)
{
    unsigned long long h = 14695981039346656037ULL;
    int64_t buf[64];
    for (unsigned i = 0; i < r; i++)
        for (unsigned j = 0; j < c; j++) {
            poly_ptr p = polymat_get_elem(A, i, j);
            if (normalise) { poly_fromcrt(p); poly_mod(p, p); poly_redp(p, p); }
            poly_get_coeffvec_i64(buf, p);
            h = fnv((const unsigned char *)buf, sizeof buf, h);
        }
    return h;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    lazer_init();

    /* stage 1: exactly build_range_A_into's first two lines */
    polymat_t A;
    polymat_alloc(A, Rp, 8, LAM + 1);
    polymat_urandom(A, stmt_p, 32, PUBSEED, 0);
    printf("stage1 after polymat_urandom      raw=%016llx\n", dig(A, 8, LAM + 1, 0));

    /* stage 2: the post-product side effect, result discarded */
    polyvec_t zs, zr;
    polyvec_alloc(zs, Rp, LAM + 1);
    polyvec_alloc(zr, Rp, 8);
    zero_polyvec(zs, LAM + 1);
    polyvec_mul(zr, A, zs);
    printf("stage2 after post-product mul     raw=%016llx\n", dig(A, 8, LAM + 1, 0));
    printf("stage2 CRT-normalised             nrm=%016llx\n", dig(A, 8, LAM + 1, 1));
    return 0;
}
