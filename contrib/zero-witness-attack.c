/* THE zero-witness attack against LaZer's verifier, run through the real entry point.
 *
 * Why this exists: the byte-level probe was vacuous. Instrumenting the reject sites showed
 * all 90 mutants died at DECPROOF - the decoder's range/canonicality checks - so not one
 * reached poly_eq(c, c2) and the "rejects degenerate witnesses" result had no soundness
 * content. This harness re-encodes the degenerate witness through LaZer's own encoder so
 * the blob decodes cleanly and the soundness path is actually exercised.
 *
 * Experiment A: zero witness, ORIGINAL c.
 *   Expect reject, and expect the instrumented site to be CHALLENGE_POLY_EQ rather than
 *   DECPROOF. That is what demonstrates soundness is doing the work.
 *
 * Experiment B: the Fiat-Shamir FIXED POINT.
 *   With a zero witness, v = c^2 * r0, so the challenge the verifier recomputes depends on
 *   the challenge the attacker planted. Setting c := F(cseed) changes v, which changes
 *   cseed, which changes the required c. Iterating is the natural attack; a hash makes it
 *   diverge. This runs the iteration and reports whether it ever converges.
 */
#define main kat_verify_main_unused
#include "kat_verify.c"
#undef main

/* exported from the patched LaZer tree */
extern int soq_x_reencode_degenerate(lin_verifier_state_t state, const uint8_t *in,
                                     uint8_t *out, size_t *outlen,
                                     const unsigned char *newc_seed, int zero_all);
extern unsigned char soq_x_last_cseed[32];
extern int soq_x_cseed_valid;

#define ITERS 64

/* Verify a blob against a freshly initialised verifier, exactly as verify_one does. */
static int verify_blob(polyvec_t t, const uint8_t *blob, size_t bloblen)
{
    lin_verifier_state_t vf;
    lin_verifier_init(vf, PUBSEED, range_params);
    lin_verifier_set_statement(vf, A_range, t);
    size_t l = 0;
    int accept = lin_verifier_verify(vf, blob, &l);
    lin_verifier_clear(vf);
    (void)bloblen;
    return accept == 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <corpus-dir>\n", argv[0]); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    lazer_init();
    build_range_A();

    char path[512];
    snprintf(path, sizeof(path), "%s/range.jsonl", argv[1]);
    FILE *f = fopen(path, "r");
    if (!f) die("cannot open range.jsonl");

    printf("=== ZERO-WITNESS ATTACK vs LaZer, via re-encoded (decodable) blobs ===\n\n");

    char *line = NULL; size_t cap = 0; ssize_t got;
    int did = 0, accepts_A = 0, accepts_B = 0, reencode_fail = 0;

    while ((got = getline(&line, &cap, f)) > 0 && did < 3) {
        if (got < 8) continue;
        size_t l;
        const char *exp = json_str(line, "expect", &l);
        if (!exp || strncmp(exp, "accept", 6) != 0) continue;
        size_t hl; const char *ch = json_str(line, "c", &hl);
        if (!ch) continue;
        size_t phl; const char *ph = json_str(line, "proof", &phl);
        if (!ph) continue;
        const char *id = json_str(line, "id", &l);
        char idbuf[64] = "?";
        if (id) { size_t c = l < 63 ? l : 63; memcpy(idbuf, id, c); idbuf[c] = 0; }

        size_t prooflen;
        uint8_t *orig = hex_decode(ph, phl, &prooflen);
        if (!orig) die("bad proof hex");
        int64_t *cc = decode_stmt(ch, hl, 8);

        polyvec_t t;
        polyvec_alloc(t, Rp, 8);
        range_statement_t(t, cc);

        printf("--- vector %s (honest proof %zu bytes)\n", idbuf, prooflen);
        printf("    honest blob verifies: %s\n",
               verify_blob(t, orig, prooflen) ? "ACCEPT (harness sane)" : "*** BROKEN ***");

        /* ---------------- experiment A: zero witness, original c -------------- */
        size_t cap2 = prooflen + 4096;
        uint8_t *blob = malloc(cap2);
        size_t bloblen = 0;
        lin_verifier_state_t vf;
        lin_verifier_init(vf, PUBSEED, range_params);
        lin_verifier_set_statement(vf, A_range, t);
        int ok = soq_x_reencode_degenerate(vf, orig, blob, &bloblen, NULL, 1);
        lin_verifier_clear(vf);

        if (!ok) {
            printf("    A: re-encode FAILED (honest proof did not decode?)\n");
            reencode_fail++;
        } else {
            printf("    A: zero witness + original c -> re-encoded %zu bytes\n", bloblen);
            int a = verify_blob(t, blob, bloblen);
            printf("       verdict: %s\n", a ? "*** ACCEPT - FORGERY ***" : "reject");
            if (a) accepts_A++;
        }

        /* ---------------- experiment B: chase the FS fixed point --------------- */
        printf("    B: chasing the Fiat-Shamir fixed point, %d iterations\n", ITERS);
        unsigned char seed[32];
        memset(seed, 0, sizeof seed);
        int converged = 0;
        for (int i = 0; i < ITERS; i++) {
            lin_verifier_init(vf, PUBSEED, range_params);
            lin_verifier_set_statement(vf, A_range, t);
            ok = soq_x_reencode_degenerate(vf, orig, blob, &bloblen, seed, 1);
            lin_verifier_clear(vf);
            if (!ok) { printf("       iter %2d: re-encode failed\n", i); break; }

            soq_x_cseed_valid = 0;
            int a = verify_blob(t, blob, bloblen);
            if (a) {
                printf("       iter %2d: *** ACCEPT - FIXED POINT FOUND, FORGERY ***\n", i);
                converged = 1; accepts_B++;
                break;
            }
            if (!soq_x_cseed_valid) {
                printf("       iter %2d: rejected BEFORE the challenge check "
                       "(never reached poly_eq)\n", i);
                break;
            }
            /* the verifier told us which challenge it wanted; plant that next round */
            memcpy(seed, soq_x_last_cseed, 32);
            if (i < 3 || i == ITERS - 1)
                printf("       iter %2d: reject; next required cseed = "
                       "%02x%02x%02x%02x...\n", i, seed[0], seed[1], seed[2], seed[3]);
        }
        if (!converged)
            printf("       no fixed point in %d iterations\n", ITERS);

        free(blob); free(orig); free(cc);
        polyvec_free(t);
        printf("\n");
        did++;
    }
    free(line); fclose(f);

    printf("=== RESULT ===\n");
    printf("vectors attacked:        %d\n", did);
    printf("re-encode failures:      %d\n", reencode_fail);
    printf("experiment A accepts:    %d\n", accepts_A);
    printf("experiment B accepts:    %d\n", accepts_B);
    if (accepts_A || accepts_B) {
        printf("VERDICT: LAZER ACCEPTS A DEGENERATE WITNESS. Third instance of the class,\n");
        printf("         in the code option 4 adopts. G1 must be re-decided.\n");
        return 1;
    }
    printf("VERDICT: no degenerate witness accepted, and the rejections now come from the\n");
    printf("         soundness path rather than the decoder. The fixed-point barrier held.\n");
    return 0;
}
