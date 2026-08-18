/* Execute the VENDORED degenerate-witness reject class against the extracted verifier.
 *
 * This is the pinned-to-executed transition. Until now the 18 vectors in
 * src/test/data/soquobscura-kat/degenerate.jsonl had never been run against anything: the
 * probe generated its own mutants on the fly, and the in-repo test only gates integrity and
 * shape because there is no verifier in-tree yet.
 *
 * Unlike the family files, degenerate.jsonl mixes all three relations in one file, so each
 * line is dispatched on its "relation" field. Every vector must REJECT; an accept is a forgery,
 * not a test case, and this harness exits non-zero on one.
 */
#define main kat_verify_main_unused
#include "kat_verify.c"
#undef main

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <jsonl> [more.jsonl ...]\n", argv[0]); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    lazer_init();
    build_range_A();
    build_balance_A();

    int total = 0, ok = 0, wrong = 0;
    for (int a = 1; a < argc; a++) {
        FILE *f = fopen(argv[a], "r");
        if (!f) { fprintf(stderr, "cannot open %s\n", argv[a]); return 2; }
        printf("=== %s\n", argv[a]);
        char *line = NULL; size_t cap = 0; ssize_t got;
        while ((got = getline(&line, &cap, f)) > 0) {
            if (got < 8) continue;
            size_t l, hl, phl;
            const char *rel = json_str(line, "relation", &l);
            const char *exp = json_str(line, "expect", &l);
            const char *ph  = json_str(line, "proof", &phl);
            const char *idp = json_str(line, "id", &l);
            if (!rel || !exp || !ph) { fprintf(stderr, "malformed line\n"); return 2; }
            char idbuf[80] = "?";
            if (idp) { size_t c = l < 79 ? l : 79; memcpy(idbuf, idp, c); idbuf[c] = 0; }
            int expect_accept = strncmp(exp, "accept", 6) == 0;

            size_t prooflen;
            uint8_t *proof = hex_decode(ph, phl, &prooflen);
            if (!proof) { fprintf(stderr, "%s: bad proof hex\n", idbuf); return 2; }

            int accept;
            if (strncmp(rel, "range", 5) == 0) {
                const char *ch = json_str(line, "c", &hl);
                int64_t *cc = decode_stmt(ch, hl, 8);
                polyvec_t t; polyvec_alloc(t, Rp, 8);
                range_statement_t(t, cc);
                accept = verify_one(A_range, t, range_params, proof, prooflen);
                polyvec_free(t); free(cc);
            } else if (strncmp(rel, "balance", 7) == 0) {
                const char *cin = strstr(line, "\"c_in\": [\"");
                const char *cout = strstr(line, "\"c_out\": [\"");
                const char *feep = json_str(line, "fee", &l);
                if (!cin || !cout || !feep) { fprintf(stderr, "%s: bad balance stmt\n", idbuf); return 2; }
                cin += strlen("\"c_in\": [\""); cout += strlen("\"c_out\": [\"");
                const char *cin1 = strstr(cin, "\", \"");
                const char *cout1 = strstr(cout, "\", \"");
                int64_t *a0 = decode_stmt(cin, (size_t)(cin1 - cin), 8);
                int64_t *a1 = decode_stmt(cin1 + 4, 8 * 512, 8);
                int64_t *b0 = decode_stmt(cout, (size_t)(cout1 - cout), 8);
                int64_t *b1 = decode_stmt(cout1 + 4, 8 * 512, 8);
                uint64_t fee = strtoull(feep, NULL, 10);
                polyvec_t t; polyvec_alloc(t, Rp, 12);
                balance_statement_t(t, a0, a1, b0, b1, fee);
                accept = verify_one(A_bal, t, balance_params, proof, prooflen);
                polyvec_free(t); free(a0); free(a1); free(b0); free(b1);
            } else if (strncmp(rel, "ve", 2) == 0) {
                const char *vks = json_str(line, "vk_seed", &hl);
                size_t vklen; uint8_t *vk = hex_decode(vks, hl, &vklen);
                const char *tvh = json_str(line, "t_v", &hl);
                int64_t *tv = decode_stmt(tvh, hl, KDIM);
                const char *ch = json_str(line, "c", &hl);
                int64_t *cc = decode_stmt(ch, hl, 8);
                const char *c0h = json_str(line, "c0", &hl);
                int64_t *c0 = decode_stmt(c0h, hl, KDIM);
                const char *c1h = json_str(line, "c1", &hl);
                int64_t *c1 = decode_stmt(c1h, hl, 1);
                polymat_t A; polymat_alloc(A, Rp, 33, 74); polymat_set_zero(A);
                polyvec_t t; polyvec_alloc(t, Rp, 33);
                ve_statement(A, t, vk, tv, cc, c0, c1);
                accept = verify_one(A, t, ve_params, proof, prooflen);
                polymat_free(A); polyvec_free(t);
                free(vk); free(tv); free(cc); free(c0); free(c1);
            } else { fprintf(stderr, "%s: unknown relation %s\n", idbuf, rel); return 2; }
            free(proof);

            total++;
            int correct = (accept == expect_accept);
            if (correct) ok++; else wrong++;
            printf("  %-38s %-8s expect=%-7s %s\n", idbuf,
                   accept ? "ACCEPT" : "reject", expect_accept ? "accept" : "reject",
                   correct ? "ok" : (accept ? "*** ACCEPTED A REJECT VECTOR - FORGERY ***"
                                            : "*** REJECTED AN ACCEPT VECTOR ***"));
        }
        free(line); fclose(f);
    }
    printf("\n=== EXECUTED %d vectors: %d correct, %d wrong\n", total, ok, wrong);
    if (wrong) { printf("VERDICT: FAILED\n"); return 1; }
    printf("VERDICT: every vendored vector reproduces its pinned verdict.\n");
    return 0;
}
