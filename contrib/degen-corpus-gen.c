/* Generate a DEGENERATE-WITNESS REJECT CLASS for the SoquObscura KAT corpus.
 *
 * Bead corpus-no-degenerate-witness-class-piz6: the pinned 64-vector corpus has 25 reject
 * vectors and NOT ONE is a degenerate witness, so it cannot detect the bug class proven
 * twice in our own consensus code. This closes that gap by emitting vectors that a sound
 * verifier must reject, produced through LaZer's own encoder so they DECODE cleanly and
 * therefore exercise the soundness path rather than the decoder.
 *
 * Three modes per source vector, and the THIRD is the one that matters:
 *   zero        - every prover-supplied field zeroed. Wire-reachable, but a
 *                 "reject if the witness is all zeros" patch would fake it.
 *   doubled     - every field doubled. Non-zero, but it EXCEEDS the per-relation wire cap,
 *                 so soq_lbpp_unwrap_proof rejects it as ERR_OVERSIZE before the verifier
 *                 ever runs. Useful as a verifier-level test, useless as a wire test.
 *   minnonzero  - all fields zeroed except a SINGLE z1 coefficient set to 1. Non-zero AND
 *                 under the cap, so it is genuinely wire-reachable. This is the member the
 *                 grading contract in DL-SOQUOBSCURA-P5-PORT-BRIEF.md actually requires.
 *
 * Every emitted vector is verified to be REJECTED before it is written. A vector that the
 * current verifier accepts is a forgery, not a test case, and the generator fails loudly.
 *
 * Output: one JSONL line per vector on stdout, derived from the source line by replacing
 * id/expect/proof/notes so that every statement field is preserved byte-for-byte.
 */
#define main kat_verify_main_unused
#include "kat_verify.c"
#undef main

extern int soq_x_reencode_degenerate2(lin_verifier_state_t state, const uint8_t *in,
                                      uint8_t *out, size_t *outlen, int mode);

/* per-relation wire caps from soq_lbpp_wire.h, so the generator can report reachability */
static unsigned wire_cap(const char *rel)
{
    if (strncmp(rel, "range", 5) == 0) return 22496u;
    if (strncmp(rel, "balance", 7) == 0) return 25140u;
    if (strncmp(rel, "ve", 2) == 0) return 30930u;
    return 0u;
}

#define MODE_ZERO 1
#define MODE_DOUBLED 2
#define MODE_MINNONZERO 3
#define PER_FAMILY 2 /* source vectors per family; x3 modes */

static const char *hexdig = "0123456789abcdef";

static char *to_hex(const uint8_t *b, size_t n)
{
    char *s = malloc(2 * n + 1);
    for (size_t i = 0; i < n; i++) {
        s[2 * i] = hexdig[b[i] >> 4];
        s[2 * i + 1] = hexdig[b[i] & 15];
    }
    s[2 * n] = 0;
    return s;
}

/* Replace the string value of "key" in a JSON line. Returns malloc'd result, or NULL. */
static char *json_replace_str(const char *line, const char *key, const char *val)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\": \"", key);
    const char *p = strstr(line, pat);
    if (!p) return NULL;
    const char *vs = p + strlen(pat);
    const char *ve = strchr(vs, '"');
    if (!ve) return NULL;
    size_t pre = (size_t)(vs - line), post = strlen(ve);
    char *out = malloc(pre + strlen(val) + post + 1);
    memcpy(out, line, pre);
    memcpy(out + pre, val, strlen(val));
    memcpy(out + pre + strlen(val), ve, post + 1);
    return out;
}

/* Build the statement for a vector and return an initialised verifier plus statement.
 * Returns 0 if the relation is unknown or fields are missing. */
struct stmt {
    polymat_t A;      /* ve only; otherwise unused          */
    int a_is_owned;   /* whether A must be freed            */
    polymat_ptr Ause; /* the matrix to hand the verifier     */
    polyvec_t t;
    const lin_params_t *params;
};

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <corpus-dir>\n", argv[0]); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    lazer_init();
    build_range_A();
    build_balance_A();

    struct { const char *file; const char *fam; } fams[] = {
        {"range.jsonl", "range"}, {"balance.jsonl", "balance"}, {"ve.jsonl", "ve"},
    };
    const struct { int mode; const char *suffix; const char *note; } modes[] = {
        {MODE_ZERO,    "degen-zero",
         "degenerate witness: every prover-supplied field zeroed, re-encoded through the LaZer encoder so it decodes cleanly. must reject."},
        {MODE_DOUBLED, "degen-doubled",
         "degenerate witness: every prover-supplied field DOUBLED. non-zero, but NOTE it exceeds the per-relation wire cap so soq_lbpp_unwrap_proof rejects it as ERR_OVERSIZE before the verifier runs. a verifier-level test only. must reject."},
        {MODE_MINNONZERO, "degen-minnonzero",
         "degenerate witness: all fields zeroed except a SINGLE z1 coefficient set to 1. the NON-ZERO member the grading contract requires, and unlike doubling it stays UNDER the wire cap so it is genuinely reachable through soq_lbpp_unwrap_proof. a reject-if-all-zeros patch cannot fake this one. must reject."},
    };

    int emitted = 0, bad_accepts = 0, reencode_fail = 0;

    for (size_t fi = 0; fi < sizeof(fams) / sizeof(fams[0]); fi++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", argv[1], fams[fi].file);
        FILE *f = fopen(path, "r");
        if (!f) { fprintf(stderr, "cannot open %s\n", path); return 2; }

        char *line = NULL; size_t cap = 0; ssize_t got;
        int used = 0;
        while ((got = getline(&line, &cap, f)) > 0 && used < PER_FAMILY) {
            if (got < 8) continue;
            size_t l;
            const char *exp = json_str(line, "expect", &l);
            if (!exp || strncmp(exp, "accept", 6) != 0) continue;
            const char *rel = json_str(line, "relation", &l);
            size_t phl; const char *ph = json_str(line, "proof", &phl);
            if (!rel || !ph) continue;
            const char *idp = json_str(line, "id", &l);
            char idbuf[64] = "?";
            if (idp) { size_t c = l < 63 ? l : 63; memcpy(idbuf, idp, c); idbuf[c] = 0; }
            /* skip the cmp-/prv- provenance vectors: keep the class on the primaries */
            if (strncmp(idbuf, "cmp-", 4) == 0 || strncmp(idbuf, "prv-", 4) == 0) continue;

            size_t prooflen;
            uint8_t *orig = hex_decode(ph, phl, &prooflen);
            if (!orig) { fprintf(stderr, "%s: bad proof hex\n", idbuf); return 2; }

            /* --- assemble the statement exactly as the gate does --- */
            polymat_t Ave; int have_ave = 0;
            polymat_ptr Ause = NULL;
            polyvec_t t;
            const lin_params_t *pp = NULL;
            size_t hl;

            if (strncmp(rel, "range", 5) == 0) {
                const char *ch = json_str(line, "c", &hl);
                int64_t *cc = decode_stmt(ch, hl, 8);
                polyvec_alloc(t, Rp, 8);
                range_statement_t(t, cc);
                Ause = A_range; pp = &range_params; free(cc);
            } else if (strncmp(rel, "balance", 7) == 0) {
                const char *cin = strstr(line, "\"c_in\": [\"");
                const char *cout = strstr(line, "\"c_out\": [\"");
                const char *feep = json_str(line, "fee", &l);
                if (!cin || !cout || !feep) { free(orig); continue; }
                cin += strlen("\"c_in\": [\""); cout += strlen("\"c_out\": [\"");
                const char *cin1 = strstr(cin, "\", \"");
                const char *cout1 = strstr(cout, "\", \"");
                if (!cin1 || !cout1) { free(orig); continue; }
                int64_t *a0 = decode_stmt(cin, (size_t)(cin1 - cin), 8);
                int64_t *a1 = decode_stmt(cin1 + 4, 8 * 512, 8);
                int64_t *b0 = decode_stmt(cout, (size_t)(cout1 - cout), 8);
                int64_t *b1 = decode_stmt(cout1 + 4, 8 * 512, 8);
                uint64_t fee = strtoull(feep, NULL, 10);
                polyvec_alloc(t, Rp, 12);
                balance_statement_t(t, a0, a1, b0, b1, fee);
                Ause = A_bal; pp = &balance_params;
                free(a0); free(a1); free(b0); free(b1);
            } else if (strncmp(rel, "ve", 2) == 0) {
                const char *vks = json_str(line, "vk_seed", &hl);
                size_t vklen; uint8_t *vk = vks ? hex_decode(vks, hl, &vklen) : NULL;
                if (!vk || vklen != 32) { free(orig); continue; }
                const char *tvh = json_str(line, "t_v", &hl);
                int64_t *tv = decode_stmt(tvh, hl, KDIM);
                const char *ch = json_str(line, "c", &hl);
                int64_t *cc = decode_stmt(ch, hl, 8);
                const char *c0h = json_str(line, "c0", &hl);
                int64_t *c0 = decode_stmt(c0h, hl, KDIM);
                const char *c1h = json_str(line, "c1", &hl);
                int64_t *c1 = decode_stmt(c1h, hl, 1);
                polymat_alloc(Ave, Rp, 33, 74);
                polymat_set_zero(Ave);
                polyvec_alloc(t, Rp, 33);
                ve_statement(Ave, t, vk, tv, cc, c0, c1);
                Ause = Ave; have_ave = 1; pp = &ve_params;
                free(vk); free(tv); free(cc); free(c0); free(c1);
            } else { free(orig); continue; }

            /* sanity: the honest proof must verify, else the statement is wrong */
            if (!verify_one(Ause, t, *pp, orig, prooflen)) {
                fprintf(stderr, "%s: honest proof does NOT verify - statement assembly "
                                "wrong, refusing to emit\n", idbuf);
                return 3;
            }

            for (size_t mi = 0; mi < sizeof(modes) / sizeof(modes[0]); mi++) {
                uint8_t *blob = malloc(prooflen + 8192);
                size_t bloblen = 0;
                lin_verifier_state_t vf;
                lin_verifier_init(vf, PUBSEED, *pp);
                lin_verifier_set_statement(vf, Ause, t);
                int ok = soq_x_reencode_degenerate2(vf, orig, blob, &bloblen, modes[mi].mode);
                lin_verifier_clear(vf);
                if (!ok) { reencode_fail++; free(blob); continue; }

                int accept = verify_one(Ause, t, *pp, blob, bloblen);
                if (accept) {
                    fprintf(stderr, "*** %s/%s ACCEPTED - that is a FORGERY, not a test "
                                    "vector. Refusing to emit.\n", idbuf, modes[mi].suffix);
                    bad_accepts++;
                    free(blob);
                    continue;
                }

                char newid[128];
                snprintf(newid, sizeof(newid), "%s-%s", idbuf, modes[mi].suffix);
                char *hex = to_hex(blob, bloblen);
                char *a = json_replace_str(line, "proof", hex);
                char *b = a ? json_replace_str(a, "expect", "reject") : NULL;
                char *c = b ? json_replace_str(b, "id", newid) : NULL;
                char *d = c ? json_replace_str(c, "notes", modes[mi].note) : NULL;
                if (!d) {
                    fprintf(stderr, "%s: JSON surgery failed\n", newid);
                    return 4;
                }
                /* strip trailing newline noise, print exactly one line */
                size_t dl = strlen(d);
                while (dl && (d[dl - 1] == '\n' || d[dl - 1] == '\r')) d[--dl] = 0;
                printf("%s\n", d);
                unsigned capb = wire_cap(rel);
                fprintf(stderr, "  emitted %-34s %6zu bytes (cap %u) %s, verdict reject\n",
                        newid, bloblen, capb,
                        bloblen <= capb ? "WIRE-REACHABLE" : "over cap: verifier-level only");
                emitted++;
                free(hex); free(a); free(b); free(c); free(d); free(blob);
            }

            polyvec_free(t);
            if (have_ave) polymat_free(Ave);
            free(orig);
            used++;
        }
        free(line);
        fclose(f);
    }

    fprintf(stderr, "\n=== emitted %d vectors, %d re-encode failures, %d BAD ACCEPTS\n",
            emitted, reencode_fail, bad_accepts);
    if (bad_accepts) { fprintf(stderr, "FAILING: a degenerate witness was accepted.\n"); return 1; }
    if (!emitted) { fprintf(stderr, "FAILING: emitted nothing.\n"); return 1; }
    return 0;
}
