#pragma once

#include <stdint.h>

extern "C"
{
    void *hexl_ntt_alloc(uint64_t d, uint64_t p);
    void hexl_ntt_fwd(void *ntt, uint64_t *out, uint64_t out_mod_factor, const uint64_t *in, uint64_t in_mod_factor);
    void hexl_ntt_inv(void *ntt, uint64_t *out, uint64_t out_mod_factor, const uint64_t *in, uint64_t in_mod_factor);
    void hexl_ntt_free(void *ntt);

    void hexl_ntt_add(uint64_t *r, const uint64_t *a, const uint64_t *b, uint64_t d, uint64_t p);
    void hexl_ntt_sub(uint64_t *r, const uint64_t *a, const uint64_t *b, uint64_t d, uint64_t p);
    void hexl_ntt_mul(uint64_t *r, const uint64_t *a, const uint64_t *b, uint64_t in_mod_factor, uint64_t d, uint64_t p);
    void hexl_ntt_scale(uint64_t *r, const uint64_t s, const uint64_t *b, uint64_t d, uint64_t p, uint64_t in_mod_factor);
    void hexl_ntt_red(uint64_t *r, uint64_t out_mod_factor, const uint64_t *a, uint64_t in_mod_factor, uint64_t d, uint64_t p);
}
