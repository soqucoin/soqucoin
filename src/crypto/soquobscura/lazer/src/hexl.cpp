#include "hexl.h"

#include "hexl/ntt/ntt.hpp"
#include "hexl/eltwise/eltwise-add-mod.hpp"
#include "hexl/eltwise/eltwise-sub-mod.hpp"
#include "hexl/eltwise/eltwise-mult-mod.hpp"
#include "hexl/eltwise/eltwise-fma-mod.hpp"
#include "hexl/eltwise/eltwise-reduce-mod.hpp"

using namespace intel::hexl;

// p prime, p == 1 mod 2d
void *hexl_ntt_alloc(uint64_t d, uint64_t p)
{
    return new NTT(d, p);
}

void hexl_ntt_fwd(void *ntt, uint64_t *out, uint64_t out_mod_factor, const uint64_t *in, uint64_t in_mod_factor)
{
    (reinterpret_cast<NTT *>(ntt))->ComputeForward(out, in, in_mod_factor, out_mod_factor);
}

void hexl_ntt_inv(void *ntt, uint64_t *out, uint64_t out_mod_factor, const uint64_t *in, uint64_t in_mod_factor)
{
    (reinterpret_cast<NTT *>(ntt))->ComputeInverse(out, in, in_mod_factor, out_mod_factor);
}

void hexl_ntt_free(void *ntt)
{
    delete (reinterpret_cast<NTT *>(ntt));
}

void hexl_ntt_add(uint64_t *r, const uint64_t *a, const uint64_t *b, uint64_t d, uint64_t p)
{
    EltwiseAddMod(r, a, b, d, p);
}

void hexl_ntt_sub(uint64_t *r, const uint64_t *a, const uint64_t *b, uint64_t d, uint64_t p)
{
    EltwiseSubMod(r, a, b, d, p);
}

void hexl_ntt_mul(uint64_t *r, const uint64_t *a, const uint64_t *b, uint64_t in_mod_factor, uint64_t d, uint64_t p)
{
    EltwiseMultMod(r, a, b, d, p, in_mod_factor);
}

void hexl_ntt_scale(uint64_t *r, const uint64_t s, const uint64_t *b, uint64_t d, uint64_t p, uint64_t in_mod_factor)
{
    EltwiseFMAMod(r, b, s, nullptr, d, p, in_mod_factor);
}

void hexl_ntt_red(uint64_t *r, uint64_t out_mod_factor, const uint64_t *a, uint64_t in_mod_factor, uint64_t d, uint64_t p)
{
    EltwiseReduceMod(r, a, d, p, in_mod_factor, out_mod_factor);
}
