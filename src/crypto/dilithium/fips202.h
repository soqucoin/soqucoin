#pragma once

#include "sha3.h"

typedef SHA3_CTX shake128ctx;
typedef SHA3_CTX shake256ctx;

#define shake128_init(ctx)                  SHA3_Init(ctx, 128)
#define shake128_absorb(ctx, in, inlen)     SHA3_Update(ctx, in, inlen)
#define shake128_finalize(ctx)              do {} while(0)
#define shake128_squeeze(out, outlen, ctx)  SHA3_Final(out, ctx)

#define shake256_init(ctx)                  SHA3_Init(ctx, 256)
#define shake256_absorb(ctx, in, inlen)     SHA3_Update(ctx, in, inlen)
#define shake256_finalize(ctx)              do {} while(0)
#define shake256_squeeze(out, outlen, ctx)  SHA3_Final(out, ctx)

#define shake128_inc_init(ctx)              SHA3_Init(ctx, 128)
#define shake128_inc_absorb(ctx, in, inlen) SHA3_Update(ctx, in, inlen)
#define shake128_inc_finalize(ctx)          do {} while(0)
#define shake128_inc_squeeze(out, outlen, ctx) SHA3_Final(out, ctx)

#define shake256_inc_init(ctx)              SHA3_Init(ctx, 256)
#define shake256_inc_absorb(ctx, in, inlen) SHA3_Update(ctx, in, inlen)
#define shake256_inc_finalize(ctx)          do {} while(0)
#define shake256_inc_squeeze(out, outlen, ctx) SHA3_Final(out, ctx)
