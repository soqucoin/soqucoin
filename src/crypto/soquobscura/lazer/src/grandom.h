#ifndef GAUSSIAN_H
#define GAUSSIAN_H

static void _grandom_sample (int_t z, unsigned int log2o,
                            const uint8_t seed[32], uint64_t dom);
#ifdef XXX
static int64_t _grandom_sample_i64 (unsigned int log2o, const uint8_t *seed,
                                   uint64_t dom);
#endif

static void _grandom_sample_i32 (int32_t *r, unsigned int nelems,
                                unsigned int log2o, const uint8_t seed[32],
                                uint64_t dom);

#endif
