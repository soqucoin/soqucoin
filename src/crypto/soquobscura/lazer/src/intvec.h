#ifndef INTVEC_H
#define INTVEC_H
#include "lazer.h"

static void _intvec_urandom (intvec_t r, const int_t mod, unsigned int log2mod,
                             const uint8_t seed[32], uint64_t dom);
static void _intvec_brandom (intvec_t r, unsigned int k,
                             const uint8_t seed[32], uint64_t dom);
static void _intvec_grandom (intvec_t r, unsigned int log2o,
                             const uint8_t seed[32], uint64_t dom);
static void _intvec_urandom_autostable (intvec_t r, int64_t bnd,
                                        unsigned int log2,
                                        const uint8_t seed[32], uint64_t dom);

#endif
