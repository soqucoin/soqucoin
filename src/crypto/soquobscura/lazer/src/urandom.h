#ifndef URANDOM_H
#define URANDOM_H

#include "lazer.h"

static void _urandom (intvec_t r, const int_t mod, unsigned int log2mod,
                      const uint8_t seed[32], uint64_t dom);

static void _urandom_bnd (intvec_t r, const int_t lo, const int_t hi,
                          const uint8_t seed[32], uint64_t dom);

static void _urandom_i64 (int64_t *vec, unsigned int nelems, int64_t mod,
                          unsigned int log2mod, const uint8_t seed[32],
                          uint64_t dom);

#endif
