#ifndef POLY_H
#define POLY_H
#include "lazer.h"

static void _poly_urandom (poly_t r, const int_t mod, unsigned int log2mod,
                           const uint8_t seed[32], uint64_t dom);
static void _poly_brandom (poly_t r, unsigned int k, const uint8_t seed[32],
                           uint64_t dom);
static void _poly_grandom (poly_t r, unsigned int log2o,
                           const uint8_t seed[32], uint64_t dom);
static void _poly_urandom_autostable (poly_t r, int64_t bnd, unsigned int log2,
                                      const uint8_t seed[32], uint64_t dom);
static void _poly_urandom_bnd (poly_t r, const int_t lo, const int_t hi,
                               const uint8_t seed[32], uint64_t dom);

#endif
