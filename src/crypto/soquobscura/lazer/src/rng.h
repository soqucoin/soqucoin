#ifndef RNG_H
#define RNG_H
#include "lazer.h"

static void _rng_init (rng_state_t state, const uint8_t seed[32],
                       uint64_t dom);
static void _rng_urandom (rng_state_t state, uint8_t *out, size_t outlen);
static void _rng_clear (rng_state_t state);

#endif
