#ifndef SHAKE128_H
#define SHAKE128_H
#include "lazer.h"

static void _shake128_init (shake128_state_t state);
static void _shake128_absorb (shake128_state_t state, const uint8_t *in,
                              size_t len);
static void _shake128_squeeze (shake128_state_t state, uint8_t *out,
                               size_t len);
static void _shake128_clear (shake128_state_t state);

#endif
