#ifndef BRANDOM_H
#define BRANDOM_H
#include <stdint.h>

static void _brandom (int8_t *vec, unsigned int nelems, unsigned int k,
                      const uint8_t seed[32], const uint64_t dom);
#endif
