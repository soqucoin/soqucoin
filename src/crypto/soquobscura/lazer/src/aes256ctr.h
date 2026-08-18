#ifndef AES256CTR_H
#define AES256CTR_H
#include "lazer.h"
#include <stddef.h>
#include <stdint.h>

#if RNG == RNG_AES256CTR

static void _aes256ctr_init (aes256ctr_state_t state, const uint8_t key[32],
                             const uint8_t nonce[16]);
static void _aes256ctr_stream (aes256ctr_state_t state, uint8_t *out,
                               size_t outlen);
static void _aes256ctr_clear (aes256ctr_state_t state);

#endif

#endif
