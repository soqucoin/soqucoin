// Minimal WASM entry point — exports only seed_keypair for SHIELD tab
#include <string.h>
#include <emscripten/emscripten.h>
#include "sign.h"
#include "params.h"

// Statically allocated buffers for pk and sk
static uint8_t pk_buf[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk_buf[CRYPTO_SECRETKEYBYTES];

// Returns pointer to public key (1312 bytes for Dilithium2)
EMSCRIPTEN_KEEPALIVE
uint8_t* get_pk_ptr(void) { return pk_buf; }

// Returns public key size
EMSCRIPTEN_KEEPALIVE
int get_pk_size(void) { return CRYPTO_PUBLICKEYBYTES; }

// Generate keypair from a 32-byte seed
// Returns 0 on success
EMSCRIPTEN_KEEPALIVE
int seed_keypair(const uint8_t *seed) {
    return pqcrystals_dilithium2_ref_seed_keypair(pk_buf, sk_buf, seed);
}

// Immediately clear the secret key from memory after address derivation
EMSCRIPTEN_KEEPALIVE
void clear_sk(void) {
    volatile uint8_t *p = sk_buf;
    for (size_t i = 0; i < CRYPTO_SECRETKEYBYTES; i++) p[i] = 0;
}
