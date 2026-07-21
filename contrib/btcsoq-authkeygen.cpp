// BTCSOQ stagenet authority keygen — one-off tool.
// Generates fresh ML-DSA-44 (FIPS 204) keypairs for the BTCSOQ issuer
// authority. Public keys go into consensus.btcsoqAuthorityKeys (chainparams);
// secret keys go to the offline registry + signer keystore, NEVER committed.
//
// Build (on a tree that has been compiled):
//   g++ -std=c++11 -I src contrib/btcsoq-authkeygen.cpp \
//       src/crypto/libsoqucoin_crypto.a -o btcsoq-authkeygen -lpthread
// Run: ./btcsoq-authkeygen 3

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <vector>

extern "C" {
#include "crypto/dilithium/api.h"
}

int main(int argc, char** argv)
{
    int n = (argc > 1) ? atoi(argv[1]) : 3;
    for (int i = 0; i < n; ++i) {
        std::vector<uint8_t> pk(pqcrystals_dilithium2_PUBLICKEYBYTES);
        std::vector<uint8_t> sk(pqcrystals_dilithium2_SECRETKEYBYTES);
        if (pqcrystals_dilithium2_ref_keypair(pk.data(), sk.data()) != 0) {
            fprintf(stderr, "keypair generation failed at index %d\n", i);
            return 1;
        }
        printf("KEY %d PUB ", i);
        for (auto b : pk) printf("%02x", b);
        printf("\n");
        printf("KEY %d SEC ", i);
        for (auto b : sk) printf("%02x", b);
        printf("\n");
    }
    return 0;
}
