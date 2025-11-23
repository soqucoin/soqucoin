#include "bench.h"
#include "crypto/dilithium/params.h"
#include "crypto/dilithium/sign.h"
#include "random.h"
#include <vector>

static void DilithiumSign(benchmark::State& state)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    std::vector<uint8_t> msg(32, 0x42);
    std::vector<uint8_t> sig(CRYPTO_BYTES);
    size_t siglen;
    const uint8_t ctx[] = "";

    while (state.KeepRunning()) {
        crypto_sign_signature(sig.data(), &siglen, msg.data(), msg.size(), ctx, 0, sk);
    }
}

static void DilithiumVerify(benchmark::State& state)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    std::vector<uint8_t> msg(32, 0x42);
    std::vector<uint8_t> sig(CRYPTO_BYTES);
    size_t siglen;
    const uint8_t ctx[] = "";
    crypto_sign_signature(sig.data(), &siglen, msg.data(), msg.size(), ctx, 0, sk);

    while (state.KeepRunning()) {
        crypto_sign_verify(sig.data(), CRYPTO_BYTES, msg.data(), msg.size(), ctx, 0, pk);
    }
}

BENCHMARK(DilithiumSign);
BENCHMARK(DilithiumVerify);
