#include <algorithm>
#include <crypto/dilithium/params.h>
#include <crypto/dilithium/sign.h>
#include <cstdint>
#include <cstring>
#include <test/fuzz/fuzz.h>
#include <vector>

void dilithium_verify(fuzzer::FuzzBuffer& buffer) noexcept
{
    // Need at least PK + SIG bytes
    if (buffer.size() < CRYPTO_PUBLICKEYBYTES + CRYPTO_BYTES) return;

    const uint8_t* data = buffer.data();
    size_t size = buffer.size();

    // Extract Public Key
    std::vector<uint8_t> pk(CRYPTO_PUBLICKEYBYTES);
    std::memcpy(pk.data(), data, CRYPTO_PUBLICKEYBYTES);
    size_t offset = CRYPTO_PUBLICKEYBYTES;

    // Extract Signature
    std::vector<uint8_t> sig(CRYPTO_BYTES);
    std::memcpy(sig.data(), data + offset, CRYPTO_BYTES);
    offset += CRYPTO_BYTES;

    // Remaining data is message
    const uint8_t* msg = data + offset;
    size_t msg_len = size - offset;

    // Context (empty for now, or could be fuzzed)
    const uint8_t ctx[] = "";

    // Call verification
    (void)crypto_sign_verify(sig.data(), CRYPTO_BYTES, msg, msg_len, ctx, 0, pk.data());
}
