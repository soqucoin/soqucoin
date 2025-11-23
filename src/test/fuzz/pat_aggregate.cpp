#include <algorithm>
#include <crypto/pat/logarithmic.h>
#include <cstdint>
#include <cstring>
#include <test/fuzz/fuzz.h>
#include <vector>

void pat_aggregate(fuzzer::FuzzBuffer& buffer) noexcept
{
    // Need at least agg_pk (32) + msg_root (32) + proof (72)
    if (buffer.size() < 32 + 32 + 72) return;

    const uint8_t* data = buffer.data();
    size_t size = buffer.size();
    size_t offset = 0;

    // Extract Aggregate PK
    pat::CValType agg_pk(32);
    std::memcpy(agg_pk.data(), data + offset, 32);
    offset += 32;

    // Extract Message Root
    pat::CValType msg_root(32);
    std::memcpy(msg_root.data(), data + offset, 32);
    offset += 32;

    // Extract Proof fields
    pat::LogarithmicProof proof;

    std::memcpy(proof.merkle_root.begin(), data + offset, 32);
    offset += 32;

    std::memcpy(proof.pk_xor.begin(), data + offset, 32);
    offset += 32;

    // Read count (4 bytes)
    uint32_t count;
    std::memcpy(&count, data + offset, 4);
    proof.count = count;
    offset += 4;

    (void)pat::VerifyLogarithmicProof(proof, agg_pk, msg_root);
}
