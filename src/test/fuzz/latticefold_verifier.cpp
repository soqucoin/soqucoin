#include <algorithm>
#include <crypto/common.h>
#include <crypto/latticefold/verifier.h>
#include <cstdint>
#include <cstring>
#include <test/fuzz/fuzz.h>
#include <vector>


void latticefold_verifier(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() < 104) return;

    const uint8_t* data = buffer.data();
    size_t size = buffer.size();

    LatticeFoldVerifier::BatchInstance instance{};
    std::memcpy(instance.batch_hash.data(), data, 32);

    size_t offset = 32;
    for (auto& coeff : instance.t_coeffs) {
        if (offset + 8 > size) return;
        coeff = Binius64(ReadLE64(data + offset));
        offset += 8;
    }
    if (offset + 8 > size) return;
    instance.c = Binius64(ReadLE64(data + offset));
    offset += 8;

    LatticeFoldVerifier::Proof proof{};
    size_t max_elements = std::min<size_t>((size - offset) / 8, 8 * 64);
    proof.sumcheck_proof.resize(max_elements);
    for (size_t i = 0; i < max_elements; ++i) {
        proof.sumcheck_proof[i] = Binius64(ReadLE64(data + offset));
        offset += 8;
    }

    // Fuzz the range and double openings if data remains
    if (offset + 128 <= size) {
        for (auto& o : proof.range_openings) {
            o = Binius64(ReadLE64(data + offset));
            offset += 8;
        }
        for (auto& o : proof.double_openings) {
            o = Binius64(ReadLE64(data + offset));
            offset += 8;
        }
    }

    // Final seed
    if (offset + 32 <= size) {
        std::memcpy(proof.fiat_shamir_seed.begin(), data + offset, 32);
    }

    (void)LatticeFoldVerifier::VerifyDilithiumBatch(instance, proof);
}
