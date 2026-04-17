#include <algorithm>
#include <crypto/common.h>
#include <crypto/latticefold/verifier.h>
#include <cstdint>
#include <cstring>
#include <test/fuzz/fuzz.h>
#include <vector>


void latticefold_verifier(fuzzer::FuzzBuffer& buffer) noexcept
{
    // Minimum: 32 (sighash) + 32 (pubkey_hash) + 32 (batch_hash) + 8*8 (t_coeffs) + 8 (c) = 168
    if (buffer.size() < 168) return;

    const uint8_t* data = buffer.data();
    size_t size = buffer.size();
    size_t offset = 0;

    // Derive consensus matrix A (deterministic, same on all nodes)
    std::array<std::array<LatticeFoldVerifier::Fp, MATRIX_A_COLS>, MATRIX_A_ROWS> matrixA;
    LatticeFoldVerifier::DeriveConsensusMatrixA(matrixA);

    // Build BatchInstance from fuzz data
    LatticeFoldVerifier::BatchInstance instance{};

    // sighash (32 bytes) — transaction context binding
    std::memcpy(instance.sighash.begin(), data + offset, 32);
    offset += 32;

    // pubkey_hash (32 bytes) — UTXO commitment
    std::memcpy(instance.pubkey_hash.data(), data + offset, 32);
    offset += 32;

    // batch_hash (32 bytes)
    std::memcpy(instance.batch_hash.data(), data + offset, 32);
    offset += 32;

    // t_coeffs (8 x 8 bytes)
    for (auto& coeff : instance.t_coeffs) {
        if (offset + 8 > size) return;
        coeff = Binius64(ReadLE64(data + offset));
        offset += 8;
    }

    // c (8 bytes)
    if (offset + 8 > size) return;
    instance.c = Binius64(ReadLE64(data + offset));
    offset += 8;

    // Build Proof from remaining fuzz data
    LatticeFoldVerifier::Proof proof{};
    size_t max_elements = std::min<size_t>((size - offset) / 8, 8 * 64);
    proof.sumcheck_proof.resize(max_elements);
    for (size_t i = 0; i < max_elements; ++i) {
        proof.sumcheck_proof[i] = Binius64(ReadLE64(data + offset));
        offset += 8;
    }

    // Fuzz range openings, folded commitment, and double openings if data remains
    if (offset + 128 <= size) {
        for (auto& o : proof.range_openings) {
            o = Binius64(ReadLE64(data + offset));
            offset += 8;
        }
    }
    if (offset + 64 <= size) {
        for (auto& o : proof.folded_commitment) {
            o = Binius64(ReadLE64(data + offset));
            offset += 8;
        }
    }
    if (offset + 32 <= size) {
        for (auto& o : proof.double_openings) {
            o = Binius64(ReadLE64(data + offset));
            offset += 8;
        }
    }

    // Final Fiat-Shamir seed
    if (offset + 32 <= size) {
        std::memcpy(proof.fiat_shamir_seed.begin(), data + offset, 32);
    }

    // Call with the redesigned 3-argument API (post-Halborn SOQ-A005)
    (void)LatticeFoldVerifier::VerifyDilithiumBatch(instance, proof, matrixA);
}
