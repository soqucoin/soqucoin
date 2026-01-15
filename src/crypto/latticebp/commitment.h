// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// Lattice-BP++: Post-Quantum Range Proofs
// Stage 3 R&D - Hybrid Lattice-Bulletproofs Implementation
//

#ifndef SOQUCOIN_CRYPTO_LATTICEBP_COMMITMENT_H
#define SOQUCOIN_CRYPTO_LATTICEBP_COMMITMENT_H

#include <array>
#include <stdint.h>
#include <vector>

namespace latticebp
{

/**
 * Ring-LWE Parameters (aligned with Dilithium ML-DSA-44)
 *
 * These parameters provide NIST Level 1 security (128-bit classical,
 * 64-bit quantum) and are compatible with the existing Dilithium
 * implementation in Soqucoin.
 */
struct LatticeParams {
    static constexpr size_t N = 256;      // Ring dimension
    static constexpr int64_t Q = 8380417; // Modulus (same as Dilithium)
    static constexpr size_t K = 4;        // Module rank
    static constexpr double SIGMA = 2.0;  // Gaussian sampling std dev

    // Derived constants
    static constexpr size_t COMMITMENT_SIZE = N * K * 3; // ~3KB
    static constexpr size_t OPENING_SIZE = N * K * 4;    // ~4KB
};

/**
 * Polynomial ring element Z_q[X]/(X^N + 1)
 *
 * Represents an element in the cyclotomic ring used for Ring-LWE.
 * All operations are modular arithmetic mod Q.
 */
class RingElement
{
public:
    std::array<int64_t, LatticeParams::N> coeffs;

    RingElement();

    // Ring operations
    RingElement operator+(const RingElement& other) const;
    RingElement operator-(const RingElement& other) const;
    RingElement operator*(const RingElement& other) const; // NTT multiplication

    // Modular reduction
    void reduce();

    // Sampling
    static RingElement sampleUniform();
    static RingElement sampleGaussian(double sigma = LatticeParams::SIGMA);

    // Serialization
    std::vector<uint8_t> serialize() const;
    static RingElement deserialize(const std::vector<uint8_t>& data);
};

/**
 * Lattice-based Pedersen Commitment
 *
 * Replaces classical EC Pedersen:
 *   Classical: C = vG + rH  (elliptic curve points)
 *   Lattice:   C = vA + rS  (Ring-LWE elements)
 *
 * Security relies on Ring-LWE hardness rather than ECDLP.
 */
class LatticeCommitment
{
public:
    // Commitment = value * A + randomness * S
    std::array<RingElement, LatticeParams::K> commitment;

    // Public parameters (generated once, shared)
    struct PublicParams {
        std::array<RingElement, LatticeParams::K> A; // Value generator
        std::array<RingElement, LatticeParams::K> S; // Randomness generator

        // Generate from seed for reproducibility
        static PublicParams generate(const std::array<uint8_t, 32>& seed);
    };

    // Create commitment to a value
    static LatticeCommitment commit(
        uint64_t value,
        const RingElement& randomness,
        const PublicParams& params);

    // Homomorphic operations (for balance proofs)
    LatticeCommitment operator+(const LatticeCommitment& other) const;
    LatticeCommitment operator-(const LatticeCommitment& other) const;

    // Verify opening
    bool verify(
        uint64_t value,
        const RingElement& randomness,
        const PublicParams& params) const;

    // Serialization
    std::vector<uint8_t> serialize() const;
    static LatticeCommitment deserialize(const std::vector<uint8_t>& data);

    // Size in bytes
    static constexpr size_t SIZE = LatticeParams::COMMITMENT_SIZE;
};

/**
 * Lattice Range Proof
 *
 * Zero-knowledge proof that a committed value lies in [0, 2^64).
 * Uses hybrid construction:
 *   - Lattice commitment for post-quantum binding
 *   - Adapted Bulletproofs++ inner product argument
 */
class LatticeRangeProof
{
public:
    // Proof components (sizes are estimates, will refine)
    std::vector<uint8_t> proof_data;

    // Range proof parameters
    static constexpr size_t RANGE_BITS = 64;
    static constexpr size_t MAX_PROOF_SIZE = 2048; // ~2KB target

    // Generate range proof
    static LatticeRangeProof prove(
        uint64_t value,
        const RingElement& randomness,
        const LatticeCommitment::PublicParams& params);

    // Verify range proof
    bool verify(
        const LatticeCommitment& commitment,
        const LatticeCommitment::PublicParams& params) const;

    // Batch verification (for LatticeFold+ integration)
    static bool batchVerify(
        const std::vector<LatticeRangeProof>& proofs,
        const std::vector<LatticeCommitment>& commitments,
        const LatticeCommitment::PublicParams& params);

    // Size in bytes
    size_t size() const { return proof_data.size(); }
};

} // namespace latticebp

#endif // SOQUCOIN_CRYPTO_LATTICEBP_COMMITMENT_H
