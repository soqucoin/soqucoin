// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// Lattice-BP++: Ring Element Implementation
// Stage 3 R&D - Polynomial ring operations using NTT
//

#include "commitment.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <random>

// For HKDF domain separation
extern "C" {
void HKDF_SHA256(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len);
}

namespace latticebp
{

// ============================================================================
// NTT (Number Theoretic Transform) Tables
// Pre-computed for q = 8380417, n = 256
// ============================================================================

namespace
{

// Primitive nth root of unity in Z_q
constexpr int64_t ZETA = 1753; // ζ^256 = 1 (mod q)

// Montgomery reduction constant
constexpr int64_t MONT_R = 4193792;     // R = 2^32 mod q
constexpr int64_t MONT_R_INV = 8265825; // R^-1 mod q
constexpr int64_t Q_INV = 58728449;     // -q^-1 mod 2^32

// Pre-computed twiddle factors for NTT
int64_t zetas[LatticeParams::N];
int64_t zetas_inv[LatticeParams::N];

// Montgomery reduction: a * R^-1 mod q
inline int64_t montgomery_reduce(int64_t a)
{
    int64_t t = (int32_t)a * Q_INV;
    t = (a - (int64_t)t * LatticeParams::Q) >> 32;
    return t;
}

// Barrett reduction: a mod q
inline int64_t barrett_reduce(int64_t a)
{
    int64_t t;
    const int64_t v = ((1ULL << 48) / LatticeParams::Q + 1);
    t = (int64_t)(((__int128)v * a) >> 48);
    t *= LatticeParams::Q;
    return a - t;
}

// Centered reduction to [-q/2, q/2]
inline int64_t center_reduce(int64_t a)
{
    a = barrett_reduce(a);
    if (a > LatticeParams::Q / 2) a -= LatticeParams::Q;
    if (a < -LatticeParams::Q / 2) a += LatticeParams::Q;
    return a;
}

// Initialize NTT tables (called once at startup)
bool ntt_tables_initialized = false;

void init_ntt_tables()
{
    if (ntt_tables_initialized) return;

    // Compute powers of zeta
    int64_t z = 1;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        zetas[i] = z;
        z = montgomery_reduce(z * ZETA);
    }

    // Compute inverse powers for inverse NTT
    z = 1;
    int64_t zeta_inv = 4808194; // ζ^-1 mod q
    for (size_t i = 0; i < LatticeParams::N; i++) {
        size_t j = LatticeParams::N - 1 - i;
        zetas_inv[j] = z;
        z = montgomery_reduce(z * zeta_inv);
    }

    ntt_tables_initialized = true;
}

} // anonymous namespace

// ============================================================================
// RingElement Implementation
// ============================================================================

RingElement::RingElement()
{
    init_ntt_tables();
    coeffs.fill(0);
}

RingElement RingElement::operator+(const RingElement& other) const
{
    RingElement result;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        result.coeffs[i] = barrett_reduce(coeffs[i] + other.coeffs[i]);
    }
    return result;
}

RingElement RingElement::operator-(const RingElement& other) const
{
    RingElement result;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        result.coeffs[i] = barrett_reduce(coeffs[i] - other.coeffs[i] + LatticeParams::Q);
    }
    return result;
}

// Naive polynomial multiplication in Z_q[X]/(X^N + 1)
// Complexity: O(n^2) - will optimize to O(n log n) NTT later
// Correctness first, performance second
RingElement RingElement::operator*(const RingElement& other) const
{
    RingElement result;
    const size_t n = LatticeParams::N;

    // Schoolbook multiplication with reduction by X^N + 1
    // X^N = -1 in this ring, so coefficients wrap with negation
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < n; j++) {
            size_t k = i + j;
            int64_t prod = (__int128)coeffs[i] * other.coeffs[j] % LatticeParams::Q;

            if (k < n) {
                // Normal term
                result.coeffs[k] = barrett_reduce(result.coeffs[k] + prod);
            } else {
                // k >= n: X^k = X^(k-n) * X^n = -X^(k-n)
                result.coeffs[k - n] = barrett_reduce(result.coeffs[k - n] - prod + LatticeParams::Q);
            }
        }
    }

    return result;
}

void RingElement::reduce()
{
    for (size_t i = 0; i < LatticeParams::N; i++) {
        coeffs[i] = center_reduce(coeffs[i]);
    }
}

RingElement RingElement::sampleUniform()
{
    RingElement result;
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int64_t> dist(0, LatticeParams::Q - 1);

    for (size_t i = 0; i < LatticeParams::N; i++) {
        result.coeffs[i] = dist(gen);
    }
    return result;
}

RingElement RingElement::sampleGaussian(double sigma)
{
    RingElement result;
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::normal_distribution<double> dist(0.0, sigma);

    for (size_t i = 0; i < LatticeParams::N; i++) {
        double sample = dist(gen);
        result.coeffs[i] = static_cast<int64_t>(std::round(sample));
        // Reduce to [-q/2, q/2]
        result.coeffs[i] = center_reduce(result.coeffs[i]);
    }
    return result;
}

std::vector<uint8_t> RingElement::serialize() const
{
    std::vector<uint8_t> result(LatticeParams::N * sizeof(int64_t));
    memcpy(result.data(), coeffs.data(), result.size());
    return result;
}

RingElement RingElement::deserialize(const std::vector<uint8_t>& data)
{
    RingElement result;
    if (data.size() >= LatticeParams::N * sizeof(int64_t)) {
        memcpy(result.coeffs.data(), data.data(), LatticeParams::N * sizeof(int64_t));
    }
    return result;
}

// ============================================================================
// LatticeCommitment::PublicParams Implementation
// ============================================================================

LatticeCommitment::PublicParams LatticeCommitment::PublicParams::generate(
    const std::array<uint8_t, 32>& seed)
{
    PublicParams params;

    // Deterministic generation using HKDF
    // A generators for value
    for (size_t i = 0; i < LatticeParams::K; i++) {
        std::array<uint8_t, LatticeParams::N * 8> a_bytes;
        std::string info = "soqucoin.latticebp.A." + std::to_string(i);
        HKDF_SHA256(seed.data(), seed.size(),
            nullptr, 0,
            reinterpret_cast<const uint8_t*>(info.c_str()), info.size(),
            a_bytes.data(), a_bytes.size());

        for (size_t j = 0; j < LatticeParams::N; j++) {
            uint64_t val;
            memcpy(&val, &a_bytes[j * 8], 8);
            params.A[i].coeffs[j] = val % LatticeParams::Q;
        }
    }

    // S generators for randomness
    for (size_t i = 0; i < LatticeParams::K; i++) {
        std::array<uint8_t, LatticeParams::N * 8> s_bytes;
        std::string info = "soqucoin.latticebp.S." + std::to_string(i);
        HKDF_SHA256(seed.data(), seed.size(),
            nullptr, 0,
            reinterpret_cast<const uint8_t*>(info.c_str()), info.size(),
            s_bytes.data(), s_bytes.size());

        for (size_t j = 0; j < LatticeParams::N; j++) {
            uint64_t val;
            memcpy(&val, &s_bytes[j * 8], 8);
            params.S[i].coeffs[j] = val % LatticeParams::Q;
        }
    }

    return params;
}

// ============================================================================
// LatticeCommitment Implementation
// ============================================================================

LatticeCommitment LatticeCommitment::commit(
    uint64_t value,
    const RingElement& randomness,
    const PublicParams& params)
{
    LatticeCommitment result;

    // C = v*A + r*S
    for (size_t i = 0; i < LatticeParams::K; i++) {
        // v * A[i]
        RingElement va;
        for (size_t j = 0; j < LatticeParams::N; j++) {
            va.coeffs[j] = barrett_reduce((int64_t)value * params.A[i].coeffs[j]);
        }

        // r * S[i]
        RingElement rs = randomness * params.S[i];

        // Sum
        result.commitment[i] = va + rs;
    }

    return result;
}

LatticeCommitment LatticeCommitment::operator+(const LatticeCommitment& other) const
{
    LatticeCommitment result;
    for (size_t i = 0; i < LatticeParams::K; i++) {
        result.commitment[i] = commitment[i] + other.commitment[i];
    }
    return result;
}

LatticeCommitment LatticeCommitment::operator-(const LatticeCommitment& other) const
{
    LatticeCommitment result;
    for (size_t i = 0; i < LatticeParams::K; i++) {
        result.commitment[i] = commitment[i] - other.commitment[i];
    }
    return result;
}

bool LatticeCommitment::verify(
    uint64_t value,
    const RingElement& randomness,
    const PublicParams& params) const
{
    LatticeCommitment expected = commit(value, randomness, params);

    for (size_t i = 0; i < LatticeParams::K; i++) {
        for (size_t j = 0; j < LatticeParams::N; j++) {
            int64_t diff = center_reduce(commitment[i].coeffs[j] - expected.commitment[i].coeffs[j]);
            if (diff != 0) return false;
        }
    }
    return true;
}

std::vector<uint8_t> LatticeCommitment::serialize() const
{
    std::vector<uint8_t> result;
    result.reserve(LatticeParams::K * LatticeParams::N * sizeof(int64_t));

    for (size_t i = 0; i < LatticeParams::K; i++) {
        auto elem_data = commitment[i].serialize();
        result.insert(result.end(), elem_data.begin(), elem_data.end());
    }
    return result;
}

LatticeCommitment LatticeCommitment::deserialize(const std::vector<uint8_t>& data)
{
    LatticeCommitment result;
    size_t offset = 0;
    size_t elem_size = LatticeParams::N * sizeof(int64_t);

    for (size_t i = 0; i < LatticeParams::K && offset + elem_size <= data.size(); i++) {
        std::vector<uint8_t> elem_data(data.begin() + offset, data.begin() + offset + elem_size);
        result.commitment[i] = RingElement::deserialize(elem_data);
        offset += elem_size;
    }
    return result;
}

// ============================================================================
// LatticeRangeProof Implementation (Stub)
// ============================================================================

LatticeRangeProof LatticeRangeProof::prove(
    uint64_t value,
    const RingElement& randomness,
    const LatticeCommitment::PublicParams& params)
{
    LatticeRangeProof proof;

    // TODO: Implement actual range proof protocol
    // This is the core research challenge - adapting Bulletproofs++
    // inner product argument to lattice-based commitments.
    //
    // Current placeholder: Store commitment parameters for verification
    proof.proof_data.resize(64);
    memcpy(proof.proof_data.data(), &value, 8);

    return proof;
}

bool LatticeRangeProof::verify(
    const LatticeCommitment& commitment,
    const LatticeCommitment::PublicParams& params) const
{
    // TODO: Implement actual range proof verification
    // This requires the adapted inner product argument

    // Placeholder: Always passes for development
    return proof_data.size() >= 64;
}

bool LatticeRangeProof::batchVerify(
    const std::vector<LatticeRangeProof>& proofs,
    const std::vector<LatticeCommitment>& commitments,
    const LatticeCommitment::PublicParams& params)
{
    // TODO: Implement batch verification using LatticeFold+
    // This should provide O(1) verification for n proofs

    for (size_t i = 0; i < proofs.size(); i++) {
        if (!proofs[i].verify(commitments[i], params)) {
            return false;
        }
    }
    return true;
}

} // namespace latticebp
