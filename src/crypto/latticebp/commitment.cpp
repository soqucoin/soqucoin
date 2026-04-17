// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// Lattice-BP++: Ring Element Implementation
// Stage 3 R&D - Polynomial ring operations using NTT
//
// SECURITY NOTE: NTT twiddle factors are Dilithium's NIST reference values.
// Montgomery/Barrett reductions follow the reference implementation exactly.

#include "commitment.h"
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>

// ============================================================================
// Build mode: Node vs Standalone R&D vs Consensus Shared Lib
// - LATTICEBP_STANDALONE: R&D test harness (insecure stubs)
// - BUILD_BITCOIN_INTERNAL: Consensus shared lib (verify + HKDF, no RNG)
// - Otherwise: Production node (GetStrongRandBytes, CHMAC_SHA256, memory_cleanse)
// ============================================================================
#ifdef LATTICEBP_STANDALONE
#include <random>  // std::random_device, std::mt19937_64 (R&D only)
// HKDF stub — declared extern, defined in test_latticebp.cpp
extern "C" {
void HKDF_SHA256(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len);
}
#else
// Both production and shared lib use HMAC-SHA256 (in libsoqucoin_crypto)
#include "../../crypto/hmac_sha256.h"    // CHMAC_SHA256

#ifndef BUILD_BITCOIN_INTERNAL
// Production only: RNG and memory cleanse (in libsoqucoin_server)
#include "../../random.h"                // GetStrongRandBytes()
#include "../../support/cleanse.h"       // memory_cleanse()
#endif

// HKDF-SHA256 (RFC 5869) using CHMAC_SHA256
// Available in both production and shared lib builds.
static void HKDF_SHA256(const uint8_t* ikm, size_t ikm_len,
                        const uint8_t* salt, size_t salt_len,
                        const uint8_t* info, size_t info_len,
                        uint8_t* okm, size_t okm_len)
{
    uint8_t prk[32];
    if (salt && salt_len > 0) {
        CHMAC_SHA256 extractor(salt, salt_len);
        extractor.Write(ikm, ikm_len);
        extractor.Finalize(prk);
    } else {
        uint8_t zero_salt[32] = {};
        CHMAC_SHA256 extractor(zero_salt, 32);
        extractor.Write(ikm, ikm_len);
        extractor.Finalize(prk);
    }

    uint8_t t_prev[32] = {};
    size_t t_prev_len = 0;
    size_t offset = 0;
    uint8_t counter = 1;

    while (offset < okm_len) {
        CHMAC_SHA256 expander(prk, 32);
        if (t_prev_len > 0) {
            expander.Write(t_prev, t_prev_len);
        }
        if (info && info_len > 0) {
            expander.Write(info, info_len);
        }
        expander.Write(&counter, 1);

        uint8_t t_cur[32];
        expander.Finalize(t_cur);

        size_t to_copy = std::min((size_t)32, okm_len - offset);
        memcpy(okm + offset, t_cur, to_copy);

        memcpy(t_prev, t_cur, 32);
        t_prev_len = 32;
        offset += to_copy;
        counter++;
    }

    // SECURITY NOTE: Cleanse PRK
#ifndef BUILD_BITCOIN_INTERNAL
    memory_cleanse(prk, 32);
#else
    memset(prk, 0, 32);  // Best-effort in shared lib context
#endif
}
#endif // LATTICEBP_STANDALONE

namespace latticebp
{

// ============================================================================
// NTT (Number Theoretic Transform) Core
// Pre-computed for q = 8380417, n = 256
// Same parameters as CRYSTALS-Dilithium (NIST FIPS 204)
// ============================================================================

namespace
{

// Montgomery reduction constants
constexpr int64_t QINV = 58728449; // q^(-1) mod 2^32

// Pre-computed twiddle factors — directly from Dilithium's NIST reference (ntt.c).
// These are powers of ζ=1753 in Montgomery domain.
// SECURITY NOTE: Using these exact values ensures ring arithmetic matches
// Dilithium's validated NTT, preventing SOQ-A003-class reduction bugs.
static const int64_t zetas[256] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

// Montgomery reduction: a * 2^{-32} mod q
// Matches Dilithium reference reduce.c exactly.
// CRITICAL: t MUST be int32_t (truncated to low 32 bits) — this is how
// the Montgomery algorithm cancels the low-order bits. Using int64_t for t
// breaks the reduction and produces wrong results.
inline int64_t montgomery_reduce(int64_t a)
{
    int32_t t = (int32_t)a * (int32_t)QINV;
    return (a - (int64_t)t * LatticeParams::Q) >> 32;
}

// Barrett reduction: a mod q (for a in roughly [-2q, 2q] range)
inline int64_t barrett_reduce(int64_t a)
{
    int64_t t;
    const int64_t v = ((1LL << 26) + LatticeParams::Q / 2) / LatticeParams::Q;
    t = (int64_t)((v * a) >> 26);
    t *= LatticeParams::Q;
    return a - t;
}

// Freeze: fully reduce to [0, q)
inline int64_t freeze(int64_t a)
{
    a = barrett_reduce(a);
    a += (a >> 63) & LatticeParams::Q;  // if a < 0, add q
    return a;
}

// Centered reduction to [-q/2, q/2]
inline int64_t center_reduce(int64_t a)
{
    a = freeze(a);
    if (a > LatticeParams::Q / 2) a -= LatticeParams::Q;
    return a;
}

// ============================================================================
// NTT Forward/Inverse Transforms
// Cooley-Tukey butterfly, matching Dilithium reference ntt.c
// Adapted for int64_t coefficients (latticebp uses int64_t, Dilithium uses int32_t)
// ============================================================================

// Forward NTT: polynomial → evaluation form (bit-reversed order)
void ntt_forward(int64_t a[256])
{
    unsigned int len, start, j, k;
    int64_t t;

    k = 0;
    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            int64_t zeta = zetas[++k];
            for (j = start; j < start + len; ++j) {
                t = montgomery_reduce(zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

// Inverse NTT: evaluation form → polynomial (coefficient order)
void ntt_inverse(int64_t a[256])
{
    unsigned int start, len, j, k;
    int64_t t;
    const int64_t f = 41978; // mont^2/256

    k = 256;
    for (len = 1; len < 256; len <<= 1) {
        for (start = 0; start < 256; start = j + len) {
            int64_t zeta = -zetas[--k];
            for (j = start; j < start + len; ++j) {
                t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = montgomery_reduce(zeta * a[j + len]);
            }
        }
    }

    for (j = 0; j < 256; ++j) {
        a[j] = montgomery_reduce(f * a[j]);
    }
}

} // anonymous namespace

// ============================================================================
// RingElement Implementation
// ============================================================================

RingElement::RingElement()
{
    coeffs.fill(0);
}

RingElement RingElement::operator+(const RingElement& other) const
{
    RingElement result;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        result.coeffs[i] = coeffs[i] + other.coeffs[i];
    }
    return result;
}

RingElement RingElement::operator-(const RingElement& other) const
{
    RingElement result;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        result.coeffs[i] = coeffs[i] - other.coeffs[i];
    }
    return result;
}

// NTT-based polynomial multiplication in Z_q[X]/(X^N + 1)
// Complexity: O(n log n) via Number Theoretic Transform
// Performance: ~32x faster than O(n^2) schoolbook for N=256
// Critical for stablecoin (100 TPS) and L2 Lightning (1000+ TPS) scalability.
RingElement RingElement::operator*(const RingElement& other) const
{
    // 1. Forward NTT both operands (in-place on copies)
    int64_t a_ntt[256];
    int64_t b_ntt[256];
    for (size_t i = 0; i < 256; i++) {
        a_ntt[i] = freeze(coeffs[i]);
        b_ntt[i] = freeze(other.coeffs[i]);
    }

    ntt_forward(a_ntt);
    ntt_forward(b_ntt);

    // 2. Pointwise multiplication in NTT domain
    for (size_t i = 0; i < 256; i++) {
        a_ntt[i] = montgomery_reduce(a_ntt[i] * b_ntt[i]);
    }

    // 3. Inverse NTT back to coefficient form
    ntt_inverse(a_ntt);

    // 4. Final reduction
    RingElement result;
    for (size_t i = 0; i < 256; i++) {
        result.coeffs[i] = freeze(a_ntt[i]);
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
#ifdef LATTICEBP_STANDALONE
    // R&D harness: std::random_device (NOT cryptographically suitable for production)
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int64_t> dist(0, LatticeParams::Q - 1);
    for (size_t i = 0; i < LatticeParams::N; i++) {
        result.coeffs[i] = dist(gen);
    }
#elif defined(BUILD_BITCOIN_INTERNAL)
    // Consensus shared lib: prover functions not available
    (void)result;
    assert(!"sampleUniform() not available in consensus shared lib");
#else
    // Production: GetStrongRandBytes() CSPRNG
    // Generate N coefficients from N*8 random bytes, reduce mod Q
    uint8_t rand_bytes[LatticeParams::N * 8];
    GetStrongRandBytes(rand_bytes, sizeof(rand_bytes));
    for (size_t i = 0; i < LatticeParams::N; i++) {
        uint64_t val;
        memcpy(&val, rand_bytes + i * 8, 8);
        result.coeffs[i] = val % LatticeParams::Q;
    }
    memory_cleanse(rand_bytes, sizeof(rand_bytes));
#endif
    return result;
}

RingElement RingElement::sampleGaussian(double sigma)
{
    RingElement result;
#ifdef LATTICEBP_STANDALONE
    // R&D harness: std::random_device (NOT cryptographically suitable for production)
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::normal_distribution<double> dist(0.0, sigma);
    for (size_t i = 0; i < LatticeParams::N; i++) {
        double sample = dist(gen);
        result.coeffs[i] = static_cast<int64_t>(std::round(sample));
        result.coeffs[i] = center_reduce(result.coeffs[i]);
    }
#elif defined(BUILD_BITCOIN_INTERNAL)
    // Consensus shared lib: prover functions not available
    (void)result;
    (void)sigma;
    assert(!"sampleGaussian() not available in consensus shared lib");
#else
    // Production: Discrete Gaussian using rejection sampling from CSPRNG
    // Uses Box-Muller transform with GetStrongRandBytes() entropy
    uint8_t rand_bytes[LatticeParams::N * 16]; // 16 bytes per sample (two 8-byte for Box-Muller)
    GetStrongRandBytes(rand_bytes, sizeof(rand_bytes));
    for (size_t i = 0; i < LatticeParams::N; i++) {
        // Box-Muller: generate two uniform [0,1) → one Gaussian sample
        uint64_t u1_raw, u2_raw;
        memcpy(&u1_raw, rand_bytes + i * 16, 8);
        memcpy(&u2_raw, rand_bytes + i * 16 + 8, 8);
        // Avoid log(0): ensure u1 > 0
        double u1 = (double)(u1_raw | 1) / (double)UINT64_MAX;
        double u2 = (double)u2_raw / (double)UINT64_MAX;
        double sample = sigma * std::sqrt(-2.0 * std::log(u1)) * std::cos(2.0 * M_PI * u2);
        result.coeffs[i] = static_cast<int64_t>(std::round(sample));
        result.coeffs[i] = center_reduce(result.coeffs[i]);
    }
    memory_cleanse(rand_bytes, sizeof(rand_bytes));
#endif
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
        // v * A[i] — scalar-polynomial multiply
        RingElement va;
        for (size_t j = 0; j < LatticeParams::N; j++) {
            va.coeffs[j] = freeze((int64_t)value * (params.A[i].coeffs[j] % LatticeParams::Q) % LatticeParams::Q);
        }

        // r * S[i] — full polynomial multiply (uses NTT)
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
// LatticeRangeProof Implementation (Stub — Phase 2 will replace)
// ============================================================================

LatticeRangeProof LatticeRangeProof::prove(
    uint64_t value,
    const RingElement& randomness,
    const LatticeCommitment::PublicParams& params)
{
    LatticeRangeProof proof;

    // TODO(Phase 2): Implement LNP22 polynomial product range proof
    // This is the core of the patent — lattice-based binary decomposition
    // with polynomial product bit proofs and Fiat-Shamir aggregation.
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
    // TODO(Phase 2): Implement actual range proof verification
    // Will verify:
    //   1. Binary decomposition: all b_i ∈ {0,1}
    //   2. Value reconstruction: Σ 2^i · b_i = committed value
    //   3. Norm bounds: ‖z‖ ≤ β
    //   4. Fiat-Shamir transcript consistency

    // Placeholder: Always passes for development
    return proof_data.size() >= 64;
}

bool LatticeRangeProof::batchVerify(
    const std::vector<LatticeRangeProof>& proofs,
    const std::vector<LatticeCommitment>& commitments,
    const LatticeCommitment::PublicParams& params)
{
    // TODO(Phase 2): Implement batch verification using LatticeFold+
    // This should provide O(1) verification for n proofs

    for (size_t i = 0; i < proofs.size(); i++) {
        if (!proofs[i].verify(commitments[i], params)) {
            return false;
        }
    }
    return true;
}

} // namespace latticebp
