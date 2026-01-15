// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// Lattice-BP++: Ring Signature Implementation
// Stage 3 R&D - LSAG-style anonymous signatures
//

#include "ring_signature.h"
#include "commitment.h"
#include <algorithm>
#include <cstring>
#include <random>

// SHA3-256 hash function (stub for testing)
extern "C" {
void SHA3_256(const uint8_t* input, size_t len, uint8_t* output);
}

namespace latticebp
{

// ============================================================================
// Utility Functions
// ============================================================================

namespace
{

// Simple SHA3-256 stub for testing
void SHA3_256(const uint8_t* input, size_t len, uint8_t* output)
{
    // Simple deterministic hash for testing (NOT cryptographically secure)
    uint64_t state[4] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL};

    for (size_t i = 0; i < len; i++) {
        state[i % 4] ^= ((uint64_t)input[i] << ((i % 8) * 8));
        state[(i + 1) % 4] = state[(i + 1) % 4] * 6364136223846793005ULL + state[i % 4];
    }

    memcpy(output, state, 32);
}

// Hash to scalar: H(data) -> element in Z_q
RingElement hashToScalar(const std::vector<uint8_t>& data)
{
    RingElement result;

    // Hash data with domain separation
    std::vector<uint8_t> prefixed;
    prefixed.reserve(data.size() + 16);
    const char* domain = "soqucoin.ring.h2s";
    prefixed.insert(prefixed.end(), domain, domain + 16);
    prefixed.insert(prefixed.end(), data.begin(), data.end());

    // Expand hash to fill all coefficients
    for (size_t i = 0; i < LatticeParams::N; i++) {
        std::vector<uint8_t> indexed = prefixed;
        indexed.push_back((i >> 0) & 0xFF);
        indexed.push_back((i >> 8) & 0xFF);

        uint8_t hash[32];
        SHA3_256(indexed.data(), indexed.size(), hash);

        uint64_t val;
        memcpy(&val, hash, 8);
        result.coeffs[i] = val % LatticeParams::Q;
    }

    return result;
}

// Hash to point: H_p(data) -> lattice element for key image
RingElement hashToPoint(const LatticePublicKey& pk)
{
    std::vector<uint8_t> data;
    data.reserve(pk.key.size() * LatticeParams::N * 8);

    const char* domain = "soqucoin.ring.h2p";
    data.insert(data.end(), domain, domain + 16);

    for (const auto& elem : pk.key) {
        auto ser = elem.serialize();
        data.insert(data.end(), ser.begin(), ser.end());
    }

    return hashToScalar(data);
}

} // anonymous namespace

// ============================================================================
// LatticePublicKey Implementation
// ============================================================================

LatticePublicKey LatticePublicKey::fromDilithium(const std::vector<uint8_t>& dilithium_pk)
{
    LatticePublicKey result;

    // Derive lattice key from Dilithium public key using HKDF
    for (size_t i = 0; i < LatticeParams::K; i++) {
        std::vector<uint8_t> info;
        const char* domain = "soqucoin.ring.pk.";
        info.insert(info.end(), domain, domain + 16);
        info.push_back(static_cast<uint8_t>(i));

        std::vector<uint8_t> combined;
        combined.insert(combined.end(), dilithium_pk.begin(), dilithium_pk.end());
        combined.insert(combined.end(), info.begin(), info.end());

        result.key[i] = hashToScalar(combined);
    }

    return result;
}

LatticePublicKey LatticePublicKey::deriveStealthAddress(
    const LatticePublicKey& recipient_pk,
    const std::array<uint8_t, 32>& tx_random)
{
    LatticePublicKey result;

    // P = H(R || pk) + pk
    // where R is tx_random (sender's random scalar)
    std::vector<uint8_t> data;
    data.insert(data.end(), tx_random.begin(), tx_random.end());
    for (const auto& elem : recipient_pk.key) {
        auto ser = elem.serialize();
        data.insert(data.end(), ser.begin(), ser.end());
    }

    RingElement h = hashToScalar(data);

    for (size_t i = 0; i < LatticeParams::K; i++) {
        result.key[i] = recipient_pk.key[i] + h;
    }

    return result;
}

std::vector<uint8_t> LatticePublicKey::serialize() const
{
    std::vector<uint8_t> result;
    result.reserve(LatticeParams::K * LatticeParams::N * sizeof(int64_t));

    for (const auto& elem : key) {
        auto ser = elem.serialize();
        result.insert(result.end(), ser.begin(), ser.end());
    }
    return result;
}

LatticePublicKey LatticePublicKey::deserialize(const std::vector<uint8_t>& data)
{
    LatticePublicKey result;
    size_t elem_size = LatticeParams::N * sizeof(int64_t);
    size_t offset = 0;

    for (size_t i = 0; i < LatticeParams::K && offset + elem_size <= data.size(); i++) {
        std::vector<uint8_t> elem_data(data.begin() + offset, data.begin() + offset + elem_size);
        result.key[i] = RingElement::deserialize(elem_data);
        offset += elem_size;
    }
    return result;
}

bool LatticePublicKey::operator==(const LatticePublicKey& other) const
{
    for (size_t i = 0; i < LatticeParams::K; i++) {
        for (size_t j = 0; j < LatticeParams::N; j++) {
            if (key[i].coeffs[j] != other.key[i].coeffs[j]) return false;
        }
    }
    return true;
}

// ============================================================================
// KeyImage Implementation
// ============================================================================

KeyImage KeyImage::generate(
    const RingElement& private_key,
    const LatticePublicKey& public_key)
{
    KeyImage result;

    // Key image I = x * H_p(P)
    // where x is private key, P is public key
    // H_p is hash-to-point function

    RingElement hp = hashToPoint(public_key);
    result.image = private_key * hp;

    return result;
}

bool KeyImage::operator==(const KeyImage& other) const
{
    for (size_t i = 0; i < LatticeParams::N; i++) {
        if (image.coeffs[i] != other.image.coeffs[i]) return false;
    }
    return true;
}

std::vector<uint8_t> KeyImage::serialize() const
{
    return image.serialize();
}

KeyImage KeyImage::deserialize(const std::vector<uint8_t>& data)
{
    KeyImage result;
    result.image = RingElement::deserialize(data);
    return result;
}

// ============================================================================
// LatticeRingSignature Implementation (LSAG)
// ============================================================================

LatticeRingSignature LatticeRingSignature::sign(
    const std::array<uint8_t, 32>& message,
    const std::vector<LatticePublicKey>& ring,
    size_t real_index,
    const RingElement& private_key)
{
    LatticeRingSignature sig;
    const size_t n = ring.size();

    if (n == 0 || real_index >= n) {
        return sig; // Invalid input
    }

    // Initialize random generator
    std::random_device rd;
    std::mt19937_64 gen(rd());

    // Generate key image
    sig.key_image = KeyImage::generate(private_key, ring[real_index]);

    // Generate random alpha (commitment randomness)
    RingElement alpha = RingElement::sampleGaussian(LatticeParams::SIGMA);

    // Compute L_real = alpha * G (where G is implicit generator)
    // In lattice setting, L = alpha (the commitment)

    // Initialize challenge chain
    sig.responses.resize(n);

    // Generate random responses for all except real_index
    for (size_t i = 0; i < n; i++) {
        if (i != real_index) {
            sig.responses[i] = RingElement::sampleGaussian(LatticeParams::SIGMA * 2);
        }
    }

    // Start challenge chain from real_index + 1
    // c_{i+1} = H(m || L_i || R_i)

    // Compute initial challenge at position (real_index + 1)
    std::vector<uint8_t> hash_input;
    hash_input.insert(hash_input.end(), message.begin(), message.end());
    auto alpha_ser = alpha.serialize();
    hash_input.insert(hash_input.end(), alpha_ser.begin(), alpha_ser.end());

    RingElement c_next = hashToScalar(hash_input);

    // Propagate challenge through the ring
    std::vector<RingElement> challenges(n);
    size_t idx = (real_index + 1) % n;
    challenges[idx] = c_next;

    for (size_t i = 0; i < n - 1; i++) {
        // L_i = s_i + c_i * P_i (simplified lattice verification)
        RingElement L = sig.responses[idx];
        for (size_t k = 0; k < LatticeParams::K; k++) {
            L = L + (challenges[idx] * ring[idx].key[k]);
        }

        // R_i = s_i * H_p(P_i) + c_i * I
        RingElement hp = hashToPoint(ring[idx]);
        RingElement R = sig.responses[idx] * hp + challenges[idx] * sig.key_image.image;

        // Next challenge
        hash_input.clear();
        hash_input.insert(hash_input.end(), message.begin(), message.end());
        auto L_ser = L.serialize();
        hash_input.insert(hash_input.end(), L_ser.begin(), L_ser.end());
        auto R_ser = R.serialize();
        hash_input.insert(hash_input.end(), R_ser.begin(), R_ser.end());

        idx = (idx + 1) % n;
        challenges[idx] = hashToScalar(hash_input);
    }

    // Store initial challenge seed
    sig.challenge_seed = challenges[(real_index + 1) % n];

    // Close the ring: compute response at real_index
    // s_real = alpha - c_real * x
    sig.responses[real_index] = alpha - challenges[real_index] * private_key;

    return sig;
}

bool LatticeRingSignature::verify(
    const std::array<uint8_t, 32>& message,
    const std::vector<LatticePublicKey>& ring) const
{
    const size_t n = ring.size();

    if (n == 0 || responses.size() != n) {
        return false;
    }

    // Verify the ring signature by reconstructing the challenge chain
    RingElement c = challenge_seed;

    for (size_t i = 0; i < n; i++) {
        // L_i = s_i + c_i * P_i
        RingElement L = responses[i];
        for (size_t k = 0; k < LatticeParams::K; k++) {
            L = L + (c * ring[i].key[k]);
        }

        // R_i = s_i * H_p(P_i) + c_i * I
        RingElement hp = hashToPoint(ring[i]);
        RingElement R = responses[i] * hp + c * key_image.image;

        // Next challenge
        std::vector<uint8_t> hash_input;
        hash_input.insert(hash_input.end(), message.begin(), message.end());
        auto L_ser = L.serialize();
        hash_input.insert(hash_input.end(), L_ser.begin(), L_ser.end());
        auto R_ser = R.serialize();
        hash_input.insert(hash_input.end(), R_ser.begin(), R_ser.end());

        c = hashToScalar(hash_input);
    }

    // Verify ring closes: final challenge should equal initial
    for (size_t i = 0; i < LatticeParams::N; i++) {
        int64_t diff = (c.coeffs[i] - challenge_seed.coeffs[i]) % LatticeParams::Q;
        if (diff < 0) diff += LatticeParams::Q;
        if (diff != 0) return false;
    }

    return true;
}

bool LatticeRingSignature::batchVerify(
    const std::vector<LatticeRingSignature>& signatures,
    const std::vector<std::array<uint8_t, 32> >& messages,
    const std::vector<std::vector<LatticePublicKey> >& rings)
{
    // TODO: Implement efficient batch verification using LatticeFold+
    // For now, verify individually

    if (signatures.size() != messages.size() || signatures.size() != rings.size()) {
        return false;
    }

    for (size_t i = 0; i < signatures.size(); i++) {
        if (!signatures[i].verify(messages[i], rings[i])) {
            return false;
        }
    }
    return true;
}

size_t LatticeRingSignature::size() const
{
    // key_image + responses + challenge_seed
    size_t elem_size = LatticeParams::N * sizeof(int64_t);
    return elem_size + (responses.size() * elem_size) + elem_size;
}

std::vector<uint8_t> LatticeRingSignature::serialize() const
{
    std::vector<uint8_t> result;

    // Key image
    auto ki_ser = key_image.serialize();
    result.insert(result.end(), ki_ser.begin(), ki_ser.end());

    // Number of responses
    uint32_t n = static_cast<uint32_t>(responses.size());
    result.push_back((n >> 0) & 0xFF);
    result.push_back((n >> 8) & 0xFF);
    result.push_back((n >> 16) & 0xFF);
    result.push_back((n >> 24) & 0xFF);

    // Responses
    for (const auto& r : responses) {
        auto r_ser = r.serialize();
        result.insert(result.end(), r_ser.begin(), r_ser.end());
    }

    // Challenge seed
    auto cs_ser = challenge_seed.serialize();
    result.insert(result.end(), cs_ser.begin(), cs_ser.end());

    return result;
}

LatticeRingSignature LatticeRingSignature::deserialize(const std::vector<uint8_t>& data)
{
    LatticeRingSignature sig;
    size_t elem_size = LatticeParams::N * sizeof(int64_t);
    size_t offset = 0;

    if (data.size() < elem_size + 4) return sig;

    // Key image
    std::vector<uint8_t> ki_data(data.begin(), data.begin() + elem_size);
    sig.key_image = KeyImage::deserialize(ki_data);
    offset += elem_size;

    // Number of responses
    uint32_t n = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
    offset += 4;

    // Responses
    sig.responses.resize(n);
    for (uint32_t i = 0; i < n && offset + elem_size <= data.size(); i++) {
        std::vector<uint8_t> r_data(data.begin() + offset, data.begin() + offset + elem_size);
        sig.responses[i] = RingElement::deserialize(r_data);
        offset += elem_size;
    }

    // Challenge seed
    if (offset + elem_size <= data.size()) {
        std::vector<uint8_t> cs_data(data.begin() + offset, data.begin() + offset + elem_size);
        sig.challenge_seed = RingElement::deserialize(cs_data);
    }

    return sig;
}

} // namespace latticebp
