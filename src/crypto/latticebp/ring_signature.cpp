// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// Lattice-BP++: Ring Signature Implementation
// Stage 3 R&D - LSAG-style anonymous signatures
//
// SECURITY NOTE (SOQ-D004 fix): The sign() function requires CSPRNG entropy.
// Build modes:
//   LATTICEBP_STANDALONE: std::random_device (R&D harness only)
//   BUILD_BITCOIN_INTERNAL: assert-fail (prover not available in shared lib)
//   Production: GetStrongRandBytes() from libsoqucoin_util
//

#include "ring_signature.h"
#include "commitment.h"
#include <algorithm>
#include <cassert>
#include <cstring>

#ifdef LATTICEBP_STANDALONE
#include <random>  // std::random_device, std::mt19937_64 (R&D only)
#else
#ifndef BUILD_BITCOIN_INTERNAL
#include "../../random.h"           // GetStrongRandBytes() — production CSPRNG
#include "../../support/cleanse.h"  // memory_cleanse()
#endif
#endif

namespace latticebp
{

// ============================================================================
// SOQ-D004 FIX: Replace non-cryptographic LCG stub with SHA256-based hash
//
// The original ring_signature.cpp contained an internal SHA3_256 function
// that used an LCG (linear congruential generator) — a non-cryptographic
// pseudo-random function. An adversary who can control input collisions
// can forge ring signatures. Fixed: use SHA256 with distinct domain
// separation per operation.
//
// Implementation: Inline SHA256 (same constants as range_proof.cpp SimpleSHA256).
// This is self-contained — no dependency on external headers beyond what's
// already available in this TU.
// ============================================================================

namespace
{

// Real SHA256 implementation (same as SimpleSHA256 in range_proof.cpp)
// SECURITY NOTE: This replaces the LCG stub that was never cryptographically
// secure. The algorithm here is FIPS 180-4 compliant SHA256.
struct RingSHA256 {
    uint8_t buffer[64];
    uint64_t total_len;
    uint32_t state[8];
    size_t buf_len;

    RingSHA256() { reset(); }

    void reset() {
        state[0] = 0x6a09e667; state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
        state[4] = 0x510e527f; state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
        total_len = 0; buf_len = 0;
        memset(buffer, 0, sizeof(buffer));
    }

    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t sig0(uint32_t x) { return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22); }
    static uint32_t sig1(uint32_t x) { return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25); }
    static uint32_t gam0(uint32_t x) { return rotr(x,7) ^ rotr(x,18) ^ (x >> 3); }
    static uint32_t gam1(uint32_t x) { return rotr(x,17) ^ rotr(x,19) ^ (x >> 10); }

    void transform(const uint8_t block[64]) {
        static const uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };
        uint32_t W[64], a, b, c, d, e, f, g, h;
        for (int i = 0; i < 16; i++)
            W[i] = ((uint32_t)block[4*i] << 24) | ((uint32_t)block[4*i+1] << 16) |
                   ((uint32_t)block[4*i+2] << 8) | block[4*i+3];
        for (int i = 16; i < 64; i++)
            W[i] = gam1(W[i-2]) + W[i-7] + gam0(W[i-15]) + W[i-16];
        a=state[0]; b=state[1]; c=state[2]; d=state[3];
        e=state[4]; f=state[5]; g=state[6]; h=state[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + sig1(e) + ch(e,f,g) + K[i] + W[i];
            uint32_t t2 = sig0(a) + maj(a,b,c);
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
        state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
    }

    void write(const uint8_t* data, size_t len) {
        total_len += len;
        while (len > 0) {
            size_t n = std::min(len, (size_t)64 - buf_len);
            memcpy(buffer + buf_len, data, n);
            buf_len += n; data += n; len -= n;
            if (buf_len == 64) { transform(buffer); buf_len = 0; }
        }
    }

    void finalize(uint8_t out[32]) {
        uint64_t bits = total_len * 8;
        uint8_t pad = 0x80;
        write(&pad, 1);
        pad = 0;
        while (buf_len != 56) write(&pad, 1);
        uint8_t len_bytes[8];
        for (int i = 7; i >= 0; i--) { len_bytes[i] = bits & 0xff; bits >>= 8; }
        write(len_bytes, 8);
        for (int i = 0; i < 8; i++) {
            out[4*i]   = (state[i] >> 24) & 0xff;
            out[4*i+1] = (state[i] >> 16) & 0xff;
            out[4*i+2] = (state[i] >>  8) & 0xff;
            out[4*i+3] =  state[i]        & 0xff;
        }
    }
};

// Hash to scalar: SHA256(domain || data) → RingElement challenge
// SOQ-D005 FIX: Each call site uses its own domain string to prevent
// cross-operation challenge confusion (stealth vs. challenge generation).
RingElement hashToScalarWithDomain(
    const char* domain,
    size_t domain_len,
    const std::vector<uint8_t>& data)
{
    RingElement result;

    // Expand SHA256(domain || data) to fill all N coefficients
    // Each coefficient gets SHA256(domain || data || index_le16)
    for (size_t i = 0; i < LatticeParams::N; i++) {
        RingSHA256 hasher;
        hasher.write(reinterpret_cast<const uint8_t*>(domain), domain_len);
        hasher.write(data.data(), data.size());
        uint8_t idx[2] = { (uint8_t)(i & 0xFF), (uint8_t)((i >> 8) & 0xFF) };
        hasher.write(idx, 2);

        uint8_t hash[32];
        hasher.finalize(hash);

        uint64_t val;
        memcpy(&val, hash, 8);
        result.coeffs[i] = (int64_t)(val % (uint64_t)LatticeParams::Q);
    }

    return result;
}

// Domain-separated wrappers — each operation has a unique domain string
// to prevent cross-operation challenge confusion (SOQ-D005).

// For Fiat-Shamir challenge generation in ring signatures
RingElement hashToScalar(const std::vector<uint8_t>& data)
{
    // SOQ-D004: Previously used insecure LCG. Now uses SHA256 with distinct domain.
    return hashToScalarWithDomain(
        "soqucoin.ring.challenge.sha256.v1",
        33, // strlen("soqucoin.ring.challenge.sha256.v1")
        data);
}

// Hash to point for key image: distinct domain from challenge generation
// SOQ-D005 FIX: Separate domain prevents key image ↔ challenge confusion.
RingElement hashToPoint(const LatticePublicKey& pk)
{
    // SOQ-D005: Changed from shared "soqucoin.ring.h2s" to distinct domain.
    std::vector<uint8_t> data;
    data.reserve(pk.key.size() * LatticeParams::N * 8);
    for (const auto& elem : pk.key) {
        auto ser = elem.serialize();
        data.insert(data.end(), ser.begin(), ser.end());
    }
    return hashToScalarWithDomain(
        "soqucoin.ring.keyimage.sha256.v1",
        32, // strlen("soqucoin.ring.keyimage.sha256.v1")
        data);
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

    // P = H_stealth(R || pk) + pk
    // SOQ-D005 FIX: Use dedicated stealth domain, distinct from challenge domain.
    // Previously: hashToScalar() with "soqucoin.ring.h2s" — same domain as
    // Fiat-Shamir challenges. Now: distinct "soqucoin.ring.stealth.sha256.v1".
    static const char STEALTH_DOMAIN[] = "soqucoin.ring.stealth.sha256.v1";

    std::vector<uint8_t> data;
    data.insert(data.end(), tx_random.begin(), tx_random.end());
    for (const auto& elem : recipient_pk.key) {
        auto ser = elem.serialize();
        data.insert(data.end(), ser.begin(), ser.end());
    }

    RingElement h = hashToScalarWithDomain(
        STEALTH_DOMAIN, sizeof(STEALTH_DOMAIN) - 1, data);

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
    // H_p uses distinct "keyimage" domain (SOQ-D005 fix in hashToPoint)
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

#ifdef BUILD_BITCOIN_INTERNAL
    // SECURITY NOTE: Ring signature *signing* is a prover-side operation.
    // The consensus shared lib only needs verification. Abort if called.
    (void)message; (void)ring; (void)real_index; (void)private_key;
    assert(!"LatticeRingSignature::sign() not available in consensus shared lib");
    return sig;
#else
    // Generate key image (uses hashToPoint with distinct domain — SOQ-D005 fixed)
    sig.key_image = KeyImage::generate(private_key, ring[real_index]);

    // Generate random alpha (commitment randomness)
    // SECURITY NOTE (SOQ-D004): Uses sampleGaussian() which routes through
    // GetStrongRandBytes() in production, std::random_device in R&D.
    RingElement alpha = RingElement::sampleGaussian(LatticeParams::SIGMA);

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
    // SOQ-D004: H now uses SHA256 via hashToScalar (not LCG)

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
        RingElement hp = hashToPoint(ring[idx]);  // uses distinct domain (SOQ-D005)
        RingElement R = sig.responses[idx] * hp + challenges[idx] * sig.key_image.image;

        // Next challenge (SOQ-D004: SHA256-based, not LCG)
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
#endif // BUILD_BITCOIN_INTERNAL
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
    // SOQ-D004: hashToScalar and hashToPoint now use SHA256 (not LCG)
    RingElement c = challenge_seed;

    for (size_t i = 0; i < n; i++) {
        // L_i = s_i + c_i * P_i
        RingElement L = responses[i];
        for (size_t k = 0; k < LatticeParams::K; k++) {
            L = L + (c * ring[i].key[k]);
        }

        // R_i = s_i * H_p(P_i) + c_i * I
        // hashToPoint uses distinct "keyimage" domain (SOQ-D005)
        RingElement hp = hashToPoint(ring[i]);
        RingElement R = responses[i] * hp + c * key_image.image;

        // Next challenge (SHA256-based — SOQ-D004)
        std::vector<uint8_t> hash_input;
        hash_input.insert(hash_input.end(), message.begin(), message.end());
        auto L_ser = L.serialize();
        hash_input.insert(hash_input.end(), L_ser.begin(), L_ser.end());
        auto R_ser = R.serialize();
        hash_input.insert(hash_input.end(), R_ser.begin(), R_ser.end());

        c = hashToScalar(hash_input);
    }

    // Verify ring closes: final challenge should equal initial
    // Constant-time comparison (avoid timing oracle)
    uint64_t diff_acc = 0;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        int64_t a = c.coeffs[i] % LatticeParams::Q;
        if (a < 0) a += LatticeParams::Q;
        int64_t b = challenge_seed.coeffs[i] % LatticeParams::Q;
        if (b < 0) b += LatticeParams::Q;
        diff_acc |= (uint64_t)(a - b);
    }

    return diff_acc == 0;
}

bool LatticeRingSignature::batchVerify(
    const std::vector<LatticeRingSignature>& signatures,
    const std::vector<std::array<uint8_t, 32>>& messages,
    const std::vector<std::vector<LatticePublicKey>>& rings)
{
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
    result.push_back((n >>  0) & 0xFF);
    result.push_back((n >>  8) & 0xFF);
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
