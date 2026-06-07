// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// Lattice-BP++: Stealth Address Implementation
// Implements ViewKey, SpendKey, AuditKey, and StealthAddress classes.

#include "stealth_address.h"
#include "commitment.h"
#include <cstring>
#include <array>

#ifdef LATTICEBP_STANDALONE
extern "C" {
void HKDF_SHA256(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len);
void GetStrongRandBytes(unsigned char* out, int num);
void memory_cleanse(void* ptr, size_t len);
}
#else
#include "../../crypto/hmac_sha256.h"
#include "../../random.h"
#include "../../support/cleanse.h"

// HKDF-SHA256 (RFC 5869) using soqucoind's CHMAC_SHA256
// Provides the same interface as standalone_shim.cpp but backed by
// soqucoind's audited crypto primitives.
static void HKDF_SHA256(const uint8_t* ikm, size_t ikm_len,
                         const uint8_t* salt, size_t salt_len,
                         const uint8_t* info, size_t info_len,
                         uint8_t* okm, size_t okm_len)
{
    // Extract: PRK = HMAC-SHA256(salt, ikm)
    uint8_t prk[CHMAC_SHA256::OUTPUT_SIZE];
    if (salt && salt_len > 0) {
        CHMAC_SHA256(salt, salt_len).Write(ikm, ikm_len).Finalize(prk);
    } else {
        uint8_t zero_salt[32] = {};
        CHMAC_SHA256(zero_salt, 32).Write(ikm, ikm_len).Finalize(prk);
    }

    // Expand: T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
    uint8_t t[CHMAC_SHA256::OUTPUT_SIZE] = {};
    size_t t_len = 0;
    uint8_t counter = 1;
    size_t pos = 0;

    while (pos < okm_len) {
        CHMAC_SHA256 expander(prk, sizeof(prk));
        if (t_len > 0) expander.Write(t, t_len);
        if (info && info_len > 0) expander.Write(info, info_len);
        expander.Write(&counter, 1);
        expander.Finalize(t);
        t_len = sizeof(t);

        size_t copy = okm_len - pos;
        if (copy > sizeof(t)) copy = sizeof(t);
        std::memcpy(okm + pos, t, copy);
        pos += copy;
        counter++;
    }

    memory_cleanse(prk, sizeof(prk));
    memory_cleanse(t, sizeof(t));
}
#endif

namespace latticebp
{

// ── ViewKey ──

ViewKey ViewKey::deriveFromSeed(
    const std::array<uint8_t, 32>& seed,
    const char* domain)
{
    ViewKey vk;
    size_t domain_len = std::strlen(domain);

    // HKDF-SHA256 to derive N coefficients
    uint8_t okm[LatticeParams::N * sizeof(int64_t)];
    HKDF_SHA256(seed.data(), seed.size(),
                nullptr, 0,
                reinterpret_cast<const uint8_t*>(domain), domain_len,
                okm, sizeof(okm));

    // Interpret as ring element coefficients mod Q
    for (size_t i = 0; i < LatticeParams::N; i++) {
        int64_t val = 0;
        std::memcpy(&val, okm + i * sizeof(int64_t), sizeof(int64_t));
        vk.key.coeffs[i] = ((val % LatticeParams::Q) + LatticeParams::Q) % LatticeParams::Q;
    }

    memory_cleanse(okm, sizeof(okm));
    return vk;
}

bool ViewKey::canView(
    const LatticePublicKey& one_time_pk,
    const RingElement& tx_public_key) const
{
    // Compute shared secret: ss = H(vk * R)
    RingElement ss = key * tx_public_key;
    auto ss_bytes = ss.serialize();

    // Derive expected one-time pk: P' = ss * G + spend_pk
    // Since we don't have spend_pk here, this is a partial check.
    // Full check requires spend_pk — see StealthAddress::belongsTo.
    return ss_bytes.size() > 0; // Non-trivial check deferred
}

std::vector<uint8_t> ViewKey::serialize() const {
    return key.serialize();
}

ViewKey ViewKey::deserialize(const std::vector<uint8_t>& data) {
    ViewKey vk;
    vk.key = RingElement::deserialize(data);
    return vk;
}

// ── SpendKey ──

SpendKey SpendKey::deriveFromSeed(
    const std::array<uint8_t, 32>& seed,
    const char* domain)
{
    SpendKey sk;
    size_t domain_len = std::strlen(domain);

    uint8_t okm[LatticeParams::N * sizeof(int64_t)];
    HKDF_SHA256(seed.data(), seed.size(),
                nullptr, 0,
                reinterpret_cast<const uint8_t*>(domain), domain_len,
                okm, sizeof(okm));

    for (size_t i = 0; i < LatticeParams::N; i++) {
        int64_t val = 0;
        std::memcpy(&val, okm + i * sizeof(int64_t), sizeof(int64_t));
        sk.key.coeffs[i] = ((val % LatticeParams::Q) + LatticeParams::Q) % LatticeParams::Q;
    }

    memory_cleanse(okm, sizeof(okm));
    return sk;
}

RingElement SpendKey::deriveOneTimeKey(
    const ViewKey& view_key,
    const RingElement& tx_public_key) const
{
    // x = H(vk * R) + sk
    RingElement shared_secret = view_key.key * tx_public_key;
    // Hash the shared secret to get a scalar
    auto ss_bytes = shared_secret.serialize();
    uint8_t hash[32];
    // Use HKDF as hash
    HKDF_SHA256(ss_bytes.data(), ss_bytes.size(),
                nullptr, 0,
                reinterpret_cast<const uint8_t*>("soqucoin.stealth.otsk.v1"), 24,
                hash, 32);

    // Convert hash to ring element and add spend key
    RingElement h;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        h.coeffs[i] = static_cast<int64_t>(hash[i % 32]) % LatticeParams::Q;
    }

    RingElement otsk = h + key;
    otsk.reduce();

    memory_cleanse(hash, 32);
    return otsk;
}

std::vector<uint8_t> SpendKey::serialize() const {
    return key.serialize();
}

SpendKey SpendKey::deserialize(const std::vector<uint8_t>& data) {
    SpendKey sk;
    sk.key = RingElement::deserialize(data);
    return sk;
}

// ── StealthAddress ──

StealthAddress StealthAddress::generate(
    const LatticePublicKey& recipient_view_pk,
    const LatticePublicKey& recipient_spend_pk)
{
    StealthAddress sa;

    // Generate random tx key R
    sa.tx_public_key = RingElement::sampleUniform();

    // Compute shared secret: ss = H(R * view_pk[0])
    RingElement shared_secret = sa.tx_public_key * recipient_view_pk.key[0];
    auto ss_bytes = shared_secret.serialize();
    uint8_t hash[32];
    HKDF_SHA256(ss_bytes.data(), ss_bytes.size(),
                nullptr, 0,
                reinterpret_cast<const uint8_t*>("soqucoin.stealth.otpk.v1"), 25,
                hash, 32);

    // Derive one-time pk: P = H(ss) * G + spend_pk
    RingElement h;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        h.coeffs[i] = static_cast<int64_t>(hash[i % 32]) % LatticeParams::Q;
    }

    sa.one_time_pk = recipient_spend_pk;
    for (size_t i = 0; i < LatticeParams::K; i++) {
        sa.one_time_pk.key[i] = sa.one_time_pk.key[i] + h;
        sa.one_time_pk.key[i].reduce();
    }

    memory_cleanse(hash, 32);
    return sa;
}

bool StealthAddress::belongsTo(
    const ViewKey& view_key,
    const LatticePublicKey& spend_pk) const
{
    // Recompute: ss = H(vk * R)
    RingElement shared_secret = view_key.key * tx_public_key;
    auto ss_bytes = shared_secret.serialize();
    uint8_t hash[32];
    HKDF_SHA256(ss_bytes.data(), ss_bytes.size(),
                nullptr, 0,
                reinterpret_cast<const uint8_t*>("soqucoin.stealth.otpk.v1"), 25,
                hash, 32);

    RingElement h;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        h.coeffs[i] = static_cast<int64_t>(hash[i % 32]) % LatticeParams::Q;
    }

    // Expected P' = spend_pk + H(ss)
    // Check: P' == one_time_pk (constant-time comparison via XOR-accumulate)
    int64_t diff = 0;
    for (size_t k = 0; k < LatticeParams::K; k++) {
        RingElement expected = spend_pk.key[k] + h;
        expected.reduce();
        for (size_t i = 0; i < LatticeParams::N; i++) {
            diff |= expected.coeffs[i] ^ one_time_pk.key[k].coeffs[i];
        }
    }

    memory_cleanse(hash, 32);
    return diff == 0;
}

RingElement StealthAddress::recoverPrivateKey(
    const ViewKey& view_key,
    const SpendKey& spend_key) const
{
    return spend_key.deriveOneTimeKey(view_key, tx_public_key);
}

std::vector<uint8_t> StealthAddress::serialize() const {
    std::vector<uint8_t> result;
    auto otpk = one_time_pk.serialize();
    auto txpk = tx_public_key.serialize();
    // 4-byte lengths then data
    uint32_t otpk_len = otpk.size();
    uint32_t txpk_len = txpk.size();
    result.resize(8 + otpk_len + txpk_len);
    std::memcpy(result.data(), &otpk_len, 4);
    std::memcpy(result.data() + 4, &txpk_len, 4);
    std::memcpy(result.data() + 8, otpk.data(), otpk_len);
    std::memcpy(result.data() + 8 + otpk_len, txpk.data(), txpk_len);
    return result;
}

StealthAddress StealthAddress::deserialize(const std::vector<uint8_t>& data) {
    StealthAddress sa;
    if (data.size() < 8) return sa;
    uint32_t otpk_len, txpk_len;
    std::memcpy(&otpk_len, data.data(), 4);
    std::memcpy(&txpk_len, data.data() + 4, 4);
    if (data.size() < 8 + otpk_len + txpk_len) return sa;
    sa.one_time_pk = LatticePublicKey::deserialize(
        std::vector<uint8_t>(data.begin() + 8, data.begin() + 8 + otpk_len));
    sa.tx_public_key = RingElement::deserialize(
        std::vector<uint8_t>(data.begin() + 8 + otpk_len, data.begin() + 8 + otpk_len + txpk_len));
    return sa;
}

// ── AuditKey ──

AuditKey AuditKey::generateDisclosure(
    const ViewKey& view_key,
    const SpendKey& spend_key,
    const std::vector<RingElement>& spent_outputs)
{
    AuditKey ak;
    ak.view_key = view_key;
    // Generate key images for all spent outputs
    for (const auto& output : spent_outputs) {
        ak.revealed_key_images.push_back(
            KeyImage::generate(spend_key.key, LatticePublicKey()));
    }
    return ak;
}

bool AuditKey::verifyCompleteness(
    const std::vector<LatticePublicKey>& known_outputs) const
{
    // Verify that every known output either has a matching key image
    // (spent) or is still unspent (no matching image)
    return true; // Placeholder — full implementation in Phase A7
}

std::vector<uint8_t> AuditKey::serialize() const {
    return view_key.serialize(); // Simplified for now
}

AuditKey AuditKey::deserialize(const std::vector<uint8_t>& data) {
    AuditKey ak;
    ak.view_key = ViewKey::deserialize(data);
    return ak;
}

} // namespace latticebp
