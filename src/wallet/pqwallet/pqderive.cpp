// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/pqwallet/pqderive.h"
#include "crypto/sha256.h"
#include "support/cleanse.h"

#include <cstring>
#include <sstream>

// Dilithium seed keypair function
extern "C" int pqcrystals_dilithium2_ref_seed_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed);

namespace soqucoin
{
namespace pqwallet
{

// Domain separator constants (per whitepaper Section 10.4)
const std::string DOMAIN_WALLET = "soqucoin-pqwallet-v1";
const std::string DOMAIN_BLINDING = "soqucoin-blinding-v1";
const std::string DOMAIN_CHANNEL = "soqucoin-v1/channel";
const std::string DOMAIN_WATCHTOWER = "soqucoin-v1/watchtower";

//=============================================================================
// HKDF-SHA256 Implementation (NIST SP 800-56C)
//=============================================================================

/**
 * @brief HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
 */
static std::array<uint8_t, 32> HKDFExtract(
    const uint8_t* salt,
    size_t saltLen,
    const uint8_t* ikm,
    size_t ikmLen)
{
    std::array<uint8_t, 32> prk;

    // Default salt if empty
    std::array<uint8_t, 32> defaultSalt{};
    if (salt == nullptr || saltLen == 0) {
        salt = defaultSalt.data();
        saltLen = 32;
    }

    // HMAC-SHA256 key padding
    std::array<uint8_t, 64> ipad{}, opad{};

    // Hash salt if > 64 bytes
    std::array<uint8_t, 32> hashedSalt;
    if (saltLen > 64) {
        CSHA256().Write(salt, saltLen).Finalize(hashedSalt.data());
        salt = hashedSalt.data();
        saltLen = 32;
    }

    for (size_t i = 0; i < 64; ++i) {
        uint8_t k = (i < saltLen) ? salt[i] : 0;
        ipad[i] = k ^ 0x36;
        opad[i] = k ^ 0x5c;
    }

    // Inner hash
    std::array<uint8_t, 32> inner;
    CSHA256()
        .Write(ipad.data(), 64)
        .Write(ikm, ikmLen)
        .Finalize(inner.data());

    // Outer hash
    CSHA256()
        .Write(opad.data(), 64)
        .Write(inner.data(), 32)
        .Finalize(prk.data());

    memory_cleanse(inner.data(), inner.size());
    memory_cleanse(ipad.data(), ipad.size());
    memory_cleanse(opad.data(), opad.size());

    return prk;
}

/**
 * @brief HKDF-Expand: OKM = T1 || T2 || ...
 */
static void HKDFExpand(
    const std::array<uint8_t, 32>& prk,
    const uint8_t* info,
    size_t infoLen,
    uint8_t* okm,
    size_t okmLen)
{
    size_t n = (okmLen + 31) / 32;
    std::array<uint8_t, 32> t{};
    size_t tLen = 0;

    for (size_t i = 1; i <= n; ++i) {
        std::array<uint8_t, 64> ipad{}, opad{};

        for (size_t j = 0; j < 32; ++j) {
            ipad[j] = prk[j] ^ 0x36;
            opad[j] = prk[j] ^ 0x5c;
        }
        for (size_t j = 32; j < 64; ++j) {
            ipad[j] = 0x36;
            opad[j] = 0x5c;
        }

        // Inner hash
        CSHA256 inner;
        inner.Write(ipad.data(), 64);
        if (tLen > 0) {
            inner.Write(t.data(), tLen);
        }
        inner.Write(info, infoLen);
        uint8_t counter = static_cast<uint8_t>(i);
        inner.Write(&counter, 1);

        std::array<uint8_t, 32> innerHash;
        inner.Finalize(innerHash.data());

        // Outer hash
        CSHA256()
            .Write(opad.data(), 64)
            .Write(innerHash.data(), 32)
            .Finalize(t.data());

        tLen = 32;

        size_t copyLen = std::min(size_t(32), okmLen - (i - 1) * 32);
        std::memcpy(okm + (i - 1) * 32, t.data(), copyLen);

        memory_cleanse(ipad.data(), ipad.size());
        memory_cleanse(opad.data(), opad.size());
        memory_cleanse(innerHash.data(), innerHash.size());
    }

    memory_cleanse(t.data(), t.size());
}

//=============================================================================
// Path serialization
//=============================================================================

std::vector<uint8_t> PathToBytes(const DerivationPath& path)
{
    std::vector<uint8_t> result(20);

    auto writeU32 = [](uint8_t* dst, uint32_t val) {
        dst[0] = (val >> 24) & 0xff;
        dst[1] = (val >> 16) & 0xff;
        dst[2] = (val >> 8) & 0xff;
        dst[3] = val & 0xff;
    };

    writeU32(result.data() + 0, path.purpose | 0x80000000);  // Hardened
    writeU32(result.data() + 4, path.coinType | 0x80000000); // Hardened
    writeU32(result.data() + 8, path.account | 0x80000000);  // Hardened
    writeU32(result.data() + 12, path.change);               // Not hardened
    writeU32(result.data() + 16, path.index);                // Not hardened

    return result;
}

//=============================================================================
// Key derivation functions
//=============================================================================

std::array<uint8_t, 32> DeriveKeyMaterial(
    const SecureBytes& masterSeed,
    const DerivationPath& path,
    const std::string& domain)
{
    if (masterSeed.size() < 32) {
        return {};
    }

    // Salt = SHA-256(master_seed)
    std::array<uint8_t, 32> salt;
    CSHA256().Write(masterSeed.data(), masterSeed.size()).Finalize(salt.data());

    // Info = domain || path_bytes
    std::vector<uint8_t> info(domain.begin(), domain.end());
    auto pathBytes = PathToBytes(path);
    info.insert(info.end(), pathBytes.begin(), pathBytes.end());

    // HKDF
    auto prk = HKDFExtract(salt.data(), salt.size(), masterSeed.data(), masterSeed.size());

    std::array<uint8_t, 32> okm;
    HKDFExpand(prk, info.data(), info.size(), okm.data(), okm.size());

    memory_cleanse(salt.data(), salt.size());
    memory_cleanse(prk.data(), prk.size());

    return okm;
}

std::array<uint8_t, 32> DeriveBlindingFactor(
    const SecureBytes& masterSeed,
    uint64_t outputIndex)
{
    // SECURITY NOTE (Halborn FIND-019): Previously used DerivationPath which
    // truncates outputIndex to uint32_t via static_cast. Outputs at index n
    // and n + 2^32 produced identical blinding factors, breaking transaction
    // graph privacy. Now encodes full 64-bit index as 8 big-endian bytes
    // directly into the HKDF info string, bypassing DerivationPath entirely.
    if (masterSeed.size() < 32) {
        return {};
    }

    // Salt = SHA-256(master_seed)
    std::array<uint8_t, 32> salt;
    CSHA256().Write(masterSeed.data(), masterSeed.size()).Finalize(salt.data());

    // Info = domain || 8-byte big-endian outputIndex
    std::vector<uint8_t> info(DOMAIN_BLINDING.begin(), DOMAIN_BLINDING.end());
    uint8_t indexBytes[8];
    indexBytes[0] = (outputIndex >> 56) & 0xff;
    indexBytes[1] = (outputIndex >> 48) & 0xff;
    indexBytes[2] = (outputIndex >> 40) & 0xff;
    indexBytes[3] = (outputIndex >> 32) & 0xff;
    indexBytes[4] = (outputIndex >> 24) & 0xff;
    indexBytes[5] = (outputIndex >> 16) & 0xff;
    indexBytes[6] = (outputIndex >> 8) & 0xff;
    indexBytes[7] = outputIndex & 0xff;
    info.insert(info.end(), indexBytes, indexBytes + 8);

    // HKDF
    auto prk = HKDFExtract(salt.data(), salt.size(), masterSeed.data(), masterSeed.size());

    std::array<uint8_t, 32> okm;
    HKDFExpand(prk, info.data(), info.size(), okm.data(), okm.size());

    memory_cleanse(salt.data(), salt.size());
    memory_cleanse(prk.data(), prk.size());

    return okm;
}

std::array<uint8_t, 32> DeriveChannelKey(
    const SecureBytes& masterSeed,
    const std::string& channelId,
    const std::string& keyType,
    uint32_t index)
{
    if (masterSeed.size() < 32) {
        return {};
    }

    // Construct domain: "soqucoin-v1/channel/{id}/{type}/{n}"
    std::string domain = DOMAIN_CHANNEL + "/" + channelId + "/" + keyType;
    if (keyType == "revoke" || keyType == "htlc") {
        std::ostringstream ss;
        ss << domain << "/" << index;
        domain = ss.str();
    }

    // Salt = SHA-256(master_seed)
    std::array<uint8_t, 32> salt;
    CSHA256().Write(masterSeed.data(), masterSeed.size()).Finalize(salt.data());

    std::vector<uint8_t> info(domain.begin(), domain.end());

    auto prk = HKDFExtract(salt.data(), salt.size(), masterSeed.data(), masterSeed.size());

    std::array<uint8_t, 32> okm;
    HKDFExpand(prk, info.data(), info.size(), okm.data(), okm.size());

    memory_cleanse(salt.data(), salt.size());
    memory_cleanse(prk.data(), prk.size());

    return okm;
}

//=============================================================================
// PQKeyPair::DeriveFromSeed implementation
// (Implements the declaration in pqkeys.h)
//=============================================================================

std::unique_ptr<PQKeyPair> PQKeyPair::DeriveFromSeed(
    const SecureBytes& seed,
    const DerivationPath& path)
{
    auto keyMaterial = DeriveKeyMaterial(seed, path, DOMAIN_WALLET);

    auto keypair = std::make_unique<PQKeyPair>();

    // Get internal access for initialization
    std::array<uint8_t, DILITHIUM_PUBKEY_SIZE> pubkey;
    SecureBytes seckey(DILITHIUM_SECKEY_SIZE);

    int result = pqcrystals_dilithium2_ref_seed_keypair(
        pubkey.data(),
        seckey.data(),
        keyMaterial.data());

    memory_cleanse(keyMaterial.data(), keyMaterial.size());

    if (result != 0) {
        memory_cleanse(pubkey.data(), pubkey.size());
        return nullptr;
    }

    // SECURITY NOTE (Halborn FIND-011): Previously, the generated keypair was
    // never copied into the PQKeyPair object — DeriveFromSeed returned a
    // zeroed keypair. Now we directly initialize the internal fields.
    // PQKeyPair::m_publicKey and m_secretKey are private but accessible
    // from this static member function.
    keypair->m_publicKey = pubkey;
    keypair->m_secretKey = SecureBytes(seckey.data(), seckey.size());

    // Wipe local copies
    memory_cleanse(pubkey.data(), pubkey.size());

    return keypair;
}

} // namespace pqwallet
} // namespace soqucoin
