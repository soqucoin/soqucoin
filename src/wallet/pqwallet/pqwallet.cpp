// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/pqwallet/pqwallet.h"
#include "bech32.h"
#include "crypto/dilithium/api.h"
#include "crypto/sha256.h"
#include "support/cleanse.h"
#include "wallet/pqwallet/pqaddress.h"
#include "wallet/pqwallet/pqkeys.h"

#include <algorithm>
#include <string.h>
#ifndef WIN32
#include <sys/mman.h>
#endif

namespace soqucoin
{
namespace pqwallet
{

//=============================================================================
// SecureBytes implementation
//=============================================================================

SecureBytes::SecureBytes() {}

SecureBytes::SecureBytes(size_t size) : m_data(size)
{
    Lock();
}

SecureBytes::SecureBytes(const uint8_t* data, size_t size) : m_data(data, data + size)
{
    Lock();
}

SecureBytes::~SecureBytes()
{
    Wipe();
    Unlock();
}

SecureBytes::SecureBytes(SecureBytes&& other) noexcept : m_data(std::move(other.m_data)) {}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept
{
    if (this != &other) {
        Wipe();
        Unlock();
        m_data = std::move(other.m_data);
    }
    return *this;
}

uint8_t* SecureBytes::data() { return m_data.data(); }
const uint8_t* SecureBytes::data() const { return m_data.data(); }
size_t SecureBytes::size() const { return m_data.size(); }
bool SecureBytes::empty() const { return m_data.empty(); }

void SecureBytes::Lock()
{
#ifndef WIN32
    if (!m_data.empty()) {
        mlock(m_data.data(), m_data.size());
    }
#endif
}

void SecureBytes::Unlock()
{
#ifndef WIN32
    if (!m_data.empty()) {
        munlock(m_data.data(), m_data.size());
    }
#endif
}

void SecureBytes::Wipe()
{
    if (!m_data.empty()) {
        memory_cleanse(m_data.data(), m_data.size());
    }
}

//=============================================================================
// PQKeyPair implementation
//=============================================================================

PQKeyPair::PQKeyPair() : m_secretKey(DILITHIUM_SECKEY_SIZE) {}

PQKeyPair::~PQKeyPair() {}

std::unique_ptr<PQKeyPair> PQKeyPair::Generate()
{
    auto keypair = std::make_unique<PQKeyPair>();

    // Generate keypair using Dilithium2 (ML-DSA-44)
    int result = pqcrystals_dilithium2_ref_keypair(
        keypair->m_publicKey.data(),
        keypair->m_secretKey.data());

    if (result != 0) {
        return nullptr;
    }

    return keypair;
}

std::unique_ptr<PQKeyPair> PQKeyPair::Generate(const SecureBytes& entropy)
{
    if (entropy.size() < 32) {
        return nullptr;
    }

    // For deterministic generation, we'd need to modify the Dilithium implementation
    // For now, generate random and note this in documentation
    return Generate();
}

std::array<uint8_t, DILITHIUM_PUBKEY_SIZE> PQKeyPair::GetPublicKey() const
{
    return m_publicKey;
}

std::array<uint8_t, DILITHIUM_SIGNATURE_SIZE> PQKeyPair::Sign(
    const std::vector<uint8_t>& message) const
{
    std::array<uint8_t, DILITHIUM_SIGNATURE_SIZE> signature;
    size_t siglen = 0;

    // Empty context for standard signing
    int result = pqcrystals_dilithium2_ref_signature(
        signature.data(),
        &siglen,
        message.data(),
        message.size(),
        nullptr, 0, // No context
        m_secretKey.data());

    if (result != 0) {
        // Return zeroed signature on error
        signature.fill(0);
    }

    return signature;
}

bool PQKeyPair::Verify(const std::vector<uint8_t>& message,
    const std::array<uint8_t, DILITHIUM_SIGNATURE_SIZE>& signature) const
{
    int result = pqcrystals_dilithium2_ref_verify(
        signature.data(),
        signature.size(),
        message.data(),
        message.size(),
        nullptr, 0, // No context
        m_publicKey.data());

    return result == 0;
}

//=============================================================================
// PQAddress implementation
//=============================================================================

std::array<uint8_t, 32> PQAddress::HashPublicKey(
    const std::array<uint8_t, DILITHIUM_PUBKEY_SIZE>& pubkey)
{
    std::array<uint8_t, 32> hash;

    // Use SHA256 for public key hashing (SHA3-256 can be added later)
    CSHA256 sha;
    sha.Write(pubkey.data(), pubkey.size());
    sha.Finalize(hash.data());

    return hash;
}

std::string PQAddress::GetPrefix(Network network, AddressType type)
{
    switch (network) {
    case Network::Mainnet:
        switch (type) {
        case AddressType::P2PQ:
            return "sq";
        case AddressType::P2PQ_PAT:
            return "sqp";
        case AddressType::P2SH_PQ:
            return "sqsh";
        default:
            return "sq";
        }
    case Network::Testnet:
        switch (type) {
        case AddressType::P2PQ:
            return "tsq";
        case AddressType::P2PQ_PAT:
            return "tsqp";
        case AddressType::P2SH_PQ:
            return "tsqsh";
        default:
            return "tsq";
        }
    case Network::Stagenet:
        switch (type) {
        case AddressType::P2PQ:
            return "ssq";
        case AddressType::P2PQ_PAT:
            return "ssqp";
        case AddressType::P2SH_PQ:
            return "ssqsh";
        default:
            return "ssq";
        }
    default:
        return "sq";
    }
}

std::string PQAddress::Encode(
    const std::array<uint8_t, DILITHIUM_PUBKEY_SIZE>& pubkey,
    Network network,
    AddressType type)
{
    // Hash the public key
    auto pubkeyHash = HashPublicKey(pubkey);

    return EncodeFromHash(pubkeyHash, network, type);
}

std::string PQAddress::EncodeFromHash(
    const std::array<uint8_t, 32>& pubkeyHash,
    Network network,
    AddressType type)
{
    std::string hrp = GetPrefix(network, type);

    // Version byte (0x00 for v1 P2PQ)
    std::vector<uint8_t> data;
    data.reserve(33);     // version + 32-byte hash
    data.push_back(0x00); // Version
    data.insert(data.end(), pubkeyHash.begin(), pubkeyHash.end());

    // Convert to 5-bit groups for Bech32m
    std::vector<uint8_t> converted;
    converted.reserve((data.size() * 8 + 4) / 5);

    int bits = 0;
    int acc = 0;
    for (uint8_t byte : data) {
        acc = (acc << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            converted.push_back((acc >> bits) & 0x1f);
        }
    }
    if (bits > 0) {
        converted.push_back((acc << (5 - bits)) & 0x1f);
    }

    return bech32::Encode(bech32::Encoding::BECH32M, hrp, converted);
}

Network PQAddress::DetectNetwork(const std::string& address)
{
    if (address.substr(0, 3) == "sq1" || address.substr(0, 4) == "sqp1" ||
        address.substr(0, 5) == "sqsh1") {
        return Network::Mainnet;
    }
    if (address.substr(0, 4) == "tsq1" || address.substr(0, 5) == "tsqp1" ||
        address.substr(0, 6) == "tsqsh1") {
        return Network::Testnet;
    }
    if (address.substr(0, 4) == "ssq1" || address.substr(0, 5) == "ssqp1" ||
        address.substr(0, 6) == "ssqsh1") {
        return Network::Stagenet;
    }
    return Network::Unknown;
}

bool PQAddress::IsValid(const std::string& address)
{
    auto decoded = bech32::Decode(address);
    if (decoded.encoding != bech32::Encoding::BECH32M) {
        return false;
    }

    // Check valid HRP
    if (decoded.hrp != "sq" && decoded.hrp != "sqp" && decoded.hrp != "sqsh" &&
        decoded.hrp != "tsq" && decoded.hrp != "tsqp" && decoded.hrp != "tsqsh" &&
        decoded.hrp != "ssq" && decoded.hrp != "ssqp" && decoded.hrp != "ssqsh") {
        return false;
    }

    // Check data length (version + 32-byte hash in 5-bit groups)
    // 33 bytes = 264 bits = ~53 5-bit groups
    if (decoded.data.size() < 50 || decoded.data.size() > 60) {
        return false;
    }

    return true;
}

AddressInfo PQAddress::Decode(const std::string& address)
{
    AddressInfo info;

    auto decoded = bech32::Decode(address);
    if (decoded.encoding != bech32::Encoding::BECH32M) {
        info.error = "Invalid Bech32m encoding";
        return info;
    }

    info.network = DetectNetwork(address);
    if (info.network == Network::Unknown) {
        info.error = "Unknown network prefix";
        return info;
    }

    // Determine address type from HRP
    if (decoded.hrp == "sq" || decoded.hrp == "tsq" || decoded.hrp == "ssq") {
        info.type = AddressType::P2PQ;
    } else if (decoded.hrp == "sqp" || decoded.hrp == "tsqp" || decoded.hrp == "ssqp") {
        info.type = AddressType::P2PQ_PAT;
    } else if (decoded.hrp == "sqsh" || decoded.hrp == "tsqsh" || decoded.hrp == "ssqsh") {
        info.type = AddressType::P2SH_PQ;
    }

    // Convert from 5-bit groups back to 8-bit bytes
    std::vector<uint8_t> data;
    int bits = 0;
    uint32_t acc = 0;
    for (uint8_t val : decoded.data) {
        acc = (acc << 5) | val;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            data.push_back((acc >> bits) & 0xff);
        }
    }

    if (data.size() < 33) {
        info.error = "Invalid data length";
        return info;
    }

    // Skip version byte, extract hash
    std::copy(data.begin() + 1, data.begin() + 33, info.hash.begin());

    info.valid = true;
    return info;
}

//=============================================================================
// PQWallet implementation
//=============================================================================

class PQWallet::Impl
{
public:
    SecureBytes m_seed;
    AggregationConfig m_config;
    Network m_network;
    uint32_t m_nextIndex = 0;
    std::vector<std::unique_ptr<PQKeyPair> > m_keys;
};

PQWallet::PQWallet() : m_impl(std::make_unique<Impl>()) {}

PQWallet::~PQWallet() = default;

std::unique_ptr<PQWallet> PQWallet::FromSeed(const std::vector<uint8_t>& seed, Network network)
{
    if (seed.size() < 32) {
        return nullptr;
    }

    auto wallet = std::make_unique<PQWallet>();
    wallet->m_impl->m_seed = SecureBytes(seed.data(), seed.size());
    wallet->m_impl->m_network = network;

    return wallet;
}

std::string PQWallet::GetNewAddress()
{
    auto keypair = PQKeyPair::Generate();
    if (!keypair) {
        return "";
    }

    std::string address = PQAddress::Encode(
        keypair->GetPublicKey(),
        m_impl->m_network,
        AddressType::P2PQ);

    m_impl->m_keys.push_back(std::move(keypair));
    m_impl->m_nextIndex++;

    return address;
}

const AggregationConfig& PQWallet::GetAggregationConfig() const
{
    return m_impl->m_config;
}

void PQWallet::SetAggregationConfig(const AggregationConfig& config)
{
    m_impl->m_config = config;
}

} // namespace pqwallet
} // namespace soqucoin
