// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file pqwallet.cpp
 * @brief Post-Quantum Wallet Core Implementation
 *
 * SECURITY OVERVIEW:
 * This file implements the core post-quantum wallet functionality using
 * Dilithium (ML-DSA-44) as specified in NIST FIPS 204.
 *
 * THREAT MODEL COVERAGE:
 * - I1 (Key disclosure via memory): SecureBytes with mlock() + Wipe()
 * - I6 (Side-channel attacks): Uses NIST reference impl (assumed constant-time)
 * - T3 (Memory tampering): SecureBytes prevents swap exposure
 * - S3 (Signature forgery): Dilithium signature verification
 *
 * AUDIT NOTES:
 * 1. SecureBytes::Wipe() uses memory_cleanse() from support/cleanse.h
 *    which is designed to prevent compiler optimization. VERIFY at assembly level.
 * 2. mlock() may silently fail if RLIMIT_MEMLOCK is exceeded. This is logged
 *    but does not abort - consider hardening for high-security deployments.
 * 3. Dilithium reference implementation is assumed constant-time per NIST
 *    guidelines. Side-channel analysis recommended during audit.
 *
 * ENTROPY SOURCES:
 * - Key generation uses randombytes() from Dilithium reference implementation
 * - randombytes() calls GetStrongRandBytes() which uses OS CSPRNG:
 *   - Linux: getrandom(2) or /dev/urandom
 *   - macOS: SecRandomCopyBytes()
 *   - Windows: BCryptGenRandom()
 *
 * See also: doc/WALLET_THREAT_MODEL.md, doc/WALLET_CRYPTOGRAPHIC_SPEC.md
 */

#include "wallet/pqwallet/pqwallet.h"
#include "bech32.h"
#include "crypto/blake2b.h"
#include "support/cleanse.h"
#include "wallet/pqwallet/pqaddress.h"
#include "wallet/pqwallet/pqderive.h"
#include "wallet/pqwallet/pqkeys.h"

extern "C" {
#include "pat/dilithium-ref/api.h"
}

// Dilithium seed keypair function (for FIND-013 deterministic generation)
extern "C" int pqcrystals_dilithium2_ref_seed_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed);

#include <algorithm>
#include <cerrno>
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
//-----------------------------------------------------------------------------
// SECURITY: Memory-locked, auto-wiping container for sensitive data.
//
// THREAT: I1 - Private key disclosure via memory dump/swap
// MITIGATION: mlock() prevents swapping, Wipe() zeros on destruction
//
// VERIFICATION REQUIRED:
// 1. Confirm memory_cleanse() is not optimized out (assembly inspection)
// 2. Verify mlock() succeeds or is appropriately logged on failure
// 3. Confirm no copies are made during vector operations
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
        // SECURITY NOTE: mlock() prevents sensitive key material from being
        // swapped to disk. If it fails (e.g., RLIMIT_MEMLOCK exceeded),
        // log a warning so operators can adjust system limits.
        if (mlock(m_data.data(), m_data.size()) != 0) {
            fprintf(stderr, "WARNING: mlock() failed for %zu bytes of sensitive data: %s. "
                            "Key material may be swapped to disk.\n",
                m_data.size(), strerror(errno));
        }
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
//-----------------------------------------------------------------------------
// SECURITY: Dilithium ML-DSA-44 keypair management (NIST FIPS 204)
//
// KEY SIZES:
// - Public key:  1,312 bytes (can be shared freely)
// - Secret key:  2,560 bytes (MUST remain in SecureBytes)
// - Signature:   2,420 bytes
//
// THREAT: S3 - Signature forgery
// MITIGATION: Uses NIST-standardized Dilithium with 128-bit security
//
// THREAT: I6 - Side-channel key extraction during signing
// MITIGATION: NIST reference implementation is designed constant-time
// VERIFICATION: Run timing analysis (dudect) on Sign() function
//
// THREAT: Nonce reuse leads to key recovery
// MITIGATION: Dilithium uses deterministic nonce derivation (ρ' = H(K||μ))
//             Nonce is derived from secret key and message - cannot reuse
//
// ENTROPY: Key generation uses randombytes() → GetStrongRandBytes()
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

    // SECURITY NOTE (Halborn FIND-013): Previously this function IGNORED the
    // provided entropy and fell back to random Generate(). Now we use the
    // seed_keypair function for deterministic generation from the entropy.
    auto keypair = std::make_unique<PQKeyPair>();

    int result = pqcrystals_dilithium2_ref_seed_keypair(
        keypair->m_publicKey.data(),
        keypair->m_secretKey.data(),
        entropy.data());

    if (result != 0) {
        return nullptr;
    }

    return keypair;
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
//-----------------------------------------------------------------------------
// SECURITY: Bech32m address encoding with BLAKE2b-160 public key hashing
//
// ADDRESS FORMAT: [HRP]1[version][pubkey_hash][checksum]
// - Mainnet:  sq1..., sqp1..., sqsh1...
// - Testnet:  tsq1..., tsqp1..., tsqsh1...
// - Stagenet: ssq1..., ssqp1..., ssqsh1...
//
// THREAT: S1 - Address substitution attack
// MITIGATION: Bech32m 6-character checksum detects random errors
//             Error detection: 1 in 10^9 for up to 4 character errors
//
// THREAT: Collision attack on address hashing
// MITIGATION: BLAKE2b-160 provides 80-bit collision resistance
//             Preimage resistance is 160-bit (quantum: 80-bit with Grover's)
//             Sufficient for address purposes per Bitcoin Core precedent
//
// PUBLIC KEY HASH: BLAKE2b-160(Dilithium_pubkey)
// RATIONALE: BLAKE2b is 3-5x faster than SHA-256 on 1,312-byte Dilithium keys
//=============================================================================

std::array<uint8_t, 20> PQAddress::HashPublicKey(
    const std::array<uint8_t, DILITHIUM_PUBKEY_SIZE>& pubkey)
{
    std::array<uint8_t, 20> hash;

    // Use BLAKE2b-160 for public key hashing
    // Why BLAKE2b-160:
    // - 3-5x faster than SHA-256 for large Dilithium keys (1,312 bytes)
    // - 160 bits provides 80-bit collision resistance (sufficient for addresses)
    // - Matches whitepaper specification for L2 compatibility
    CBLAKE2b blake(20);
    blake.Write(pubkey.data(), pubkey.size());
    blake.Finalize(hash.data());

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
    const std::array<uint8_t, 20>& pubkeyHash,
    Network network,
    AddressType type)
{
    std::string hrp = GetPrefix(network, type);

    // Version byte (0x00 for v1 P2PQ)
    std::vector<uint8_t> data;
    data.reserve(21);     // version + 20-byte hash
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

    // Check data length (version + 20-byte hash in 5-bit groups)
    // 21 bytes = 168 bits = ~34 5-bit groups
    if (decoded.data.size() < 30 || decoded.data.size() > 40) {
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

    if (data.size() < 21) {
        info.error = "Invalid data length";
        return info;
    }

    // Skip version byte, extract 20-byte hash
    std::copy(data.begin() + 1, data.begin() + 21, info.hash.begin());

    info.valid = true;
    return info;
}

//=============================================================================
// PQWallet implementation
//-----------------------------------------------------------------------------
// SECURITY: High-level wallet management with HD key derivation
//
// SEED SECURITY:
// - Master seed stored in SecureBytes (mlock'd, auto-wiped)
// - 64 bytes from BIP-39 mnemonic derivation
// - All keys derived deterministically from seed
//
// THREAT: Complete fund loss if seed is compromised
// MITIGATION: User education, wallet encryption at rest (pqcrypto.cpp)
//
// TODO (GAP-010): Blinding factor derivation currently uses random bytes.
//                 Must implement HKDF derivation for privacy output recovery.
//                 See: WALLET_RECOVERY_SPEC.md section 4
//
// KEY DERIVATION:
// - HD keys derived deterministically from seed via HKDF + DeriveFromSeed
// - Legacy fallback to random Generate() for seedless wallets
// - Path: m/44'/21329'/account'/change/index
// - (Halborn FIND-010/011/013 remediation, March 2026)
//=============================================================================

class PQWallet::Impl
{
public:
    SecureBytes m_seed;
    AggregationConfig m_config;
    Network m_network;
    uint32_t m_nextIndex = 0;
    std::vector<std::unique_ptr<PQKeyPair> > m_keys;

    // Watch-only support
    bool m_isWatchOnly = false;
    std::vector<std::pair<std::string, std::string> > m_watchedAddresses;        // (address, label)
    std::vector<std::pair<std::vector<uint8_t>, std::string> > m_watchedPubKeys; // (pubkey, label)
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
    wallet->m_impl->m_isWatchOnly = false;

    return wallet;
}

std::unique_ptr<PQWallet> PQWallet::FromPublicKey(
    const std::vector<uint8_t>& masterPubKey,
    Network network)
{
    if (masterPubKey.size() != DILITHIUM_PUBKEY_SIZE) {
        return nullptr;
    }

    auto wallet = std::make_unique<PQWallet>();
    wallet->m_impl->m_network = network;
    wallet->m_impl->m_isWatchOnly = true;
    wallet->m_impl->m_watchedPubKeys.emplace_back(masterPubKey, "master");

    return wallet;
}

std::unique_ptr<PQWallet> PQWallet::WatchOnly(const std::vector<std::string>& addresses)
{
    auto wallet = std::make_unique<PQWallet>();
    wallet->m_impl->m_isWatchOnly = true;
    wallet->m_impl->m_network = Network::Mainnet; // Will be detected from first address

    for (const auto& addr : addresses) {
        // Detect network from address prefix
        if (addr.substr(0, 4) == "tsq1") {
            wallet->m_impl->m_network = Network::Testnet;
        } else if (addr.substr(0, 4) == "ssq1") {
            wallet->m_impl->m_network = Network::Stagenet;
        }
        wallet->m_impl->m_watchedAddresses.emplace_back(addr, "");
    }

    return wallet;
}

bool PQWallet::IsWatchOnly() const
{
    return m_impl->m_isWatchOnly;
}

bool PQWallet::ImportWatchOnlyAddress(const std::string& address, const std::string& label)
{
    // Basic address format validation (prefix check)
    bool validPrefix = (address.substr(0, 3) == "sq1" ||
                        address.substr(0, 4) == "tsq1" ||
                        address.substr(0, 4) == "ssq1");
    if (!validPrefix || address.size() < 40) {
        return false;
    }

    // Check for duplicates
    for (size_t i = 0; i < m_impl->m_watchedAddresses.size(); ++i) {
        if (m_impl->m_watchedAddresses[i].first == address) {
            return false; // Already watching
        }
    }

    m_impl->m_watchedAddresses.emplace_back(address, label);
    return true;
}

bool PQWallet::ImportExtendedPublicKey(const std::vector<uint8_t>& extPubKey, const std::string& label)
{
    if (extPubKey.size() != DILITHIUM_PUBKEY_SIZE) {
        return false;
    }

    m_impl->m_watchedPubKeys.emplace_back(extPubKey, label);
    return true;
}

std::vector<std::pair<std::string, std::string> > PQWallet::GetWatchedAddresses() const
{
    return m_impl->m_watchedAddresses;
}

std::string PQWallet::GetNewAddress()
{
    if (m_impl->m_isWatchOnly) {
        // Watch-only wallets cannot generate new addresses without extended pubkey
        return "";
    }

    // SECURITY NOTE (Halborn FIND-010): Previously used random PQKeyPair::Generate()
    // which meant seed backup could NOT recover addresses. Now uses deterministic
    // DeriveFromSeed() so all keys are recoverable from the master seed.
    std::unique_ptr<PQKeyPair> keypair;

    if (!m_impl->m_seed.empty()) {
        // HD derivation from seed (correct path)
        DerivationPath path;
        path.purpose = 44;
        path.coinType = 21329;
        path.account = 0;
        path.change = 0;
        path.index = m_impl->m_nextIndex;

        keypair = PQKeyPair::DeriveFromSeed(m_impl->m_seed, path);
    } else {
        // Fallback for legacy wallets without seed (defense-in-depth)
        keypair = PQKeyPair::Generate();
    }

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
