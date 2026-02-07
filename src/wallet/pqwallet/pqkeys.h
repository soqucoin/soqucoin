// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_WALLET_PQKEYS_H
#define SOQUCOIN_WALLET_PQKEYS_H

/**
 * @file pqkeys.h
 * @brief Dilithium key management for post-quantum wallet
 *
 * Implements secure key derivation and storage using CRYSTALS-Dilithium
 * (ML-DSA-44) as specified in NIST FIPS 204.
 *
 * Security considerations:
 * - Private keys stored in SecureBytes (mlock'd, zeroed on free)
 * - BIP-44 derivation path: m/44'/21329'/account'/change/index
 * - Hardware wallet compatible (signing can be delegated)
 */

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace soqucoin
{
namespace pqwallet
{

/// Dilithium ML-DSA-44 public key size (1312 bytes)
constexpr size_t DILITHIUM_PUBKEY_SIZE = 1312;

/// Dilithium ML-DSA-44 secret key size (2560 bytes)
constexpr size_t DILITHIUM_SECKEY_SIZE = 2560;

/// Dilithium ML-DSA-44 signature size (2420 bytes)
constexpr size_t DILITHIUM_SIGNATURE_SIZE = 2420;

/**
 * @brief Secure memory wrapper that zeros on destruction
 *
 * Uses mlock() to prevent swapping and explicit_bzero() on destruction.
 * Critical for private key storage.
 */
class SecureBytes
{
public:
    SecureBytes();
    explicit SecureBytes(size_t size);
    SecureBytes(const uint8_t* data, size_t size);
    ~SecureBytes();

    // Non-copyable
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;

    // Movable
    SecureBytes(SecureBytes&& other) noexcept;
    SecureBytes& operator=(SecureBytes&& other) noexcept;

    uint8_t* data();
    const uint8_t* data() const;
    size_t size() const;
    bool empty() const;

private:
    std::vector<uint8_t> m_data;
    void Lock();
    void Unlock();
    void Wipe();
};

/**
 * @brief BIP-44 derivation path for Soqucoin
 */
struct DerivationPath {
    uint32_t purpose = 44;     ///< BIP-44
    uint32_t coinType = 21329; ///< Soqucoin (0x5351)
    uint32_t account = 0;
    uint32_t change = 0; ///< 0 = external, 1 = internal
    uint32_t index = 0;

    std::string ToString() const;
    static DerivationPath FromString(const std::string& path);
};

/**
 * @brief Dilithium keypair for signing and verification
 */
class PQKeyPair
{
public:
    /**
     * @brief Generate new keypair using system entropy
     * @return Keypair or nullptr on error
     */
    static std::unique_ptr<PQKeyPair> Generate();

    /**
     * @brief Generate new keypair from entropy
     * @param entropy 32+ bytes of random data
     * @return Keypair or nullptr on error
     */
    static std::unique_ptr<PQKeyPair> Generate(const SecureBytes& entropy);

    /**
     * @brief Derive keypair from seed and path
     * @param seed 64-byte BIP-39 seed
     * @param path Derivation path
     * @return Keypair or nullptr on error
     */
    static std::unique_ptr<PQKeyPair> DeriveFromSeed(const SecureBytes& seed,
        const DerivationPath& path);

    /**
     * @brief Get public key bytes
     */
    std::array<uint8_t, DILITHIUM_PUBKEY_SIZE> GetPublicKey() const;

    /**
     * @brief Sign message with private key
     * @param message Message to sign
     * @return Signature bytes
     */
    std::array<uint8_t, DILITHIUM_SIGNATURE_SIZE> Sign(
        const std::vector<uint8_t>& message) const;

    /**
     * @brief Verify signature against public key
     * @param message Original message
     * @param signature Signature to verify
     * @return true if valid
     */
    bool Verify(const std::vector<uint8_t>& message,
        const std::array<uint8_t, DILITHIUM_SIGNATURE_SIZE>& signature) const;

    /**
     * @brief Serialize keypair for encrypted storage
     * @param encryptionKey AES-256-CBC encryption key
     * @return Encrypted serialization
     */
    SecureBytes Serialize(const SecureBytes& encryptionKey) const;

    /**
     * @brief Deserialize keypair from encrypted storage
     * @param data Encrypted data
     * @param encryptionKey AES-256-CBC encryption key
     * @return Keypair or nullptr on error
     */
    static std::unique_ptr<PQKeyPair> Deserialize(const SecureBytes& data,
        const SecureBytes& encryptionKey);

    ~PQKeyPair();

    // Constructor is public to enable make_unique
    PQKeyPair();

private:
    SecureBytes m_secretKey;
    std::array<uint8_t, DILITHIUM_PUBKEY_SIZE> m_publicKey;
};

} // namespace pqwallet
} // namespace soqucoin

#endif // SOQUCOIN_WALLET_PQKEYS_H
