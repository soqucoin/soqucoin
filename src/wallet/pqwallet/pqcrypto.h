// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_WALLET_PQCRYPTO_H
#define SOQUCOIN_WALLET_PQCRYPTO_H

/**
 * @file pqcrypto.h
 * @brief Wallet file encryption using AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) + Argon2id key derivation
 *
 * Implements secure wallet file encryption as recommended by
 * Monero/Zcash audit research findings.
 *
 * Security properties:
 * - AES-256-CBC + HMAC-SHA256: Authenticated encryption via Encrypt-then-MAC (confidentiality + integrity)
 * - Argon2id: Memory-hard key derivation (resistant to GPU attacks)
 * - Random IV: Unique per encryption operation
 */

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace soqucoin
{
namespace pqwallet
{

/// AES-256-CBC parameters (using CBC with HMAC until GCM available)
constexpr size_t AES_KEY_SIZE = 32; // 256 bits
constexpr size_t AES_IV_SIZE = 16;  // 128 bits (AES block size for CBC)
constexpr size_t AES_TAG_SIZE = 16; // 128 bits (HMAC truncated)

/// Argon2id parameters (OWASP recommendations for passwords)
constexpr uint32_t ARGON2_TIME_COST = 3;       // Iterations
constexpr uint32_t ARGON2_MEMORY_COST = 65536; // 64 MB
constexpr uint32_t ARGON2_PARALLELISM = 4;
constexpr size_t ARGON2_SALT_SIZE = 16;

/**
 * @brief Encrypted data container
 */
struct EncryptedData {
    std::array<uint8_t, ARGON2_SALT_SIZE> salt; ///< Argon2 salt
    std::array<uint8_t, AES_IV_SIZE> iv;        ///< AES-GCM IV
    std::array<uint8_t, AES_TAG_SIZE> tag;      ///< GCM auth tag
    std::vector<uint8_t> ciphertext;            ///< Encrypted data

    /**
     * @brief Serialize to bytes for storage
     */
    std::vector<uint8_t> Serialize() const;

    /**
     * @brief Deserialize from stored bytes
     */
    static std::optional<EncryptedData> Deserialize(const std::vector<uint8_t>& data);
};

/**
 * @brief Wallet file encryption utilities
 */
class WalletCrypto
{
public:
    /**
     * @brief Encrypt data with passphrase
     * @param plaintext Data to encrypt
     * @param passphrase User passphrase
     * @return Encrypted data container
     */
    static EncryptedData Encrypt(const std::vector<uint8_t>& plaintext,
        const std::string& passphrase);

    /**
     * @brief Decrypt data with passphrase
     * @param encrypted Encrypted data container
     * @param passphrase User passphrase
     * @return Decrypted data or nullopt if auth fails
     */
    static std::optional<std::vector<uint8_t> > Decrypt(
        const EncryptedData& encrypted,
        const std::string& passphrase);

    /**
     * @brief Derive encryption key from passphrase using Argon2id
     * @param passphrase User passphrase
     * @param salt Random salt
     * @return 256-bit derived key
     */
    static std::array<uint8_t, AES_KEY_SIZE> DeriveKey(
        const std::string& passphrase,
        const std::array<uint8_t, ARGON2_SALT_SIZE>& salt);

    /**
     * @brief Encrypt wallet file in-place
     * @param path Path to wallet file
     * @param passphrase Encryption passphrase
     * @return true on success
     */
    static bool EncryptFile(const std::string& path, const std::string& passphrase);

    /**
     * @brief Decrypt wallet file in-place
     * @param path Path to encrypted wallet file
     * @param passphrase Decryption passphrase
     * @return true on success
     */
    static bool DecryptFile(const std::string& path, const std::string& passphrase);

    /**
     * @brief Check if wallet file is encrypted
     * @param path Path to wallet file
     * @return true if encrypted
     */
    static bool IsEncrypted(const std::string& path);
};

} // namespace pqwallet
} // namespace soqucoin

#endif // SOQUCOIN_WALLET_PQCRYPTO_H
