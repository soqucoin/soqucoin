// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_WALLET_PQCRYPTO_H
#define SOQUCOIN_WALLET_PQCRYPTO_H

/**
 * @file pqcrypto.h
 * @brief Wallet file encryption using AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) + Argon2id key derivation
 *
 * Wallet format v2 (Halborn FIND-008/009/016/025/026 remediation):
 * - AES-256-CBC + HMAC-SHA256: Authenticated encryption via Encrypt-then-MAC
 * - Argon2id: Memory-hard key derivation (resistant to GPU attacks)
 * - Random IV: Unique per encryption operation
 * - KDF ID persisted in file format (FIND-009)
 * - HMAC covers version + kdf_id + salt + iv + ciphertext (FIND-016)
 * - DeriveKey returns nullopt on total KDF failure (FIND-008)
 * - All passphrases use SecureString for zero-on-free (FIND-025)
 * - Derived key cleansed before every return (FIND-026)
 */

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "support/allocators/secure.h" // FIND-025: SecureString (zero-on-free)

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

/// KDF algorithm identifiers (FIND-009: persisted in wallet format v2)
static constexpr uint8_t KDF_ID_PBKDF2   = 1;
static constexpr uint8_t KDF_ID_SCRYPT   = 2;
static constexpr uint8_t KDF_ID_ARGON2ID = 3;

/**
 * @brief Encrypted data container (wallet format v2)
 */
struct EncryptedData {
    uint8_t kdf_id{0};                                  ///< KDF algorithm that produced the key (FIND-009)
    std::array<uint8_t, ARGON2_SALT_SIZE> salt;          ///< KDF salt
    std::array<uint8_t, AES_IV_SIZE> iv;                 ///< AES-CBC IV
    std::array<uint8_t, AES_TAG_SIZE> tag;               ///< HMAC-SHA256 auth tag (truncated to 128 bits)
    std::vector<uint8_t> ciphertext;                     ///< Encrypted data

    /**
     * @brief Serialize to bytes for storage (v2 format)
     * Layout: magic(4) + version(4) + kdf_id(1) + salt(16) + iv(16) + tag(16) + ctlen(4) + ciphertext
     */
    std::vector<uint8_t> Serialize() const;

    /**
     * @brief Deserialize from stored bytes (v2 format)
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
     * @param passphrase User passphrase (FIND-025: SecureString, zero-on-free)
     * @return Encrypted data container, or nullopt on KDF failure
     */
    static std::optional<EncryptedData> Encrypt(const std::vector<uint8_t>& plaintext,
        const SecureString& passphrase);

    /**
     * @brief Decrypt data with passphrase
     * @param encrypted Encrypted data container
     * @param passphrase User passphrase (FIND-025: SecureString, zero-on-free)
     * @return Decrypted data or nullopt if auth fails or KDF fails
     */
    static std::optional<std::vector<uint8_t> > Decrypt(
        const EncryptedData& encrypted,
        const SecureString& passphrase);

    /**
     * @brief Derive encryption key from passphrase using Argon2id/scrypt/PBKDF2 cascade
     * @param passphrase User passphrase (FIND-025: SecureString)
     * @param salt Random salt
     * @return {256-bit derived key, kdf_id} or nullopt on total failure (FIND-008)
     *
     * SECURITY NOTE (Halborn FIND-008): Returns nullopt instead of all-zero key
     * when all 3 KDFs fail. Defense-in-depth: verifies derived key is non-zero.
     * SECURITY NOTE (Halborn FIND-026): Cleanses derived key on stack before return.
     *
     * This overload auto-detects the best available KDF. Use for ENCRYPTION only.
     */
    static std::optional<std::pair<std::array<uint8_t, AES_KEY_SIZE>, uint8_t>> DeriveKey(
        const SecureString& passphrase,
        const std::array<uint8_t, ARGON2_SALT_SIZE>& salt);

    /**
     * @brief Derive encryption key using a SPECIFIC KDF (decrypt path)
     * @param passphrase User passphrase (FIND-025: SecureString)
     * @param salt Random salt from stored wallet file
     * @param required_kdf_id KDF algorithm ID read from wallet file header
     * @return {256-bit derived key, kdf_id} or nullopt if required KDF unavailable
     *
     * SECURITY NOTE (Halborn FIND-009): This overload does NOT fall back to other
     * KDFs. If the required KDF is unavailable on this system, it returns nullopt
     * with a diagnostic log message. This prevents the cross-platform key mismatch
     * where an OS upgrade (e.g., OpenSSL 3.0 → 3.2) changes KDF availability,
     * causing DeriveKey to silently select a different KDF and produce a different
     * key from the same passphrase — permanently bricking the wallet.
     *
     * Use for DECRYPTION only. The encrypt path should use the 2-arg auto-detect.
     */
    static std::optional<std::pair<std::array<uint8_t, AES_KEY_SIZE>, uint8_t>> DeriveKey(
        const SecureString& passphrase,
        const std::array<uint8_t, ARGON2_SALT_SIZE>& salt,
        uint8_t required_kdf_id);

private:
    // KDF-specific derivation helpers (shared by both DeriveKey overloads)
    // Extracted to eliminate code duplication between auto-detect and targeted paths.
    // Each returns the raw derived key or nullopt if that specific KDF is unavailable.
    static std::optional<std::array<uint8_t, AES_KEY_SIZE>> DeriveArgon2id(
        const SecureString& passphrase, const std::array<uint8_t, ARGON2_SALT_SIZE>& salt);
    static std::optional<std::array<uint8_t, AES_KEY_SIZE>> DeriveScrypt(
        const SecureString& passphrase, const std::array<uint8_t, ARGON2_SALT_SIZE>& salt);
    static std::optional<std::array<uint8_t, AES_KEY_SIZE>> DerivePbkdf2(
        const SecureString& passphrase, const std::array<uint8_t, ARGON2_SALT_SIZE>& salt);

    /**
     * @brief Encrypt wallet file in-place
     * @param path Path to wallet file
     * @param passphrase Encryption passphrase
     * @return true on success
     */
    static bool EncryptFile(const std::string& path, const SecureString& passphrase);

    /**
     * @brief Decrypt wallet file in-place
     * @param path Path to encrypted wallet file
     * @param passphrase Decryption passphrase (FIND-025: SecureString)
     * @return true on success
     */
    static bool DecryptFile(const std::string& path, const SecureString& passphrase);

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
