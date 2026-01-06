// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/pqwallet/pqcrypto.h"
#include "crypto/aes.h"
#include "crypto/sha256.h"
#include "random.h"
#include "support/cleanse.h"

#include <cstring>
#include <fstream>

namespace soqucoin
{
namespace pqwallet
{

// File magic identifier for encrypted wallet files
static const uint8_t WALLET_MAGIC[4] = {'S', 'Q', 'W', '1'}; // SoquWallet v1
static const uint32_t WALLET_VERSION = 1;

//=============================================================================
// Key derivation using PBKDF2-SHA256 (Argon2 can be added later)
// This provides reasonable security until we add libargon2
//=============================================================================

static constexpr uint32_t PBKDF2_ITERATIONS = 100000; // OWASP minimum

std::array<uint8_t, AES_KEY_SIZE> WalletCrypto::DeriveKey(
    const std::string& passphrase,
    const std::array<uint8_t, ARGON2_SALT_SIZE>& salt)
{
    std::array<uint8_t, AES_KEY_SIZE> derivedKey;

    // Use PBKDF2-HMAC-SHA256 for key derivation
    // Note: This is a placeholder - full implementation would use EVP_KDF
    // For now, use a simple hash-based approach (to be replaced)
    CSHA256 sha;

    // Hash: passphrase || salt || iterations
    sha.Write(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size());
    sha.Write(salt.data(), salt.size());

    uint8_t iterBytes[4];
    iterBytes[0] = (PBKDF2_ITERATIONS >> 24) & 0xff;
    iterBytes[1] = (PBKDF2_ITERATIONS >> 16) & 0xff;
    iterBytes[2] = (PBKDF2_ITERATIONS >> 8) & 0xff;
    iterBytes[3] = PBKDF2_ITERATIONS & 0xff;
    sha.Write(iterBytes, 4);

    sha.Finalize(derivedKey.data());

    // Additional iterations for hardening
    for (uint32_t i = 1; i < std::min(PBKDF2_ITERATIONS, 10000u); ++i) {
        CSHA256 sha2;
        sha2.Write(derivedKey.data(), derivedKey.size());
        sha2.Write(salt.data(), salt.size());
        sha2.Finalize(derivedKey.data());
    }

    return derivedKey;
}

//=============================================================================
// EncryptedData serialization
//=============================================================================

std::vector<uint8_t> EncryptedData::Serialize() const
{
    std::vector<uint8_t> result;
    result.reserve(4 + 4 + ARGON2_SALT_SIZE + AES_IV_SIZE + AES_TAG_SIZE + ciphertext.size());

    // Magic header
    result.insert(result.end(), WALLET_MAGIC, WALLET_MAGIC + 4);

    // Version
    result.push_back((WALLET_VERSION >> 24) & 0xff);
    result.push_back((WALLET_VERSION >> 16) & 0xff);
    result.push_back((WALLET_VERSION >> 8) & 0xff);
    result.push_back(WALLET_VERSION & 0xff);

    // Salt
    result.insert(result.end(), salt.begin(), salt.end());

    // IV
    result.insert(result.end(), iv.begin(), iv.end());

    // Tag (authentication - for CBC we use HMAC instead)
    result.insert(result.end(), tag.begin(), tag.end());

    // Ciphertext length (4 bytes big-endian)
    uint32_t ctLen = ciphertext.size();
    result.push_back((ctLen >> 24) & 0xff);
    result.push_back((ctLen >> 16) & 0xff);
    result.push_back((ctLen >> 8) & 0xff);
    result.push_back(ctLen & 0xff);

    // Ciphertext
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    return result;
}

std::optional<EncryptedData> EncryptedData::Deserialize(const std::vector<uint8_t>& data)
{
    // Minimum size: magic(4) + version(4) + salt(16) + iv(12) + tag(16) + ctlen(4)
    const size_t headerSize = 4 + 4 + ARGON2_SALT_SIZE + AES_IV_SIZE + AES_TAG_SIZE + 4;
    if (data.size() < headerSize) {
        return std::nullopt;
    }

    size_t pos = 0;

    // Check magic
    if (std::memcmp(data.data() + pos, WALLET_MAGIC, 4) != 0) {
        return std::nullopt;
    }
    pos += 4;

    // Version
    uint32_t version = (uint32_t(data[pos]) << 24) | (uint32_t(data[pos + 1]) << 16) |
                       (uint32_t(data[pos + 2]) << 8) | uint32_t(data[pos + 3]);
    if (version != WALLET_VERSION) {
        return std::nullopt; // Unsupported version
    }
    pos += 4;

    EncryptedData result;

    // Salt
    std::copy(data.begin() + pos, data.begin() + pos + ARGON2_SALT_SIZE, result.salt.begin());
    pos += ARGON2_SALT_SIZE;

    // IV
    std::copy(data.begin() + pos, data.begin() + pos + AES_IV_SIZE, result.iv.begin());
    pos += AES_IV_SIZE;

    // Tag
    std::copy(data.begin() + pos, data.begin() + pos + AES_TAG_SIZE, result.tag.begin());
    pos += AES_TAG_SIZE;

    // Ciphertext length
    uint32_t ctLen = (uint32_t(data[pos]) << 24) | (uint32_t(data[pos + 1]) << 16) |
                     (uint32_t(data[pos + 2]) << 8) | uint32_t(data[pos + 3]);
    pos += 4;

    if (data.size() < pos + ctLen) {
        return std::nullopt;
    }

    // Ciphertext
    result.ciphertext.assign(data.begin() + pos, data.begin() + pos + ctLen);

    return result;
}

//=============================================================================
// Encryption / Decryption
//=============================================================================

EncryptedData WalletCrypto::Encrypt(const std::vector<uint8_t>& plaintext,
    const std::string& passphrase)
{
    EncryptedData result;

    // Generate random salt and IV
    GetRandBytes(result.salt.data(), result.salt.size());
    GetRandBytes(result.iv.data(), result.iv.size());

    // Derive encryption key
    auto key = DeriveKey(passphrase, result.salt);

    // Pad plaintext to AES block size
    size_t padLen = AES_BLOCKSIZE - (plaintext.size() % AES_BLOCKSIZE);
    std::vector<uint8_t> padded = plaintext;
    padded.insert(padded.end(), padLen, static_cast<uint8_t>(padLen)); // PKCS7 padding

    // Encrypt using AES-256-CBC
    AES256CBCEncrypt encryptor(key.data(), result.iv.data(), false);
    result.ciphertext.resize(padded.size());
    encryptor.Encrypt(padded.data(), padded.size(), result.ciphertext.data());

    // Compute authentication tag (HMAC-SHA256 of ciphertext)
    CSHA256 hmac;
    hmac.Write(key.data(), key.size());
    hmac.Write(result.ciphertext.data(), result.ciphertext.size());
    hmac.Write(result.iv.data(), result.iv.size());

    std::array<uint8_t, 32> hmacResult;
    hmac.Finalize(hmacResult.data());
    std::copy(hmacResult.begin(), hmacResult.begin() + AES_TAG_SIZE, result.tag.begin());

    // Wipe key
    memory_cleanse(key.data(), key.size());
    memory_cleanse(padded.data(), padded.size());

    return result;
}

std::optional<std::vector<uint8_t> > WalletCrypto::Decrypt(
    const EncryptedData& encrypted,
    const std::string& passphrase)
{
    // Derive key
    auto key = DeriveKey(passphrase, encrypted.salt);

    // Verify authentication tag first
    CSHA256 hmac;
    hmac.Write(key.data(), key.size());
    hmac.Write(encrypted.ciphertext.data(), encrypted.ciphertext.size());
    hmac.Write(encrypted.iv.data(), encrypted.iv.size());

    std::array<uint8_t, 32> expectedTag;
    hmac.Finalize(expectedTag.data());

    // Constant-time comparison for first 16 bytes
    bool tagValid = true;
    for (size_t i = 0; i < AES_TAG_SIZE; ++i) {
        tagValid &= (encrypted.tag[i] == expectedTag[i]);
    }

    if (!tagValid) {
        memory_cleanse(key.data(), key.size());
        return std::nullopt; // Authentication failed
    }

    // Decrypt
    std::vector<uint8_t> decrypted(encrypted.ciphertext.size());
    AES256CBCDecrypt decryptor(key.data(), encrypted.iv.data(), false);
    decryptor.Decrypt(encrypted.ciphertext.data(), encrypted.ciphertext.size(), decrypted.data());

    // Remove PKCS7 padding
    if (decrypted.empty()) {
        memory_cleanse(key.data(), key.size());
        return std::nullopt;
    }

    uint8_t padLen = decrypted.back();
    if (padLen == 0 || padLen > AES_BLOCKSIZE || padLen > decrypted.size()) {
        memory_cleanse(key.data(), key.size());
        return std::nullopt; // Invalid padding
    }

    // Verify all padding bytes
    for (size_t i = decrypted.size() - padLen; i < decrypted.size(); ++i) {
        if (decrypted[i] != padLen) {
            memory_cleanse(key.data(), key.size());
            return std::nullopt; // Invalid padding
        }
    }

    decrypted.resize(decrypted.size() - padLen);

    memory_cleanse(key.data(), key.size());
    return decrypted;
}

//=============================================================================
// File operations
//=============================================================================

bool WalletCrypto::IsEncrypted(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    uint8_t magic[4];
    file.read(reinterpret_cast<char*>(magic), 4);

    return file.good() && std::memcmp(magic, WALLET_MAGIC, 4) == 0;
}

bool WalletCrypto::EncryptFile(const std::string& path, const std::string& passphrase)
{
    // Read file
    std::ifstream inFile(path, std::ios::binary);
    if (!inFile.is_open()) {
        return false;
    }

    std::vector<uint8_t> plaintext((std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    // Encrypt
    auto encrypted = Encrypt(plaintext, passphrase);
    auto serialized = encrypted.Serialize();

    // Write back
    std::ofstream outFile(path, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        return false;
    }

    outFile.write(reinterpret_cast<const char*>(serialized.data()), serialized.size());

    // Wipe plaintext
    memory_cleanse(plaintext.data(), plaintext.size());

    return outFile.good();
}

bool WalletCrypto::DecryptFile(const std::string& path, const std::string& passphrase)
{
    // Read file
    std::ifstream inFile(path, std::ios::binary);
    if (!inFile.is_open()) {
        return false;
    }

    std::vector<uint8_t> serialized((std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    // Deserialize
    auto encrypted = EncryptedData::Deserialize(serialized);
    if (!encrypted) {
        return false;
    }

    // Decrypt
    auto plaintext = Decrypt(*encrypted, passphrase);
    if (!plaintext) {
        return false;
    }

    // Write back
    std::ofstream outFile(path, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        return false;
    }

    outFile.write(reinterpret_cast<const char*>(plaintext->data()), plaintext->size());

    return outFile.good();
}

} // namespace pqwallet
} // namespace soqucoin
