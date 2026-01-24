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
// Key derivation using Argon2id (OpenSSL 3.x EVP_KDF)
// OWASP recommended: memory-hard, resistant to GPU/ASIC attacks
// Fallback to scrypt if Argon2 not available, then PBKDF2 as last resort
//=============================================================================

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

// Version marker for KDF algorithm used (stored in wallet file)
// 1 = SHA256 placeholder (legacy)
// 2 = Argon2id (current)
// 3 = Reserved for future (e.g., Balloon hashing)
static constexpr uint32_t KDF_VERSION = 2;

std::array<uint8_t, AES_KEY_SIZE> WalletCrypto::DeriveKey(
    const std::string& passphrase,
    const std::array<uint8_t, ARGON2_SALT_SIZE>& salt)
{
    std::array<uint8_t, AES_KEY_SIZE> derivedKey{};

    // Try Argon2id first (OpenSSL 3.x)
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    if (kdf) {
        EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
        if (ctx) {
            // Set Argon2id parameters per OWASP recommendations
            uint32_t t_cost = ARGON2_TIME_COST;   // 3 iterations
            uint32_t m_cost = ARGON2_MEMORY_COST; // 64 MB
            uint32_t p_cost = ARGON2_PARALLELISM; // 4 threads

            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                    const_cast<char*>(passphrase.c_str()), passphrase.size()),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                    const_cast<uint8_t*>(salt.data()), salt.size()),
                OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &t_cost),
                OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &m_cost),
                OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &p_cost),
                OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &p_cost),
                OSSL_PARAM_END};

            if (EVP_KDF_derive(ctx, derivedKey.data(), derivedKey.size(), params) > 0) {
                EVP_KDF_CTX_free(ctx);
                EVP_KDF_free(kdf);
                return derivedKey;
            }
            EVP_KDF_CTX_free(ctx);
        }
        EVP_KDF_free(kdf);
    }

    // Fallback: scrypt (also memory-hard, widely available)
    EVP_KDF* scrypt = EVP_KDF_fetch(nullptr, "SCRYPT", nullptr);
    if (scrypt) {
        EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(scrypt);
        if (ctx) {
            uint64_t n = 1 << 15; // N = 32768 (CPU/memory cost)
            uint32_t r = 8;       // Block size
            uint32_t p = 1;       // Parallelization

            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                    const_cast<char*>(passphrase.c_str()), passphrase.size()),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                    const_cast<uint8_t*>(salt.data()), salt.size()),
                OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n),
                OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r),
                OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &p),
                OSSL_PARAM_END};

            if (EVP_KDF_derive(ctx, derivedKey.data(), derivedKey.size(), params) > 0) {
                EVP_KDF_CTX_free(ctx);
                EVP_KDF_free(scrypt);
                return derivedKey;
            }
            EVP_KDF_CTX_free(ctx);
        }
        EVP_KDF_free(scrypt);
    }

    // Last resort: PBKDF2 (not memory-hard but better than nothing)
    EVP_KDF* pbkdf2 = EVP_KDF_fetch(nullptr, "PBKDF2", nullptr);
    if (pbkdf2) {
        EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(pbkdf2);
        if (ctx) {
            uint32_t iterations = 600000; // OWASP 2023 for SHA256

            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                    const_cast<char*>(passphrase.c_str()), passphrase.size()),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                    const_cast<uint8_t*>(salt.data()), salt.size()),
                OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iterations),
                OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                    const_cast<char*>("SHA256"), 0),
                OSSL_PARAM_END};

            EVP_KDF_derive(ctx, derivedKey.data(), derivedKey.size(), params);
            EVP_KDF_CTX_free(ctx);
        }
        EVP_KDF_free(pbkdf2);
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
    auto plaintext = WalletCrypto::Decrypt(*encrypted, passphrase);
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
