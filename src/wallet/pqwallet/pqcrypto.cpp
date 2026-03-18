// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/pqwallet/pqcrypto.h"
#include "crypto/aes.h"
#include "crypto/hmac_sha256.h"
#include "random.h"
#include "support/cleanse.h"

#include <cstring>
#include <fstream>
#include <limits>

namespace soqucoin
{
namespace pqwallet
{

// File magic identifier for encrypted wallet files
static const uint8_t WALLET_MAGIC[4] = {'S', 'Q', 'W', '2'}; // SoquWallet v2 (FIND-009)
static const uint32_t WALLET_VERSION = 2;

//=============================================================================
// Key derivation using Argon2id (OpenSSL 3.x EVP_KDF)
// OWASP recommended: memory-hard, resistant to GPU/ASIC attacks
// Fallback to scrypt if Argon2 not available, then PBKDF2 as last resort
//=============================================================================

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

// KDF version marker (legacy — see KDF_ID_* constants in pqcrypto.h for v2 format)
static constexpr uint32_t KDF_VERSION = 2;

std::optional<std::pair<std::array<uint8_t, AES_KEY_SIZE>, uint8_t>> WalletCrypto::DeriveKey(
    const SecureString& passphrase,
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
                // SECURITY NOTE (FIND-026): Caller receives copy; we cleanse our local
                auto result = std::make_pair(derivedKey, KDF_ID_ARGON2ID);
                memory_cleanse(derivedKey.data(), derivedKey.size());
                return result;
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
                // SECURITY NOTE (FIND-026): Cleanse local before return
                auto result = std::make_pair(derivedKey, KDF_ID_SCRYPT);
                memory_cleanse(derivedKey.data(), derivedKey.size());
                return result;
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

            if (EVP_KDF_derive(ctx, derivedKey.data(), derivedKey.size(), params) > 0) {
                EVP_KDF_CTX_free(ctx);
                EVP_KDF_free(pbkdf2);
                // SECURITY NOTE (FIND-008): Defense-in-depth — verify key is non-zero
                bool allZero = true;
                for (size_t i = 0; i < derivedKey.size(); ++i) {
                    if (derivedKey[i] != 0) { allZero = false; break; }
                }
                if (allZero) {
                    memory_cleanse(derivedKey.data(), derivedKey.size());
                    return std::nullopt;
                }
                // SECURITY NOTE (FIND-026): Cleanse local before return
                auto result = std::make_pair(derivedKey, KDF_ID_PBKDF2);
                memory_cleanse(derivedKey.data(), derivedKey.size());
                return result;
            }
            EVP_KDF_CTX_free(ctx);
        }
        EVP_KDF_free(pbkdf2);
    }

    // SECURITY NOTE (Halborn FIND-008): All 3 KDFs failed.
    // Return nullopt instead of zero key to prevent wallet encryption
    // with trivially brutable key.
    memory_cleanse(derivedKey.data(), derivedKey.size());
    return std::nullopt;
}

//=============================================================================
// EncryptedData serialization
//=============================================================================

std::vector<uint8_t> EncryptedData::Serialize() const
{
    // v2 layout: magic(4) + version(4) + kdf_id(1) + salt(16) + iv(16) + tag(16) + ctlen(4) + ciphertext
    std::vector<uint8_t> result;
    result.reserve(4 + 4 + 1 + ARGON2_SALT_SIZE + AES_IV_SIZE + AES_TAG_SIZE + 4 + ciphertext.size());

    // Magic header
    result.insert(result.end(), WALLET_MAGIC, WALLET_MAGIC + 4);

    // Version
    result.push_back((WALLET_VERSION >> 24) & 0xff);
    result.push_back((WALLET_VERSION >> 16) & 0xff);
    result.push_back((WALLET_VERSION >> 8) & 0xff);
    result.push_back(WALLET_VERSION & 0xff);

    // KDF ID (FIND-009: persist which KDF produced the key)
    result.push_back(kdf_id);

    // Salt
    result.insert(result.end(), salt.begin(), salt.end());

    // IV
    result.insert(result.end(), iv.begin(), iv.end());

    // Tag (HMAC-SHA256, truncated to 128 bits)
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
    // v2 minimum: magic(4) + version(4) + kdf_id(1) + salt(16) + iv(16) + tag(16) + ctlen(4) = 61
    const size_t headerSize = 4 + 4 + 1 + ARGON2_SALT_SIZE + AES_IV_SIZE + AES_TAG_SIZE + 4;
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

    // KDF ID (FIND-009: read persisted KDF identifier)
    result.kdf_id = data[pos];
    pos += 1;

    // Validate kdf_id is a known algorithm
    if (result.kdf_id != KDF_ID_PBKDF2 && result.kdf_id != KDF_ID_SCRYPT && result.kdf_id != KDF_ID_ARGON2ID) {
        return std::nullopt; // Unknown KDF
    }

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

    // SECURITY NOTE (Halborn FIND-015): Subtraction-safe bounds check.
    // Previously: `data.size() < pos + ctLen` — on 32-bit platforms, when
    // pos=60 and ctLen=0xFFFFFFFF, pos+ctLen wraps to 59, bypassing the check.
    // Since pos <= data.size() is guaranteed by the sequential parsing above,
    // data.size() - pos is always non-negative.
    if (ctLen > data.size() - pos) {
        return std::nullopt;
    }

    // Ciphertext
    result.ciphertext.assign(data.begin() + pos, data.begin() + pos + ctLen);

    return result;
}

//=============================================================================
// Encryption / Decryption
//=============================================================================

std::optional<EncryptedData> WalletCrypto::Encrypt(const std::vector<uint8_t>& plaintext,
    const SecureString& passphrase)
{
    EncryptedData result;

    // SECURITY NOTE: Uses GetStrongRandBytes (ChaCha20 mixing over OS CSPRNG)
    // for consistency with key generation entropy in pqwallet.cpp.
    GetStrongRandBytes(result.salt.data(), result.salt.size());
    GetStrongRandBytes(result.iv.data(), result.iv.size());

    // Derive encryption key (FIND-008: returns nullopt on total failure)
    auto keyResult = DeriveKey(passphrase, result.salt);
    if (!keyResult) {
        return std::nullopt; // All KDFs failed — refuse to encrypt
    }
    auto& [key, kdfId] = *keyResult;
    result.kdf_id = kdfId; // FIND-009: persist which KDF succeeded

    // SECURITY NOTE (Halborn FIND-024): Pre-allocate padded vector to prevent
    // reallocation leak. Without reserve(), `padded = plaintext` allocates
    // capacity == size; the subsequent insert() always exceeds capacity,
    // causing reallocation that frees the original buffer without zeroing.
    size_t padLen = AES_BLOCKSIZE - (plaintext.size() % AES_BLOCKSIZE);
    std::vector<uint8_t> padded;
    padded.reserve(plaintext.size() + AES_BLOCKSIZE); // worst case: 16 bytes padding
    padded.assign(plaintext.begin(), plaintext.end());
    padded.insert(padded.end(), padLen, static_cast<uint8_t>(padLen)); // PKCS7 padding

    // SECURITY NOTE (Halborn FIND-014): AES256CBCEncrypt::Encrypt takes int size.
    // If padded.size() > INT_MAX, implicit conversion wraps to negative.
    if (padded.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        memory_cleanse(key.data(), key.size());
        memory_cleanse(padded.data(), padded.size());
        return std::nullopt;
    }

    // Encrypt using AES-256-CBC
    AES256CBCEncrypt encryptor(key.data(), result.iv.data(), false);
    result.ciphertext.resize(padded.size());
    encryptor.Encrypt(padded.data(), padded.size(), result.ciphertext.data());

    // SECURITY NOTE (Halborn FIND-016): HMAC scope expanded to cover full header.
    // Compute HMAC-SHA256(key, version || kdf_id || salt || iv || ciphertext)
    // This prevents an attacker from swapping salt/kdf_id without detection.
    CHMAC_SHA256 hmac(key.data(), key.size());
    // Include version bytes in HMAC
    uint8_t versionBytes[4];
    versionBytes[0] = (WALLET_VERSION >> 24) & 0xff;
    versionBytes[1] = (WALLET_VERSION >> 16) & 0xff;
    versionBytes[2] = (WALLET_VERSION >> 8) & 0xff;
    versionBytes[3] = WALLET_VERSION & 0xff;
    hmac.Write(versionBytes, 4);
    hmac.Write(&result.kdf_id, 1);
    hmac.Write(result.salt.data(), result.salt.size());
    hmac.Write(result.iv.data(), result.iv.size());
    hmac.Write(result.ciphertext.data(), result.ciphertext.size());

    std::array<uint8_t, CHMAC_SHA256::OUTPUT_SIZE> hmacResult;
    hmac.Finalize(hmacResult.data());
    // SECURITY NOTE: HMAC-SHA256 output (32 bytes) is truncated to AES_TAG_SIZE
    // (16 bytes), providing 128-bit MAC security. This is acceptable per NIST
    // SP 800-107 Rev. 1 §5.3.4 guidelines for HMAC output truncation.
    std::copy(hmacResult.begin(), hmacResult.begin() + AES_TAG_SIZE, result.tag.begin());

    // SECURITY NOTE (Halborn FIND-017): Cleanse HMAC intermediate output.
    // The full 32-byte HMAC result persists on stack after truncation to 16 bytes.
    memory_cleanse(hmacResult.data(), hmacResult.size());

    // Wipe sensitive data
    memory_cleanse(key.data(), key.size());
    memory_cleanse(padded.data(), padded.size());

    return result;
}

std::optional<std::vector<uint8_t> > WalletCrypto::Decrypt(
    const EncryptedData& encrypted,
    const SecureString& passphrase)
{
    // Derive key (FIND-008: returns nullopt on total failure)
    auto keyResult = DeriveKey(passphrase, encrypted.salt);
    if (!keyResult) {
        return std::nullopt; // All KDFs failed
    }
    auto& [key, kdfId] = *keyResult;

    // SECURITY NOTE (Halborn FIND-016): Verify HMAC over full header.
    // HMAC-SHA256(key, version || kdf_id || salt || iv || ciphertext)
    CHMAC_SHA256 hmac(key.data(), key.size());
    uint8_t versionBytes[4];
    versionBytes[0] = (WALLET_VERSION >> 24) & 0xff;
    versionBytes[1] = (WALLET_VERSION >> 16) & 0xff;
    versionBytes[2] = (WALLET_VERSION >> 8) & 0xff;
    versionBytes[3] = WALLET_VERSION & 0xff;
    hmac.Write(versionBytes, 4);
    hmac.Write(&encrypted.kdf_id, 1);
    hmac.Write(encrypted.salt.data(), encrypted.salt.size());
    hmac.Write(encrypted.iv.data(), encrypted.iv.size());
    hmac.Write(encrypted.ciphertext.data(), encrypted.ciphertext.size());

    std::array<uint8_t, CHMAC_SHA256::OUTPUT_SIZE> expectedTag;
    hmac.Finalize(expectedTag.data());

    // Constant-time tag comparison using XOR-accumulate pattern.
    // Prevents timing side-channels that could leak byte positions.
    uint8_t diff = 0;
    for (size_t i = 0; i < AES_TAG_SIZE; ++i) {
        diff |= encrypted.tag[i] ^ expectedTag[i];
    }

    // SECURITY NOTE (Halborn FIND-017): Cleanse HMAC intermediate output.
    memory_cleanse(expectedTag.data(), expectedTag.size());

    if (diff != 0) {
        memory_cleanse(key.data(), key.size());
        return std::nullopt; // Authentication failed
    }

    // Decrypt
    // SECURITY NOTE (Halborn FIND-023): Use sized allocation and cleanse on
    // ALL exit paths. Previously, error paths (invalid padding, empty buffer)
    // returned without wiping the decrypted buffer, leaving wallet private
    // keys (Dilithium, 2560 bytes each) in freed heap memory.

    // SECURITY NOTE (Halborn FIND-014): AES256CBCDecrypt::Decrypt takes int size.
    // If ciphertext.size() > INT_MAX, implicit conversion wraps to negative.
    if (encrypted.ciphertext.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        memory_cleanse(key.data(), key.size());
        return std::nullopt;
    }

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
        // SECURITY NOTE (Halborn FIND-023): Wipe decrypted buffer on error
        memory_cleanse(decrypted.data(), decrypted.size());
        memory_cleanse(key.data(), key.size());
        return std::nullopt; // Invalid padding
    }

    // Verify all padding bytes
    bool paddingValid = true;
    for (size_t i = decrypted.size() - padLen; i < decrypted.size(); ++i) {
        if (decrypted[i] != padLen) {
            paddingValid = false;
            break;
        }
    }
    if (!paddingValid) {
        // SECURITY NOTE (Halborn FIND-023): Wipe decrypted buffer on error
        memory_cleanse(decrypted.data(), decrypted.size());
        memory_cleanse(key.data(), key.size());
        return std::nullopt; // Invalid padding
    }

    // Wipe the tail bytes that will be lost to resize (padding area)
    size_t newSize = decrypted.size() - padLen;
    memory_cleanse(decrypted.data() + newSize, padLen);
    decrypted.resize(newSize);

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

bool WalletCrypto::EncryptFile(const std::string& path, const SecureString& passphrase)
{
    // Read file
    std::ifstream inFile(path, std::ios::binary);
    if (!inFile.is_open()) {
        return false;
    }

    std::vector<uint8_t> plaintext((std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    // Encrypt (FIND-008: returns nullopt on KDF failure)
    auto encrypted = Encrypt(plaintext, passphrase);

    // SECURITY NOTE (Halborn FIND-022): Wipe plaintext immediately after
    // Encrypt() returns — it is no longer needed. Previously, plaintext was
    // only wiped after outFile.write() on the success path. On output failure,
    // the entire unencrypted wallet (including Dilithium secret keys, 2560
    // bytes each) persisted in heap memory.
    memory_cleanse(plaintext.data(), plaintext.size());

    if (!encrypted) {
        return false;
    }
    auto serialized = encrypted->Serialize();

    // Write back
    std::ofstream outFile(path, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        return false;
    }

    outFile.write(reinterpret_cast<const char*>(serialized.data()), serialized.size());

    return outFile.good();
}

bool WalletCrypto::DecryptFile(const std::string& path, const SecureString& passphrase)
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
        // SECURITY NOTE (Halborn FIND-012): Wipe decrypted plaintext even on
        // output failure. Contains Dilithium secret keys (2560 bytes each).
        memory_cleanse(plaintext->data(), plaintext->size());
        return false;
    }

    outFile.write(reinterpret_cast<const char*>(plaintext->data()), plaintext->size());

    // SECURITY NOTE (Halborn FIND-012): Wipe decrypted plaintext after write.
    memory_cleanse(plaintext->data(), plaintext->size());

    return outFile.good();
}

} // namespace pqwallet
} // namespace soqucoin
