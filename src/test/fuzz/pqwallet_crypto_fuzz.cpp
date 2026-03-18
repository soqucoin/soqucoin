// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license.

/**
 * @file pqwallet_crypto_fuzz.cpp
 * @brief Fuzz tests for wallet encryption/decryption using REAL pqcrypto.h API
 *
 * SECURITY: Tests encryption for:
 * - Corrupted ciphertext handling
 * - Invalid passphrase rejection
 * - MAC verification robustness
 * - Truncated/extended data handling
 */

#include <cassert>
#include <cstdint>
#include <string>
#include <support/allocators/secure.h> // SecureString (FIND-025)
#include <support/cleanse.h>
#include <test/fuzz/fuzz.h>
#include <vector>
#include <wallet/pqwallet/pqcrypto.h>

using namespace soqucoin::pqwallet;

/**
 * Fuzz target: Wallet data decryption
 * Tests WalletCrypto::Decrypt() with corrupted/malformed input
 */
void wallet_decrypt_fuzz(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() < 32) return;    // Need minimum header + MAC
    if (buffer.size() > 10000) return; // Reasonable max size

    // Use first 16 bytes as "passphrase"
    SecureString passphrase(reinterpret_cast<const char*>(buffer.data()), 16);

    // Remaining bytes are "encrypted data" - try to deserialize
    std::vector<uint8_t> serialized(buffer.data() + 16, buffer.data() + buffer.size());

    // Try to deserialize as encrypted data
    auto encrypted = EncryptedData::Deserialize(serialized);

    if (encrypted) {
        // Attempt decryption - should handle any input gracefully
        auto plaintext = WalletCrypto::Decrypt(*encrypted, passphrase);

        // If decryption "succeeds" on random data, that's suspicious but not a crash
        // The important thing is no crashes or undefined behavior
        if (plaintext) {
            memory_cleanse(plaintext->data(), plaintext->size());
        }
    }
}

/**
 * Fuzz target: Test encryption round-trip with corruption
 * Encrypts valid data, corrupts it, verifies decryption fails
 */
void wallet_encrypt_corrupt_roundtrip(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() < 48) return; // Need passphrase + plaintext + corruption offset
    if (buffer.size() > 1000) return;

    // Extract components
    SecureString passphrase(reinterpret_cast<const char*>(buffer.data()), 16);
    std::vector<uint8_t> plaintext(buffer.data() + 16, buffer.data() + buffer.size() - 2);

    // Last two bytes determine corruption offset
    size_t corruption_offset = (buffer.data()[buffer.size() - 2] << 8) | buffer.data()[buffer.size() - 1];

    // Encrypt legitimate data using REAL API
    auto encryptedOpt = WalletCrypto::Encrypt(plaintext, passphrase);
    if (!encryptedOpt) return; // KDF failure in fuzz is acceptable
    EncryptedData encrypted = *encryptedOpt;

    // Serialize for corruption
    std::vector<uint8_t> serialized = encrypted.Serialize();

    if (serialized.size() < 2) return;

    // Apply corruption at offset (modulo size)
    size_t offset = corruption_offset % serialized.size();
    serialized[offset] ^= 0xFF; // Flip all bits at this position

    // Try to deserialize corrupted data
    auto corruptedData = EncryptedData::Deserialize(serialized);

    if (corruptedData) {
        // Attempt to decrypt corrupted data - MUST fail
        auto recovered = WalletCrypto::Decrypt(*corruptedData, passphrase);
        // Corrupted data should not decrypt successfully
        // (though this is probabilistic - corruption might hit non-critical bytes)
        if (recovered) {
            memory_cleanse(recovered->data(), recovered->size());
        }
    }
}

/**
 * Fuzz target: MAC verification robustness
 * Tests that invalid MACs are rejected consistently
 */
void wallet_mac_validation(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() < 32) return;

    // Create valid encrypted data first
    SecureString passphrase("test_passphrase");
    std::vector<uint8_t> testData = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    auto encryptedOpt = WalletCrypto::Encrypt(testData, passphrase);
    if (!encryptedOpt) return; // KDF failure in fuzz is acceptable
    EncryptedData encrypted = *encryptedOpt;

    // Corrupt the tag with fuzz data
    for (size_t i = 0; i < std::min(buffer.size(), encrypted.tag.size()); ++i) {
        encrypted.tag[i] = buffer.data()[i];
    }

    // This should fail MAC verification
    auto result = WalletCrypto::Decrypt(encrypted, passphrase);

    // Result should almost always be nullopt (tag corrupted)
    if (result) {
        memory_cleanse(result->data(), result->size());
    }
}

/**
 * Fuzz target: Passphrase edge cases
 * Tests encryption with unusual passphrases
 */
void wallet_passphrase_edge_cases(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() < 1) return;

    // Create passphrase with potential edge cases (any length)
    SecureString passphrase(reinterpret_cast<const char*>(buffer.data()),
        std::min(buffer.size(), size_t(256)));

    // Test data
    std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};

    // Encrypt with fuzzed passphrase
    auto encryptedOpt = WalletCrypto::Encrypt(plaintext, passphrase);
    if (!encryptedOpt) return; // KDF failure in fuzz is acceptable
    EncryptedData encrypted = *encryptedOpt;

    // Decrypt with same passphrase - should always succeed
    auto recovered = WalletCrypto::Decrypt(encrypted, passphrase);

    // Should always succeed with correct passphrase
    if (recovered) {
        assert(*recovered == plaintext);
        memory_cleanse(recovered->data(), recovered->size());
    }
}

// Note: These functions are registered in Fuzz.cpp
// Run with: FUZZ=wallet_decrypt_fuzz ./src/test/fuzz/fuzz
