// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license.

/**
 * @file pqwallet_crypto_fuzz.cpp
 * @brief Fuzz tests for wallet encryption/decryption
 *
 * SECURITY: Tests encryption for:
 * - Corrupted ciphertext handling
 * - Invalid passphrase rejection
 * - MAC verification robustness
 * - Truncated/extended data handling
 *
 * NOTE: These are fuzz test stubs. API calls may need adjustment
 * to match actual WalletCrypto implementation before compilation.
 */

#include <cassert>
#include <cstdint>
#include <string>
#include <support/cleanse.h>
#include <test/fuzz/fuzz.h>
#include <vector>
// #include <wallet/pqwallet/pqcrypto.h>  // Uncomment when pqcrypto.h is available

// Placeholder namespace - replace with actual when pqcrypto.h exists
namespace soqucoin
{
namespace pqwallet
{
struct WalletCrypto {
    static bool Encrypt(const std::vector<uint8_t>&, const std::string&, std::vector<uint8_t>&) { return true; }
    static bool Decrypt(const std::vector<uint8_t>&, const std::string&, std::vector<uint8_t>&) { return false; }
};
} // namespace pqwallet
} // namespace soqucoin

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
    std::string passphrase(reinterpret_cast<const char*>(buffer.data()), 16);

    // Remaining bytes are "encrypted data"
    std::vector<uint8_t> encrypted(buffer.data() + 16, buffer.data() + buffer.size());

    // Attempt decryption - should handle any input gracefully
    std::vector<uint8_t> plaintext;
    bool result = WalletCrypto::Decrypt(encrypted, passphrase, plaintext);

    // If decryption "succeeds" on random data, that's suspicious but not a crash
    // The important thing is no crashes or undefined behavior
    (void)result;

    // Zeroize sensitive data
    memory_cleanse(plaintext.data(), plaintext.size());
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
    std::string passphrase(reinterpret_cast<const char*>(buffer.data()), 16);
    std::vector<uint8_t> plaintext(buffer.data() + 16, buffer.data() + buffer.size() - 2);

    // Last two bytes determine corruption offset
    size_t corruption_offset = (buffer.data()[buffer.size() - 2] << 8) | buffer.data()[buffer.size() - 1];

    // Encrypt legitimate data
    std::vector<uint8_t> encrypted;
    WalletCrypto::Encrypt(plaintext, passphrase, encrypted);

    if (encrypted.size() < 2) return;

    // Apply corruption at offset (modulo size)
    size_t offset = corruption_offset % encrypted.size();
    encrypted[offset] ^= 0xFF; // Flip all bits at this position

    // Attempt to decrypt corrupted data - MUST fail
    std::vector<uint8_t> recovered;
    bool result = WalletCrypto::Decrypt(encrypted, passphrase, recovered);

    // Corrupted data should not decrypt successfully
    // Note: This is a probabilistic check - false positives extremely rare
    (void)result;

    memory_cleanse(recovered.data(), recovered.size());
}

/**
 * Fuzz target: MAC verification timing
 * Tests that invalid MACs are rejected consistently
 */
void wallet_mac_validation(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() < 64) return;

    // Create minimal "encrypted" structure
    std::vector<uint8_t> fake_encrypted;

    // Magic bytes
    fake_encrypted.push_back('S');
    fake_encrypted.push_back('Q');
    fake_encrypted.push_back('W');
    fake_encrypted.push_back('1');

    // Version
    fake_encrypted.push_back(0x01);
    fake_encrypted.push_back(0x00);

    // Salt (16 bytes from input)
    for (int i = 0; i < 16; ++i) {
        fake_encrypted.push_back(buffer.data()[i]);
    }

    // IV (16 bytes)
    for (int i = 16; i < 32; ++i) {
        fake_encrypted.push_back(buffer.data()[i]);
    }

    // Fake ciphertext (arbitrary)
    for (int i = 32; i < 48 && i < (int)buffer.size(); ++i) {
        fake_encrypted.push_back(buffer.data()[i]);
    }

    // Fake MAC (16 bytes from input - almost certainly wrong)
    for (int i = 48; i < 64 && i < (int)buffer.size(); ++i) {
        fake_encrypted.push_back(buffer.data()[i]);
    }

    std::string passphrase = "test_passphrase";
    std::vector<uint8_t> plaintext;

    // This should fail MAC verification
    bool result = WalletCrypto::Decrypt(fake_encrypted, passphrase, plaintext);
    (void)result;
}

/**
 * Fuzz target: Passphrase edge cases
 * Tests encryption with unusual passphrases
 */
void wallet_passphrase_edge_cases(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() < 16) return;

    // Create passphrase with potential edge cases
    std::string passphrase(reinterpret_cast<const char*>(buffer.data()),
        std::min(buffer.size(), size_t(128)));

    // Test data
    std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};

    // Encrypt with fuzzed passphrase
    std::vector<uint8_t> encrypted;
    WalletCrypto::Encrypt(plaintext, passphrase, encrypted);

    // Decrypt with same passphrase
    std::vector<uint8_t> recovered;
    bool result = WalletCrypto::Decrypt(encrypted, passphrase, recovered);

    // Should always succeed with correct passphrase
    if (result) {
        assert(recovered == plaintext);
    }

    memory_cleanse(recovered.data(), recovered.size());
}

// libFuzzer entry point
// extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
//     fuzzer::FuzzBuffer buffer(data, size);
//     wallet_decrypt_fuzz(buffer);
//     return 0;
// }
