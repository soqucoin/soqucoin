// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file pqwallet_test.cpp
 * @brief Simple CLI tool to test PQ wallet address generation
 *
 * Usage: pqwallet-test [network]
 *   network: mainnet, testnet, stagenet (default: testnet)
 */

#include "wallet/pqwallet/pqaddress.h"
#include "wallet/pqwallet/pqcrypto.h"
#include "wallet/pqwallet/pqderive.h"
#include "wallet/pqwallet/pqkeys.h"
#include "wallet/pqwallet/pqwallet.h"

#include <iomanip>
#include <iostream>
#include <vector>

#include "support/allocators/secure.h" // SecureString (FIND-025)

using namespace soqucoin::pqwallet;

void PrintHex(const uint8_t* data, size_t len, size_t maxLen = 32)
{
    for (size_t i = 0; i < std::min(len, maxLen); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    if (len > maxLen) {
        std::cout << "...";
    }
    std::cout << std::dec;
}

int main(int argc, char* argv[])
{
    std::cout << "=== Soqucoin PQ Wallet Test ===" << std::endl;
    std::cout << std::endl;

    // Parse network from command line
    Network network = Network::Testnet; // Default to testnet
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "mainnet")
            network = Network::Mainnet;
        else if (arg == "testnet")
            network = Network::Testnet;
        else if (arg == "stagenet")
            network = Network::Stagenet;
    }

    std::cout << "Network: " << (network == Network::Mainnet ? "mainnet" : network == Network::Testnet ? "testnet" :
                                                                                                         "stagenet")
              << std::endl;
    std::cout << std::endl;

    // Test 1: Key Generation
    std::cout << "1. Generating Dilithium keypair..." << std::endl;
    auto keypair = PQKeyPair::Generate();
    if (!keypair) {
        std::cerr << "   ERROR: Key generation failed!" << std::endl;
        return 1;
    }

    auto pubkey = keypair->GetPublicKey();
    std::cout << "   Public key (" << pubkey.size() << " bytes): ";
    PrintHex(pubkey.data(), pubkey.size());
    std::cout << std::endl;
    std::cout << std::endl;

    // Test 2: Public Key Hashing
    std::cout << "2. Hashing public key (SHA3-256)..." << std::endl;
    auto pubkeyHash = PQAddress::HashPublicKey(pubkey);
    std::cout << "   Hash (32 bytes): ";
    PrintHex(pubkeyHash.data(), pubkeyHash.size(), 64);
    std::cout << std::endl;
    std::cout << std::endl;

    // Test 3: Address Encoding
    std::cout << "3. Encoding address (Bech32m)..." << std::endl;
    std::string address = PQAddress::Encode(pubkey, network, AddressType::P2PQ);
    std::cout << "   Address: " << address << std::endl;
    std::cout << "   Length: " << address.length() << " characters" << std::endl;
    std::cout << std::endl;

    // Test 4: Address Validation
    std::cout << "4. Validating address..." << std::endl;
    bool valid = PQAddress::IsValid(address);
    std::cout << "   Valid: " << (valid ? "YES" : "NO") << std::endl;

    Network detected = PQAddress::DetectNetwork(address);
    std::cout << "   Detected network: " << (detected == Network::Mainnet ? "mainnet" : detected == Network::Testnet ? "testnet" :
                                                                                    detected == Network::Stagenet    ? "stagenet" :
                                                                                                                       "unknown")
              << std::endl;
    std::cout << std::endl;

    // Test 5: Address Decoding
    std::cout << "5. Decoding address..." << std::endl;
    auto info = PQAddress::Decode(address);
    std::cout << "   Decoded valid: " << (info.valid ? "YES" : "NO") << std::endl;
    if (info.valid) {
        std::cout << "   Type: " << (info.type == AddressType::P2PQ ? "P2PQ" : info.type == AddressType::P2PQ_PAT ? "P2PQ_PAT" :
                                                                                                                    "P2SH_PQ")
                  << std::endl;
        std::cout << "   Hash matches: " << (info.hash == pubkeyHash ? "YES" : "NO") << std::endl;
    } else {
        std::cout << "   Error: " << info.error << std::endl;
    }
    std::cout << std::endl;

    // Test 6: Signing
    std::cout << "6. Testing signature..." << std::endl;
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'S', 'o', 'q', 'u', '!'};
    auto signature = keypair->Sign(message);
    std::cout << "   Signed message (11 bytes)" << std::endl;
    std::cout << "   Signature (" << signature.size() << " bytes): ";
    PrintHex(signature.data(), signature.size());
    std::cout << std::endl;
    std::cout << std::endl;

    // Test 7: Verification
    std::cout << "7. Verifying signature..." << std::endl;
    bool verified = keypair->Verify(message, signature);
    std::cout << "   Verified: " << (verified ? "YES" : "NO") << std::endl;

    // Test with wrong message
    std::vector<uint8_t> wrongMessage = {'W', 'r', 'o', 'n', 'g'};
    bool wrongVerified = keypair->Verify(wrongMessage, signature);
    std::cout << "   Wrong message rejected: " << (!wrongVerified ? "YES" : "NO (BUG!)") << std::endl;
    std::cout << std::endl;

    std::cout << "8. Generating 3 more addresses..." << std::endl;
    for (int i = 0; i < 3; ++i) {
        auto kp = PQKeyPair::Generate();
        if (kp) {
            std::string addr = PQAddress::Encode(kp->GetPublicKey(), network, AddressType::P2PQ);
            std::cout << "   [" << (i + 1) << "] " << addr << std::endl;
        }
    }
    std::cout << std::endl;

    // ============================================================
    // ENCRYPTION TESTS - Expert-level best practices
    // Based on: Bitcoin Core, Monero, Zcash audit recommendations
    // ============================================================
    std::cout << "=== Encryption Security Tests ===" << std::endl;
    std::cout << std::endl;

    // Test 9: Basic Encrypt/Decrypt Round-trip
    std::cout << "9. Testing encryption round-trip..." << std::endl;
    {
        std::vector<uint8_t> plaintext = {'S', 'e', 'c', 'r', 'e', 't', ' ',
            'k', 'e', 'y', ' ', 'd', 'a', 't', 'a'};
        SecureString passphrase("TestPassphrase123!@#");

        WalletCrypto crypto;
        auto encryptedOpt = crypto.Encrypt(plaintext, passphrase);
        if (!encryptedOpt) {
            std::cerr << "   ERROR: Encryption failed (KDF failure)!" << std::endl;
            return 1;
        }
        auto& encrypted = *encryptedOpt;

        std::cout << "   Plaintext size: " << plaintext.size() << " bytes" << std::endl;
        std::cout << "   Ciphertext size: " << encrypted.ciphertext.size() << " bytes" << std::endl;
        std::cout << "   Salt (16 bytes): ";
        PrintHex(encrypted.salt.data(), encrypted.salt.size(), 16);
        std::cout << std::endl;

        auto decrypted = crypto.Decrypt(encrypted, passphrase);
        if (decrypted && *decrypted == plaintext) {
            std::cout << "   Round-trip: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Round-trip: FAIL ✗" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 10: Wrong Passphrase Rejection (Critical security test)
    // Per Bitcoin Core: HMAC must be verified BEFORE decryption
    std::cout << "10. Testing wrong passphrase rejection..." << std::endl;
    {
        std::vector<uint8_t> plaintext = {'C', 'r', 'i', 't', 'i', 'c', 'a', 'l'};
        SecureString correctPass("CorrectHorseBatteryStaple");
        SecureString wrongPass("WrongPassword123");

        WalletCrypto crypto;
        auto encryptedOpt = crypto.Encrypt(plaintext, correctPass);
        if (!encryptedOpt) {
            std::cerr << "   ERROR: Encryption failed!" << std::endl;
            return 1;
        }
        auto& encrypted = *encryptedOpt;

        // Attempt decryption with wrong passphrase
        auto wrongDecrypt = crypto.Decrypt(encrypted, wrongPass);
        if (!wrongDecrypt.has_value()) {
            std::cout << "   Wrong passphrase rejected: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Wrong passphrase rejected: FAIL ✗ (SECURITY BUG!)" << std::endl;
            return 1;
        }

        // Verify correct passphrase still works
        auto correctDecrypt = crypto.Decrypt(encrypted, correctPass);
        if (correctDecrypt && *correctDecrypt == plaintext) {
            std::cout << "   Correct passphrase accepted: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Correct passphrase accepted: FAIL ✗" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 11: Empty Passphrase Handling
    // Per Monero audit: Must not crash, should reject or warn
    std::cout << "11. Testing empty passphrase handling..." << std::endl;
    {
        std::vector<uint8_t> plaintext = {'T', 'e', 's', 't'};
        SecureString emptyPass("");

        WalletCrypto crypto;
        // Empty passphrase should still work (user choice) but encrypt
        auto encryptedOpt = crypto.Encrypt(plaintext, emptyPass);
        if (!encryptedOpt) {
            std::cerr << "   ERROR: Encryption failed!" << std::endl;
            return 1;
        }
        auto decrypted = crypto.Decrypt(*encryptedOpt, emptyPass);

        if (decrypted && *decrypted == plaintext) {
            std::cout << "   Empty passphrase round-trip: PASS ✓" << std::endl;
            std::cout << "   WARNING: Empty passphrase provides no protection" << std::endl;
        } else {
            std::cout << "   Empty passphrase rejected (policy decision): OK" << std::endl;
        }
    }
    std::cout << std::endl;

    // Test 12: Ciphertext Tampering Detection
    // Per Zcash audit: HMAC must detect any bit flip
    std::cout << "12. Testing ciphertext tampering detection..." << std::endl;
    {
        std::vector<uint8_t> plaintext = {'I', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y'};
        SecureString passphrase("IntegrityTest");

        WalletCrypto crypto;
        auto encryptedOpt = crypto.Encrypt(plaintext, passphrase);
        if (!encryptedOpt) {
            std::cerr << "   ERROR: Encryption failed!" << std::endl;
            return 1;
        }
        auto& encrypted = *encryptedOpt;

        // Tamper with ciphertext (flip one bit)
        if (!encrypted.ciphertext.empty()) {
            encrypted.ciphertext[0] ^= 0x01; // Flip least significant bit
        }

        auto tampered = crypto.Decrypt(encrypted, passphrase);
        if (!tampered.has_value()) {
            std::cout << "   Ciphertext tampering detected: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Ciphertext tampering detected: FAIL ✗ (SECURITY BUG!)" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 13: IV/Salt Uniqueness
    // Per NIST guidelines: Same plaintext + passphrase must produce different ciphertext
    std::cout << "13. Testing IV/Salt uniqueness..." << std::endl;
    {
        std::vector<uint8_t> plaintext = {'S', 'a', 'm', 'e', ' ', 'd', 'a', 't', 'a'};
        SecureString passphrase("SamePassphrase");

        WalletCrypto crypto;
        auto encrypted1Opt = crypto.Encrypt(plaintext, passphrase);
        auto encrypted2Opt = crypto.Encrypt(plaintext, passphrase);
        if (!encrypted1Opt || !encrypted2Opt) {
            std::cerr << "   ERROR: Encryption failed!" << std::endl;
            return 1;
        }
        auto& encrypted1 = *encrypted1Opt;
        auto& encrypted2 = *encrypted2Opt;

        bool saltsDifferent = (encrypted1.salt != encrypted2.salt);
        bool ivsDifferent = (encrypted1.iv != encrypted2.iv);
        bool ciphertextsDifferent = (encrypted1.ciphertext != encrypted2.ciphertext);

        if (saltsDifferent && ivsDifferent && ciphertextsDifferent) {
            std::cout << "   Salt uniqueness: PASS ✓" << std::endl;
            std::cout << "   IV uniqueness: PASS ✓" << std::endl;
            std::cout << "   Ciphertext uniqueness: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Uniqueness test: FAIL ✗ (SECURITY BUG!)" << std::endl;
            std::cerr << "   Salt different: " << (saltsDifferent ? "YES" : "NO") << std::endl;
            std::cerr << "   IV different: " << (ivsDifferent ? "YES" : "NO") << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 14: Serialization/Deserialization
    // Per Bitcoin Core: File format must be stable and versioned
    std::cout << "14. Testing serialization round-trip..." << std::endl;
    {
        std::vector<uint8_t> plaintext = {'F', 'i', 'l', 'e', ' ', 't', 'e', 's', 't'};
        SecureString passphrase("SerializationTest");

        WalletCrypto crypto;
        auto encryptedOpt = crypto.Encrypt(plaintext, passphrase);
        if (!encryptedOpt) {
            std::cerr << "   ERROR: Encryption failed!" << std::endl;
            return 1;
        }
        auto& encrypted = *encryptedOpt;

        // Serialize to bytes (as if writing to file)
        auto serialized = encrypted.Serialize();
        std::cout << "   Serialized size: " << serialized.size() << " bytes" << std::endl;

        // Deserialize (as if reading from file)
        auto deserialized = EncryptedData::Deserialize(serialized);
        if (!deserialized.has_value()) {
            std::cerr << "   Deserialization: FAIL ✗" << std::endl;
            return 1;
        }

        // Decrypt the deserialized data
        auto decrypted = crypto.Decrypt(*deserialized, passphrase);
        if (decrypted && *decrypted == plaintext) {
            std::cout << "   Serialization round-trip: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Serialization round-trip: FAIL ✗" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 15: Large Data Handling
    // Per audit best practices: Test with realistic wallet sizes
    std::cout << "15. Testing large data encryption (simulated wallet)..." << std::endl;
    {
        // Simulate a wallet with 100 Dilithium keys (~250KB)
        std::vector<uint8_t> largeData(250000, 0x42); // 250KB of test data
        SecureString passphrase("LargeWalletTest");

        WalletCrypto crypto;
        auto encryptedOpt = crypto.Encrypt(largeData, passphrase);
        if (!encryptedOpt) {
            std::cerr << "   ERROR: Encryption failed!" << std::endl;
            return 1;
        }
        auto& encrypted = *encryptedOpt;

        std::cout << "   Original size: " << largeData.size() << " bytes" << std::endl;
        std::cout << "   Encrypted size: " << encrypted.ciphertext.size() << " bytes" << std::endl;

        auto decrypted = crypto.Decrypt(encrypted, passphrase);
        if (decrypted && *decrypted == largeData) {
            std::cout << "   Large data round-trip: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Large data round-trip: FAIL ✗" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // ============================================================
    // HD KEY DERIVATION TESTS - Design Log #051
    // Per whitepaper Section 10: HKDF-SHA256 key derivation
    // ============================================================
    std::cout << "=== HD Key Derivation Tests ===" << std::endl;
    std::cout << std::endl;

    // Test 16: HD Derivation Determinism
    std::cout << "16. Testing HD derivation determinism..." << std::endl;
    {
        // Create fixed test seed (64 bytes)
        SecureBytes seed(64);
        std::memset(seed.data(), 0x42, 64);

        DerivationPath path1;
        path1.account = 0;
        path1.change = 0;
        path1.index = 0;

        DerivationPath path2;
        path2.account = 0;
        path2.change = 0;
        path2.index = 0;

        // Derive same path twice
        auto key1 = DeriveKeyMaterial(seed, path1, DOMAIN_WALLET);
        auto key2 = DeriveKeyMaterial(seed, path2, DOMAIN_WALLET);

        if (key1 == key2) {
            std::cout << "   Same path produces same key: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Same path produces same key: FAIL ✗" << std::endl;
            return 1;
        }

        // Different index should produce different key
        DerivationPath path3;
        path3.account = 0;
        path3.change = 0;
        path3.index = 1; // Different index

        auto key3 = DeriveKeyMaterial(seed, path3, DOMAIN_WALLET);

        if (key1 != key3) {
            std::cout << "   Different index produces different key: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Different index produces different key: FAIL ✗" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 17: Account Separation
    std::cout << "17. Testing account separation..." << std::endl;
    {
        SecureBytes seed(64);
        std::memset(seed.data(), 0x42, 64);

        DerivationPath account0;
        account0.account = 0;

        DerivationPath account1;
        account1.account = 1;

        auto key0 = DeriveKeyMaterial(seed, account0, DOMAIN_WALLET);
        auto key1 = DeriveKeyMaterial(seed, account1, DOMAIN_WALLET);

        if (key0 != key1) {
            std::cout << "   Different accounts produce different keys: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Different accounts produce different keys: FAIL ✗" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 18: Domain Separation (signing vs blinding)
    std::cout << "18. Testing domain separation (signing vs blinding)..." << std::endl;
    {
        SecureBytes seed(64);
        std::memset(seed.data(), 0x42, 64);

        DerivationPath path;
        path.index = 0;

        auto signingKey = DeriveKeyMaterial(seed, path, DOMAIN_WALLET);
        auto blindingKey = DeriveKeyMaterial(seed, path, DOMAIN_BLINDING);

        if (signingKey != blindingKey) {
            std::cout << "   Signing and blinding keys differ: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Signing and blinding keys differ: FAIL ✗ (SECURITY BUG!)" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 19: Blinding Factor Derivation (GAP-010)
    std::cout << "19. Testing blinding factor derivation (GAP-010)..." << std::endl;
    {
        SecureBytes seed(64);
        std::memset(seed.data(), 0x42, 64);

        auto blind0 = DeriveBlindingFactor(seed, 0);
        auto blind1 = DeriveBlindingFactor(seed, 1);
        auto blind0_again = DeriveBlindingFactor(seed, 0);

        if (blind0 == blind0_again) {
            std::cout << "   Same output index produces same blinding factor: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Same output index produces same blinding factor: FAIL ✗" << std::endl;
            return 1;
        }

        if (blind0 != blind1) {
            std::cout << "   Different output indices produce different blinding factors: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Different output indices produce different blinding factors: FAIL ✗" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 20: L2 Channel Key Derivation (Stage 5 forward compat)
    std::cout << "20. Testing L2 channel key derivation..." << std::endl;
    {
        SecureBytes seed(64);
        std::memset(seed.data(), 0x42, 64);

        std::string channelId = "abc123";

        auto fundingKey = DeriveChannelKey(seed, channelId, "funding", 0);
        auto revokeKey0 = DeriveChannelKey(seed, channelId, "revoke", 0);
        auto revokeKey1 = DeriveChannelKey(seed, channelId, "revoke", 1);
        auto htlcKey = DeriveChannelKey(seed, channelId, "htlc", 0);

        // All keys should be different
        bool allDifferent = (fundingKey != revokeKey0) &&
                            (fundingKey != htlcKey) &&
                            (revokeKey0 != revokeKey1) &&
                            (revokeKey0 != htlcKey);

        if (allDifferent) {
            std::cout << "   Channel keys are distinct: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Channel keys are distinct: FAIL ✗" << std::endl;
            return 1;
        }

        // Same key type should be deterministic
        auto fundingKey2 = DeriveChannelKey(seed, channelId, "funding", 0);
        if (fundingKey == fundingKey2) {
            std::cout << "   Channel key derivation is deterministic: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Channel key derivation is deterministic: FAIL ✗" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 21: Path Serialization Round-trip
    std::cout << "21. Testing derivation path serialization..." << std::endl;
    {
        DerivationPath path;
        path.purpose = 44;
        path.coinType = 21329;
        path.account = 5;
        path.change = 1;
        path.index = 1000;

        auto bytes = PathToBytes(path);

        if (bytes.size() == 20) {
            std::cout << "   Path serialization produces 20 bytes: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Path serialization produces 20 bytes: FAIL ✗ (got "
                      << bytes.size() << ")" << std::endl;
            return 1;
        }

        // Check that different paths produce different serializations
        DerivationPath path2;
        path2.index = 1001;

        auto bytes2 = PathToBytes(path2);

        if (bytes != bytes2) {
            std::cout << "   Different paths produce different serializations: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Different paths produce different serializations: FAIL ✗" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    std::cout << "=== All tests completed ===" << std::endl;

    return 0;
}
