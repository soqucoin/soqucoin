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
#include "wallet/pqwallet/pqkeys.h"
#include "wallet/pqwallet/pqwallet.h"

#include <iomanip>
#include <iostream>
#include <vector>

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
        std::string passphrase = "TestPassphrase123!@#";

        WalletCrypto crypto;
        auto encrypted = crypto.Encrypt(plaintext, passphrase);

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
        std::string correctPass = "CorrectHorseBatteryStaple";
        std::string wrongPass = "WrongPassword123";

        WalletCrypto crypto;
        auto encrypted = crypto.Encrypt(plaintext, correctPass);

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
        std::string emptyPass = "";

        WalletCrypto crypto;
        // Empty passphrase should still work (user choice) but encrypt
        auto encrypted = crypto.Encrypt(plaintext, emptyPass);
        auto decrypted = crypto.Decrypt(encrypted, emptyPass);

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
        std::string passphrase = "IntegrityTest";

        WalletCrypto crypto;
        auto encrypted = crypto.Encrypt(plaintext, passphrase);

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
        std::string passphrase = "SamePassphrase";

        WalletCrypto crypto;
        auto encrypted1 = crypto.Encrypt(plaintext, passphrase);
        auto encrypted2 = crypto.Encrypt(plaintext, passphrase);

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
        std::string passphrase = "SerializationTest";

        WalletCrypto crypto;
        auto encrypted = crypto.Encrypt(plaintext, passphrase);

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
        std::string passphrase = "LargeWalletTest";

        WalletCrypto crypto;
        auto encrypted = crypto.Encrypt(largeData, passphrase);

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

    std::cout << "=== All tests completed ===" << std::endl;

    return 0;
}
