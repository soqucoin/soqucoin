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

    // Test 8: Generate multiple addresses
    std::cout << "8. Generating 3 more addresses..." << std::endl;
    for (int i = 0; i < 3; ++i) {
        auto kp = PQKeyPair::Generate();
        if (kp) {
            std::string addr = PQAddress::Encode(kp->GetPublicKey(), network, AddressType::P2PQ);
            std::cout << "   [" << (i + 1) << "] " << addr << std::endl;
        }
    }
    std::cout << std::endl;

    std::cout << "=== All tests completed ===" << std::endl;

    return 0;
}
