// Copyright (c) 2026 The Soqucoin Core developers
// Minimal HD derivation test

#include "wallet/pqwallet/pqderive.h"
#include "wallet/pqwallet/pqkeys.h"

#include <cstring>
#include <iomanip>
#include <iostream>

using namespace soqucoin::pqwallet;

int main()
{
    std::cout << "=== HD Key Derivation Tests ===" << std::endl;
    std::cout << std::endl;

    // Test 1: HD Derivation Determinism
    std::cout << "1. Testing HD derivation determinism..." << std::endl;
    {
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

        auto key1 = DeriveKeyMaterial(seed, path1, DOMAIN_WALLET);
        auto key2 = DeriveKeyMaterial(seed, path2, DOMAIN_WALLET);

        if (key1 == key2) {
            std::cout << "   Same path produces same key: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Same path produces same key: FAIL ✗" << std::endl;
            return 1;
        }

        DerivationPath path3;
        path3.account = 0;
        path3.change = 0;
        path3.index = 1;

        auto key3 = DeriveKeyMaterial(seed, path3, DOMAIN_WALLET);

        if (key1 != key3) {
            std::cout << "   Different index produces different key: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Different index produces different key: FAIL ✗" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 2: Account Separation
    std::cout << "2. Testing account separation..." << std::endl;
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

    // Test 3: Domain Separation
    std::cout << "3. Testing domain separation (signing vs blinding)..." << std::endl;
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
            std::cerr << "   Signing and blinding keys differ: FAIL ✗" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 4: Blinding Factor Derivation
    std::cout << "4. Testing blinding factor derivation (GAP-010)..." << std::endl;
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

    // Test 5: L2 Channel Key Derivation
    std::cout << "5. Testing L2 channel key derivation..." << std::endl;
    {
        SecureBytes seed(64);
        std::memset(seed.data(), 0x42, 64);

        std::string channelId = "abc123";

        auto fundingKey = DeriveChannelKey(seed, channelId, "funding", 0);
        auto revokeKey0 = DeriveChannelKey(seed, channelId, "revoke", 0);
        auto revokeKey1 = DeriveChannelKey(seed, channelId, "revoke", 1);
        auto htlcKey = DeriveChannelKey(seed, channelId, "htlc", 0);

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

        auto fundingKey2 = DeriveChannelKey(seed, channelId, "funding", 0);
        if (fundingKey == fundingKey2) {
            std::cout << "   Channel key derivation is deterministic: PASS ✓" << std::endl;
        } else {
            std::cerr << "   Channel key derivation is deterministic: FAIL ✗" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;

    // Test 6: Path Serialization
    std::cout << "6. Testing derivation path serialization..." << std::endl;
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
            std::cerr << "   Path serialization produces 20 bytes: FAIL ✗" << std::endl;
            return 1;
        }

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

    std::cout << "=== All HD derivation tests PASSED ✓ ===" << std::endl;
    return 0;
}
