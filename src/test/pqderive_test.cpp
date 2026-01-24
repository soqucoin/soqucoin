// Copyright (c) 2026 The Soqucoin Core developers
// HD derivation test + test vector generator
// Usage: pqderive-test [--json-vectors]

#include "wallet/pqwallet/pqderive.h"
#include "wallet/pqwallet/pqkeys.h"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace soqucoin::pqwallet;

// Hex encoding helper
static std::string ToHex(const uint8_t* data, size_t len)
{
    std::ostringstream ss;
    for (size_t i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

// Generate JSON test vectors (for auditors)
static void OutputJsonVectors()
{
    // Standard BIP-39 test mnemonic: "abandon abandon ... about"
    const uint8_t bip39_seed[64] = {
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08,
        0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56, 0x81,
        0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70,
        0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1,
        0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70,
        0xd0, 0x86, 0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4,
        0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
        0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4};
    SecureBytes seed(bip39_seed, 64);

    std::cout << "{\n";
    std::cout << "  \"test_suite\": \"soqucoin_key_derivation_vectors\",\n";
    std::cout << "  \"version\": \"1.0.0\",\n";
    std::cout << "  \"generated_by\": \"pqderive-test --json-vectors\",\n";
    std::cout << "  \"algorithm\": \"HKDF-SHA256 (RFC 5869, NIST SP 800-56C)\",\n";
    std::cout << "\n";

    std::cout << "  \"seed\": {\n";
    std::cout << "    \"mnemonic\": \"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\",\n";
    std::cout << "    \"passphrase\": \"\",\n";
    std::cout << "    \"seed_hex\": \"" << ToHex(bip39_seed, 64) << "\"\n";
    std::cout << "  },\n\n";

    // Signing key vectors
    std::cout << "  \"signing_key_vectors\": [\n";
    for (uint32_t i = 0; i < 3; ++i) {
        DerivationPath path;
        path.purpose = 44;
        path.coinType = 21329;
        path.account = 0;
        path.change = 0;
        path.index = i;

        auto key = DeriveKeyMaterial(seed, path, DOMAIN_WALLET);
        auto pathBytes = PathToBytes(path);

        std::cout << "    {\n";
        std::cout << "      \"path\": \"m/44'/21329'/0'/0/" << i << "\",\n";
        std::cout << "      \"path_bytes_hex\": \"" << ToHex(pathBytes.data(), 20) << "\",\n";
        std::cout << "      \"key_material_hex\": \"" << ToHex(key.data(), 32) << "\"\n";
        std::cout << "    }" << (i < 2 ? "," : "") << "\n";
    }
    std::cout << "  ],\n\n";

    // Blinding factor vectors (GAP-010)
    std::cout << "  \"blinding_factor_vectors\": [\n";
    for (uint32_t i = 0; i < 3; ++i) {
        auto blind = DeriveBlindingFactor(seed, i);
        std::cout << "    {\n";
        std::cout << "      \"output_index\": " << i << ",\n";
        std::cout << "      \"blinding_factor_hex\": \"" << ToHex(blind.data(), 32) << "\"\n";
        std::cout << "    }" << (i < 2 ? "," : "") << "\n";
    }
    std::cout << "  ],\n\n";

    // L2 channel key vectors
    std::string channelId = "test-channel-001";
    std::cout << "  \"l2_channel_key_vectors\": {\n";
    std::cout << "    \"channel_id\": \"" << channelId << "\",\n";
    std::cout << "    \"keys\": [\n";

    auto funding = DeriveChannelKey(seed, channelId, "funding", 0);
    auto revoke = DeriveChannelKey(seed, channelId, "revoke", 0);
    auto htlc = DeriveChannelKey(seed, channelId, "htlc", 0);

    std::cout << "      {\"key_type\": \"funding\", \"key_hex\": \"" << ToHex(funding.data(), 32) << "\"},\n";
    std::cout << "      {\"key_type\": \"revoke\", \"index\": 0, \"key_hex\": \"" << ToHex(revoke.data(), 32) << "\"},\n";
    std::cout << "      {\"key_type\": \"htlc\", \"index\": 0, \"key_hex\": \"" << ToHex(htlc.data(), 32) << "\"}\n";
    std::cout << "    ]\n";
    std::cout << "  },\n\n";

    // Domain separation proof
    DerivationPath p0;
    p0.purpose = 44;
    p0.coinType = 21329;
    p0.account = 0;
    p0.change = 0;
    p0.index = 0;
    auto walletKey = DeriveKeyMaterial(seed, p0, DOMAIN_WALLET);
    auto blindKey = DeriveKeyMaterial(seed, p0, DOMAIN_BLINDING);

    std::cout << "  \"domain_separation_proof\": {\n";
    std::cout << "    \"path\": \"m/44'/21329'/0'/0/0\",\n";
    std::cout << "    \"wallet_domain_key\": \"" << ToHex(walletKey.data(), 32) << "\",\n";
    std::cout << "    \"blinding_domain_key\": \"" << ToHex(blindKey.data(), 32) << "\",\n";
    std::cout << "    \"must_differ\": true\n";
    std::cout << "  }\n";
    std::cout << "}\n";
}

int main(int argc, char* argv[])
{
    // Check for --json-vectors flag (for auditors)
    if (argc > 1 && std::string(argv[1]) == "--json-vectors") {
        OutputJsonVectors();
        return 0;
    }

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
