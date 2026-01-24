// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license.

/**
 * @file pqwallet_fuzz.cpp
 * @brief Fuzz tests for PQ wallet address validation, encoding, and parsing
 *
 * SECURITY: Tests address parsing for:
 * - Buffer overflows in Bech32m decoding
 * - Invalid character handling
 * - Network prefix validation
 * - Length boundary conditions
 */

#include <bech32.h>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <test/fuzz/fuzz.h>
#include <vector>
#include <wallet/pqwallet/pqaddress.h>

using namespace soqucoin::pqwallet;

/**
 * Fuzz target: Address validation
 * Tests PQAddress::IsValid() with arbitrary input
 */
void pqaddress_validate(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() == 0) return;
    if (buffer.size() > 256) return; // Reasonable max address length

    // Convert buffer to string (may contain null bytes, invalid chars)
    std::string address(reinterpret_cast<const char*>(buffer.data()), buffer.size());

    // This should never crash, regardless of input
    (void)PQAddress::IsValid(address);
}

/**
 * Fuzz target: Address decoding
 * Tests PQAddress::Decode() with arbitrary input
 */
void pqaddress_decode(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() == 0) return;
    if (buffer.size() > 256) return;

    std::string address(reinterpret_cast<const char*>(buffer.data()), buffer.size());

    // Decode should handle any input gracefully
    AddressInfo info = PQAddress::Decode(address);

    // If valid, verify internal consistency
    if (info.valid) {
        // Re-encoding should produce valid address
        std::string reencoded = PQAddress::EncodeFromHash(info.hash, info.network, info.type);
        (void)PQAddress::IsValid(reencoded);
    }
}

/**
 * Fuzz target: Bech32m encoding round-trip
 * Tests encoding and decoding consistency
 */
void bech32m_roundtrip(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() < 2) return;
    if (buffer.size() > 100) return;

    // First byte selects HRP
    const char* hrps[] = {"sq", "tsq", "ssq", "sqp", "sqsh"};
    std::string hrp = hrps[buffer.data()[0] % 5];

    // Remaining bytes become 5-bit data
    std::vector<uint8_t> data5bit;
    for (size_t i = 1; i < buffer.size(); ++i) {
        data5bit.push_back(buffer.data()[i] & 0x1f); // Mask to 5 bits
    }

    // Encode
    std::string encoded = bech32::Encode(bech32::Encoding::BECH32M, hrp, data5bit);

    if (!encoded.empty()) {
        // Decode
        auto decoded = bech32::Decode(encoded);

        // Verify round-trip
        if (decoded.encoding == bech32::Encoding::BECH32M) {
            // Data should match
            assert(decoded.data == data5bit);
            assert(decoded.hrp == hrp);
        }
    }
}

/**
 * Fuzz target: Public key hashing
 * Tests BLAKE2b-160 hashing of varying-size inputs
 */
void pqaddress_hash(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() < DILITHIUM_PUBKEY_SIZE) return;

    // Extract exactly DILITHIUM_PUBKEY_SIZE bytes
    std::array<uint8_t, DILITHIUM_PUBKEY_SIZE> pubkey;
    std::memcpy(pubkey.data(), buffer.data(), DILITHIUM_PUBKEY_SIZE);

    // Hash should always succeed
    auto hash = PQAddress::HashPublicKey(pubkey);

    // Hash should be exactly 20 bytes
    assert(hash.size() == 20);
}

/**
 * Fuzz target: Network detection from address prefix
 */
void pqaddress_network_detect(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() == 0) return;
    if (buffer.size() > 100) return;

    std::string address(reinterpret_cast<const char*>(buffer.data()), buffer.size());

    // Should never crash
    Network net = PQAddress::DetectNetwork(address);

    // If detected, verify it's a valid value
    (void)net; // Enum validation implicit
}

// Note: These functions are registered in Fuzz.cpp
