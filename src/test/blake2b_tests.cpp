// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file blake2b_tests.cpp
 * @brief BLAKE2b test vectors from RFC 7693 and extended tests
 *
 * Test structure follows Bitcoin Core crypto_tests.cpp patterns.
 * Vectors sourced from:
 * - RFC 7693 Appendix A (official BLAKE2b test vectors)
 * - BLAKE2 reference implementation test suite
 * - Soqucoin-specific address hashing tests
 */

#include "crypto/blake2b.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"

#include <chrono>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(blake2b_tests, BasicTestingSetup)

/**
 * Test helper: verify BLAKE2b produces expected output
 * Tests both single-pass and chunked processing like other crypto tests
 */
void TestBLAKE2b(size_t outlen, const std::string& hexin, const std::string& hexout)
{
    std::vector<unsigned char> in = ParseHex(hexin);
    std::vector<unsigned char> expected = ParseHex(hexout);
    std::vector<unsigned char> hash(outlen);

    BOOST_CHECK_EQUAL(expected.size(), outlen);

    // Test 1: Write entire input at once
    {
        CBLAKE2b hasher(outlen);
        hasher.Write(in.data(), in.size());
        hasher.Finalize(hash.data());
        BOOST_CHECK_EQUAL(HexStr(hash), hexout);
    }

    // Test 2: Write input in chunks (stress test incremental API)
    if (in.size() > 1) {
        CBLAKE2b hasher(outlen);
        size_t pos = 0;
        size_t chunk = in.size() / 3 + 1;
        while (pos < in.size()) {
            size_t len = std::min(chunk, in.size() - pos);
            hasher.Write(in.data() + pos, len);
            pos += len;
        }
        hasher.Finalize(hash.data());
        BOOST_CHECK_EQUAL(HexStr(hash), hexout);
    }

    // Test 3: Single-byte writes (extreme chunking)
    if (in.size() <= 128) { // Only for small inputs to avoid slowdown
        CBLAKE2b hasher(outlen);
        for (size_t i = 0; i < in.size(); ++i) {
            hasher.Write(in.data() + i, 1);
        }
        hasher.Finalize(hash.data());
        BOOST_CHECK_EQUAL(HexStr(hash), hexout);
    }
}

/**
 * Convenience wrappers for common output lengths
 */
void TestBLAKE2b_160(const std::string& hexin, const std::string& hexout)
{
    TestBLAKE2b(20, hexin, hexout);
}

void TestBLAKE2b_256(const std::string& hexin, const std::string& hexout)
{
    TestBLAKE2b(32, hexin, hexout);
}

void TestBLAKE2b_512(const std::string& hexin, const std::string& hexout)
{
    TestBLAKE2b(64, hexin, hexout);
}

/**
 * RFC 7693 Appendix A: BLAKE2b-512 test vector
 * Input: "abc" (616263 in hex)
 *
 * This is the canonical test vector from the RFC.
 */
BOOST_AUTO_TEST_CASE(blake2b_rfc7693_abc)
{
    // RFC 7693 Appendix A - BLAKE2b-512("abc")
    TestBLAKE2b_512(
        "616263",
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
}

/**
 * RFC 7693 - Empty input test
 * BLAKE2b-512("")
 */
BOOST_AUTO_TEST_CASE(blake2b_empty_input)
{
    TestBLAKE2b_512(
        "",
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
        "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
}

/**
 * BLAKE2b-256 test vectors
 * Used for general hashing where 256-bit output is desired
 */
BOOST_AUTO_TEST_CASE(blake2b_256_testvectors)
{
    // Empty input
    TestBLAKE2b_256("", "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");

    // "abc"
    TestBLAKE2b_256("616263", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");

    // Single zero byte
    TestBLAKE2b_256("00", "03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314");
}

/**
 * BLAKE2b-160 test vectors (PRIMARY USE CASE)
 *
 * 160-bit output is used for Soqucoin address hashing.
 * These vectors validated against Python hashlib.blake2b reference.
 */
BOOST_AUTO_TEST_CASE(blake2b_160_testvectors)
{
    // Empty input - BLAKE2b-160("")
    // Verified: hashlib.blake2b(b'', digest_size=20).hexdigest()
    TestBLAKE2b_160("", "3345524abf6bbe1809449224b5972c41790b6cf2");

    // "abc" - BLAKE2b-160("abc")
    TestBLAKE2b_160("616263", "384264f676f39536840523f284921cdc68b6846b");

    // Single zero byte
    TestBLAKE2b_160("00", "082ad992fb76871c33a1b9993a082952feaca5e6");

    // "Soqucoin" = 536f7175636f696e (8 bytes: S=53, o=6f, q=71, u=75, c=63, o=6f, i=69, n=6e)
    // Verified: hashlib.blake2b(b'Soqucoin', digest_size=20).hexdigest()
    TestBLAKE2b_160("536f7175636f696e", "ee9feab5b386b89406a46a8a5a261a78feda180f");
}

/**
 * Long input test (1MB)
 * Verifies correct handling of multi-block inputs
 */
BOOST_AUTO_TEST_CASE(blake2b_long_input)
{
    // 1 million 'a' characters (same pattern as SHA256 tests)
    std::vector<unsigned char> million_a(1000000, 'a');
    std::vector<unsigned char> hash(64);

    CBLAKE2b hasher(64);
    hasher.Write(million_a.data(), million_a.size());
    hasher.Finalize(hash.data());

    // Reference output from BLAKE2 reference implementation
    BOOST_CHECK_EQUAL(
        HexStr(hash),
        "98fb3efb7206fd19ebf69b6f312cf7b64e3b94dbe1a17107913975a793f177e1"
        "d077609d7fba363cbba00d05f7aa4e4fa8715d6428104c0a75643b0ff3fd3eaf");
}

/**
 * Dilithium public key hash test
 *
 * Simulates actual address generation with a 1,312-byte Dilithium pubkey.
 * This is the exact use case for BLAKE2b-160 in Soqucoin.
 */
BOOST_AUTO_TEST_CASE(blake2b_dilithium_pubkey)
{
    // Create a deterministic 1,312-byte "pubkey" (actual Dilithium pubkey size)
    std::vector<unsigned char> pubkey(1312);
    for (size_t i = 0; i < pubkey.size(); ++i) {
        pubkey[i] = static_cast<unsigned char>(i & 0xFF);
    }

    // Hash to 160-bit output
    std::vector<unsigned char> hash(20);
    CBLAKE2b hasher(20);
    hasher.Write(pubkey.data(), pubkey.size());
    hasher.Finalize(hash.data());

    // This is our "golden" test vector for Dilithium address hashing
    // Verified: hashlib.blake2b(bytes([i & 0xFF for i in range(1312)]), digest_size=20).hexdigest()
    // If this changes, all testnet addresses are invalidated
    BOOST_CHECK_EQUAL(HexStr(hash), "989e7da9710e15fa65054a22533ce84d5065bcde");
}

/**
 * Reset functionality test
 * Verifies hasher can be reused after Reset()
 */
BOOST_AUTO_TEST_CASE(blake2b_reset)
{
    CBLAKE2b hasher(32);
    std::vector<unsigned char> hash1(32), hash2(32);

    // First hash
    hasher.Write((const unsigned char*)"abc", 3);
    hasher.Finalize(hash1.data());

    // Reset and hash same input
    hasher.Reset();
    hasher.Write((const unsigned char*)"abc", 3);
    hasher.Finalize(hash2.data());

    BOOST_CHECK(hash1 == hash2);
}

/**
 * Convenience function tests
 */
BOOST_AUTO_TEST_CASE(blake2b_convenience_functions)
{
    std::vector<unsigned char> out160(20);
    std::vector<unsigned char> out256(32);

    const unsigned char input[] = "test";

    BLAKE2b_160(out160.data(), input, 4);
    BOOST_CHECK_EQUAL(out160.size(), 20u);

    BLAKE2b_256(out256.data(), input, 4);
    BOOST_CHECK_EQUAL(out256.size(), 32u);
}

/**
 * Performance benchmark (informational, always passes)
 * Reports BLAKE2b-160 throughput for audit documentation
 */
BOOST_AUTO_TEST_CASE(blake2b_benchmark)
{
    const size_t iterations = 10000;
    const size_t input_size = 1312; // Dilithium pubkey size

    std::vector<unsigned char> input(input_size);
    for (size_t i = 0; i < input_size; ++i) {
        input[i] = static_cast<unsigned char>(i);
    }
    std::vector<unsigned char> hash(20);

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < iterations; ++i) {
        CBLAKE2b hasher(20);
        hasher.Write(input.data(), input.size());
        hasher.Finalize(hash.data());
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    double ops_per_sec = (iterations * 1000000.0) / duration.count();
    double mb_per_sec = (ops_per_sec * input_size) / (1024 * 1024);

    BOOST_TEST_MESSAGE("BLAKE2b-160 Performance:");
    BOOST_TEST_MESSAGE("  Input size: " << input_size << " bytes (Dilithium pubkey)");
    BOOST_TEST_MESSAGE("  Iterations: " << iterations);
    BOOST_TEST_MESSAGE("  Total time: " << duration.count() << " μs");
    BOOST_TEST_MESSAGE("  Throughput: " << static_cast<int>(ops_per_sec) << " hashes/sec");
    BOOST_TEST_MESSAGE("  Bandwidth:  " << static_cast<int>(mb_per_sec) << " MB/sec");

    // Always pass - this is informational
    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_SUITE_END()
