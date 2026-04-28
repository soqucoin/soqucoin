// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-ARCH-001 Phase 2: Key-Image Unit & Integration Tests
// Design Log: DL-PRIVACY-INTEGRATION-ARCHITECTURE.md
//
// Test coverage for:
//   1. LatticeKeyImageHash construction, equality, hashing, serialization
//   2. CCoinsViewDB key-image CRUD (Write/Have/Read/Erase round-trip)
//   3. Intra-block duplicate key-image detection
//   4. Cross-block duplicate detection (DB + intra-block combined)
//   5. Reorg: Connect → Disconnect → Reconnect simulation
//   6. ViewKeyData serialization
//   7. Hash collision resistance
//   8. Batch stress test

#include "consensus/privacy.h"
#include "hash.h"
#include "test/test_bitcoin.h"
#include "txdb.h"
#include "uint256.h"
#include "streams.h"

#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <set>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(keyimage_tests, BasicTestingSetup)

// =========================================================================
// 1. LatticeKeyImageHash — Struct unit tests
// =========================================================================

BOOST_AUTO_TEST_CASE(keyimage_hash_default_is_null)
{
    LatticeKeyImageHash ki;
    BOOST_CHECK(ki.IsNull());
    BOOST_CHECK(ki.hash.IsNull());
}

BOOST_AUTO_TEST_CASE(keyimage_hash_explicit_construction)
{
    uint256 h = uint256S("0xdeadbeef00000000000000000000000000000000000000000000000000000001");
    LatticeKeyImageHash ki(h);
    BOOST_CHECK(!ki.IsNull());
    BOOST_CHECK(ki.hash == h);
}

BOOST_AUTO_TEST_CASE(keyimage_hash_from_serialized)
{
    // Simulate a 2048-byte key image (256 * 8 bytes, as per LatticeParams::N)
    std::vector<uint8_t> fakeKeyImage(2048);
    for (size_t i = 0; i < fakeKeyImage.size(); i++) {
        fakeKeyImage[i] = static_cast<uint8_t>(i & 0xFF);
    }

    LatticeKeyImageHash ki = LatticeKeyImageHash::FromSerializedKeyImage(fakeKeyImage);
    BOOST_CHECK(!ki.IsNull());

    // Verify determinism: same input → same hash
    LatticeKeyImageHash ki2 = LatticeKeyImageHash::FromSerializedKeyImage(fakeKeyImage);
    BOOST_CHECK(ki == ki2);

    // Verify sensitivity: different input → different hash
    fakeKeyImage[0] ^= 0xFF;
    LatticeKeyImageHash ki3 = LatticeKeyImageHash::FromSerializedKeyImage(fakeKeyImage);
    BOOST_CHECK(ki != ki3);
}

BOOST_AUTO_TEST_CASE(keyimage_hash_equality_operators)
{
    uint256 h1 = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 h2 = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");

    LatticeKeyImageHash ki1(h1);
    LatticeKeyImageHash ki2(h1);
    LatticeKeyImageHash ki3(h2);

    BOOST_CHECK(ki1 == ki2);
    BOOST_CHECK(ki1 != ki3);
    BOOST_CHECK(ki2 != ki3);
}

BOOST_AUTO_TEST_CASE(keyimage_hash_ordering)
{
    uint256 h1 = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");
    uint256 h2 = uint256S("0x0000000000000000000000000000000000000000000000000000000000000002");

    LatticeKeyImageHash ki1(h1);
    LatticeKeyImageHash ki2(h2);

    BOOST_CHECK(ki1 < ki2);
    BOOST_CHECK(!(ki2 < ki1));
    BOOST_CHECK(!(ki1 < ki1));
}

BOOST_AUTO_TEST_CASE(keyimage_hash_serialization_roundtrip)
{
    uint256 h = uint256S("0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    LatticeKeyImageHash ki(h);

    // Serialize
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << ki;

    // Deserialize
    LatticeKeyImageHash ki2;
    ss >> ki2;

    BOOST_CHECK(ki == ki2);
    BOOST_CHECK(ki.hash == ki2.hash);
}

BOOST_AUTO_TEST_CASE(keyimage_hash_from_empty_input)
{
    // Edge case: empty input should still produce a valid (non-null) hash
    // because SHA256d("") is well-defined
    std::vector<uint8_t> emptyInput;
    LatticeKeyImageHash ki = LatticeKeyImageHash::FromSerializedKeyImage(emptyInput);
    BOOST_CHECK(!ki.IsNull());
}

BOOST_AUTO_TEST_CASE(keyimage_hash_from_small_input)
{
    // Edge case: 1-byte input
    std::vector<uint8_t> smallInput = {0x42};
    LatticeKeyImageHash ki = LatticeKeyImageHash::FromSerializedKeyImage(smallInput);
    BOOST_CHECK(!ki.IsNull());

    // Different 1-byte input → different hash
    std::vector<uint8_t> smallInput2 = {0x43};
    LatticeKeyImageHash ki2 = LatticeKeyImageHash::FromSerializedKeyImage(smallInput2);
    BOOST_CHECK(ki != ki2);
}

// =========================================================================
// 2. CCoinsViewDB Key-Image CRUD (in-memory LevelDB)
// =========================================================================

BOOST_AUTO_TEST_CASE(txdb_keyimage_write_have_read_roundtrip)
{
    // Use in-memory LevelDB (fMemory=true) for isolated testing
    CCoinsViewDB db(1 << 20, true, true); // 1MB cache, in-memory, wipe

    uint256 kiHash = uint256S("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    int32_t blockHeight = 42;

    // Initially should not exist
    BOOST_CHECK(!db.HaveKeyImage(kiHash));

    // Write
    BOOST_CHECK(db.WriteKeyImage(kiHash, blockHeight));

    // Now should exist
    BOOST_CHECK(db.HaveKeyImage(kiHash));

    // Read back height
    int32_t readHeight = -1;
    BOOST_CHECK(db.ReadKeyImageHeight(kiHash, readHeight));
    BOOST_CHECK_EQUAL(readHeight, blockHeight);
}

BOOST_AUTO_TEST_CASE(txdb_keyimage_erase)
{
    CCoinsViewDB db(1 << 20, true, true);

    uint256 kiHash = uint256S("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    // Write then erase
    BOOST_CHECK(db.WriteKeyImage(kiHash, 100));
    BOOST_CHECK(db.HaveKeyImage(kiHash));

    BOOST_CHECK(db.EraseKeyImage(kiHash));
    BOOST_CHECK(!db.HaveKeyImage(kiHash));

    // Read should fail after erase
    int32_t readHeight = -1;
    BOOST_CHECK(!db.ReadKeyImageHeight(kiHash, readHeight));
}

BOOST_AUTO_TEST_CASE(txdb_keyimage_multiple_independent)
{
    CCoinsViewDB db(1 << 20, true, true);

    uint256 ki1 = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 ki2 = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
    uint256 ki3 = uint256S("0x3333333333333333333333333333333333333333333333333333333333333333");

    // Write all three at different heights
    BOOST_CHECK(db.WriteKeyImage(ki1, 10));
    BOOST_CHECK(db.WriteKeyImage(ki2, 20));
    BOOST_CHECK(db.WriteKeyImage(ki3, 30));

    // All should exist
    BOOST_CHECK(db.HaveKeyImage(ki1));
    BOOST_CHECK(db.HaveKeyImage(ki2));
    BOOST_CHECK(db.HaveKeyImage(ki3));

    // Heights should be independent
    int32_t h1, h2, h3;
    BOOST_CHECK(db.ReadKeyImageHeight(ki1, h1));
    BOOST_CHECK(db.ReadKeyImageHeight(ki2, h2));
    BOOST_CHECK(db.ReadKeyImageHeight(ki3, h3));
    BOOST_CHECK_EQUAL(h1, 10);
    BOOST_CHECK_EQUAL(h2, 20);
    BOOST_CHECK_EQUAL(h3, 30);

    // Erase middle one — others should remain
    BOOST_CHECK(db.EraseKeyImage(ki2));
    BOOST_CHECK(db.HaveKeyImage(ki1));
    BOOST_CHECK(!db.HaveKeyImage(ki2));
    BOOST_CHECK(db.HaveKeyImage(ki3));
}

BOOST_AUTO_TEST_CASE(txdb_keyimage_overwrite_height)
{
    // Simulate a reorg scenario: key-image first seen at height 50,
    // then block is disconnected (erased), then re-connected at height 55.
    CCoinsViewDB db(1 << 20, true, true);

    uint256 kiHash = uint256S("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

    // Write at height 50
    BOOST_CHECK(db.WriteKeyImage(kiHash, 50));

    int32_t h;
    BOOST_CHECK(db.ReadKeyImageHeight(kiHash, h));
    BOOST_CHECK_EQUAL(h, 50);

    // Erase (simulate DisconnectBlock)
    BOOST_CHECK(db.EraseKeyImage(kiHash));
    BOOST_CHECK(!db.HaveKeyImage(kiHash));

    // Re-write at height 55 (simulate ConnectBlock on new chain)
    BOOST_CHECK(db.WriteKeyImage(kiHash, 55));
    BOOST_CHECK(db.ReadKeyImageHeight(kiHash, h));
    BOOST_CHECK_EQUAL(h, 55);
}

// =========================================================================
// 3. ViewKeyData — Serialization tests
// =========================================================================

BOOST_AUTO_TEST_CASE(viewkeydata_default_is_null)
{
    ViewKeyData vkd;
    BOOST_CHECK(vkd.IsNull());
    BOOST_CHECK_EQUAL(vkd.nVersion, 0);
    BOOST_CHECK_EQUAL(vkd.SerializedSize(), 0u);
}

BOOST_AUTO_TEST_CASE(viewkeydata_populated)
{
    ViewKeyData vkd;
    vkd.nVersion = 0x01;
    vkd.tx_public_key.assign(32, 0xAA);
    vkd.encrypted_amount.assign(64, 0xBB);
    vkd.amount_commitment_check.assign(32, 0xCC);

    BOOST_CHECK(!vkd.IsNull());
    BOOST_CHECK(vkd.SerializedSize() > 0);
}

BOOST_AUTO_TEST_CASE(viewkeydata_serialization_roundtrip)
{
    ViewKeyData vkd;
    vkd.nVersion = 0x01;
    vkd.tx_public_key.assign(32, 0xAA);
    vkd.encrypted_amount.assign(64, 0xBB);
    vkd.amount_commitment_check.assign(32, 0xCC);

    // Serialize
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << vkd;

    // Deserialize
    ViewKeyData vkd2;
    ss >> vkd2;

    BOOST_CHECK_EQUAL(vkd2.nVersion, 0x01);
    BOOST_CHECK(vkd2.tx_public_key == vkd.tx_public_key);
    BOOST_CHECK(vkd2.encrypted_amount == vkd.encrypted_amount);
    BOOST_CHECK(vkd2.amount_commitment_check == vkd.amount_commitment_check);
}

BOOST_AUTO_TEST_CASE(viewkeydata_null_serialization)
{
    ViewKeyData vkd; // version 0 = null

    // Serialize
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << vkd;

    // Deserialize
    ViewKeyData vkd2;
    ss >> vkd2;

    BOOST_CHECK(vkd2.IsNull());
    BOOST_CHECK_EQUAL(vkd2.nVersion, 0);
}

// =========================================================================
// 4. Intra-block duplicate detection (unit-level simulation)
// =========================================================================

BOOST_AUTO_TEST_CASE(intrablock_duplicate_detection)
{
    // Simulate the intra-block duplicate detection logic from ConnectBlock.
    // This tests the algorithm without requiring a full blockchain setup.

    std::vector<LatticeKeyImageHash> vBlockKeyImages;

    // Create three distinct key-image hashes
    std::vector<uint8_t> ki1_bytes(64, 0x11);
    std::vector<uint8_t> ki2_bytes(64, 0x22);
    std::vector<uint8_t> ki3_bytes(64, 0x33);

    LatticeKeyImageHash ki1 = LatticeKeyImageHash::FromSerializedKeyImage(ki1_bytes);
    LatticeKeyImageHash ki2 = LatticeKeyImageHash::FromSerializedKeyImage(ki2_bytes);
    LatticeKeyImageHash ki3 = LatticeKeyImageHash::FromSerializedKeyImage(ki3_bytes);

    // All distinct
    BOOST_CHECK(ki1 != ki2);
    BOOST_CHECK(ki2 != ki3);
    BOOST_CHECK(ki1 != ki3);

    // Lambda matching ConnectBlock's intra-block duplicate check
    auto hasIntraBlockDuplicate = [&](const LatticeKeyImageHash& candidate) -> bool {
        for (const auto& existing : vBlockKeyImages) {
            if (existing == candidate) return true;
        }
        return false;
    };

    // Add ki1 — no duplicate
    BOOST_CHECK(!hasIntraBlockDuplicate(ki1));
    vBlockKeyImages.push_back(ki1);

    // Add ki2 — no duplicate
    BOOST_CHECK(!hasIntraBlockDuplicate(ki2));
    vBlockKeyImages.push_back(ki2);

    // Add ki3 — no duplicate
    BOOST_CHECK(!hasIntraBlockDuplicate(ki3));
    vBlockKeyImages.push_back(ki3);

    // Try ki1 again — MUST detect duplicate
    BOOST_CHECK_MESSAGE(hasIntraBlockDuplicate(ki1),
        "Intra-block duplicate key-image not detected!");

    // Try ki2 again — MUST detect duplicate
    BOOST_CHECK_MESSAGE(hasIntraBlockDuplicate(ki2),
        "Intra-block duplicate key-image not detected!");
}

// =========================================================================
// 5. Cross-block duplicate detection (DB + intra-block combined)
// =========================================================================

BOOST_AUTO_TEST_CASE(crossblock_duplicate_detection)
{
    // Simulate the full ConnectBlock key-image flow:
    // Block N: key-image A is recorded in DB
    // Block N+1: key-image A appears again → MUST be rejected

    CCoinsViewDB db(1 << 20, true, true);

    // Block N: record key-image A at height 100
    std::vector<uint8_t> kiA_bytes(128, 0xAA);
    LatticeKeyImageHash kiA = LatticeKeyImageHash::FromSerializedKeyImage(kiA_bytes);

    // Phase 1: Check for cross-block duplicate (should not exist yet)
    BOOST_CHECK(!db.HaveKeyImage(kiA.hash));

    // Phase 2: Record it
    BOOST_CHECK(db.WriteKeyImage(kiA.hash, 100));

    // Block N+1: try to use key-image A again
    // Phase 1: Check for cross-block duplicate — MUST be found
    BOOST_CHECK_MESSAGE(db.HaveKeyImage(kiA.hash),
        "Cross-block duplicate key-image not detected!");

    int32_t prevHeight = 0;
    BOOST_CHECK(db.ReadKeyImageHeight(kiA.hash, prevHeight));
    BOOST_CHECK_EQUAL(prevHeight, 100);
}

// =========================================================================
// 6. Reorg simulation: Connect → Disconnect → Reconnect
// =========================================================================

BOOST_AUTO_TEST_CASE(reorg_connect_disconnect_reconnect)
{
    // Full reorg simulation:
    // 1. Connect block at height 50 with key-images {A, B}
    // 2. Disconnect block at height 50 — erase {A, B}
    // 3. Connect new block at height 50 with key-images {A, C}
    //    (A is re-used on the new chain, C is new, B is gone)

    CCoinsViewDB db(1 << 20, true, true);

    std::vector<uint8_t> kiA_bytes(128, 0xAA);
    std::vector<uint8_t> kiB_bytes(128, 0xBB);
    std::vector<uint8_t> kiC_bytes(128, 0xCC);

    LatticeKeyImageHash kiA = LatticeKeyImageHash::FromSerializedKeyImage(kiA_bytes);
    LatticeKeyImageHash kiB = LatticeKeyImageHash::FromSerializedKeyImage(kiB_bytes);
    LatticeKeyImageHash kiC = LatticeKeyImageHash::FromSerializedKeyImage(kiC_bytes);

    // Step 1: Connect block at height 50 with {A, B}
    BOOST_CHECK(db.WriteKeyImage(kiA.hash, 50));
    BOOST_CHECK(db.WriteKeyImage(kiB.hash, 50));
    BOOST_CHECK(db.HaveKeyImage(kiA.hash));
    BOOST_CHECK(db.HaveKeyImage(kiB.hash));
    BOOST_CHECK(!db.HaveKeyImage(kiC.hash));

    // Step 2: Disconnect block at height 50 — erase {A, B}
    BOOST_CHECK(db.EraseKeyImage(kiA.hash));
    BOOST_CHECK(db.EraseKeyImage(kiB.hash));
    BOOST_CHECK(!db.HaveKeyImage(kiA.hash));
    BOOST_CHECK(!db.HaveKeyImage(kiB.hash));

    // Step 3: Connect new block at height 50 with {A, C}
    // A should be allowed again (it was erased)
    BOOST_CHECK(!db.HaveKeyImage(kiA.hash));
    BOOST_CHECK(db.WriteKeyImage(kiA.hash, 50));
    BOOST_CHECK(db.WriteKeyImage(kiC.hash, 50));

    // Final state: A and C exist, B does not
    BOOST_CHECK(db.HaveKeyImage(kiA.hash));
    BOOST_CHECK(!db.HaveKeyImage(kiB.hash));
    BOOST_CHECK(db.HaveKeyImage(kiC.hash));
}

// =========================================================================
// 7. Hash collision resistance: distinct inputs → distinct hashes
// =========================================================================

BOOST_AUTO_TEST_CASE(keyimage_hash_collision_resistance)
{
    // Generate 256 distinct key-images and verify all produce unique hashes
    std::set<uint256> seen;

    for (int i = 0; i < 256; i++) {
        std::vector<uint8_t> ki_bytes(64, static_cast<uint8_t>(i));
        LatticeKeyImageHash ki = LatticeKeyImageHash::FromSerializedKeyImage(ki_bytes);
        BOOST_CHECK_MESSAGE(
            seen.find(ki.hash) == seen.end(),
            "Hash collision at input index " + std::to_string(i));
        seen.insert(ki.hash);
    }

    BOOST_CHECK_EQUAL(seen.size(), 256u);
}

// =========================================================================
// 8. Stress: large key-image batch write/verify/erase
// =========================================================================

BOOST_AUTO_TEST_CASE(txdb_keyimage_batch_write_verify)
{
    CCoinsViewDB db(1 << 20, true, true);

    const int BATCH_SIZE = 100;

    // Write 100 key-images at various heights
    std::vector<uint256> hashes;
    for (int i = 0; i < BATCH_SIZE; i++) {
        std::vector<uint8_t> ki_bytes(64);
        // Create unique input for each
        ki_bytes[0] = static_cast<uint8_t>(i & 0xFF);
        ki_bytes[1] = static_cast<uint8_t>((i >> 8) & 0xFF);
        LatticeKeyImageHash ki = LatticeKeyImageHash::FromSerializedKeyImage(ki_bytes);
        hashes.push_back(ki.hash);

        BOOST_CHECK(db.WriteKeyImage(ki.hash, i * 10));
    }

    // Verify all exist with correct heights
    for (int i = 0; i < BATCH_SIZE; i++) {
        BOOST_CHECK_MESSAGE(db.HaveKeyImage(hashes[i]),
            "Key-image " + std::to_string(i) + " not found after batch write");
        int32_t h;
        BOOST_CHECK(db.ReadKeyImageHeight(hashes[i], h));
        BOOST_CHECK_EQUAL(h, i * 10);
    }

    // Erase all
    for (int i = 0; i < BATCH_SIZE; i++) {
        BOOST_CHECK(db.EraseKeyImage(hashes[i]));
    }

    // Verify all erased
    for (int i = 0; i < BATCH_SIZE; i++) {
        BOOST_CHECK_MESSAGE(!db.HaveKeyImage(hashes[i]),
            "Key-image " + std::to_string(i) + " still exists after batch erase");
    }
}

BOOST_AUTO_TEST_SUITE_END()
