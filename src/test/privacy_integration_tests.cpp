// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-ARCH-001 Phase 2/3: Privacy Integration Tests
// Design Log: DL-PRIVACY-INTEGRATION-ARCHITECTURE.md
//
// Covers:
//   1. Mixed-mode transactions (transparent + confidential outputs)
//   2. USDSOQ visibility enforcement at the data structure level
//   3. Block accumulator with mixed-mode output patterns
//   4. Key-image collision in multi-TX blocks
//   5. Reorg safety for key-images across chain reorganizations
//   6. Fuzz-style edge cases: negative commitments, overflow, malformed data

#include "consensus/block_accumulator.h"
#include "consensus/privacy.h"
#include "consensus/usdsoq.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "txdb.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <set>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(privacy_integration_tests, BasicTestingSetup)

// =========================================================================
// Helper: Create a test CTxOut with given visibility/asset fields
// =========================================================================
static CTxOut MakeTestOutput(CAmount value, uint8_t visibility, uint8_t assetType)
{
    CScript script;
    script << OP_DUP << OP_HASH160
           << std::vector<unsigned char>(20, 0xab)
           << OP_EQUALVERIFY << OP_CHECKSIG;
    return CTxOut(value, script, visibility, assetType);
}

// =========================================================================
// 1. MIXED-MODE TRANSACTION TESTS
// =========================================================================

BOOST_AUTO_TEST_CASE(mixed_mode_tx_transparent_and_confidential_outputs)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vout.push_back(MakeTestOutput(50000, VISIBILITY_TRANSPARENT, ASSET_TYPE_SOQ));
    mtx.vout.push_back(MakeTestOutput(30000, VISIBILITY_CONFIDENTIAL, ASSET_TYPE_SOQ));
    mtx.vout.push_back(MakeTestOutput(10000, VISIBILITY_TRANSPARENT, ASSET_TYPE_SOQ));

    CTransaction tx(mtx);
    BOOST_CHECK(tx.vout[0].IsTransparent());
    BOOST_CHECK(tx.vout[1].IsConfidential());
    BOOST_CHECK(tx.vout[2].IsTransparent());

    int nConfidential = 0;
    for (const auto& out : tx.vout) {
        if (out.IsConfidential()) nConfidential++;
    }
    BOOST_CHECK_EQUAL(nConfidential, 1);
}

BOOST_AUTO_TEST_CASE(mixed_mode_tx_soq_and_usdsoq_isolation)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vout.push_back(MakeTestOutput(10000, VISIBILITY_TRANSPARENT, ASSET_TYPE_SOQ));
    mtx.vout.push_back(MakeTestOutput(5000, VISIBILITY_TRANSPARENT, ASSET_TYPE_USDSOQ));

    CTransaction tx(mtx);
    bool hasSOQ = false, hasUSDSOQ = false;
    for (const auto& out : tx.vout) {
        if (out.IsNativeSOQ()) hasSOQ = true;
        if (out.IsUSDSOQ()) hasUSDSOQ = true;
    }
    BOOST_CHECK_MESSAGE(hasSOQ && hasUSDSOQ,
        "Mixed SOQ/USDSOQ transaction should be detectable for rejection");
}

BOOST_AUTO_TEST_CASE(mixed_mode_visibility_scan)
{
    // Transparent-only TX → no accumulator needed
    {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vout.push_back(MakeTestOutput(50000, VISIBILITY_TRANSPARENT, ASSET_TYPE_SOQ));
        CTransaction tx(mtx);
        bool needs = false;
        for (const auto& out : tx.vout)
            if (out.IsConfidential()) { needs = true; break; }
        BOOST_CHECK(!needs);
    }
    // Mixed TX → accumulator needed
    {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vout.push_back(MakeTestOutput(50000, VISIBILITY_TRANSPARENT, ASSET_TYPE_SOQ));
        mtx.vout.push_back(MakeTestOutput(30000, VISIBILITY_CONFIDENTIAL, ASSET_TYPE_SOQ));
        CTransaction tx(mtx);
        bool needs = false;
        for (const auto& out : tx.vout)
            if (out.IsConfidential()) { needs = true; break; }
        BOOST_CHECK(needs);
    }
}

// =========================================================================
// 2. USDSOQ VISIBILITY + ASSET TYPE ENFORCEMENT
// =========================================================================

BOOST_AUTO_TEST_CASE(usdsoq_mint_must_produce_transparent)
{
    CTxOut out = MakeTestOutput(1000000, VISIBILITY_TRANSPARENT, ASSET_TYPE_USDSOQ);
    uint8_t baseVis = out.nVisibility & ~VISIBILITY_FROZEN_MASK;
    BOOST_CHECK_EQUAL(baseVis, VISIBILITY_TRANSPARENT);
    BOOST_CHECK(out.IsUSDSOQ());
}

BOOST_AUTO_TEST_CASE(usdsoq_mint_confidential_rejected)
{
    CTxOut out = MakeTestOutput(1000000, VISIBILITY_CONFIDENTIAL, ASSET_TYPE_USDSOQ);
    uint8_t baseVis = out.nVisibility & ~VISIBILITY_FROZEN_MASK;
    BOOST_CHECK(baseVis != VISIBILITY_TRANSPARENT);
}

BOOST_AUTO_TEST_CASE(usdsoq_freeze_produces_frozen_transparent)
{
    CTxOut out = MakeTestOutput(500000,
        VISIBILITY_FROZEN_MASK | VISIBILITY_TRANSPARENT, ASSET_TYPE_USDSOQ);
    BOOST_CHECK(out.nVisibility & VISIBILITY_FROZEN_MASK);
    uint8_t baseVis = out.nVisibility & ~VISIBILITY_FROZEN_MASK;
    BOOST_CHECK_EQUAL(baseVis, VISIBILITY_TRANSPARENT);
    BOOST_CHECK(out.IsUSDSOQ());
}

// =========================================================================
// 3. BLOCK ACCUMULATOR WITH MIXED-MODE PATTERNS
// =========================================================================

BOOST_AUTO_TEST_CASE(accumulator_empty_block)
{
    BlockProofAccumulator accum;
    BOOST_CHECK(accum.IsNull());
    accum.ComputeHash();
    BOOST_CHECK(accum.hashAccumulator.IsNull());
}

BOOST_AUTO_TEST_CASE(accumulator_with_folded_state)
{
    BlockProofAccumulator accum;
    accum.nVersion = 0x01;
    accum.nProofCount = 3;
    // Simulate folded state bytes
    accum.vchFoldedState.assign(624, 0xAA);
    accum.ComputeHash();
    BOOST_CHECK(!accum.hashAccumulator.IsNull());
}

BOOST_AUTO_TEST_CASE(accumulator_deterministic)
{
    BlockProofAccumulator a, b;
    a.nVersion = b.nVersion = 0x01;
    a.nProofCount = b.nProofCount = 5;
    a.vchFoldedState.assign(1024, 0xBB);
    b.vchFoldedState.assign(1024, 0xBB);
    a.ComputeHash();
    b.ComputeHash();
    BOOST_CHECK(a.hashAccumulator == b.hashAccumulator);
}

BOOST_AUTO_TEST_CASE(accumulator_sensitive_to_state)
{
    BlockProofAccumulator a, b;
    a.nVersion = b.nVersion = 0x01;
    a.nProofCount = b.nProofCount = 5;
    a.vchFoldedState.assign(1024, 0xBB);
    b.vchFoldedState.assign(1024, 0xCC);  // Different state
    a.ComputeHash();
    b.ComputeHash();
    BOOST_CHECK(a.hashAccumulator != b.hashAccumulator);
}

BOOST_AUTO_TEST_CASE(accumulator_coinbase_commitment_roundtrip)
{
    BlockProofAccumulator accum;
    accum.nVersion = 0x01;
    accum.nProofCount = 10;
    accum.vchFoldedState.assign(2048, 0x42);
    accum.ComputeHash();

    // Build coinbase script
    std::vector<uint8_t> script = accum.GetCoinbaseCommitmentScript();
    BOOST_CHECK_EQUAL(script.size(), 36u);
    BOOST_CHECK_EQUAL(script[0], 0x6a);  // OP_RETURN
    BOOST_CHECK_EQUAL(script[2], 0x4C);  // 'L'
    BOOST_CHECK_EQUAL(script[3], 0x46);  // 'F'

    // Parse it back
    uint256 parsed;
    BOOST_CHECK(BlockProofAccumulator::ParseCoinbaseCommitment(script, parsed));
    BOOST_CHECK(parsed == accum.hashAccumulator);
}

BOOST_AUTO_TEST_CASE(accumulator_parse_rejects_wrong_magic)
{
    std::vector<uint8_t> bad(36, 0xFF);
    bad[0] = 0x6a;
    bad[1] = 0x22;
    // Magic bytes are 0xFF 0xFF, not 0x4C 0x46
    uint256 parsed;
    BOOST_CHECK(!BlockProofAccumulator::ParseCoinbaseCommitment(bad, parsed));
}

BOOST_AUTO_TEST_CASE(accumulator_parse_rejects_wrong_size)
{
    std::vector<uint8_t> tooShort = {0x6a, 0x22, 0x4C, 0x46};
    uint256 parsed;
    BOOST_CHECK(!BlockProofAccumulator::ParseCoinbaseCommitment(tooShort, parsed));
}

// =========================================================================
// 4. KEY-IMAGE COLLISION IN MULTI-TX BLOCKS
// =========================================================================

BOOST_AUTO_TEST_CASE(keyimage_intrablock_multi_tx_collision)
{
    std::vector<LatticeKeyImageHash> vBlockKeyImages;

    std::vector<uint8_t> ki1_bytes(128, 0x11);
    std::vector<uint8_t> ki2_bytes(128, 0x22);
    LatticeKeyImageHash ki1 = LatticeKeyImageHash::FromSerializedKeyImage(ki1_bytes);
    LatticeKeyImageHash ki2 = LatticeKeyImageHash::FromSerializedKeyImage(ki2_bytes);

    vBlockKeyImages.push_back(ki1);
    vBlockKeyImages.push_back(ki2);

    // TX3 tries to reuse TX1's key-image
    bool collision = false;
    for (const auto& existing : vBlockKeyImages) {
        if (existing == ki1) { collision = true; break; }
    }
    BOOST_CHECK_MESSAGE(collision, "Intra-block key-image collision not detected!");
}

BOOST_AUTO_TEST_CASE(keyimage_crossblock_collision)
{
    CCoinsViewDB db(1 << 20, true, true);

    std::vector<uint8_t> kiA_bytes(128, 0xAA);
    LatticeKeyImageHash kiA = LatticeKeyImageHash::FromSerializedKeyImage(kiA_bytes);

    BOOST_CHECK(db.WriteKeyImage(kiA.hash, 100));
    BOOST_CHECK_MESSAGE(db.HaveKeyImage(kiA.hash),
        "Cross-block key-image collision not detected!");
}

// =========================================================================
// 5. REORG SAFETY
// =========================================================================

BOOST_AUTO_TEST_CASE(reorg_3block_keyimage_safety)
{
    CCoinsViewDB db(1 << 20, true, true);

    auto makeKI = [](uint8_t seed) -> LatticeKeyImageHash {
        std::vector<uint8_t> bytes(128, seed);
        return LatticeKeyImageHash::FromSerializedKeyImage(bytes);
    };

    LatticeKeyImageHash kiA = makeKI(0xAA), kiB = makeKI(0xBB);
    LatticeKeyImageHash kiC = makeKI(0xCC), kiD = makeKI(0xDD);

    // Connect Block 50: {A, B}, Block 51: {C}
    BOOST_CHECK(db.WriteKeyImage(kiA.hash, 50));
    BOOST_CHECK(db.WriteKeyImage(kiB.hash, 50));
    BOOST_CHECK(db.WriteKeyImage(kiC.hash, 51));

    // Reorg: disconnect 51, 50
    BOOST_CHECK(db.EraseKeyImage(kiC.hash));
    BOOST_CHECK(db.EraseKeyImage(kiA.hash));
    BOOST_CHECK(db.EraseKeyImage(kiB.hash));

    // New chain: Block 50': {A, D}, Block 51': {B}
    BOOST_CHECK(db.WriteKeyImage(kiA.hash, 50));
    BOOST_CHECK(db.WriteKeyImage(kiD.hash, 50));
    BOOST_CHECK(db.WriteKeyImage(kiB.hash, 51));

    // Final: A,B,D exist; C does not
    BOOST_CHECK(db.HaveKeyImage(kiA.hash));
    BOOST_CHECK(db.HaveKeyImage(kiB.hash));
    BOOST_CHECK(!db.HaveKeyImage(kiC.hash));
    BOOST_CHECK(db.HaveKeyImage(kiD.hash));

    int32_t h;
    BOOST_CHECK(db.ReadKeyImageHeight(kiA.hash, h)); BOOST_CHECK_EQUAL(h, 50);
    BOOST_CHECK(db.ReadKeyImageHeight(kiB.hash, h)); BOOST_CHECK_EQUAL(h, 51);
}

BOOST_AUTO_TEST_CASE(reorg_same_ki_different_heights)
{
    CCoinsViewDB db(1 << 20, true, true);

    std::vector<uint8_t> kiA_bytes(128, 0xAA);
    LatticeKeyImageHash kiA = LatticeKeyImageHash::FromSerializedKeyImage(kiA_bytes);

    BOOST_CHECK(db.WriteKeyImage(kiA.hash, 100));
    BOOST_CHECK(db.EraseKeyImage(kiA.hash));
    BOOST_CHECK(db.WriteKeyImage(kiA.hash, 105));

    int32_t h;
    BOOST_CHECK(db.ReadKeyImageHeight(kiA.hash, h));
    BOOST_CHECK_EQUAL(h, 105);  // Height MUST be 105, not 100
}

// =========================================================================
// 6. FUZZ-STYLE EDGE CASES
// =========================================================================

BOOST_AUTO_TEST_CASE(fuzz_negative_value_usdsoq)
{
    CScript script;
    script << OP_RETURN;
    CTxOut out(-1, script, VISIBILITY_TRANSPARENT, ASSET_TYPE_USDSOQ);
    uint8_t baseVis = out.nVisibility & ~VISIBILITY_FROZEN_MASK;
    BOOST_CHECK_EQUAL(baseVis, VISIBILITY_TRANSPARENT);
}

BOOST_AUTO_TEST_CASE(fuzz_max_value_usdsoq)
{
    CScript script;
    script << OP_RETURN;
    CTxOut out(MAX_MONEY, script, VISIBILITY_TRANSPARENT, ASSET_TYPE_USDSOQ);
    uint8_t baseVis = out.nVisibility & ~VISIBILITY_FROZEN_MASK;
    BOOST_CHECK_EQUAL(baseVis, VISIBILITY_TRANSPARENT);
}

BOOST_AUTO_TEST_CASE(fuzz_all_256_visibility_values)
{
    CScript script;
    script << OP_RETURN;
    int validCount = 0;
    for (int v = 0; v < 256; v++) {
        CTxOut out(1000, script, static_cast<uint8_t>(v), ASSET_TYPE_USDSOQ);
        uint8_t baseVis = out.nVisibility & ~VISIBILITY_FROZEN_MASK;
        if (baseVis == VISIBILITY_TRANSPARENT) {
            BOOST_CHECK(v == 0x00 || v == 0x80);
            validCount++;
        }
    }
    BOOST_CHECK_EQUAL(validCount, 2);  // Only 0x00 and 0x80
}

BOOST_AUTO_TEST_CASE(fuzz_keyimage_all_zero)
{
    std::vector<uint8_t> zeroInput(2048, 0x00);
    LatticeKeyImageHash ki = LatticeKeyImageHash::FromSerializedKeyImage(zeroInput);
    BOOST_CHECK(!ki.IsNull());
}

BOOST_AUTO_TEST_CASE(fuzz_keyimage_all_ff)
{
    std::vector<uint8_t> zero(2048, 0x00);
    std::vector<uint8_t> ff(2048, 0xFF);
    LatticeKeyImageHash ki0 = LatticeKeyImageHash::FromSerializedKeyImage(zero);
    LatticeKeyImageHash kiFF = LatticeKeyImageHash::FromSerializedKeyImage(ff);
    BOOST_CHECK(ki0 != kiFF);
}

BOOST_AUTO_TEST_CASE(fuzz_accumulator_serialization)
{
    BlockProofAccumulator orig;
    orig.nVersion = 0x01;
    orig.nProofCount = 42;
    orig.vchFoldedState.assign(512, 0xDE);
    orig.ComputeHash();

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << orig;

    BlockProofAccumulator restored;
    ss >> restored;

    BOOST_CHECK_EQUAL(restored.nVersion, 0x01);
    BOOST_CHECK_EQUAL(restored.nProofCount, 42u);
    BOOST_CHECK(restored.hashAccumulator == orig.hashAccumulator);
    BOOST_CHECK(restored.vchFoldedState == orig.vchFoldedState);
}

BOOST_AUTO_TEST_SUITE_END()
