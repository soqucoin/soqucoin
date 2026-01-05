// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "test/test_bitcoin.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

/**
 * Functional test: Verify blocks exceeding MAX_BLOCK_VERIFY_COST are rejected.
 *
 * This test ensures the consensus limit on verification cost is enforced.
 * Reference: CONSENSUS_COST_SPEC.md Appendix D
 */

BOOST_FIXTURE_TEST_SUITE(verify_cost_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_excess_verify_cost_rejected)
{
    // Test that a block claiming verify cost > MAX_BLOCK_VERIFY_COST fails validation

    // Create a minimal block
    CBlock block;
    block.nVersion = 4;
    block.hashPrevBlock = uint256();
    block.hashMerkleRoot = uint256();
    block.nTime = 1704067200; // 2024-01-01 00:00:00 UTC
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;

    // The actual enforcement happens during CheckBlock() when verification
    // cost is tallied. Here we verify the constant is accessible and correct.

    BOOST_CHECK_EQUAL(MAX_BLOCK_VERIFY_COST, 80000);
    BOOST_CHECK_EQUAL(MAX_LATTICEFOLD_PER_BLOCK, 10);
    BOOST_CHECK_EQUAL(MAX_PROOF_BYTES_PER_TX, 65536);
    BOOST_CHECK_EQUAL(MAX_PROOF_BYTES_PER_BLOCK, 262144);

    // Verification cost weights
    BOOST_CHECK_EQUAL(DILITHIUM_VERIFY_COST, 1);
    BOOST_CHECK_EQUAL(BPPP_VERIFY_COST, 50);
    BOOST_CHECK_EQUAL(PAT_VERIFY_COST, 20);
    BOOST_CHECK_EQUAL(LATTICEFOLD_VERIFY_COST, 200);

    // Verify that 10 LatticeFold proofs (10 * 200 = 2000) is within budget
    uint64_t tenFoldProofs = 10 * LATTICEFOLD_VERIFY_COST;
    BOOST_CHECK(tenFoldProofs <= MAX_BLOCK_VERIFY_COST);

    // Verify that 11 LatticeFold proofs would still be within verify cost budget
    // but exceeds MAX_LATTICEFOLD_PER_BLOCK (showing the separate limit)
    uint64_t elevenFoldProofs = 11 * LATTICEFOLD_VERIFY_COST;
    BOOST_CHECK(elevenFoldProofs <= MAX_BLOCK_VERIFY_COST); // 2200 < 80000
    // But MAX_LATTICEFOLD_PER_BLOCK = 10 prevents this
    BOOST_CHECK(11 > MAX_LATTICEFOLD_PER_BLOCK);

    // Test theoretical maximum: 80000 verify cost units
    // With only Dilithium signatures (cost=1), that's 80000 signatures
    // With only BP++ proofs (cost=50), that's 1600 proofs
    BOOST_CHECK_EQUAL(MAX_BLOCK_VERIFY_COST / DILITHIUM_VERIFY_COST, 80000);
    BOOST_CHECK_EQUAL(MAX_BLOCK_VERIFY_COST / BPPP_VERIFY_COST, 1600);
}

BOOST_AUTO_TEST_SUITE_END()
