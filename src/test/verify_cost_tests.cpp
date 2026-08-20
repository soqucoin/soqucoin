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
 * ⛔ THE POST-QUANTUM VERIFICATION-COST SYSTEM IS NOT IMPLEMENTED.
 *
 * This file used to be called a functional test for rejecting blocks that exceed
 * MAX_BLOCK_VERIFY_COST, and its only case was named
 * test_excess_verify_cost_rejected. It never drove a block, and there is nothing
 * for it to drive: every constant below is DEFINED AND NEVER READ.
 * MAX_BLOCK_VERIFY_COST, MAX_LATTICEFOLD_PER_BLOCK, MAX_PROOF_BYTES_PER_TX,
 * MAX_PROOF_BYTES_PER_BLOCK and all four *_VERIFY_COST weights have zero
 * consumers outside consensus.h, this file, and one doc comment in
 * crypto/pat/logarithmic.h. Verified by grep across the tree, 2026-08-20.
 *
 * Meanwhile doc/specifications/CONSENSUS_COST_SPEC.md states the rule in the
 * present tense as an enforced consensus limit: "The total verification cost in
 * a block cannot exceed MAX_BLOCK_VERIFY_COST (80,000 units)." It cannot, and
 * does not.
 *
 * This file is therefore renamed to what it actually does: pin the constants so
 * they cannot drift before someone implements the accounting. That is worth
 * having. Claiming to test enforcement was not: a green test named
 * test_excess_verify_cost_rejected is exactly how a rule that does not exist
 * comes to look like a rule that works. Bead v7xm F6.
 *
 * ⚠️ AND THE NUMBERS DO NOT MEAN WHAT THEY APPEAR TO. Dividing each cost by its
 * own benchmark from the spec's table gives the price of one unit in
 * milliseconds: Dilithium 0.175, PAT 0.25, Lattice-BP++ 0.0011, LatticeFold+
 * 0.0038. That is a 160x spread, so the units are not a measure of verification
 * time. At the Dilithium price, a full 80,000-unit budget would authorise about
 * 14 SECONDS of verification, while block weight already caps a block of
 * Dilithium-path inputs at roughly 179 ms (see sigop_budget_tests.cpp).
 * Implementing the spec verbatim would therefore add a limit that never binds:
 * a DoS control that looks real and is not. The table needs re-deriving from
 * measured verification times before the accounting is worth building.
 *
 * Reference: CONSENSUS_COST_SPEC.md section 4.
 */

BOOST_FIXTURE_TEST_SUITE(verify_cost_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(verify_cost_constants_are_defined_but_unenforced)
{
    // Pins the values. Does NOT test enforcement, because there is none.

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
