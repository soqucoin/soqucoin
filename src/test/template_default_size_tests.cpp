// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * The default block template admits every standard transaction (bead zq1xc).
 * DEFAULT_BLOCK_MAX_SIZE is the byte cap the assembler applies when neither
 * -blockmaxsize nor -blockmaxweight is given. A standard transaction is bound
 * by weight (MAX_STANDARD_TX_WEIGHT), and a witness-heavy one carries nearly
 * as many bytes as weight units, so a byte cap below the weight bound keeps
 * the largest standard transactions out of a default node's template while
 * they relay and wait in its mempool. This suite builds that transaction with
 * real ML-DSA-44 inputs, has the mempool accept it under the real policy, and
 * asserts the default template carries it. The transaction is heavier than
 * the standard lane (DEFAULT_BLOCK_LANE_WEIGHT), so it pays the bulk rate
 * (DEFAULT_BLOCK_BULK_TX_FEE), the rate at which a default template takes it.
 */

#include "amount.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "miner.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "streams.h"
#include "txmempool.h"
#include "util.h"
#include "validation.h"
#include "version.h"

#include "test/dilithium_chain_setup.h"

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>

BOOST_FIXTURE_TEST_SUITE(template_default_size_tests, DilithiumChainSetup)

namespace {
//! The most ML-DSA-44 keyhash inputs a standard transaction holds; the test
//! asserts that one more would take it past MAX_STANDARD_TX_WEIGHT.
const int kInputs = 204;
const CAmount kInputValue = 20 * COIN;
} // namespace

BOOST_AUTO_TEST_CASE(the_largest_standard_witness_transaction_enters_the_default_template)
{
    BOOST_REQUIRE(!IsArgSet("-blockmaxsize"));
    BOOST_REQUIRE(!IsArgSet("-blockmaxweight"));
    BOOST_REQUIRE_EQUAL(mempool.size(), 0u);

    CMutableTransaction tx;
    tx.nVersion = 2;
    for (int i = 0; i < kInputs; ++i) {
        // Tags from 1 give each seeded coin its own txid, none of them the null hash.
        tx.vin.push_back(CTxIn(SeedCoin(coinbaseSpk, kInputValue, (uint8_t)(i + 1))));
    }
    tx.vout.push_back(CTxOut(kInputs * kInputValue, coinbaseSpk));
    for (int i = 0; i < kInputs; ++i) {
        SignInput(tx, i, coinbaseSpk, kInputValue);
    }
    // The fee is the bulk rate for the virtual size, which the value of the
    // output does not change; the inputs are signed again over the new output.
    const CAmount kFee = CFeeRate(DEFAULT_BLOCK_BULK_TX_FEE).GetFee(GetVirtualTransactionSize(CTransaction(tx)));
    tx.vout[0].nValue -= kFee;
    for (int i = 0; i < kInputs; ++i) {
        SignInput(tx, i, coinbaseSpk, kInputValue);
    }
    const CTransaction ctx(tx);
    BOOST_CHECK_GT(GetTransactionWeight(ctx), (int64_t)DEFAULT_BLOCK_LANE_WEIGHT);

    // The shape: standard by weight, one input short of the bound, and more
    // bytes than the byte cap a default template applied before this change.
    const int64_t weight = GetTransactionWeight(ctx);
    const int64_t inputWeight = (WITNESS_SCALE_FACTOR - 1) * ::GetSerializeSize(ctx.vin[0], SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS)
                                + ::GetSerializeSize(ctx.vin[0], SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS)
                                + ::GetSerializeSize(ctx.vin[0].scriptWitness.stack, SER_NETWORK, PROTOCOL_VERSION);
    BOOST_TEST_MESSAGE("inputs " << kInputs << ", weight " << weight << ", one more input " << (weight + inputWeight) << ", size " << ::GetSerializeSize(ctx, SER_NETWORK, PROTOCOL_VERSION));
    BOOST_CHECK_LE(weight, (int64_t)MAX_STANDARD_TX_WEIGHT);
    BOOST_CHECK_GT(weight + inputWeight, (int64_t)MAX_STANDARD_TX_WEIGHT);
    const unsigned int size = ::GetSerializeSize(ctx, SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK_GT(size, 750000u);
    BOOST_CHECK_LT(size, DEFAULT_BLOCK_MAX_SIZE);
    std::string reason;
    BOOST_CHECK_MESSAGE(IsStandardTx(ctx, reason), "not standard: " + reason);

    // Accepted under the real policy.
    CValidationState state;
    bool missingInputs = false;
    const bool accepted = AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), false, &missingInputs, nullptr, false, 0);
    BOOST_REQUIRE_MESSAGE(accepted, "refused by the mempool: " + state.GetRejectReason() + " " + state.GetDebugMessage());
    BOOST_REQUIRE_EQUAL(mempool.size(), 1u);

    // In the default template, under the default weight cap.
    std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(Params()).CreateNewBlock(coinbaseSpk, true);
    BOOST_REQUIRE(tmpl != nullptr);
    BOOST_REQUIRE_EQUAL(tmpl->block.vtx.size(), 2u);
    BOOST_CHECK(tmpl->block.vtx[1]->GetHash() == ctx.GetHash());
    BOOST_CHECK_LE(GetBlockWeight(tmpl->block), (int64_t)DEFAULT_BLOCK_MAX_WEIGHT);
    mempool.clear();
}

BOOST_AUTO_TEST_SUITE_END()
