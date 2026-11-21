// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// miner_lane_tests.cpp — the two lanes of block assembly, on a mined regtest
// chain with signed ML-DSA-44 spends sent through the mempool.
//
//   The standard lane. A template holds at most -blocklaneweight of
//   transactions that pay less than -blockbulktxfee, counted as four times
//   their virtual size. The lane is strict: a transaction or package enters
//   only while the lane has room for the whole of it.
//
//   The bulk rate. A transaction or package that pays -blockbulktxfee for its
//   virtual size is outside the lane and is bound by the block limits alone.
//
// Neither is a rule on blocks. The cases read the template CreateNewBlock
// returns, which TestBlockValidity has checked.

#include "amount.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "miner.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "test/dilithium_chain_setup.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <memory>
#include <set>
#include <string>
#include <vector>

namespace {

//! The value of each output of the fan the cases spend from.
const CAmount FAN_VALUE = 100 * COIN;
//! The value of each output a case adds to make a transaction heavier.
const CAmount EXTRA_VALUE = COIN;

struct LaneSetup : public DilithiumChainSetup {
    CMutableTransaction fan;
    const CFeeRate floorRate;
    const CFeeRate bulkRate;

    LaneSetup() : floorRate(DEFAULT_BLOCK_MIN_TX_FEE), bulkRate(DEFAULT_BLOCK_BULK_TX_FEE)
    {
        // Eight more blocks, so that the first eight coinbases are mature.
        for (int i = 0; i < 8; ++i)
            Mine({});
        // The space for priority is off except in the case that is about it.
        ForceSetArg("-blockprioritysize", "0");

        // Coinbase 0 paid into 70 outputs, confirmed.
        const CTransaction& cb = coinbaseTxns[0];
        fan.nVersion = 2;
        fan.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        for (int i = 0; i < 70; ++i)
            fan.vout.push_back(CTxOut(FAN_VALUE, coinbaseSpk));
        fan.vout.push_back(CTxOut(cb.vout[0].nValue - 70 * FAN_VALUE - COIN, coinbaseSpk));
        SignInput(fan, 0, coinbaseSpk, cb.vout[0].nValue);
        Mine({fan});
    }

    ~LaneSetup()
    {
        mempool.clear();
        ForceSetArg("-blockprioritysize", strprintf("%u", DEFAULT_BLOCK_PRIORITY_SIZE));
        ForceSetArg("-blocklaneweight", strprintf("%u", DEFAULT_BLOCK_LANE_WEIGHT));
        ForceSetArg("-blockbulktxfee", FormatMoney(DEFAULT_BLOCK_BULK_TX_FEE));
        ForceSetArg("-blockmintxfee", FormatMoney(DEFAULT_BLOCK_MIN_TX_FEE));
    }

    //! A block on the tip with the given transactions, which must be the new tip.
    void Mine(const std::vector<CMutableTransaction>& txns)
    {
        mempool.clear();
        const CBlock block = CreateAndProcessBlock(txns, coinbaseSpk);
        LOCK(cs_main);
        BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == block.GetHash());
    }

    static uint64_t VSize(const CMutableTransaction& tx) { return GetVirtualTransactionSize(CTransaction(tx)); }
    //! The weight the lane counts for a transaction: four times its virtual size.
    static uint64_t LaneWeight(const CMutableTransaction& tx) { return WITNESS_SCALE_FACTOR * VSize(tx); }

    //! A signed spend of one output to coinbaseSpk, with `extra` more outputs,
    //! paying `fee`.
    CMutableTransaction SpendWithFee(const COutPoint& out, CAmount value, CAmount fee, unsigned int extra = 0)
    {
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(out, CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout.push_back(CTxOut(value - extra * EXTRA_VALUE - fee, coinbaseSpk));
        for (unsigned int i = 0; i < extra; ++i)
            tx.vout.push_back(CTxOut(EXTRA_VALUE, coinbaseSpk));
        SignInput(tx, 0, coinbaseSpk, value);
        return tx;
    }

    //! The same, paying `rate` for its virtual size and `adjust` on top.
    CMutableTransaction Spend(const COutPoint& out, CAmount value, const CFeeRate& rate, unsigned int extra = 0, CAmount adjust = 0)
    {
        const uint64_t nSize = VSize(SpendWithFee(out, value, 0, extra));
        return SpendWithFee(out, value, rate.GetFee(nSize) + adjust, extra);
    }

    //! A spend of output n of the fan.
    CMutableTransaction SpendFan(unsigned int n, const CFeeRate& rate, unsigned int extra = 0, CAmount adjust = 0)
    {
        return Spend(COutPoint(fan.GetHash(), n), FAN_VALUE, rate, extra, adjust);
    }

    //! Sends the transaction to the mempool, which must accept it and hold it
    //! at the virtual size the cases compute.
    void Send(const CMutableTransaction& tx)
    {
        LOCK(cs_main);
        CValidationState state;
        bool fMissingInputs = false;
        BOOST_REQUIRE_MESSAGE(AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), false, &fMissingInputs, nullptr, true, 0),
            "the mempool refused a transaction of the case: " << state.GetRejectReason());
        LOCK(mempool.cs);
        CTxMemPool::txiter it = mempool.mapTx.find(tx.GetHash());
        BOOST_REQUIRE(it != mempool.mapTx.end());
        BOOST_REQUIRE_EQUAL(it->GetTxSize(), VSize(tx));
    }

    struct Template {
        std::set<uint256> ids;
        //! The weight of the transactions that pay less than `bulk`, each for
        //! itself, as the lane counts it.
        uint64_t nLaneWeight;
        bool Holds(const CMutableTransaction& tx) const { return ids.count(tx.GetHash()) != 0; }
        size_t Count() const { return ids.size(); }
    };

    //! The template of the next block from the mempool as it stands.
    Template Build(const CFeeRate& bulk)
    {
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(Params()).CreateNewBlock(coinbaseSpk, true);
        BOOST_REQUIRE(tmpl != nullptr);
        Template t;
        t.nLaneWeight = 0;
        for (size_t i = 1; i < tmpl->block.vtx.size(); ++i) {
            const CTransaction& tx = *tmpl->block.vtx[i];
            t.ids.insert(tx.GetHash());
            const uint64_t nSize = GetVirtualTransactionSize(tx);
            if (tmpl->vTxFees[i] < bulk.GetFee(nSize))
                t.nLaneWeight += WITNESS_SCALE_FACTOR * nSize;
        }
        return t;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(miner_lane_tests, LaneSetup)

// Sixty transactions of one input at one low rate are more than the lane
// holds. The template takes the lane's weight of them and no more, at the
// relay minimum under a lowered -blockmintxfee and at five times the default
// floor. With the lane as wide as the block, or the bulk rate at the floor,
// the template takes all sixty.
BOOST_AUTO_TEST_CASE(a_flood_below_the_bulk_rate_fills_the_lane_and_no_more)
{
    struct Config {
        const char* blockMinTxFee;
        CFeeRate rate;
    };
    const Config configs[] = {
        {"0.00001", ::minRelayTxFeeRate},
        {"0.01", CFeeRate(5 * DEFAULT_BLOCK_MIN_TX_FEE)},
    };
    for (const Config& config : configs) {
        mempool.clear();
        ForceSetArg("-blockmintxfee", config.blockMinTxFee);
        ForceSetArg("-blocklaneweight", strprintf("%u", DEFAULT_BLOCK_LANE_WEIGHT));
        ForceSetArg("-blockbulktxfee", FormatMoney(DEFAULT_BLOCK_BULK_TX_FEE));

        uint64_t nEach = 0;
        for (unsigned int i = 0; i < 60; ++i) {
            const CMutableTransaction tx = SpendFan(i, config.rate);
            nEach = LaneWeight(tx);
            Send(tx);
        }
        const uint64_t nFit = DEFAULT_BLOCK_LANE_WEIGHT / nEach;
        BOOST_REQUIRE(nFit > 0 && nFit < 60);

        const Template bounded = Build(bulkRate);
        BOOST_CHECK_EQUAL(bounded.Count(), nFit);
        BOOST_CHECK(bounded.nLaneWeight <= DEFAULT_BLOCK_LANE_WEIGHT);

        ForceSetArg("-blocklaneweight", strprintf("%u", DEFAULT_BLOCK_MAX_WEIGHT));
        BOOST_CHECK_EQUAL(Build(bulkRate).Count(), 60u);

        ForceSetArg("-blocklaneweight", strprintf("%u", DEFAULT_BLOCK_LANE_WEIGHT));
        ForceSetArg("-blockbulktxfee", config.blockMinTxFee);
        BOOST_CHECK_EQUAL(Build(bulkRate).Count(), 60u);
    }
}

// Beside a flood, six transactions that pay the bulk rate to the atom are all
// in the template, and the lane still holds its weight of the rest. One atom
// under the bulk rate is in the lane.
BOOST_AUTO_TEST_CASE(the_bulk_rate_is_outside_the_lane)
{
    const CFeeRate low(2 * DEFAULT_BLOCK_MIN_TX_FEE);
    std::vector<CMutableTransaction> bulk;
    for (unsigned int i = 0; i < 6; ++i) {
        bulk.push_back(SpendFan(i, bulkRate));
        Send(bulk.back());
    }
    const CMutableTransaction under = SpendFan(6, bulkRate, 0, -1);
    Send(under);
    uint64_t nEach = 0;
    for (unsigned int i = 7; i < 62; ++i) {
        const CMutableTransaction tx = SpendFan(i, low);
        nEach = LaneWeight(tx);
        Send(tx);
    }
    const uint64_t nFit = DEFAULT_BLOCK_LANE_WEIGHT / nEach;
    BOOST_REQUIRE(nFit < 56);

    const Template t = Build(bulkRate);
    for (const CMutableTransaction& tx : bulk)
        BOOST_CHECK(t.Holds(tx));
    BOOST_CHECK(t.Holds(under));
    BOOST_CHECK_EQUAL(t.Count(), 6 + nFit);
    BOOST_CHECK(t.nLaneWeight <= DEFAULT_BLOCK_LANE_WEIGHT);
    BOOST_CHECK_EQUAL(t.nLaneWeight, nFit * nEach);
}

// The lane is strict. Four transactions in the order of their rates: A, a
// heavier one, C and D. The lane has room for A, C and half of D. The heavier
// one does not fit the room A leaves and is passed over, C below it in rate
// is taken, and D is left out. A transaction heavier than the whole lane is
// left out at any rate below the bulk rate and taken at the bulk rate.
BOOST_AUTO_TEST_CASE(the_lane_is_strict)
{
    const CAmount f = DEFAULT_BLOCK_MIN_TX_FEE;
    const CMutableTransaction a = SpendFan(0, CFeeRate(5 * f));
    const CMutableTransaction heavy = SpendFan(1, CFeeRate(4 * f), 30);
    const CMutableTransaction c = SpendFan(2, CFeeRate(3 * f));
    const CMutableTransaction d = SpendFan(3, CFeeRate(2 * f));
    const uint64_t nLane = LaneWeight(a) + LaneWeight(c) + LaneWeight(d) / 2;
    BOOST_REQUIRE(LaneWeight(heavy) > nLane - LaneWeight(a));
    BOOST_REQUIRE(LaneWeight(heavy) <= nLane);
    ForceSetArg("-blocklaneweight", strprintf("%u", nLane));
    Send(a);
    Send(heavy);
    Send(c);
    Send(d);

    Template t = Build(bulkRate);
    BOOST_CHECK(t.Holds(a));
    BOOST_CHECK(!t.Holds(heavy));
    BOOST_CHECK(t.Holds(c));
    BOOST_CHECK(!t.Holds(d));
    BOOST_CHECK_EQUAL(t.Count(), 2u);

    // Heavier than the lane: one atom under the bulk rate, then at it.
    const CMutableTransaction overUnder = SpendFan(4, bulkRate, 40, -1);
    const CMutableTransaction overAt = SpendFan(5, bulkRate, 40);
    BOOST_REQUIRE(LaneWeight(overUnder) > nLane);
    Send(overUnder);
    Send(overAt);
    t = Build(bulkRate);
    BOOST_CHECK(!t.Holds(overUnder));
    BOOST_CHECK(t.Holds(overAt));
    BOOST_CHECK(t.Holds(a));
    BOOST_CHECK(t.Holds(c));
    BOOST_CHECK_EQUAL(t.Count(), 3u);
}

// A package is counted whole. With a lane too small for any transaction of
// the case, a parent at a low rate and its child are both left out while the
// child pays the bulk rate for itself alone, and both are taken when the
// child pays the bulk rate for the two.
BOOST_AUTO_TEST_CASE(a_package_pays_the_bulk_rate_for_the_whole_of_it)
{
    const CFeeRate low(2 * DEFAULT_BLOCK_MIN_TX_FEE);
    const CMutableTransaction parent = SpendFan(0, low);
    const CAmount parentFee = FAN_VALUE - parent.vout[0].nValue;
    const COutPoint parentOut(parent.GetHash(), 0);
    ForceSetArg("-blocklaneweight", strprintf("%u", LaneWeight(parent) / 2));
    Send(parent);

    const CMutableTransaction alone = Spend(parentOut, parent.vout[0].nValue, bulkRate);
    Send(alone);
    Template t = Build(bulkRate);
    BOOST_CHECK_EQUAL(t.Count(), 0u);

    mempool.clear();
    Send(parent);
    const uint64_t nBoth = VSize(parent) + VSize(alone);
    const CMutableTransaction child = SpendWithFee(parentOut, parent.vout[0].nValue, bulkRate.GetFee(nBoth) - parentFee);
    BOOST_REQUIRE_EQUAL(VSize(child), VSize(alone));
    Send(child);
    t = Build(bulkRate);
    BOOST_CHECK(t.Holds(parent));
    BOOST_CHECK(t.Holds(child));
    BOOST_CHECK_EQUAL(t.Count(), 2u);
}

// A child of two parents, one that pays the bulk rate for itself and the
// child, one small at a low rate. The lane has room for the small parent and
// not for it with the child. The first parent is taken outside the lane, the
// child with the small parent is passed over, and the small parent is taken
// alone. The child stays out: the fee of the first parent is in the block and
// is not counted for the child again.
BOOST_AUTO_TEST_CASE(a_fee_already_in_the_block_is_not_counted_again)
{
    const CAmount f = DEFAULT_BLOCK_MIN_TX_FEE;
    const CMutableTransaction small = SpendFan(1, CFeeRate(2 * f));

    // The child's size does not depend on its values, so a first build measures it.
    CMutableTransaction child;
    child.nVersion = 2;
    child.vin.push_back(CTxIn(COutPoint(uint256(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    child.vin.push_back(CTxIn(COutPoint(small.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    child.vout.push_back(CTxOut(COIN, coinbaseSpk));
    SignInput(child, 0, coinbaseSpk, COIN);
    SignInput(child, 1, coinbaseSpk, small.vout[0].nValue);
    const uint64_t nChild = VSize(child);

    const uint64_t nPaying = VSize(SpendFan(0, bulkRate));
    const CMutableTransaction paying = SpendWithFee(COutPoint(fan.GetHash(), 0), FAN_VALUE, bulkRate.GetFee(nPaying + nChild));
    const CAmount in = paying.vout[0].nValue + small.vout[0].nValue;
    child.vin[0].prevout = COutPoint(paying.GetHash(), 0);
    child.vout[0].nValue = in - CFeeRate(5 * f).GetFee(nChild);
    SignInput(child, 0, coinbaseSpk, paying.vout[0].nValue);
    SignInput(child, 1, coinbaseSpk, small.vout[0].nValue);
    BOOST_REQUIRE_EQUAL(VSize(child), nChild);

    ForceSetArg("-blocklaneweight", strprintf("%u", LaneWeight(small) + LaneWeight(small) / 2));
    Send(paying);
    Send(small);
    Send(child);

    const Template t = Build(bulkRate);
    BOOST_CHECK(t.Holds(paying));
    BOOST_CHECK(t.Holds(small));
    BOOST_CHECK(!t.Holds(child));
    BOOST_CHECK_EQUAL(t.Count(), 2u);
}

// The space for priority is inside the lane. Two spends of mature coinbases
// pay the relay minimum, which is below the block floor, so only the space
// for priority admits them. The one heavier than the lane is left out. The
// other is taken and takes room in the lane: of the transactions at twice the
// floor, the lane then holds one where it held two.
BOOST_AUTO_TEST_CASE(the_space_for_priority_is_inside_the_lane)
{
    ForceSetArg("-blockprioritysize", strprintf("%u", DEFAULT_BLOCK_PRIORITY_SIZE));
    const CFeeRate low(2 * DEFAULT_BLOCK_MIN_TX_FEE);
    const CAmount coinbaseValue = coinbaseTxns[1].vout[0].nValue;
    const CMutableTransaction aged = Spend(COutPoint(coinbaseTxns[1].GetHash(), 0), coinbaseValue, ::minRelayTxFeeRate);
    const CMutableTransaction agedHeavy = Spend(COutPoint(coinbaseTxns[2].GetHash(), 0), coinbaseValue, ::minRelayTxFeeRate, 70);
    const std::vector<CMutableTransaction> plain = {SpendFan(0, low), SpendFan(1, low), SpendFan(2, low)};
    const uint64_t nLane = 2 * LaneWeight(plain[0]) + LaneWeight(plain[0]) / 2;
    BOOST_REQUIRE_EQUAL(LaneWeight(aged), LaneWeight(plain[0]));
    BOOST_REQUIRE(LaneWeight(agedHeavy) > nLane);
    ForceSetArg("-blocklaneweight", strprintf("%u", nLane));

    for (const CMutableTransaction& tx : plain)
        Send(tx);
    BOOST_CHECK_EQUAL(Build(bulkRate).Count(), 2u);

    Send(aged);
    Send(agedHeavy);
    const Template t = Build(bulkRate);
    BOOST_CHECK(t.Holds(aged));
    BOOST_CHECK(!t.Holds(agedHeavy));
    BOOST_CHECK_EQUAL(t.Count(), 2u);
    BOOST_CHECK(t.nLaneWeight <= nLane);
}

// The lane's rate for the fee estimate. Zero while the mempool does not fill
// the lane. Once it does, the rate is above the flood's and below the bulk
// rate, and a transaction that pays it is in the next template.
BOOST_AUTO_TEST_CASE(the_estimate_is_the_rate_that_enters_the_lane)
{
    const CFeeRate flood(2 * DEFAULT_BLOCK_MIN_TX_FEE);
    BOOST_CHECK(EstimateLaneFeeRate(mempool) == CFeeRate(0));

    for (unsigned int i = 0; i < 40; ++i)
        Send(SpendFan(i, flood));
    BOOST_CHECK(EstimateLaneFeeRate(mempool) == CFeeRate(0));

    for (unsigned int i = 40; i < 60; ++i)
        Send(SpendFan(i, flood));
    const CFeeRate lane = EstimateLaneFeeRate(mempool);
    BOOST_CHECK(lane > flood);
    BOOST_CHECK(lane < bulkRate);

    const CMutableTransaction atFlood = SpendFan(60, flood);
    const CMutableTransaction atLane = SpendFan(61, lane);
    Send(atFlood);
    Send(atLane);
    const Template t = Build(bulkRate);
    BOOST_CHECK(t.Holds(atLane));
    BOOST_CHECK(t.nLaneWeight <= DEFAULT_BLOCK_LANE_WEIGHT);

    // With -incrementalrelayfee at zero the rate is still above the flood's.
    {
        const CFeeRate previous = ::incrementalRelayFee;
        ::incrementalRelayFee = CFeeRate(0);
        BOOST_CHECK(EstimateLaneFeeRate(mempool) > flood);
        ::incrementalRelayFee = previous;
    }

    // Children at a low rate fill the lane though each parent pays the bulk
    // rate for itself and its child: the rate is above the children's.
    mempool.clear();
    for (unsigned int i = 0; i < 55; ++i) {
        const uint64_t nSize = VSize(SpendFan(i, flood));
        const CMutableTransaction parent = SpendWithFee(COutPoint(fan.GetHash(), i), FAN_VALUE, bulkRate.GetFee(2 * nSize));
        Send(parent);
        Send(Spend(COutPoint(parent.GetHash(), 0), parent.vout[0].nValue, flood));
    }
    BOOST_CHECK(EstimateLaneFeeRate(mempool) > flood);
    BOOST_CHECK(Build(bulkRate).nLaneWeight <= DEFAULT_BLOCK_LANE_WEIGHT);

    // A lane that is already full at the bulk rate's edge answers the bulk rate.
    mempool.clear();
    for (unsigned int i = 0; i < 60; ++i)
        Send(SpendFan(i, bulkRate, 0, -1));
    BOOST_CHECK(EstimateLaneFeeRate(mempool) == bulkRate);
}

BOOST_AUTO_TEST_SUITE_END()
