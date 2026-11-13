// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * The activation heights a node reports (chainparams.h,
 * REPORTED_ACTIVATION_HEIGHTS and ReportedActivationHeight): the
 * "activation_heights" object of getblockchaininfo and one startup line per
 * deployment. The functional test activation-heights.py drives a regtest node
 * through the -activationheight argument; this suite covers what it cannot
 * start, the other three networks, and the property the number is printed
 * for: a reader that compares a block height with the reported number gets
 * the answer of Consensus::DeploymentActiveAtHeight, at every height and on
 * every network. That holds because every reported deployment is height-gated
 * (never BIP9Deployment::NO_HEIGHT_ACTIVATION, -1, which the comparison would
 * read as active) and a deployment with no height stores
 * BIP9Deployment::NOT_SCHEDULED, 2147483647.
 */

#include "chainparams.h"
#include "chainparamsbase.h"
#include "consensus/params.h"
#include "rpc/server.h"
#include "test/test_bitcoin.h"
#include "versionbits.h"

#include <boost/test/unit_test.hpp>
#include <limits>
#include <string>
#include <univalue.h>
#include <vector>

namespace
{
// The rows in the order the node lists them.
const char* const kNames[] = {"p2wsh_dilithium", "dilithium_keyhash", "v6_controlflow"};
const int kNotScheduled = 2147483647;

// What each network holds for the three today: mainnet no height
// (chainparams.cpp, CMainParams), the others 0.
int ExpectedToday(const std::string& net)
{
    return net == CBaseChainParams::MAIN ? kNotScheduled : 0;
}

// Built at the call: the names are strings of another translation unit.
std::vector<std::string> Networks()
{
    return {CBaseChainParams::MAIN, CBaseChainParams::TESTNET, CBaseChainParams::STAGENET, CBaseChainParams::REGTEST};
}

// Sets a regtest deployment's height for one scope and puts regtest's own
// height, 0, back.
struct RegtestHeight {
    const Consensus::DeploymentPos pos;
    RegtestHeight(Consensus::DeploymentPos posIn, int nHeight) : pos(posIn) { UpdateRegtestActivationHeight(pos, nHeight); }
    ~RegtestHeight() { UpdateRegtestActivationHeight(pos, 0); }
};

// Parameters of two tiers that hold different heights for one deployment, a
// state no network is in (genesis_chainparams_tests,
// f8_deployment_posture_is_uniform_across_consensus_tiers). The root tier
// validates the heights below nUpperFrom and the upper tier the others.
struct TwoTierParams : public CChainParams {
    Consensus::Params upper;
    TwoTierParams(Consensus::DeploymentPos pos, int nRootHeight, int nUpperHeight, uint32_t nUpperFrom)
    {
        consensus = Consensus::Params();
        consensus.nHeightEffective = 0;
        consensus.vDeployments[pos].nActivationHeight = nRootHeight;
        upper = consensus;
        upper.nHeightEffective = nUpperFrom;
        upper.vDeployments[pos].nActivationHeight = nUpperHeight;
        consensus.pRight = &upper;
        pConsensusRoot = &consensus;
    }
};
} // namespace

BOOST_AUTO_TEST_SUITE(activation_heights_tests)

BOOST_FIXTURE_TEST_CASE(reported_deployments_and_their_names, BasicTestingSetup)
{
    BOOST_CHECK_EQUAL(Consensus::BIP9Deployment::NOT_SCHEDULED, kNotScheduled);
    BOOST_CHECK_EQUAL(std::numeric_limits<int>::max(), kNotScheduled);
    BOOST_REQUIRE_EQUAL(sizeof(REPORTED_ACTIVATION_HEIGHTS) / sizeof(REPORTED_ACTIVATION_HEIGHTS[0]),
                        sizeof(kNames) / sizeof(kNames[0]));
    size_t i = 0;
    for (const Consensus::DeploymentPos pos : REPORTED_ACTIVATION_HEIGHTS) {
        BOOST_CHECK_EQUAL(std::string(VersionBitsDeploymentInfo[pos].name), kNames[i++]);
    }
}

BOOST_FIXTURE_TEST_CASE(reported_height_per_network_is_the_predicate, BasicTestingSetup)
{
    // Heights on both sides of every tier boundary of every network, and the
    // largest height an int holds.
    const int kProbes[] = {0, 1, 2, 9, 10, 11, 19, 20, 21, 99, 100, 101, 66999, 67000, 1000000, kNotScheduled - 1, kNotScheduled};

    for (const std::string& net : Networks()) {
        const CChainParams& params = Params(net);
        for (const Consensus::DeploymentPos pos : REPORTED_ACTIVATION_HEIGHTS) {
            const int nReported = ReportedActivationHeight(params, pos);
            BOOST_CHECK_MESSAGE(nReported == ExpectedToday(net),
                                net << ": " << VersionBitsDeploymentInfo[pos].name << " reports " << nReported);
            BOOST_CHECK(nReported != Consensus::BIP9Deployment::NO_HEIGHT_ACTIVATION);
            for (const int nHeight : kProbes) {
                BOOST_CHECK_MESSAGE(
                    Consensus::DeploymentActiveAtHeight(nHeight, params.GetConsensus(nHeight), pos) == (nHeight >= nReported),
                    net << ": " << VersionBitsDeploymentInfo[pos].name << " at height " << nHeight);
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(reported_height_follows_the_regtest_setter, BasicTestingSetup)
{
    const CChainParams& params = Params(CBaseChainParams::REGTEST);
    const Consensus::DeploymentPos pos = Consensus::DEPLOYMENT_P2WSH_DILITHIUM;
    // One height per regtest tier (below 10, 10 to 19, from 20), then no height.
    for (const int nSet : {5, 15, 70, kNotScheduled}) {
        RegtestHeight set(pos, nSet);
        BOOST_CHECK_EQUAL(ReportedActivationHeight(params, pos), nSet);
        // The other two keep their own.
        BOOST_CHECK_EQUAL(ReportedActivationHeight(params, Consensus::DEPLOYMENT_DILITHIUM_KEYHASH), 0);
        BOOST_CHECK_EQUAL(ReportedActivationHeight(params, Consensus::DEPLOYMENT_V6_CONTROLFLOW), 0);
        if (nSet != kNotScheduled) {
            BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(nSet - 1, params.GetConsensus(nSet - 1), pos));
            BOOST_CHECK(Consensus::DeploymentActiveAtHeight(nSet, params.GetConsensus(nSet), pos));
        }
    }
    BOOST_CHECK_EQUAL(ReportedActivationHeight(params, pos), 0);
}

// The number is read in the tier that validates the height the root tier
// stores, the struct ConnectBlock consults for a block at that height.
BOOST_AUTO_TEST_CASE(reported_height_is_read_in_the_tier_that_validates_it)
{
    const int kProbes[] = {0, 19, 20, 49, 50, 59, 60, 61, kNotScheduled};

    for (const Consensus::DeploymentPos pos : REPORTED_ACTIVATION_HEIGHTS) {
        // The root tier stores 50, or no height, and the upper tier, which
        // validates from height 20, stores 60: 60 is enforced and reported.
        for (const int nRootHeight : {50, kNotScheduled}) {
            const TwoTierParams params(pos, nRootHeight, 60, 20);
            BOOST_CHECK_EQUAL(ReportedActivationHeight(params, pos), 60);
            for (const int nHeight : kProbes) {
                BOOST_CHECK_MESSAGE(
                    Consensus::DeploymentActiveAtHeight(nHeight, params.GetConsensus(nHeight), pos) == (nHeight >= 60),
                    "root tier " << nRootHeight << ": " << VersionBitsDeploymentInfo[pos].name << " at height " << nHeight);
            }
        }
        // The root tier stores 5, a height it validates itself, so the number
        // reported is the root tier's own 5. As in the two states above the
        // tiers hold different heights, so the precondition of
        // ReportedActivationHeight does not hold, and here 5 is only the
        // number stored in the tier that validates the root tier's stored
        // height: the deployment is inactive at 4 and active at 5, which the
        // last two checks pin, and inactive again from 20 to 59, the heights
        // the upper tier validates below its 60.
        {
            const TwoTierParams params(pos, 5, 60, 20);
            BOOST_CHECK_EQUAL(ReportedActivationHeight(params, pos), 5);
            BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(4, params.GetConsensus(4), pos));
            BOOST_CHECK(Consensus::DeploymentActiveAtHeight(5, params.GetConsensus(5), pos));
        }
    }
}

// The object getblockchaininfo returns on each network, from a chain state
// that holds that network's genesis block: the three names in order, each
// with a number.
BOOST_AUTO_TEST_CASE(getblockchaininfo_on_every_network)
{
    for (const std::string& net : Networks()) {
        TestingSetup setup(net);
        const CRPCCommand* command = tableRPC["getblockchaininfo"];
        BOOST_REQUIRE(command);
        JSONRPCRequest request;
        request.strMethod = "getblockchaininfo";
        request.params = UniValue(UniValue::VARR);
        request.fHelp = false;
        const UniValue info = (*command->actor)(request);
        BOOST_CHECK_EQUAL(find_value(info, "chain").get_str(), net);
        const UniValue& heights = find_value(info, "activation_heights");
        BOOST_REQUIRE(heights.isObject());
        BOOST_REQUIRE_EQUAL(heights.size(), sizeof(kNames) / sizeof(kNames[0]));
        for (size_t i = 0; i < heights.size(); i++) {
            BOOST_CHECK_EQUAL(heights.getKeys()[i], kNames[i]);
            BOOST_REQUIRE(heights.getValues()[i].isNum());
            BOOST_CHECK_MESSAGE(heights.getValues()[i].get_int() == ExpectedToday(net),
                                net << ": " << kNames[i] << " prints " << heights.getValues()[i].getValStr());
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
