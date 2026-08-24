// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// dormancy_matrix_tests.cpp — the deployment posture of every network, asserted
// against an explicit declared table.
//
// WHY THIS FILE EXISTS
// ────────────────────
// SOQ-I009 was possible because mainnet's actual consensus configuration had
// almost no test coverage. Every suite in this tree runs on regtest with every
// deployment ACTIVE from height 0, so the dormant posture that mainnet actually
// ships was exercised by nothing. A rule could be wrong in exactly the state
// mainnet runs in and the suite would stay green — and did, 684 cases green
// while a miner could spend any UTXO unsigned.
//
// The obvious fix, "run the whole suite a second time with mainnet's deployment
// table", does not work: most suites deliberately depend on features being
// active (the covenant tests, both USDSOQ harnesses, the lightning scripts), so
// a mainnet-posture run would emit a wall of expected failures and be ignored
// within a week. What is wanted is one deterministic signal per deployment.
//
// So: a declared table of what each deployment's posture is SUPPOSED to be on
// each network, asserted against what chainparams actually says. Changing a
// deployment's posture then cannot be done quietly — the change has to be made
// here too, which is the point. Every entry below is a decision someone has to
// re-affirm in writing.
//
// ⛔ IF A TEST HERE FAILS, DO NOT EDIT THE TABLE TO MATCH THE CODE. Work out
// which of the two is wrong first. The table is the intent; chainparams is the
// implementation; a divergence is a finding, not a chore.

#include "chainparams.h"
#include "chainparamsbase.h"
#include "consensus/params.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <limits>
#include <string>
#include <vector>

namespace {

//! How a deployment is switched on, independent of which mechanism it uses.
enum Posture {
    ACTIVE_FROM_GENESIS,  //!< live at height 0 (BIP9 ALWAYS_ACTIVE, or height 0)
    DORMANT_WITHDRAWN,    //!< height-gated and NOT_SCHEDULED — cannot activate
    DORMANT_BIP9_NEVER,   //!< BIP9 with nStartTime=0/nTimeout=0 — terminal FAILED
    EXPIRED_BIP9,         //!< BIP9 whose window closed in the past (TESTDUMMY)
};

const char* PostureName(Posture p)
{
    switch (p) {
    case ACTIVE_FROM_GENESIS: return "ACTIVE";
    case DORMANT_WITHDRAWN:   return "DORMANT(withdrawn)";
    case DORMANT_BIP9_NEVER:  return "DORMANT(bip9-never)";
    case EXPIRED_BIP9:        return "EXPIRED";
    }
    return "?";
}

//! Read the posture chainparams actually declares.
Posture ActualPosture(const Consensus::Params& c, Consensus::DeploymentPos pos)
{
    const Consensus::BIP9Deployment& d = c.vDeployments[pos];

    if (d.nActivationHeight != Consensus::BIP9Deployment::NO_HEIGHT_ACTIVATION) {
        // Height-gated (p96 / Option D). nStartTime and nTimeout are NOT read.
        if (d.nActivationHeight == Consensus::BIP9Deployment::NOT_SCHEDULED) return DORMANT_WITHDRAWN;
        if (d.nActivationHeight == 0) return ACTIVE_FROM_GENESIS;
        return DORMANT_WITHDRAWN;  // a real future height is still "not live now"
    }
    // BIP9 state machine.
    if (d.nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE) return ACTIVE_FROM_GENESIS;
    if (d.nStartTime == 0 && d.nTimeout == 0) return DORMANT_BIP9_NEVER;
    return EXPIRED_BIP9;
}

struct Row {
    Consensus::DeploymentPos pos;
    const char* name;
    Posture main;
    //! The witness version this deployment gates, or -1 if it gates no output
    //! shape. Used to assert the SOQ-I009 reservation invariant.
    int witnessVersion;
};

//! ⚠️ THE DECLARED TABLE. Mainnet column only — the test nets deliberately run
//! everything active and are asserted separately and more loosely.
//!
//! Exactly THREE deployments are live on mainnet at genesis. That is the whole
//! consensus surface a launch-day attacker can reach through a deployment gate,
//! and it is dramatically smaller than the size of this repo suggests.
const std::vector<Row> MAINNET_TABLE = {
    { Consensus::DEPLOYMENT_TESTDUMMY,         "TESTDUMMY",         EXPIRED_BIP9,        -1 },
    { Consensus::DEPLOYMENT_CSV,               "CSV",               ACTIVE_FROM_GENESIS, -1 },
    { Consensus::DEPLOYMENT_SEGWIT,            "SEGWIT",            ACTIVE_FROM_GENESIS, -1 },
    { Consensus::DEPLOYMENT_CHECKPATAGG,       "CHECKPATAGG",       ACTIVE_FROM_GENESIS,  2 },
    { Consensus::DEPLOYMENT_LATTICEFOLD,       "LATTICEFOLD",       DORMANT_BIP9_NEVER,   3 },
    { Consensus::DEPLOYMENT_SOQUOBSCURA,       "SOQUOBSCURA",       DORMANT_WITHDRAWN,    4 },
    { Consensus::DEPLOYMENT_USDSOQ,            "USDSOQ",            DORMANT_WITHDRAWN,    5 },
    { Consensus::DEPLOYMENT_CTV,               "CTV",               DORMANT_WITHDRAWN,   -1 },
    { Consensus::DEPLOYMENT_APO,               "APO",               DORMANT_WITHDRAWN,   -1 },
    { Consensus::DEPLOYMENT_CSFS,              "CSFS",              DORMANT_WITHDRAWN,   -1 },
    { Consensus::DEPLOYMENT_P2WSH_DILITHIUM,   "P2WSH_DILITHIUM",   DORMANT_WITHDRAWN,    6 },
    { Consensus::DEPLOYMENT_UTXO_COST,         "UTXO_COST",         DORMANT_WITHDRAWN,   -1 },
    { Consensus::DEPLOYMENT_DILITHIUM_KEYHASH, "DILITHIUM_KEYHASH", DORMANT_WITHDRAWN,   -1 },
    { Consensus::DEPLOYMENT_V6_CONTROLFLOW,    "V6_CONTROLFLOW",    DORMANT_WITHDRAWN,   -1 },
    { Consensus::DEPLOYMENT_BTCSOQ,            "BTCSOQ",            DORMANT_WITHDRAWN,    8 },
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(dormancy_matrix_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// THE MATRIX. Mainnet's declared posture must match chainparams exactly.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(mainnet_posture_matches_the_declared_table)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& c = Params().GetConsensus(0);

    for (const Row& r : MAINNET_TABLE) {
        const Posture actual = ActualPosture(c, r.pos);
        BOOST_TEST_MESSAGE(std::string(r.name) + ": " + PostureName(actual));
        BOOST_CHECK_MESSAGE(actual == r.main,
            std::string("MAINNET POSTURE CHANGED for ") + r.name + ": table says " +
            PostureName(r.main) + ", chainparams says " + PostureName(actual) +
            ". Do not edit the table to match the code until you know which is wrong. "
            "If this is a deliberate activation, it needs a soak, an audit and a "
            "release — not a table edit");
    }
}

// The table must cover every deployment. A new deployment added to the enum
// without a row here would otherwise be silently unasserted, which is exactly
// how a dormant feature acquires an ungated exemption.
BOOST_AUTO_TEST_CASE(table_covers_every_deployment)
{
    BOOST_CHECK_MESSAGE(MAINNET_TABLE.size() == (size_t)Consensus::MAX_VERSION_BITS_DEPLOYMENTS,
        "A deployment exists that this table does not describe (table has " +
        std::to_string(MAINNET_TABLE.size()) + ", enum has " +
        std::to_string((int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS) + "). Add a row: "
        "an undescribed deployment is an unasserted one");
}

// ---------------------------------------------------------------------------
// The live surface, stated as a number. Three deployments are reachable on
// mainnet at genesis. This is the claim that makes the pre-mainnet build window
// defensible: everything else is provably unreachable, not merely unused.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(mainnet_has_exactly_three_active_deployments)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& c = Params().GetConsensus(0);

    std::vector<std::string> active;
    for (const Row& r : MAINNET_TABLE) {
        if (ActualPosture(c, r.pos) == ACTIVE_FROM_GENESIS) active.push_back(r.name);
    }

    std::string joined;
    for (const std::string& s : active) joined += (joined.empty() ? "" : ", ") + s;
    BOOST_TEST_MESSAGE("mainnet-active: " + joined);

    BOOST_CHECK_MESSAGE(active.size() == 3,
        "mainnet active-deployment count changed to " + std::to_string(active.size()) +
        " (" + joined + "). Expected exactly CSV, SEGWIT, CHECKPATAGG");
}

// ---------------------------------------------------------------------------
// Withdrawn means withdrawn AT EVERY HEIGHT, not just at genesis. A dormant
// deployment given a real (large) activation height would pass a
// height-0 check and still go live later, unaudited.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(withdrawn_deployments_are_inactive_at_every_height)
{
    SelectParams(CBaseChainParams::MAIN);
    const int probes[] = {0, 1, 1000, 100000, 10000000, std::numeric_limits<int>::max() - 1};

    for (const Row& r : MAINNET_TABLE) {
        if (r.main != DORMANT_WITHDRAWN) continue;
        for (int h : probes) {
            const Consensus::Params& c = Params().GetConsensus(h);
            BOOST_CHECK_MESSAGE(
                !Consensus::DeploymentActiveAtHeight(h, c, r.pos),
                std::string(r.name) + " is ACTIVE at height " + std::to_string(h) +
                " despite being declared withdrawn. A scheduled height is not dormancy");
        }
    }
}

// ---------------------------------------------------------------------------
// NO_HEIGHT_ACTIVATION silently defers to the BIP9 state machine. For a feature
// intended to be withdrawn, that sentinel is a trapdoor: it reads like "no
// activation" and behaves like "ask version bits". The comment in chainparams
// warns about it; this asserts it.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(withdrawn_deployments_do_not_use_the_bip9_fallback_sentinel)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& c = Params().GetConsensus(0);

    for (const Row& r : MAINNET_TABLE) {
        if (r.main != DORMANT_WITHDRAWN) continue;
        BOOST_CHECK_MESSAGE(
            c.vDeployments[r.pos].nActivationHeight !=
                Consensus::BIP9Deployment::NO_HEIGHT_ACTIVATION,
            std::string(r.name) + " uses NO_HEIGHT_ACTIVATION, which defers to "
            "VersionBitsState instead of withdrawing the feature. Use NOT_SCHEDULED");
    }
}

// ---------------------------------------------------------------------------
// Belt and braces on the same set: a withdrawn deployment must ALSO be dead on
// the BIP9 side, so that removing the activation height cannot silently
// re-enable it via miner signalling.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(withdrawn_deployments_are_also_dead_on_the_bip9_path)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& c = Params().GetConsensus(0);

    for (const Row& r : MAINNET_TABLE) {
        if (r.main != DORMANT_WITHDRAWN) continue;
        const Consensus::BIP9Deployment& d = c.vDeployments[r.pos];
        BOOST_CHECK_MESSAGE(d.nStartTime == 0 && d.nTimeout == 0,
            std::string(r.name) + " is withdrawn by height but its BIP9 window is live "
            "(nStartTime=" + std::to_string(d.nStartTime) + ", nTimeout=" +
            std::to_string(d.nTimeout) + "). Deleting the activation height would then "
            "hand activation to miner signalling");
    }
}

// ---------------------------------------------------------------------------
// The test nets are the mirror image and that is deliberate: they run
// everything active so the features can be developed and drilled. Asserted so
// that an accidental withdrawal on stagenet (which would silently stop
// exercising a money path) is visible.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(testnets_run_the_asset_deployments_active)
{
    const Consensus::DeploymentPos assets[] = {
        Consensus::DEPLOYMENT_USDSOQ,
        Consensus::DEPLOYMENT_BTCSOQ,
        Consensus::DEPLOYMENT_P2WSH_DILITHIUM,
    };
    for (const std::string& net : {CBaseChainParams::TESTNET, CBaseChainParams::REGTEST,
                                   CBaseChainParams::STAGENET}) {
        SelectParams(net);
        const Consensus::Params& c = Params().GetConsensus(0);
        for (Consensus::DeploymentPos pos : assets) {
            BOOST_CHECK_MESSAGE(ActualPosture(c, pos) == ACTIVE_FROM_GENESIS,
                net + ": an asset deployment is not active. The test nets exist to "
                "exercise these money paths; withdrawing one here silently removes "
                "that coverage while every test stays green");
        }
    }
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()
