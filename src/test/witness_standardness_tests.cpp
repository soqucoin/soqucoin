// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Policy must never admit an output whose consensus rule is dormant.
//
// A gated witness version is anyone-can-spend until its deployment activates. If
// relay policy also calls it standard, the two together are a fund-loss path
// rather than a safe failure: the output relays, confirms, and then anybody may
// spend it. That combination existed on mainnet for witness versions v5 through
// v9, because policy.cpp carved them out of the future-version rejection
// UNCONDITIONALLY — correct on stagenet where those deployments are
// ALWAYS_ACTIVE, wrong on mainnet where every one of them ships
// nStartTime=0/nTimeout=0 or NOT_SCHEDULED.
//
// These tests pin the rule that replaced the carve-out: a v2-v16 program is
// standard only while the matching bit is set in the activation mask.

#include "policy/policy.h"
#include "script/script.h"
#include "script/standard.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(witness_standardness_tests, BasicTestingSetup)

namespace {

//! A 34-byte witness program: OP_<version> followed by a 32-byte push.
CScript WitnessProgram(int version)
{
    BOOST_REQUIRE(version >= 1 && version <= 16);
    CScript s;
    s << CScript::EncodeOP_N(version);
    s << std::vector<unsigned char>(32, 0x01);
    BOOST_REQUIRE_EQUAL(s.size(), 34U);
    return s;
}

bool StandardWith(const CScript& spk, WitnessVersionMask mask)
{
    txnouttype whichType;
    return IsStandard(spk, whichType, /*witnessEnabled=*/true, mask);
}

} // namespace

// The regression. Every gated version must be non-standard when nothing is
// active, which is the state mainnet actually ships in.
BOOST_AUTO_TEST_CASE(gated_versions_nonstandard_when_dormant)
{
    for (int v = 2; v <= 16; ++v) {
        BOOST_CHECK_MESSAGE(!StandardWith(WitnessProgram(v), 0),
                            "witness v" << v << " was standard with no deployment active; "
                            "relay-standard plus anyone-can-spend is a fund-loss path");
    }
}

// v5-v9 specifically, because those were the unconditional carve-outs.
BOOST_AUTO_TEST_CASE(v5_through_v9_were_the_carve_outs)
{
    for (int v = 5; v <= 9; ++v) {
        BOOST_CHECK(!StandardWith(WitnessProgram(v), 0));
        // ...and become standard only once their own bit is set.
        BOOST_CHECK(StandardWith(WitnessProgram(v), WitnessVersionBit(v)));
    }
}

// The gated set is exactly {v5..v9} — the versions Solver() recognises as named
// output types. Everything else in v2-v16 is rejected earlier, by Solver itself,
// and the mask never gets a say. That second layer is why only v5-v9 were ever
// reachable, and therefore why only v5-v9 were ever the fund-loss path.
BOOST_AUTO_TEST_CASE(activation_does_not_leak_across_versions)
{
    const int gated[] = {5, 6, 7, 8, 9};
    for (int active : gated) {
        const WitnessVersionMask mask = WitnessVersionBit(active);
        for (int v : gated) {
            const bool standard = StandardWith(WitnessProgram(v), mask);
            BOOST_CHECK_MESSAGE(standard == (v == active),
                                "activating v" << active << " changed standardness of v" << v);
        }
    }
}

// Defence in depth: versions Solver() does not name can never be standard, no
// matter what the activation mask says. If a future change teaches Solver a new
// version, this test fails and forces a deliberate decision about its mask entry
// rather than letting it become relayable by accident.
BOOST_AUTO_TEST_CASE(unrecognised_versions_ignore_the_mask_entirely)
{
    // Every bit set — a mask the acceptance path can never actually produce.
    WitnessVersionMask everything = 0;
    for (int v = 2; v <= 16; ++v) everything |= WitnessVersionBit(v);

    const int notNamedBySolver[] = {2, 3, 4, 10, 11, 12, 13, 14, 15, 16};
    for (int v : notNamedBySolver) {
        BOOST_CHECK_MESSAGE(!StandardWith(WitnessProgram(v), everything),
                            "witness v" << v << " became standard despite Solver not naming it");
    }
}

// The base forms must be unaffected by the change.
BOOST_AUTO_TEST_CASE(v0_and_v1_unaffected)
{
    CScript v0keyhash;
    v0keyhash << OP_0 << std::vector<unsigned char>(20, 0x02);
    txnouttype t;
    BOOST_CHECK(IsStandard(v0keyhash, t, /*witnessEnabled=*/true, 0));

    CScript v0scripthash;
    v0scripthash << OP_0 << std::vector<unsigned char>(32, 0x03);
    BOOST_CHECK(IsStandard(v0scripthash, t, /*witnessEnabled=*/true, 0));

    // v1 is the single-key Dilithium form and is not part of the gated range.
    BOOST_CHECK(StandardWith(WitnessProgram(1), 0));
}

BOOST_AUTO_TEST_SUITE_END()
