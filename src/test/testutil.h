// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Utility functions shared by unit tests
 */
#ifndef BITCOIN_TEST_TESTUTIL_H
#define BITCOIN_TEST_TESTUTIL_H

#include "chainparams.h"
#include "consensus/params.h"
#include "fs.h"

#include <cstdint>
#include <vector>

fs::path GetTempPath();

/**
 * Turn a height-gated regtest deployment on for the duration of a scope, and
 * restore whatever was there on the way out.
 *
 * Needed because UpdateRegtestBIP9Parameters cannot activate any Soqucoin
 * deployment: it writes nStartTime/nTimeout, and DeploymentActiveAtHeight reads
 * nActivationHeight and nothing else (flag-day activation, bead p96 Option D).
 * Without a lever, every SCRIPT_VERIFY_SOQUOBSCURA-gated reject path was
 * unreachable from the suite, which is a large part of why two of them sat dead
 * through a fully green run (beads don9, n1vf, r0vn).
 *
 * Restores the value that was actually present rather than assuming
 * NOT_SCHEDULED, so a leak in one test cannot silently arm another. The regtest
 * params are a process-wide singleton, so scope discipline here is load-bearing.
 */
class ScopedRegtestActivation
{
public:
    ScopedRegtestActivation(Consensus::DeploymentPos pos, int nActivationHeight)
        : m_pos(pos),
          m_saved(Params().GetConsensus(0).vDeployments[pos].nActivationHeight)
    {
        UpdateRegtestActivationHeight(m_pos, nActivationHeight);
    }
    ~ScopedRegtestActivation() { UpdateRegtestActivationHeight(m_pos, m_saved); }

    ScopedRegtestActivation(const ScopedRegtestActivation&) = delete;
    ScopedRegtestActivation& operator=(const ScopedRegtestActivation&) = delete;

private:
    Consensus::DeploymentPos m_pos;
    int m_saved;
};

/**
 * Build the seven-element authority witness stack shared by the USDSOQ and
 * BTCSOQ marker-spend paths.
 *
 * Layout, which is consensus-visible:
 *   [0] payout_sig placeholder
 *   [1] payout_pk placeholder
 *   [2] op tag (must equal the signed OP_RETURN tag)
 *   [3] payload placeholder
 *   [4] authority signature 0
 *   [5] authority signature 1
 *   [6] authority_set placeholder
 *
 * This existed twice, once in dilithium_chain_setup.h for the USDSOQ harnesses
 * and once inline in btcsoq_lifecycle_harness_tests.cpp for the BTCSOQ ones.
 * Two copies of one consensus-visible layout is the exact shape of SOQ-I012 and
 * SOQ-I013, where a fix landed on the BTCSOQ side and never reached its USDSOQ
 * twin. Changing the layout must now be a single edit that both siblings see.
 *
 * Signing stays at the call sites: the two harnesses hold their keys
 * differently, and only the layout is genuinely common.
 */
inline void BuildAuthorityWitnessStack(
    std::vector<std::vector<unsigned char>>& stack,
    unsigned char opTag,
    const std::vector<uint8_t>& sig0,
    const std::vector<uint8_t>& sig1)
{
    stack.clear();
    stack.push_back(std::vector<unsigned char>{0x00});   // [0] payout_sig
    stack.push_back(std::vector<unsigned char>{0x00});   // [1] payout_pk
    stack.push_back(std::vector<unsigned char>{opTag});  // [2] op tag
    stack.push_back(std::vector<unsigned char>{0x00});   // [3] payload
    stack.push_back(std::vector<unsigned char>(sig0.begin(), sig0.end()));
    stack.push_back(std::vector<unsigned char>(sig1.begin(), sig1.end()));
    stack.push_back(std::vector<unsigned char>{0x00});   // [6] authority_set
}

#endif // BITCOIN_TEST_TESTUTIL_H
