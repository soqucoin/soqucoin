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

#endif // BITCOIN_TEST_TESTUTIL_H
