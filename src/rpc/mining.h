// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2021-2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPCMINING_H
#define BITCOIN_RPCMINING_H

#include "arith_uint256.h"
#include "primitives/block.h"
#include "validation.h"
#include "validationinterface.h"

#include <univalue.h>

/**
 * Catches the state of a submitted block.
 * Registers as a validation interface and waits for the BlockChecked callback.
 * Thread-safe with the new CScheduler-based validation interface.
 */
class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    submitblock_StateCatcher(const uint256& hashIn) : hash(hashIn), found(false), state() {}

    // Called when block validation completes - this is now dispatched through the scheduler
    void BlockChecked(const CBlock& block, const CValidationState& stateIn) override
    {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

UniValue BIP22ValidationResult(const CValidationState& state);

/**
 * Launch mining posture (ratified 2026-08-29, bead
 * launch-mining-posture-gate-92yq): the work-serving RPCs — getblocktemplate,
 * generate, generatetoaddress and the createauxblock/getauxblock/submitauxblock
 * family — refuse to serve unless -enablemining is set. Default: ON everywhere
 * except mainnet. This is deliberately friction, not a security boundary (the
 * source is public); its purpose is that the default path for hashrate is the
 * pool, whose vesting and caps are the launch-period dump controls. submitblock
 * is NOT gated: blocks arrive over P2P regardless, so gating it buys nothing.
 * Revisit the mainnet default in a post-launch release.
 */
void EnsureMiningRPCsEnabled();

#endif // BITCOIN_RPCMINING_H
