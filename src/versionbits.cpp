// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "versionbits.h"

#include "consensus/params.h"

// NOTE: declared without an explicit array bound on purpose — the size is deduced
// from the initializer count so the static_assert below can detect a missing entry.
// (With an explicit [MAX_VERSION_BITS_DEPLOYMENTS] bound, a missing initializer would
// silently zero-init the last slot to a nullptr name — the soqucoin-build-z45 bug.)
const struct BIP9DeploymentInfo VersionBitsDeploymentInfo[] = {
    {
        /*.name =*/"testdummy",
        /*.gbt_force =*/true,
    },
    {
        /*.name =*/"csv",
        /*.gbt_force =*/true,
    },
    {
        /*.name =*/"segwit",
        /*.gbt_force =*/true,
    },
    {
        /*.name =*/"checkpatagg",
        /*.gbt_force =*/true,
    },
    {
        /*.name =*/"latticefold",
        /*.gbt_force =*/true,
    },
    {
        /*.name =*/"latticebp",
        /*.gbt_force =*/true,
    },
    {
        /*.name =*/"usdsoq",
        /*.gbt_force =*/true,
    },
    {
        /*.name =*/"ctv",
        /*.gbt_force =*/true,
    },
    {
        /*.name =*/"apo",
        /*.gbt_force =*/true,
    },
    {
        /*.name =*/"csfs",
        /*.gbt_force =*/true,
    },
    {
        /*.name =*/"p2wsh_dilithium",
        /*.gbt_force =*/true,
    },
    {
        /*.name =*/"utxo_cost",
        /*.gbt_force =*/true,
    },
    {
        // SOQ-COV-013: must match DEPLOYMENT_DILITHIUM_KEYHASH (params.h index 12).
        // Without this entry, index 12 zero-inits to a nullptr name and getblocktemplate
        // (gbt_vb_name) constructs std::string from null → crash on stagenet (ALWAYS_ACTIVE).
        /*.name =*/"dilithium_keyhash",
        /*.gbt_force =*/true,
    },
    {
        // DL-V6-CONTROLFLOW-RESTORE: must match DEPLOYMENT_V6_CONTROLFLOW (params.h index 13).
        /*.name =*/"v6_controlflow",
        /*.gbt_force =*/true,
    }};

// Compile-time guard: the VersionBitsDeploymentInfo array is indexed by the
// DeploymentPos enum (consensus/params.h). If a new deployment is added to the
// enum but its entry here is forgotten, the missing slot zero-inits to a nullptr
// name and getblocktemplate (gbt_vb_name) constructs std::string from null →
// daemon crash (the soqucoin-build-z45 launch-gate bug). This static_assert turns
// that runtime crash into a build failure.
static_assert(sizeof(VersionBitsDeploymentInfo) / sizeof(VersionBitsDeploymentInfo[0]) == Consensus::MAX_VERSION_BITS_DEPLOYMENTS,
              "VersionBitsDeploymentInfo is missing an entry for a DeploymentPos enum value (see consensus/params.h)");

ThresholdState AbstractThresholdConditionChecker::GetStateFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, ThresholdConditionCache& cache) const
{
    int64_t nTimeStart = BeginTime(params);
    if (nTimeStart == Consensus::BIP9Deployment::ALWAYS_ACTIVE) {
        return THRESHOLD_ACTIVE;
    }
    int nPeriod = Period(params);
    int nThreshold = Threshold(params);
    int64_t nTimeTimeout = EndTime(params);

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    if (pindexPrev != NULL) {
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod));
    }

    // Walk backwards in steps of nPeriod to find a pindexPrev whose information is known
    std::vector<const CBlockIndex*> vToCompute;
    while (cache.count(pindexPrev) == 0) {
        if (pindexPrev == NULL) {
            // The genesis block is by definition defined.
            cache[pindexPrev] = THRESHOLD_DEFINED;
            break;
        }
        if (pindexPrev->GetMedianTimePast() < nTimeStart) {
            // Optimization: don't recompute down further, as we know every earlier block will be before the start time
            cache[pindexPrev] = THRESHOLD_DEFINED;
            break;
        }
        vToCompute.push_back(pindexPrev);
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // At this point, cache[pindexPrev] is known
    assert(cache.count(pindexPrev));
    ThresholdState state = cache[pindexPrev];

    // Now walk forward and compute the state of descendants of pindexPrev
    while (!vToCompute.empty()) {
        ThresholdState stateNext = state;
        pindexPrev = vToCompute.back();
        vToCompute.pop_back();

        switch (state) {
        case THRESHOLD_DEFINED: {
            if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                stateNext = THRESHOLD_FAILED;
            } else if (pindexPrev->GetMedianTimePast() >= nTimeStart) {
                stateNext = THRESHOLD_STARTED;
            }
            break;
        }
        case THRESHOLD_STARTED: {
            if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                stateNext = THRESHOLD_FAILED;
                break;
            }
            // We need to count
            const CBlockIndex* pindexCount = pindexPrev;
            int count = 0;
            for (int i = 0; i < nPeriod; i++) {
                if (Condition(pindexCount, params)) {
                    count++;
                }
                pindexCount = pindexCount->pprev;
            }
            if (count >= nThreshold) {
                stateNext = THRESHOLD_LOCKED_IN;
            }
            break;
        }
        case THRESHOLD_LOCKED_IN: {
            // Always progresses into ACTIVE.
            stateNext = THRESHOLD_ACTIVE;
            break;
        }
        case THRESHOLD_FAILED:
        case THRESHOLD_ACTIVE: {
            // Nothing happens, these are terminal states.
            break;
        }
        }
        cache[pindexPrev] = state = stateNext;
    }

    return state;
}

int AbstractThresholdConditionChecker::GetStateSinceHeightFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, ThresholdConditionCache& cache) const
{
    const ThresholdState initialState = GetStateFor(pindexPrev, params, cache);

    // BIP 9 about state DEFINED: "The genesis block is by definition in this state for each deployment."
    if (initialState == THRESHOLD_DEFINED) {
        return 0;
    }

    const int nPeriod = Period(params);

    // SECURITY NOTE: For ALWAYS_ACTIVE deployments (or any state) on chains shorter
    // than one confirmation window, GetAncestor(height - nPeriod) would compute a
    // negative index and return NULL, causing a segfault. Since ALWAYS_ACTIVE
    // deployments are active from genesis, return 0 (active since block 0).
    // For non-ALWAYS_ACTIVE deployments on short chains, the state must be DEFINED
    // (handled above) so this is defense-in-depth.
    if (pindexPrev->nHeight < nPeriod) {
        return 0;
    }

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    // To ease understanding of the following height calculation, it helps to remember that
    // right now pindexPrev points to the block prior to the block that we are computing for, thus:
    // if we are computing for the last block of a period, then pindexPrev points to the second to last block of the period, and
    // if we are computing for the first block of a period, then pindexPrev points to the last block of the previous period.
    // The parent of the genesis block is represented by NULL.
    pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod));

    const CBlockIndex* previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);

    while (previousPeriodParent != NULL && GetStateFor(previousPeriodParent, params, cache) == initialState) {
        pindexPrev = previousPeriodParent;
        previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // Adjust the result because right now we point to the parent block.
    return pindexPrev->nHeight + 1;
}

namespace
{
/**
 * Class to implement versionbits logic.
 */
class VersionBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    const Consensus::DeploymentPos id;

protected:
    int64_t BeginTime(const Consensus::Params& params) const { return params.vDeployments[id].nStartTime; }
    int64_t EndTime(const Consensus::Params& params) const { return params.vDeployments[id].nTimeout; }
    int Period(const Consensus::Params& params) const { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const { return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const
    {
        return (((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) && (pindex->nVersion & Mask(params)) != 0);
    }

public:
    VersionBitsConditionChecker(Consensus::DeploymentPos id_) : id(id_) {}
    uint32_t Mask(const Consensus::Params& params) const
    {
        if (params.vDeployments[id].nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE) {
            return 0;
        }
        return ((uint32_t)1) << params.vDeployments[id].bit;
    }
};

} // namespace

ThresholdState VersionBitsState(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos, VersionBitsCache& cache)
{
    return VersionBitsConditionChecker(pos).GetStateFor(pindexPrev, params, cache.caches[pos]);
}

int VersionBitsStateSinceHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos, VersionBitsCache& cache)
{
    return VersionBitsConditionChecker(pos).GetStateSinceHeightFor(pindexPrev, params, cache.caches[pos]);
}

uint32_t VersionBitsMask(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    return VersionBitsConditionChecker(pos).Mask(params);
}

void VersionBitsCache::Clear()
{
    for (unsigned int d = 0; d < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; d++) {
        caches[d].clear();
    }
}
