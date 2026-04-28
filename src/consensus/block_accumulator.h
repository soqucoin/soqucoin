// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-ARCH-001 Phase 2.3: Block-Level Range Proof Accumulation
// Design Log: DL-LATTICEFOLD-BLOCK-ACCUMULATOR.md
//
// This header defines the per-block LatticeFold accumulator structure.
// When DEPLOYMENT_LATTICEBP is active, each block's confidential range proofs
// are folded into a single accumulated proof commitment via LatticeFold+.
//
// The accumulator hash is committed in the coinbase OP_RETURN (similar to
// SegWit's coinbase commitment), enabling light clients to verify that all
// range proofs in the block are valid without checking each individually.
//
// Wire format:
//   Coinbase output: OP_RETURN OP_PUSHBYTES_34 [0x4C 0x46] [32-byte accumulator hash]
//   Where 0x4C46 = "LF" (LatticeFold magic bytes)

#ifndef SOQUCOIN_CONSENSUS_BLOCK_ACCUMULATOR_H
#define SOQUCOIN_CONSENSUS_BLOCK_ACCUMULATOR_H

#include "serialize.h"
#include "uint256.h"
#include "hash.h"

#include <cstdint>
#include <vector>

// =========================================================================
// LatticeFold magic bytes for coinbase commitment
// =========================================================================
static const uint8_t LATTICEFOLD_MAGIC[2] = {0x4C, 0x46}; // "LF"

// =========================================================================
// BlockProofAccumulator — Per-block LatticeFold accumulation state
// =========================================================================
//
// Created during ConnectBlock when DEPLOYMENT_LATTICEBP is active and the
// block contains one or more confidential transaction outputs.
//
// The accumulator takes N individual Lattice-BP++ range proofs and folds
// them into a single LatticeFold+ accumulator state. The hash of this
// state is committed in the coinbase transaction via OP_RETURN.
//
// Verification flow:
//   1. Extract all range proofs from confidential outputs in the block
//   2. Fold via LatticeFold+: N proofs → 1 accumulated state
//   3. Hash the accumulated state → hashAccumulator (32 bytes)
//   4. Check: coinbase OP_RETURN commitment == hashAccumulator
//   5. Verify the accumulated state against the block's commitments
//
// Empty blocks (no confidential TXs) have nProofCount == 0 and no
// coinbase commitment is required.

struct BlockProofAccumulator
{
    //! Protocol version (0x01 = LatticeFold+ based)
    uint8_t nVersion;

    //! Number of individual range proofs that were folded
    uint32_t nProofCount;

    //! SHA256d hash of the serialized folded state (committed in coinbase)
    uint256 hashAccumulator;

    //! Serialized LatticeFold+ accumulator state
    //! This contains the folded t-vector, challenge, and Ajtai commitment
    //! that can be verified against the block's individual commitments.
    //! Size: ~624–8816 bytes depending on folding rounds (typically 1-2KB for ≤100 proofs)
    std::vector<uint8_t> vchFoldedState;

    BlockProofAccumulator() : nVersion(0), nProofCount(0), hashAccumulator() {}

    bool IsNull() const { return nVersion == 0 && nProofCount == 0; }

    //! Compute the accumulator hash from the folded state
    void ComputeHash()
    {
        if (vchFoldedState.empty()) {
            hashAccumulator.SetNull();
            return;
        }
        CHash256().Write(vchFoldedState.data(), vchFoldedState.size())
                  .Finalize((unsigned char*)&hashAccumulator);
    }

    //! Build the OP_RETURN script for coinbase commitment
    //! Format: OP_RETURN OP_PUSHBYTES_34 [0x4C 0x46] [32-byte hash]
    std::vector<uint8_t> GetCoinbaseCommitmentScript() const
    {
        std::vector<uint8_t> script;
        script.push_back(0x6a);  // OP_RETURN
        script.push_back(0x22);  // OP_PUSHBYTES_34 (34 bytes follow)
        script.push_back(LATTICEFOLD_MAGIC[0]);  // 'L'
        script.push_back(LATTICEFOLD_MAGIC[1]);  // 'F'
        script.insert(script.end(), hashAccumulator.begin(), hashAccumulator.end());
        return script;
    }

    //! Extract accumulator hash from a coinbase OP_RETURN script
    //! Returns true if the script matches the LatticeFold commitment format
    static bool ParseCoinbaseCommitment(const std::vector<uint8_t>& script, uint256& hashOut)
    {
        // Expected: OP_RETURN(0x6a) OP_PUSHBYTES_34(0x22) LF_MAGIC(2) HASH(32) = 36 bytes
        if (script.size() != 36) return false;
        if (script[0] != 0x6a) return false;  // OP_RETURN
        if (script[1] != 0x22) return false;  // 34 bytes
        if (script[2] != LATTICEFOLD_MAGIC[0] || script[3] != LATTICEFOLD_MAGIC[1])
            return false;
        memcpy(hashOut.begin(), &script[4], 32);
        return true;
    }

    //! Estimated serialized size
    size_t SerializedSize() const
    {
        if (IsNull()) return 0;
        return 1 + 4 + 32 + vchFoldedState.size() + 8; // version + count + hash + state + varint overhead
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(nProofCount);
        READWRITE(hashAccumulator);
        READWRITE(vchFoldedState);
    }
};

// =========================================================================
// LatticeFold Block Accumulation Functions
// =========================================================================
// These are the consensus-level APIs that ConnectBlock and the miner call.
// The actual folding math lives in crypto/latticefold/verifier.cpp.

//! Accumulate a set of range proof blobs into a single BlockProofAccumulator.
//!
//! Each proof_data blob is the serialized LatticeRangeProofV2 from a
//! confidential output's witness data.
//!
//! @param vProofData   Vector of serialized range proofs
//! @param vCommitData  Vector of serialized commitments (parallel to proofs)
//! @param accum_out    Output accumulator
//! @return true on success
bool AccumulateBlockRangeProofs(
    const std::vector<std::vector<uint8_t>>& vProofData,
    const std::vector<std::vector<uint8_t>>& vCommitData,
    BlockProofAccumulator& accum_out);

//! Verify that a BlockProofAccumulator is consistent with a set of
//! individual range proofs and commitments.
//!
//! @param accum        The accumulator to verify
//! @param vProofData   Vector of serialized range proofs
//! @param vCommitData  Vector of serialized commitments
//! @return true if the accumulator is valid
bool VerifyBlockAccumulator(
    const BlockProofAccumulator& accum,
    const std::vector<std::vector<uint8_t>>& vProofData,
    const std::vector<std::vector<uint8_t>>& vCommitData);

#endif // SOQUCOIN_CONSENSUS_BLOCK_ACCUMULATOR_H
