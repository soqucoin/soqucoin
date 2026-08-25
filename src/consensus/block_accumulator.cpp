// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-ARCH-001 Phase 2.3: Block-Level Range Proof Accumulation
// Design Log: DL-LATTICEFOLD-BLOCK-ACCUMULATOR.md
//
// Implementation of LatticeFold+ per-block range proof accumulation.
//
// The folding algorithm follows ePrint 2025/247 (Boneh & Chen) §4.1:
//   1. For each range proof Pᵢ, extract the t-vector and challenge
//   2. Compute random linear combination: r ← Fiat-Shamir(P₁..Pₙ)
//   3. Fold: T_acc = Σ rⁱ · tᵢ, c_acc = Σ rⁱ · cᵢ
//   4. Verify: matA · T_acc = c_acc (Ajtai commitment check)
//
// SECURITY NOTE: The Fiat-Shamir challenge includes ALL proof data and
// commitments to prevent selective proof omission attacks. A miner who
// excludes a proof from the accumulation must also exclude it from the
// Fiat-Shamir transcript, which changes the accumulator hash, which
// invalidates the coinbase commitment.
//
// NOTE: This is consensus-critical code. No logging, no I/O, no exceptions.
// All error conditions return false. Callers (validation.cpp) handle logging.

#include "consensus/block_accumulator.h"
#include "hash.h"

#include <algorithm>
#include <cassert>
#include <cstring>

// =========================================================================
// AccumulateBlockRangeProofs
// =========================================================================
// Commits N individual range proof blobs to a single 72-byte accumulator state.
//
// What it actually does -- a hash chain, NOT an algebraic fold:
//   1. Hash all proofs + commitments -> Fiat-Shamir seed
//   2. Derive per-proof challenge r_i = SHA256d(seed || i)
//   3. Chain: fold = H(domain || n || H(r_0||proof_0||commit_0) || ...)
//   4. Serialise [version][count][seed][fold]
//
// WHAT THIS DOES AND DOES NOT GIVE YOU. Read this before citing it as a
// security property.
//
//   - Binding: yes. Changing any proof or commitment, or their order or count,
//     changes the output, under SHA256d collision resistance. That is the whole
//     of the guarantee.
//   - Deterministic: yes. Same inputs give the same accumulator on every node,
//     which is what consensus needs.
//   - Sound: NO, and the earlier comment here claiming "a false proof cannot
//     cancel a true proof" was misleading in two ways. First, there is no
//     algebraic structure here for anything to cancel in, so the statement is
//     vacuous rather than a property that was designed for. Second, and the
//     part that matters: this function never inspects whether a proof is
//     VALID. It commits to whatever bytes it is handed. An accumulator over N
//     invalid proofs succeeds exactly as readily as one over N valid proofs.
//
// Validity comes only from per-input verification elsewhere. Note that the
// range proof that verification relies on does not currently bind the committed
// amount (SOQ-I011, tripwired and not fixed), so do not read a successful
// accumulation as evidence that any amount is in range.
//
// The r_i challenges are redundant with the ordered writes into the fold
// transcript: position is already committed by the write order and the count.
// They are kept because the serialised format is consensus-visible.
//
// If LatticeFold+ algebraic folding is ever wired in, this becomes a real fold
// with O(1) verification and the claims above have to be rewritten, not
// extended.

bool AccumulateBlockRangeProofs(
    const std::vector<std::vector<uint8_t>>& vProofData,
    const std::vector<std::vector<uint8_t>>& vCommitData,
    BlockProofAccumulator& accum_out)
{
    // Empty block — no accumulation needed
    if (vProofData.empty()) {
        accum_out = BlockProofAccumulator();
        return true;
    }

    // Proof count mismatch
    if (vProofData.size() != vCommitData.size()) {
        return false;
    }

    // Maximum proofs per block (DoS protection)
    // At ~12KB per proof and 4MB block weight limit with 75% witness discount,
    // theoretical max is ~340 proofs. Use 512 as generous upper bound.
    static constexpr size_t MAX_PROOFS_PER_BLOCK = 512;
    if (vProofData.size() > MAX_PROOFS_PER_BLOCK) {
        return false;
    }

    // Step 1: Compute Fiat-Shamir seed from ALL proof and commitment data
    // This binds the accumulator to the exact set of proofs in this block.
    //
    // SECURITY NOTE: Domain separation prevents cross-protocol attacks.
    // Including the proof count prevents length-extension.
    CHash256 fsHasher;
    const char* domain = "soqucoin-latticefold-blockaccum-v1";
    fsHasher.Write((const unsigned char*)domain, strlen(domain));

    // Include proof count in transcript
    uint32_t nCount = static_cast<uint32_t>(vProofData.size());
    fsHasher.Write((const unsigned char*)&nCount, sizeof(nCount));

    // Hash all proofs
    for (const auto& proof : vProofData) {
        uint32_t proofLen = static_cast<uint32_t>(proof.size());
        fsHasher.Write((const unsigned char*)&proofLen, sizeof(proofLen));
        if (!proof.empty()) {
            fsHasher.Write(proof.data(), proof.size());
        }
    }

    // Hash all commitments
    for (const auto& commit : vCommitData) {
        uint32_t commitLen = static_cast<uint32_t>(commit.size());
        fsHasher.Write((const unsigned char*)&commitLen, sizeof(commitLen));
        if (!commit.empty()) {
            fsHasher.Write(commit.data(), commit.size());
        }
    }

    // Finalize Fiat-Shamir seed
    uint256 fsSeed;
    fsHasher.Finalize((unsigned char*)&fsSeed);

    // Step 2: Derive per-proof random challenges via HKDF-style expansion
    // r_i = SHA256d(fsSeed || i) for i = 0..N-1
    // These challenges ensure each proof contributes uniquely to the fold.
    std::vector<uint256> vChallenges(vProofData.size());
    for (size_t i = 0; i < vProofData.size(); i++) {
        CHash256 challengeHasher;
        challengeHasher.Write((const unsigned char*)&fsSeed, sizeof(fsSeed));
        uint32_t idx = static_cast<uint32_t>(i);
        challengeHasher.Write((const unsigned char*)&idx, sizeof(idx));
        challengeHasher.Finalize((unsigned char*)&vChallenges[i]);
    }

    // Step 3: build the folded state as a hash chain over
    // (challenge_i, proof_i, commit_i). This is not a linear combination and
    // there is no field arithmetic here; see the header comment.
    //
    // What this buys, precisely:
    //   1. The commitment fixes the exact multiset AND order of proofs the
    //      miner included, so a miner cannot drop or reorder one silently.
    //   2. It is binding under SHA256d collision resistance.
    //
    // What it does not buy: any statement about the proofs being valid. That
    // is per-input verification's job, and see SOQ-I011 in the header for the
    // current limits of that verification.

    CHash256 foldHasher;
    const char* foldDomain = "soqucoin-latticefold-fold-v1";
    foldHasher.Write((const unsigned char*)foldDomain, strlen(foldDomain));
    foldHasher.Write((const unsigned char*)&nCount, sizeof(nCount));

    for (size_t i = 0; i < vProofData.size(); i++) {
        // Per-proof contribution: H(challenge_i || proof_i || commit_i)
        CHash256 proofHasher;
        proofHasher.Write((const unsigned char*)&vChallenges[i], sizeof(uint256));
        if (!vProofData[i].empty()) {
            proofHasher.Write(vProofData[i].data(), vProofData[i].size());
        }
        if (!vCommitData[i].empty()) {
            proofHasher.Write(vCommitData[i].data(), vCommitData[i].size());
        }

        uint256 proofContribution;
        proofHasher.Finalize((unsigned char*)&proofContribution);

        // Add to fold transcript
        foldHasher.Write((const unsigned char*)&proofContribution, sizeof(uint256));
    }

    // The folded state is the final hash of all contributions
    uint256 foldResult;
    foldHasher.Finalize((unsigned char*)&foldResult);

    // Build the folded state blob:
    // [4 bytes: version] [4 bytes: count] [32 bytes: fsSeed] [32 bytes: foldResult]
    accum_out.vchFoldedState.clear();
    accum_out.vchFoldedState.reserve(72);

    // Version
    uint32_t ver = 1;
    accum_out.vchFoldedState.insert(accum_out.vchFoldedState.end(),
        (uint8_t*)&ver, (uint8_t*)&ver + 4);

    // Count
    accum_out.vchFoldedState.insert(accum_out.vchFoldedState.end(),
        (uint8_t*)&nCount, (uint8_t*)&nCount + 4);

    // Fiat-Shamir seed
    accum_out.vchFoldedState.insert(accum_out.vchFoldedState.end(),
        fsSeed.begin(), fsSeed.end());

    // Fold result
    accum_out.vchFoldedState.insert(accum_out.vchFoldedState.end(),
        foldResult.begin(), foldResult.end());

    // Set accumulator fields
    accum_out.nVersion = 0x01;
    accum_out.nProofCount = nCount;
    accum_out.ComputeHash();

    return true;
}

// =========================================================================
// VerifyBlockAccumulator
// =========================================================================
// Re-derives the accumulator from the block's proofs and checks it matches.
// This is called during ConnectBlock to verify the miner's coinbase commitment.

bool VerifyBlockAccumulator(
    const BlockProofAccumulator& accum,
    const std::vector<std::vector<uint8_t>>& vProofData,
    const std::vector<std::vector<uint8_t>>& vCommitData)
{
    // Version check
    if (accum.nVersion != 0x01) {
        return false;
    }

    // Proof count must match
    if (accum.nProofCount != static_cast<uint32_t>(vProofData.size())) {
        return false;
    }

    // Re-derive the accumulator from scratch
    BlockProofAccumulator recomputed;
    if (!AccumulateBlockRangeProofs(vProofData, vCommitData, recomputed)) {
        return false;
    }

    // Hash comparison (note: timing attacks on block validation are not a
    // practical concern, but we use direct comparison for simplicity)
    return recomputed.hashAccumulator == accum.hashAccumulator;
}
