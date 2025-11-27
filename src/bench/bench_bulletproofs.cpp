// Copyright (c) 2025 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"
#include "random.h"
#include "zk/bulletproofs.h"

static void Bulletproofs_GenRangeProof(benchmark::State& state)
{
    zk::InitRangeProofContext();
    CAmount value = 50 * COIN;
    uint256 blinding;
    GetStrongRandBytes(blinding.begin(), 32);
    zk::Commitment commitment;
    zk::GenerateCommitment(value, blinding, commitment);

    uint256 nonce = blinding; // Use blinding as nonce for bench

    while (state.KeepRunning()) {
        zk::RangeProof proof;
        zk::GenRangeProof(value, blinding, nonce, commitment, proof);
    }
}

static void Bulletproofs_VerifyRangeProof(benchmark::State& state)
{
    zk::InitRangeProofContext();
    CAmount value = 50 * COIN;
    uint256 blinding;
    GetStrongRandBytes(blinding.begin(), 32);
    zk::Commitment commitment;
    zk::GenerateCommitment(value, blinding, commitment);

    uint256 nonce = blinding;
    zk::RangeProof proof;
    zk::GenRangeProof(value, blinding, nonce, commitment, proof);

    while (state.KeepRunning()) {
        zk::VerifyRangeProof(proof, commitment);
    }
}

BENCHMARK(Bulletproofs_GenRangeProof);
BENCHMARK(Bulletproofs_VerifyRangeProof);
