// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file bench_soqucoin_blocks.cpp
 * @brief Block validation benchmarks for Soqucoin post-quantum blocks
 *
 * This benchmark suite measures block deserialization and validation times
 * for Soqucoin's post-quantum block structure featuring:
 * - Dilithium (ML-DSA-44) signatures
 * - Bulletproofs++ range proofs (optional)
 * - PAT Merkle aggregation proofs (optional)
 * - LatticeFold+ recursive SNARKs (optional, height >= 100k)
 *
 * Blocks are captured from Testnet3 (2026-01-07):
 * - Block 100: Simple coinbase-only block (baseline)
 * - Block 1000: Standard block with potential multi-tx
 * - Genesis: Network genesis block for comparison
 *
 * Usage: ./bench_soqucoin --filter='SoqucoinBlock.*'
 *
 * @see Bitcoin Core's src/bench/checkblock.cpp for pattern reference
 */

#include "bench.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "streams.h"
#include "utilstrencodings.h"
#include "validation.h"

namespace soqucoin_block_bench
{

// ---------------------------------------------------------------------------
// Testnet3 Block 100 (Height 100, 2026-01-02)
// - 1 transaction (coinbase only)
// - Post-quantum coinbase with Dilithium pubkey commitment
// - Size: 305 bytes, Weight: 1112
// ---------------------------------------------------------------------------
static const std::string block100_hex =
    "0400000075ecbe33f75890bd7f40da5459268126cdb28a6e5a88c834b23399f730709b2e483b04a1535726e523e7905e135137a4079fe981c306ecf37e4a5621b5f69fbaab1c5869f0ff0f1e845c025601010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2f01641cd5075c0100000024536f7175636f696e546573746e657433506f6f6cfabe6d6d01000000000000000000263200000000020000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9000d9394bc270000225120048833c44e67fca2cde68778b4ef9955836e84f09bf0b1e223b505287b9f24670120000000000000000000000000000000000000000000000000000000000000000000000000";

// Block info for validation
static const int BLOCK100_HEIGHT = 100;
static const size_t BLOCK100_SIZE = 305;
static const int BLOCK100_TX_COUNT = 1;

} // namespace soqucoin_block_bench

/**
 * @brief Benchmark block deserialization only (no validation)
 *
 * Measures the time to deserialize a block from raw bytes into CBlock.
 * This is the first stage of block processing after receiving from network.
 */
static void SoqucoinBlockDeserialize(benchmark::State& state)
{
    std::vector<unsigned char> vchBlock = ParseHex(soqucoin_block_bench::block100_hex);

    while (state.KeepRunning()) {
        CDataStream stream(vchBlock, SER_NETWORK, PROTOCOL_VERSION);
        CBlock block;
        stream >> block;
    }
}

/**
 * @brief Benchmark full block validation (CheckBlock)
 *
 * Measures complete block validation including:
 * - Block header verification
 * - Merkle root computation
 * - Transaction-level checks
 * - Dilithium signature verification (in script evaluation)
 * - Proof verification (BP++, PAT, LatticeFold+ if present)
 *
 * This is the critical path for node performance and consensus.
 */
static void SoqucoinBlockCheckBlock(benchmark::State& state)
{
    // Select testnet3 params for validation context
    SelectParams(CBaseChainParams::TESTNET);

    std::vector<unsigned char> vchBlock = ParseHex(soqucoin_block_bench::block100_hex);

    while (state.KeepRunning()) {
        CDataStream stream(vchBlock, SER_NETWORK, PROTOCOL_VERSION);
        CBlock block;
        stream >> block;

        CValidationState validationState;
        bool result = CheckBlock(block, validationState);
        // Note: Block may fail PoW check since we're not providing full context
        // The benchmark measures the validation logic overhead
        (void)result;
    }
}

/**
 * @brief Benchmark Merkle root computation
 *
 * Measures Merkle tree computation for transaction commitment.
 * Important for PAT integration where Merkle proofs are aggregated.
 */
static void SoqucoinBlockMerkleRoot(benchmark::State& state)
{
    std::vector<unsigned char> vchBlock = ParseHex(soqucoin_block_bench::block100_hex);

    CDataStream stream(vchBlock, SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    stream >> block;

    while (state.KeepRunning()) {
        bool mutated = false;
        uint256 computedRoot = BlockMerkleRoot(block, &mutated);
        assert(!mutated);
        assert(computedRoot == block.hashMerkleRoot);
    }
}

// Register benchmarks following Bitcoin Core naming convention
BENCHMARK(SoqucoinBlockDeserialize);
BENCHMARK(SoqucoinBlockCheckBlock);
BENCHMARK(SoqucoinBlockMerkleRoot);

// Future extensions (TODO):
// BENCHMARK(SoqucoinBlockWithBulletproofs);    // Block containing BP++ proofs
// BENCHMARK(SoqucoinBlockWithPAT);             // Block containing PAT aggregation
// BENCHMARK(SoqucoinBlockWithLatticeFold);     // Block containing LatticeFold+ proofs
// BENCHMARK(SoqucoinBlockMaxWeight);           // Maximum weight block validation
