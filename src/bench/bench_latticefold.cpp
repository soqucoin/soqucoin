// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file bench_latticefold.cpp
 * @brief LatticeFold+ 512-signature batch verification benchmark
 *
 * Measures the performance of LatticeFold+ recursive proof verification
 * for Dilithium signature batches. This is the key TPS metric for Stage 2.
 *
 * Usage: ./bench_soqucoin --filter='LatticeFold.*'
 */

#include "bench.h"
#include "crypto/common.h"
#include "crypto/latticefold/verifier.h"
#include "crypto/sha256.h"
#include "random.h"

#include <cstring>

namespace latticefold_bench
{

using Fp = LatticeFoldVerifier::Fp;

// Local replica of the verifier's Fiat-Shamir sponge (verifier.cpp,
// FiatShamirChallenge). The verifier keeps its sponge private; the fixture
// needs an identical copy to precompute the final seed for a proof that
// satisfies every check. If the verifier's sponge changes, this must change
// with it (the benchmark asserts success, so drift fails loudly).
static Fp BenchFiatShamir(const std::vector<Fp>& transcript)
{
    CSHA256 hasher;
    for (const auto& elem : transcript) {
        uint8_t buf[16];
        std::memcpy(buf, elem.limbs.data(), 16);
        hasher.Write(buf, 16);
    }
    uint8_t out[32];
    hasher.Finalize(out);
    return Fp(ReadLE64(out), ReadLE64(out + 8));
}

// Generate an instance/proof pair that SATISFIES the post-remediation
// verifier (SOQ-A005 external binding, SOQ-D001 per-row Ajtai check), so the
// benchmark measures the full verification path ending in `return true`.
//
// Construction:
//   - t_coeffs = 0 satisfies both the per-row check (A*0 == 0) and the final
//     folded_commitment == t_coeffs check simultaneously.
//   - all-zero range openings satisfy the range identity for any challenge.
//   - mirrored double openings ([2]=[0], [3]=[1]) satisfy lhs == rhs for any r.
//   - each sumcheck round is [claim, 0, ..., 0], so sum == claim and
//     next_claim == claim for all 8 rounds.
//   - the final Fiat-Shamir seed is computed by replaying the verifier's
//     transcript exactly.
// Wall-clock cost is data-independent (the same field and hash operations
// execute regardless of values), so this measures the true cost of a
// successful verification.
static void GenerateTestBatch(LatticeFoldVerifier::BatchInstance& instance,
    LatticeFoldVerifier::Proof& proof)
{
    // External binding context (SOQ-A005): random transaction/UTXO/batch context
    GetRandBytes(instance.sighash.begin(), 32);
    GetRandBytes(instance.pubkey_hash.data(), 32);
    GetRandBytes(instance.batch_hash.data(), 32);

    // 1. t_coeffs = 0: satisfies per-row A*t == folded_commitment (both zero,
    //    SOQ-D001) and the final folded_commitment == t_coeffs check.
    for (int i = 0; i < 8; ++i) {
        instance.t_coeffs[i] = Fp::zero();
        proof.folded_commitment[i] = Fp::zero();
    }

    // Random folded challenge c (the sumcheck claim)
    instance.c = Fp(GetRand(UINT64_MAX), GetRand(UINT64_MAX));

    // 2. Range openings: all zeros satisfy the range identity for any challenge
    for (int i = 0; i < 16; ++i) {
        proof.range_openings[i] = Fp::zero();
    }

    // 3. Double openings: [2]=[0], [3]=[1] gives lhs == rhs for any r
    proof.double_openings[0] = Fp(GetRand(UINT64_MAX), GetRand(UINT64_MAX));
    proof.double_openings[1] = Fp(GetRand(UINT64_MAX), GetRand(UINT64_MAX));
    proof.double_openings[2] = proof.double_openings[0];
    proof.double_openings[3] = proof.double_openings[1];

    // 4. Sumcheck: [claim, 0, ..., 0] per round; sum == claim and
    //    next_claim == claim, so the claim is invariant across all 8 rounds
    proof.sumcheck_proof.resize(512);
    for (int round = 0; round < 8; ++round) {
        const size_t offset = round * 64;
        proof.sumcheck_proof[offset] = instance.c;
        for (int i = 1; i < 64; ++i) {
            proof.sumcheck_proof[offset + i] = Fp::zero();
        }
    }

    // 5. Final Fiat-Shamir seed: replay the verifier's transcript exactly
    //    (VerifyDilithiumBatch, verifier.cpp) and store the resulting seed.
    std::vector<Fp> tr;
    tr.reserve(256);
    tr.push_back(Fp(ReadLE64(instance.sighash.begin()),
                    ReadLE64(instance.sighash.begin() + 8)));
    tr.push_back(Fp(ReadLE64(instance.pubkey_hash.data()),
                    ReadLE64(instance.pubkey_hash.data() + 8)));
    tr.push_back(Fp(ReadLE64(instance.batch_hash.data()),
                    ReadLE64(instance.batch_hash.data() + 8)));

    (void)BenchFiatShamir(tr); // r_range (zeros pass for any challenge)
    tr.insert(tr.end(), proof.range_openings.begin(), proof.range_openings.end());

    (void)BenchFiatShamir(tr); // r_double (mirrored openings pass for any r)
    tr.insert(tr.end(), proof.double_openings.begin(), proof.double_openings.end());

    for (int round = 0; round < 8; ++round) {
        const size_t offset = round * 64;
        tr.insert(tr.end(),
                  proof.sumcheck_proof.begin() + offset,
                  proof.sumcheck_proof.begin() + offset + 64);
        Fp next_r = BenchFiatShamir(tr);
        tr.push_back(next_r);
    }

    const Fp seed = BenchFiatShamir(tr);
    std::memset(proof.fiat_shamir_seed.begin(), 0, 32);
    WriteLE64(proof.fiat_shamir_seed.begin(), seed.limbs[0]);
    WriteLE64(proof.fiat_shamir_seed.begin() + 8, seed.limbs[1]);
}

} // namespace latticefold_bench

/**
 * @brief Benchmark LatticeFold+ full-path proof verification (512-sig batch shape)
 *
 * Measures a verification that runs every phase and returns true: external
 * binding absorption, range identity, per-row Ajtai double-commitment check,
 * 8 sumcheck rounds with transcript growth, and the final Fiat-Shamir seed
 * comparison. The fixture satisfies the post-remediation verifier by
 * construction (see GenerateTestBatch); the loop asserts success so any
 * verifier change that breaks the fixture fails loudly instead of silently
 * benchmarking an early abort.
 */
static void LatticeFoldVerify512(benchmark::State& state)
{
    LatticeFoldVerifier::BatchInstance instance;
    LatticeFoldVerifier::Proof proof;
    latticefold_bench::GenerateTestBatch(instance, proof);

    // Derive consensus matrix A (same as production)
    std::array<std::array<LatticeFoldVerifier::Fp, MATRIX_A_COLS>, MATRIX_A_ROWS> matrixA;
    LatticeFoldVerifier::DeriveConsensusMatrixA(matrixA);

    // The fixture must satisfy the current verifier; abort loudly if not.
    assert(LatticeFoldVerifier::VerifyDilithiumBatch(instance, proof, matrixA));

    while (state.KeepRunning()) {
        bool valid = LatticeFoldVerifier::VerifyDilithiumBatch(instance, proof, matrixA);
        assert(valid);
    }
}

/**
 * @brief Benchmark EvalCheckFoldProof (OP_CHECKFOLDPROOF opcode)
 *
 * This is what the script interpreter calls for on-chain verification.
 * Includes proof parsing overhead.
 */
static void LatticeFoldOpcode(benchmark::State& state)
{
    // DoS-path metric: cost of parsing and rejecting a malformed proof blob.
    // This deliberately measures the attacker-facing early-abort path (what a
    // node pays per garbage proof), NOT a successful verification; see
    // LatticeFoldVerify512 for the full-path cost.
    // Min size = 176 (header) + 8192 (sumcheck) + 480 (footer) = 8848 bytes
    std::vector<unsigned char> proof(8848, 0);

    // Fill with random data
    GetRandBytes(proof.data(), proof.size());

    // Create dummy external binding parameters (matching post-SOQ-A005 API)
    uint256 sighash;
    GetRandBytes(sighash.begin(), 32);
    std::array<uint8_t, 32> pubkey_hash{};
    GetRandBytes(pubkey_hash.data(), 32);
    std::vector<valtype> dilithium_sigs;  // empty — proof will fail, but exercises parser

    while (state.KeepRunning()) {
        (void)EvalCheckFoldProof(proof, sighash, pubkey_hash, dilithium_sigs);
    }
}

// Register benchmarks
BENCHMARK(LatticeFoldVerify512);
BENCHMARK(LatticeFoldOpcode);

// =========================================================================
// SOQ-ARCH-001 Phase 2.3: Block Accumulator Benchmarks
// Measures the cost of per-block range proof accumulation.
// Target: < 5ms for 25 proofs (typical block), < 50ms for 100 proofs (heavy block)
// =========================================================================

#include "consensus/block_accumulator.h"

static std::vector<uint8_t> MakeBenchProof(int seed, size_t size = 4096)
{
    std::vector<uint8_t> proof(size);
    for (size_t i = 0; i < size; i++)
        proof[i] = static_cast<uint8_t>((seed * 17 + i * 31) & 0xFF);
    return proof;
}

static std::vector<uint8_t> MakeBenchCommit(int seed, size_t size = 3072)
{
    std::vector<uint8_t> commit(size);
    for (size_t i = 0; i < size; i++)
        commit[i] = static_cast<uint8_t>((seed * 13 + i * 37) & 0xFF);
    return commit;
}

static void BlockAccumulate1(benchmark::State& state)
{
    std::vector<std::vector<uint8_t>> proofs = {MakeBenchProof(1)};
    std::vector<std::vector<uint8_t>> commits = {MakeBenchCommit(1)};
    while (state.KeepRunning()) {
        BlockProofAccumulator acc;
        AccumulateBlockRangeProofs(proofs, commits, acc);
    }
}

static void BlockAccumulate10(benchmark::State& state)
{
    std::vector<std::vector<uint8_t>> proofs, commits;
    for (int i = 0; i < 10; i++) {
        proofs.push_back(MakeBenchProof(i));
        commits.push_back(MakeBenchCommit(i));
    }
    while (state.KeepRunning()) {
        BlockProofAccumulator acc;
        AccumulateBlockRangeProofs(proofs, commits, acc);
    }
}

static void BlockAccumulate25(benchmark::State& state)
{
    std::vector<std::vector<uint8_t>> proofs, commits;
    for (int i = 0; i < 25; i++) {
        proofs.push_back(MakeBenchProof(i));
        commits.push_back(MakeBenchCommit(i));
    }
    while (state.KeepRunning()) {
        BlockProofAccumulator acc;
        AccumulateBlockRangeProofs(proofs, commits, acc);
    }
}

static void BlockAccumulate100(benchmark::State& state)
{
    std::vector<std::vector<uint8_t>> proofs, commits;
    for (int i = 0; i < 100; i++) {
        proofs.push_back(MakeBenchProof(i));
        commits.push_back(MakeBenchCommit(i));
    }
    while (state.KeepRunning()) {
        BlockProofAccumulator acc;
        AccumulateBlockRangeProofs(proofs, commits, acc);
    }
}

static void BlockAccumVerify25(benchmark::State& state)
{
    std::vector<std::vector<uint8_t>> proofs, commits;
    for (int i = 0; i < 25; i++) {
        proofs.push_back(MakeBenchProof(i));
        commits.push_back(MakeBenchCommit(i));
    }
    BlockProofAccumulator acc;
    AccumulateBlockRangeProofs(proofs, commits, acc);

    while (state.KeepRunning()) {
        VerifyBlockAccumulator(acc, proofs, commits);
    }
}

BENCHMARK(BlockAccumulate1);
BENCHMARK(BlockAccumulate10);
BENCHMARK(BlockAccumulate25);
BENCHMARK(BlockAccumulate100);
BENCHMARK(BlockAccumVerify25);
