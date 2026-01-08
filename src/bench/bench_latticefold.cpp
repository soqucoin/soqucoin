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
#include "crypto/latticefold/verifier.h"
#include "crypto/sha256.h"
#include "random.h"

namespace latticefold_bench
{

// Generate test data that exercises the FULL verification path
// Crafted to pass intermediate checks, fails only at final Fiat-Shamir seed check
static void GenerateTestBatch(LatticeFoldVerifier::BatchInstance& instance,
    LatticeFoldVerifier::Proof& proof)
{
    // Generate random batch_hash
    GetRandBytes(instance.batch_hash.data(), 32);

    // Generate random t_coeffs (these will match folded_commitment)
    for (int i = 0; i < 8; ++i) {
        uint64_t lo = GetRand(UINT64_MAX);
        uint64_t hi = GetRand(UINT64_MAX);
        instance.t_coeffs[i] = LatticeFoldVerifier::Fp(lo, hi);
    }

    // Generate challenge c
    uint64_t c_lo = GetRand(UINT64_MAX);
    uint64_t c_hi = GetRand(UINT64_MAX);
    instance.c = LatticeFoldVerifier::Fp(c_lo, c_hi);

    // ---- CRAFTED DATA TO PASS INTERMEDIATE CHECKS ----

    // 1. Range openings: all zeros → sum = 0 → passes VerifyRangeAlgebraic
    for (int i = 0; i < 16; ++i) {
        proof.range_openings[i] = LatticeFoldVerifier::Fp::zero();
    }

    // 2. Double openings: set [0]=[2] and [1]=[3] → lhs==rhs → passes VerifyDoubleCommitmentOpening
    uint64_t d_lo = GetRand(UINT64_MAX);
    uint64_t d_hi = GetRand(UINT64_MAX);
    proof.double_openings[0] = LatticeFoldVerifier::Fp(d_lo, d_hi);
    proof.double_openings[1] = LatticeFoldVerifier::Fp(d_lo ^ 0x1234, d_hi ^ 0x5678);
    proof.double_openings[2] = proof.double_openings[0];
    proof.double_openings[3] = proof.double_openings[1];

    // 3. Sumcheck: set first element = claim, rest = 0 → sum==claim → passes VerifySumcheckRound
    proof.sumcheck_proof.resize(512);
    LatticeFoldVerifier::Fp claim = instance.c;
    for (int round = 0; round < 8; ++round) {
        size_t offset = round * 64;
        proof.sumcheck_proof[offset] = claim;
        for (int i = 1; i < 64; ++i) {
            proof.sumcheck_proof[offset + i] = LatticeFoldVerifier::Fp::zero();
        }
        claim = proof.sumcheck_proof[offset]; // next claim = first element
    }

    // 4. Folded commitment: must match t_coeffs → passes commitment check
    for (int i = 0; i < 8; ++i) {
        proof.folded_commitment[i] = instance.t_coeffs[i];
    }

    // 5. Fiat-Shamir seed: random → fails only at final check (all crypto computed)
    GetRandBytes(proof.fiat_shamir_seed.begin(), 32);
}

} // namespace latticefold_bench

/**
 * @brief Benchmark LatticeFold+ 512-signature batch verification
 *
 * This is the key metric for Stage 2 TPS claims:
 * - Verifies 512 Dilithium signatures in a single proof
 * - Replaces 512 individual Dilithium verifications (~90ms)
 * - Target: <2ms for production viability
 */
static void LatticeFoldVerify512(benchmark::State& state)
{
    LatticeFoldVerifier::BatchInstance instance;
    LatticeFoldVerifier::Proof proof;
    latticefold_bench::GenerateTestBatch(instance, proof);

    while (state.KeepRunning()) {
        // Note: This will fail verification (random data), but we're measuring
        // the computational cost of the verification algorithm itself.
        // The failure happens at the final check, after all crypto operations.
        (void)LatticeFoldVerifier::VerifyDilithiumBatch(instance, proof);
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
    // Create a valid-format proof (will fail verification, but exercises parser)
    // Min size = 176 (header) + 8192 (sumcheck) + 480 (footer) = 8848 bytes
    std::vector<unsigned char> proof(8848, 0);

    // Fill with random data
    GetRandBytes(proof.data(), proof.size());

    while (state.KeepRunning()) {
        (void)EvalCheckFoldProof(proof);
    }
}

// Register benchmarks
BENCHMARK(LatticeFoldVerify512);
BENCHMARK(LatticeFoldOpcode);
