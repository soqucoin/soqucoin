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

// Generate a test batch instance with random data
static void GenerateTestBatch(LatticeFoldVerifier::BatchInstance& instance,
    LatticeFoldVerifier::Proof& proof)
{
    // Generate random batch_hash (simulating Merkle root of 512 sigs)
    GetRandBytes(instance.batch_hash.data(), 32);

    // Generate random t_coeffs (folded t vector)
    for (int i = 0; i < 8; ++i) {
        uint64_t lo = GetRand(UINT64_MAX);
        uint64_t hi = GetRand(UINT64_MAX);
        instance.t_coeffs[i] = LatticeFoldVerifier::Fp(lo, hi);
    }

    // Generate random challenge c
    uint64_t c_lo = GetRand(UINT64_MAX);
    uint64_t c_hi = GetRand(UINT64_MAX);
    instance.c = LatticeFoldVerifier::Fp(c_lo, c_hi);

    // Generate sumcheck proof (8 rounds * 64 elements = 512 elements)
    proof.sumcheck_proof.resize(512);
    for (size_t i = 0; i < 512; ++i) {
        uint64_t lo = GetRand(UINT64_MAX);
        uint64_t hi = GetRand(UINT64_MAX);
        proof.sumcheck_proof[i] = LatticeFoldVerifier::Fp(lo, hi);
    }

    // Generate range openings (16 elements)
    for (int i = 0; i < 16; ++i) {
        uint64_t lo = GetRand(UINT64_MAX);
        uint64_t hi = GetRand(UINT64_MAX);
        proof.range_openings[i] = LatticeFoldVerifier::Fp(lo, hi);
    }

    // Generate folded commitment (8 elements) - must match t_coeffs for valid proof
    for (int i = 0; i < 8; ++i) {
        proof.folded_commitment[i] = instance.t_coeffs[i];
    }

    // Generate double openings (4 elements)
    for (int i = 0; i < 4; ++i) {
        uint64_t lo = GetRand(UINT64_MAX);
        uint64_t hi = GetRand(UINT64_MAX);
        proof.double_openings[i] = LatticeFoldVerifier::Fp(lo, hi);
    }

    // Generate Fiat-Shamir seed
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
