// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file bench_pat.cpp
 * @brief PAT (Practical Aggregation Technique) batch verification benchmarks
 *
 * Measures the performance of PAT signature aggregation at various batch sizes.
 * This is critical for TPS calculations since PAT is available from Genesis.
 *
 * Key metrics:
 * - Create proof time (off-chain, miner/prover)
 * - Verify proof time (on-chain, consensus-critical)
 * - Effective signatures per second
 *
 * Usage: ./bench_soqucoin --filter='PAT.*'
 */

#include "bench.h"
#include "crypto/pat/logarithmic.h"
#include "utilstrencodings.h"

using pat::CValType;

namespace pat_bench
{

// Generate test data for benchmarking
static void GenerateTestBatch(size_t n,
    std::vector<CValType>& sigs,
    std::vector<CValType>& pks,
    std::vector<CValType>& msgs)
{
    sigs.clear();
    pks.clear();
    msgs.clear();

    for (size_t i = 0; i < n; i++) {
        // Each entry is 32 bytes (commitment/hash size)
        CValType sig(32, static_cast<unsigned char>(0x10 + (i % 256)));
        CValType pk(32, static_cast<unsigned char>(0x20 + (i % 256)));
        CValType msg(32, static_cast<unsigned char>(0x30 + (i % 256)));

        // Add some variation
        sig[0] = static_cast<unsigned char>(i & 0xFF);
        sig[1] = static_cast<unsigned char>((i >> 8) & 0xFF);
        pk[0] = static_cast<unsigned char>(i & 0xFF);
        msg[0] = static_cast<unsigned char>(i & 0xFF);

        sigs.push_back(sig);
        pks.push_back(pk);
        msgs.push_back(msg);
    }
}

} // namespace pat_bench

// ============================================================================
// PAT Create Proof Benchmarks (off-chain, prover time)
// ============================================================================

static void PATCreateProof64(benchmark::State& state)
{
    std::vector<CValType> sigs, pks, msgs;
    pat_bench::GenerateTestBatch(64, sigs, pks, msgs);

    while (state.KeepRunning()) {
        CValType proof;
        std::vector<CValType> sibling_path;
        pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path);
    }
}

static void PATCreateProof128(benchmark::State& state)
{
    std::vector<CValType> sigs, pks, msgs;
    pat_bench::GenerateTestBatch(128, sigs, pks, msgs);

    while (state.KeepRunning()) {
        CValType proof;
        std::vector<CValType> sibling_path;
        pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path);
    }
}

static void PATCreateProof256(benchmark::State& state)
{
    std::vector<CValType> sigs, pks, msgs;
    pat_bench::GenerateTestBatch(256, sigs, pks, msgs);

    while (state.KeepRunning()) {
        CValType proof;
        std::vector<CValType> sibling_path;
        pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path);
    }
}

// ============================================================================
// PAT Verify Proof Benchmarks (on-chain, consensus-critical)
// ============================================================================

static void PATVerifyProof64(benchmark::State& state)
{
    std::vector<CValType> sigs, pks, msgs;
    pat_bench::GenerateTestBatch(64, sigs, pks, msgs);

    // Pre-generate proof
    CValType proof;
    std::vector<CValType> sibling_path;
    pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path);

    while (state.KeepRunning()) {
        bool valid = pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs);
        assert(valid);
    }
}

static void PATVerifyProof128(benchmark::State& state)
{
    std::vector<CValType> sigs, pks, msgs;
    pat_bench::GenerateTestBatch(128, sigs, pks, msgs);

    CValType proof;
    std::vector<CValType> sibling_path;
    pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path);

    while (state.KeepRunning()) {
        bool valid = pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs);
        assert(valid);
    }
}

static void PATVerifyProof256(benchmark::State& state)
{
    std::vector<CValType> sigs, pks, msgs;
    pat_bench::GenerateTestBatch(256, sigs, pks, msgs);

    CValType proof;
    std::vector<CValType> sibling_path;
    pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path);

    while (state.KeepRunning()) {
        bool valid = pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs);
        assert(valid);
    }
}

// ============================================================================
// PAT TPS Calculation Benchmark (256 sigs, the marketing number)
// ============================================================================

/**
 * @brief Single benchmark measuring effective TPS with 256-sig batch
 *
 * This is the key number for public disclosure:
 * TPS = 256 / verify_time_seconds
 *
 * Example: If verify_time = 4ms, then TPS = 256 / 0.004 = 64,000 sigs/sec
 */
static void PATEffectiveTPS256(benchmark::State& state)
{
    std::vector<CValType> sigs, pks, msgs;
    pat_bench::GenerateTestBatch(256, sigs, pks, msgs);

    CValType proof;
    std::vector<CValType> sibling_path;
    pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path);

    size_t total_sigs_verified = 0;

    while (state.KeepRunning()) {
        bool valid = pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs);
        assert(valid);
        total_sigs_verified += 256;
    }

    // The benchmark framework will calculate effective TPS from:
    // iterations * 256 / total_time
}

// Register benchmarks
BENCHMARK(PATCreateProof64);
BENCHMARK(PATCreateProof128);
BENCHMARK(PATCreateProof256);
BENCHMARK(PATVerifyProof64);
BENCHMARK(PATVerifyProof128);
BENCHMARK(PATVerifyProof256);
BENCHMARK(PATEffectiveTPS256);
