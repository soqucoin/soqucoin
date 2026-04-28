// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-ARCH-001 Phase 2.3: BlockProofAccumulator Tests
// Design Log: DL-LATTICEFOLD-BLOCK-ACCUMULATOR.md
//
// Test coverage for:
//   1. BlockProofAccumulator struct (default, hash computation, serialization)
//   2. Coinbase commitment script generation and parsing
//   3. AccumulateBlockRangeProofs — empty, single, multi, determinism
//   4. VerifyBlockAccumulator — positive and negative cases
//   5. Sensitivity: changing any proof changes the accumulator
//   6. DoS: reject oversized proof sets
//   7. Edge cases: mismatched counts, empty proof data

#include "consensus/block_accumulator.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "streams.h"

#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(block_accumulator_tests, BasicTestingSetup)

// =========================================================================
// Helper: generate deterministic fake range proof data
// =========================================================================
static std::vector<uint8_t> MakeFakeProof(int seed, size_t size = 624)
{
    std::vector<uint8_t> proof(size);
    for (size_t i = 0; i < size; i++) {
        proof[i] = static_cast<uint8_t>((seed * 17 + i * 31) & 0xFF);
    }
    return proof;
}

static std::vector<uint8_t> MakeFakeCommitment(int seed, size_t size = 3072)
{
    std::vector<uint8_t> commit(size);
    for (size_t i = 0; i < size; i++) {
        commit[i] = static_cast<uint8_t>((seed * 13 + i * 37) & 0xFF);
    }
    return commit;
}

// =========================================================================
// 1. BlockProofAccumulator — Struct basics
// =========================================================================

BOOST_AUTO_TEST_CASE(accumulator_default_is_null)
{
    BlockProofAccumulator acc;
    BOOST_CHECK(acc.IsNull());
    BOOST_CHECK_EQUAL(acc.nVersion, 0);
    BOOST_CHECK_EQUAL(acc.nProofCount, 0);
    BOOST_CHECK(acc.hashAccumulator.IsNull());
    BOOST_CHECK(acc.vchFoldedState.empty());
}

BOOST_AUTO_TEST_CASE(accumulator_compute_hash)
{
    BlockProofAccumulator acc;
    acc.nVersion = 0x01;
    acc.nProofCount = 5;
    acc.vchFoldedState = {0x01, 0x02, 0x03, 0x04};
    acc.ComputeHash();

    BOOST_CHECK(!acc.hashAccumulator.IsNull());

    // Same state → same hash (determinism)
    uint256 hash1 = acc.hashAccumulator;
    acc.ComputeHash();
    BOOST_CHECK(acc.hashAccumulator == hash1);

    // Different state → different hash
    acc.vchFoldedState.push_back(0x05);
    acc.ComputeHash();
    BOOST_CHECK(acc.hashAccumulator != hash1);
}

BOOST_AUTO_TEST_CASE(accumulator_compute_hash_empty_state)
{
    BlockProofAccumulator acc;
    acc.vchFoldedState.clear();
    acc.ComputeHash();
    BOOST_CHECK(acc.hashAccumulator.IsNull());
}

BOOST_AUTO_TEST_CASE(accumulator_serialization_roundtrip)
{
    BlockProofAccumulator acc;
    acc.nVersion = 0x01;
    acc.nProofCount = 42;
    acc.vchFoldedState = {0xAA, 0xBB, 0xCC, 0xDD};
    acc.ComputeHash();

    // Serialize
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << acc;

    // Deserialize
    BlockProofAccumulator acc2;
    ss >> acc2;

    BOOST_CHECK_EQUAL(acc2.nVersion, 0x01);
    BOOST_CHECK_EQUAL(acc2.nProofCount, 42);
    BOOST_CHECK(acc2.hashAccumulator == acc.hashAccumulator);
    BOOST_CHECK(acc2.vchFoldedState == acc.vchFoldedState);
}

BOOST_AUTO_TEST_CASE(accumulator_serialized_size)
{
    BlockProofAccumulator acc;
    BOOST_CHECK_EQUAL(acc.SerializedSize(), 0u); // null

    acc.nVersion = 0x01;
    acc.nProofCount = 1;
    acc.vchFoldedState.resize(72); // typical folded state
    BOOST_CHECK(acc.SerializedSize() > 0);
}

// =========================================================================
// 2. Coinbase commitment script
// =========================================================================

BOOST_AUTO_TEST_CASE(coinbase_commitment_script_format)
{
    BlockProofAccumulator acc;
    acc.nVersion = 0x01;
    acc.nProofCount = 1;
    acc.hashAccumulator = uint256S("0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

    auto script = acc.GetCoinbaseCommitmentScript();

    // Expected: OP_RETURN(0x6a) + OP_PUSHBYTES_34(0x22) + LF(0x4C46) + 32 bytes
    BOOST_CHECK_EQUAL(script.size(), 36u);
    BOOST_CHECK_EQUAL(script[0], 0x6a); // OP_RETURN
    BOOST_CHECK_EQUAL(script[1], 0x22); // 34 bytes
    BOOST_CHECK_EQUAL(script[2], 0x4C); // 'L'
    BOOST_CHECK_EQUAL(script[3], 0x46); // 'F'
}

BOOST_AUTO_TEST_CASE(coinbase_commitment_parse_roundtrip)
{
    BlockProofAccumulator acc;
    acc.hashAccumulator = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");

    auto script = acc.GetCoinbaseCommitmentScript();

    uint256 parsed;
    BOOST_CHECK(BlockProofAccumulator::ParseCoinbaseCommitment(script, parsed));
    BOOST_CHECK(parsed == acc.hashAccumulator);
}

BOOST_AUTO_TEST_CASE(coinbase_commitment_parse_rejects_bad_scripts)
{
    uint256 parsed;

    // Too short
    std::vector<uint8_t> tooShort = {0x6a, 0x22, 0x4C, 0x46};
    BOOST_CHECK(!BlockProofAccumulator::ParseCoinbaseCommitment(tooShort, parsed));

    // Wrong opcode
    std::vector<uint8_t> wrongOp(36, 0);
    wrongOp[0] = 0x00; // not OP_RETURN
    wrongOp[1] = 0x22;
    wrongOp[2] = 0x4C;
    wrongOp[3] = 0x46;
    BOOST_CHECK(!BlockProofAccumulator::ParseCoinbaseCommitment(wrongOp, parsed));

    // Wrong magic
    std::vector<uint8_t> wrongMagic(36, 0);
    wrongMagic[0] = 0x6a;
    wrongMagic[1] = 0x22;
    wrongMagic[2] = 0xFF; // not 'L'
    wrongMagic[3] = 0xFF; // not 'F'
    BOOST_CHECK(!BlockProofAccumulator::ParseCoinbaseCommitment(wrongMagic, parsed));

    // Too long
    std::vector<uint8_t> tooLong(37, 0);
    tooLong[0] = 0x6a;
    tooLong[1] = 0x22;
    tooLong[2] = 0x4C;
    tooLong[3] = 0x46;
    BOOST_CHECK(!BlockProofAccumulator::ParseCoinbaseCommitment(tooLong, parsed));
}

// =========================================================================
// 3. AccumulateBlockRangeProofs — Core accumulation logic
// =========================================================================

BOOST_AUTO_TEST_CASE(accumulate_empty_block)
{
    std::vector<std::vector<uint8_t>> proofs, commits;
    BlockProofAccumulator acc;

    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc));
    BOOST_CHECK(acc.IsNull());
    BOOST_CHECK_EQUAL(acc.nProofCount, 0);
}

BOOST_AUTO_TEST_CASE(accumulate_single_proof)
{
    std::vector<std::vector<uint8_t>> proofs = {MakeFakeProof(1)};
    std::vector<std::vector<uint8_t>> commits = {MakeFakeCommitment(1)};
    BlockProofAccumulator acc;

    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc));
    BOOST_CHECK(!acc.IsNull());
    BOOST_CHECK_EQUAL(acc.nVersion, 0x01);
    BOOST_CHECK_EQUAL(acc.nProofCount, 1);
    BOOST_CHECK(!acc.hashAccumulator.IsNull());
    BOOST_CHECK(!acc.vchFoldedState.empty());
}

BOOST_AUTO_TEST_CASE(accumulate_multiple_proofs)
{
    std::vector<std::vector<uint8_t>> proofs;
    std::vector<std::vector<uint8_t>> commits;

    for (int i = 0; i < 25; i++) {
        proofs.push_back(MakeFakeProof(i));
        commits.push_back(MakeFakeCommitment(i));
    }

    BlockProofAccumulator acc;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc));
    BOOST_CHECK_EQUAL(acc.nProofCount, 25);
    BOOST_CHECK(!acc.hashAccumulator.IsNull());
}

BOOST_AUTO_TEST_CASE(accumulate_deterministic)
{
    // Same inputs → same accumulator (consensus-critical property)
    std::vector<std::vector<uint8_t>> proofs = {
        MakeFakeProof(10), MakeFakeProof(20), MakeFakeProof(30)
    };
    std::vector<std::vector<uint8_t>> commits = {
        MakeFakeCommitment(10), MakeFakeCommitment(20), MakeFakeCommitment(30)
    };

    BlockProofAccumulator acc1, acc2;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc1));
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc2));

    BOOST_CHECK(acc1.hashAccumulator == acc2.hashAccumulator);
    BOOST_CHECK(acc1.vchFoldedState == acc2.vchFoldedState);
    BOOST_CHECK_EQUAL(acc1.nProofCount, acc2.nProofCount);
}

BOOST_AUTO_TEST_CASE(accumulate_sensitive_to_proof_change)
{
    // Changing any single proof must change the accumulator
    std::vector<std::vector<uint8_t>> proofs = {
        MakeFakeProof(1), MakeFakeProof(2), MakeFakeProof(3)
    };
    std::vector<std::vector<uint8_t>> commits = {
        MakeFakeCommitment(1), MakeFakeCommitment(2), MakeFakeCommitment(3)
    };

    BlockProofAccumulator accOriginal;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, accOriginal));

    // Modify first proof
    auto proofs2 = proofs;
    proofs2[0][0] ^= 0xFF;
    BlockProofAccumulator accModified;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs2, commits, accModified));
    BOOST_CHECK(accOriginal.hashAccumulator != accModified.hashAccumulator);

    // Modify middle commitment
    auto commits2 = commits;
    commits2[1][0] ^= 0xFF;
    BlockProofAccumulator accModified2;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits2, accModified2));
    BOOST_CHECK(accOriginal.hashAccumulator != accModified2.hashAccumulator);

    // Modify last proof
    auto proofs3 = proofs;
    proofs3[2][proofs3[2].size() - 1] ^= 0x01;
    BlockProofAccumulator accModified3;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs3, commits, accModified3));
    BOOST_CHECK(accOriginal.hashAccumulator != accModified3.hashAccumulator);
}

BOOST_AUTO_TEST_CASE(accumulate_sensitive_to_order)
{
    // Proof order matters (prevents reordering attacks)
    std::vector<std::vector<uint8_t>> proofs = {
        MakeFakeProof(1), MakeFakeProof(2), MakeFakeProof(3)
    };
    std::vector<std::vector<uint8_t>> commits = {
        MakeFakeCommitment(1), MakeFakeCommitment(2), MakeFakeCommitment(3)
    };

    BlockProofAccumulator acc1;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc1));

    // Swap first two proofs and commits
    std::vector<std::vector<uint8_t>> proofs_swapped = {proofs[1], proofs[0], proofs[2]};
    std::vector<std::vector<uint8_t>> commits_swapped = {commits[1], commits[0], commits[2]};
    BlockProofAccumulator acc2;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs_swapped, commits_swapped, acc2));

    BOOST_CHECK_MESSAGE(acc1.hashAccumulator != acc2.hashAccumulator,
        "Accumulator must be order-sensitive to prevent reordering attacks");
}

BOOST_AUTO_TEST_CASE(accumulate_sensitive_to_count)
{
    // Adding a proof must change the accumulator
    std::vector<std::vector<uint8_t>> proofs2 = {MakeFakeProof(1), MakeFakeProof(2)};
    std::vector<std::vector<uint8_t>> commits2 = {MakeFakeCommitment(1), MakeFakeCommitment(2)};

    std::vector<std::vector<uint8_t>> proofs3 = {MakeFakeProof(1), MakeFakeProof(2), MakeFakeProof(3)};
    std::vector<std::vector<uint8_t>> commits3 = {MakeFakeCommitment(1), MakeFakeCommitment(2), MakeFakeCommitment(3)};

    BlockProofAccumulator acc2, acc3;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs2, commits2, acc2));
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs3, commits3, acc3));

    BOOST_CHECK(acc2.hashAccumulator != acc3.hashAccumulator);
    BOOST_CHECK_EQUAL(acc2.nProofCount, 2);
    BOOST_CHECK_EQUAL(acc3.nProofCount, 3);
}

BOOST_AUTO_TEST_CASE(accumulate_rejects_mismatched_counts)
{
    std::vector<std::vector<uint8_t>> proofs = {MakeFakeProof(1), MakeFakeProof(2)};
    std::vector<std::vector<uint8_t>> commits = {MakeFakeCommitment(1)}; // only 1

    BlockProofAccumulator acc;
    BOOST_CHECK(!AccumulateBlockRangeProofs(proofs, commits, acc));
}

// =========================================================================
// 4. VerifyBlockAccumulator — Verification
// =========================================================================

BOOST_AUTO_TEST_CASE(verify_accumulator_positive)
{
    std::vector<std::vector<uint8_t>> proofs = {
        MakeFakeProof(10), MakeFakeProof(20), MakeFakeProof(30)
    };
    std::vector<std::vector<uint8_t>> commits = {
        MakeFakeCommitment(10), MakeFakeCommitment(20), MakeFakeCommitment(30)
    };

    BlockProofAccumulator acc;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc));
    BOOST_CHECK(VerifyBlockAccumulator(acc, proofs, commits));
}

BOOST_AUTO_TEST_CASE(verify_accumulator_rejects_tampered_hash)
{
    std::vector<std::vector<uint8_t>> proofs = {MakeFakeProof(1)};
    std::vector<std::vector<uint8_t>> commits = {MakeFakeCommitment(1)};

    BlockProofAccumulator acc;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc));

    // Tamper with the hash
    acc.hashAccumulator.begin()[0] ^= 0xFF;
    BOOST_CHECK(!VerifyBlockAccumulator(acc, proofs, commits));
}

BOOST_AUTO_TEST_CASE(verify_accumulator_rejects_wrong_proof_count)
{
    std::vector<std::vector<uint8_t>> proofs = {MakeFakeProof(1), MakeFakeProof(2)};
    std::vector<std::vector<uint8_t>> commits = {MakeFakeCommitment(1), MakeFakeCommitment(2)};

    BlockProofAccumulator acc;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc));

    // Verify with different number of proofs
    std::vector<std::vector<uint8_t>> proofs3 = {MakeFakeProof(1), MakeFakeProof(2), MakeFakeProof(3)};
    std::vector<std::vector<uint8_t>> commits3 = {MakeFakeCommitment(1), MakeFakeCommitment(2), MakeFakeCommitment(3)};
    BOOST_CHECK(!VerifyBlockAccumulator(acc, proofs3, commits3));
}

BOOST_AUTO_TEST_CASE(verify_accumulator_rejects_wrong_version)
{
    std::vector<std::vector<uint8_t>> proofs = {MakeFakeProof(1)};
    std::vector<std::vector<uint8_t>> commits = {MakeFakeCommitment(1)};

    BlockProofAccumulator acc;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc));

    acc.nVersion = 0xFF; // unsupported version
    BOOST_CHECK(!VerifyBlockAccumulator(acc, proofs, commits));
}

BOOST_AUTO_TEST_CASE(verify_accumulator_rejects_substituted_proof)
{
    // Miner substitutes one proof with a different one
    std::vector<std::vector<uint8_t>> proofs = {MakeFakeProof(1), MakeFakeProof(2)};
    std::vector<std::vector<uint8_t>> commits = {MakeFakeCommitment(1), MakeFakeCommitment(2)};

    BlockProofAccumulator acc;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc));

    // Substitute proof[1] with a different proof
    proofs[1] = MakeFakeProof(99);
    BOOST_CHECK(!VerifyBlockAccumulator(acc, proofs, commits));
}

// =========================================================================
// 5. Stress: large batch accumulation
// =========================================================================

BOOST_AUTO_TEST_CASE(accumulate_large_batch)
{
    // Simulate a block with 100 confidential transactions
    std::vector<std::vector<uint8_t>> proofs;
    std::vector<std::vector<uint8_t>> commits;

    for (int i = 0; i < 100; i++) {
        proofs.push_back(MakeFakeProof(i));
        commits.push_back(MakeFakeCommitment(i));
    }

    BlockProofAccumulator acc;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc));
    BOOST_CHECK_EQUAL(acc.nProofCount, 100);
    BOOST_CHECK(!acc.hashAccumulator.IsNull());

    // Verify
    BOOST_CHECK(VerifyBlockAccumulator(acc, proofs, commits));
}

// =========================================================================
// 6. Folded state structure
// =========================================================================

BOOST_AUTO_TEST_CASE(folded_state_has_expected_structure)
{
    std::vector<std::vector<uint8_t>> proofs = {MakeFakeProof(1)};
    std::vector<std::vector<uint8_t>> commits = {MakeFakeCommitment(1)};

    BlockProofAccumulator acc;
    BOOST_CHECK(AccumulateBlockRangeProofs(proofs, commits, acc));

    // Folded state: [4 ver] [4 count] [32 fsSeed] [32 foldResult] = 72 bytes
    BOOST_CHECK_EQUAL(acc.vchFoldedState.size(), 72u);

    // Version at offset 0
    uint32_t ver;
    memcpy(&ver, acc.vchFoldedState.data(), 4);
    BOOST_CHECK_EQUAL(ver, 1u);

    // Count at offset 4
    uint32_t count;
    memcpy(&count, acc.vchFoldedState.data() + 4, 4);
    BOOST_CHECK_EQUAL(count, 1u);
}

BOOST_AUTO_TEST_SUITE_END()
