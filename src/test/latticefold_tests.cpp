// Copyright (c) 2025-2026 The Soqucoin Core developers
// Distributed under the MIT software license
//
// LatticeFold verifier tests — updated for SOQ-A005 redesign.
// Tests the new API with external binding (sighash, pubkey_hash, dilithium_sigs).

#include "crypto/latticefold/verifier.h"
#include "test/test_bitcoin.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(latticefold_tests, BasicTestingSetup)

// Helper: create dummy external binding parameters
static uint256 MakeDummySighash()
{
    uint256 h;
    memset(h.begin(), 0xAA, 32);
    return h;
}

static std::array<uint8_t, 32> MakeDummyPubkeyHash()
{
    std::array<uint8_t, 32> h;
    h.fill(0xBB);
    return h;
}

static std::vector<valtype> MakeDummySigs(int n = 1)
{
    std::vector<valtype> sigs;
    for (int i = 0; i < n; ++i) {
        valtype sig(2420, static_cast<uint8_t>(i + 1)); // Dilithium-44 sig size
        sigs.push_back(sig);
    }
    return sigs;
}

BOOST_AUTO_TEST_CASE(proof_parsing_bounds_v2)
{
    auto sighash = MakeDummySighash();
    auto pk_hash = MakeDummyPubkeyHash();
    auto sigs = MakeDummySigs();

    // v2 header = 144 bytes (t_coeffs + c, no batch_hash)
    // v2 footer = 480 bytes
    // Min size = 144 + 480 = 624 bytes

    // Too small
    std::vector<unsigned char> vchSmall(623, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vchSmall, sighash, pk_hash, sigs));

    // Exact minimum — will parse but fail verification (all zeros)
    std::vector<unsigned char> vchMin(624, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vchMin, sighash, pk_hash, sigs));

    // Too large
    std::vector<unsigned char> vchLarge(10001, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vchLarge, sighash, pk_hash, sigs));
}

BOOST_AUTO_TEST_CASE(proof_structure_check_v2)
{
    auto sighash = MakeDummySighash();
    auto pk_hash = MakeDummyPubkeyHash();
    auto sigs = MakeDummySigs();

    // v2 wire format: header(144) + sumcheck(8192) + footer(480) = 8816 bytes
    std::vector<unsigned char> vch(8816, 0);

    // Should parse correctly but fail verification (all zeros)
    BOOST_CHECK(!EvalCheckFoldProof(vch, sighash, pk_hash, sigs));

    // Wrong round count: 7 rounds = 7*64*16 = 7168 bytes
    // Total = 144 + 7168 + 480 = 7792 bytes
    std::vector<unsigned char> vchWrongRounds(7792, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vchWrongRounds, sighash, pk_hash, sigs));
}

BOOST_AUTO_TEST_CASE(consensus_matrix_a_deterministic)
{
    // Matrix A must be identical across multiple derivations
    std::array<std::array<Binius64, MATRIX_A_COLS>, MATRIX_A_ROWS> matA1, matA2;
    LatticeFoldVerifier::DeriveConsensusMatrixA(matA1);
    LatticeFoldVerifier::DeriveConsensusMatrixA(matA2);

    for (size_t i = 0; i < MATRIX_A_ROWS; ++i) {
        for (size_t j = 0; j < MATRIX_A_COLS; ++j) {
            BOOST_CHECK(matA1[i][j] == matA2[i][j]);
            // Elements should be nonzero (random from SHAKE-128)
            BOOST_CHECK(matA1[i][j] != Binius64::zero());
        }
    }
}

BOOST_AUTO_TEST_CASE(batch_hash_recomputation)
{
    // Same sigs must produce same batch_hash
    auto sigs = MakeDummySigs(5);
    std::array<uint8_t, 32> hash1, hash2;
    LatticeFoldVerifier::ComputeBatchHash(sigs, hash1);
    LatticeFoldVerifier::ComputeBatchHash(sigs, hash2);
    BOOST_CHECK(hash1 == hash2);

    // Different sigs must produce different batch_hash
    auto sigs2 = MakeDummySigs(6);
    std::array<uint8_t, 32> hash3;
    LatticeFoldVerifier::ComputeBatchHash(sigs2, hash3);
    BOOST_CHECK(hash1 != hash3);
}

BOOST_AUTO_TEST_CASE(external_binding_different_sighash)
{
    // Two proofs with different sighash must not be interchangeable
    // (Both will fail verification since proofs are zeroed, but the
    // Fiat-Shamir transcript must differ)
    auto pk_hash = MakeDummyPubkeyHash();
    auto sigs = MakeDummySigs();

    uint256 sighash1;
    memset(sighash1.begin(), 0x11, 32);
    uint256 sighash2;
    memset(sighash2.begin(), 0x22, 32);

    // Both should fail (zeroed proof), but they exercise different transcript paths
    std::vector<unsigned char> vch(8816, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vch, sighash1, pk_hash, sigs));
    BOOST_CHECK(!EvalCheckFoldProof(vch, sighash2, pk_hash, sigs));
}

BOOST_AUTO_TEST_SUITE_END()
