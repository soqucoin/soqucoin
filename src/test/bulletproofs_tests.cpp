#include "random.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"
#include "zk/bulletproofs.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bulletproofs_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bulletproofs_completeness)
{
    // Test that a valid proof verifies
    CAmount value = 123456789;
    uint256 blinding;
    GetStrongRandBytes(blinding.begin(), 32);

    zk::Commitment commitment;
    BOOST_CHECK(zk::GenerateCommitment(value, blinding, commitment));

    zk::RangeProof proof;
    uint256 nonce = blinding; // Use blinding as nonce for testing
    BOOST_CHECK(zk::GenRangeProof(value, blinding, nonce, commitment, proof));

    BOOST_CHECK(zk::VerifyRangeProof(proof, commitment));
}

BOOST_AUTO_TEST_CASE(bulletproofs_soundness)
{
    // Test that a tampered proof fails to verify
    CAmount value = 1000;
    uint256 blinding;
    GetStrongRandBytes(blinding.begin(), 32);

    zk::Commitment commitment;
    zk::GenerateCommitment(value, blinding, commitment);

    zk::RangeProof proof;
    uint256 nonce = blinding;
    zk::GenRangeProof(value, blinding, nonce, commitment, proof);

    // Tamper with the proof
    proof.data[0] ^= 0xFF;

    BOOST_CHECK(!zk::VerifyRangeProof(proof, commitment));
}

BOOST_AUTO_TEST_CASE(bulletproofs_binding)
{
    // Test that a proof doesn't verify against a different commitment
    CAmount value = 1000;
    uint256 blinding;
    GetStrongRandBytes(blinding.begin(), 32);

    zk::Commitment commitment;
    zk::GenerateCommitment(value, blinding, commitment);

    zk::RangeProof proof;
    uint256 nonce = blinding;
    zk::GenRangeProof(value, blinding, nonce, commitment, proof);

    // Generate a different commitment (different value)
    zk::Commitment commitment2;
    zk::GenerateCommitment(value + 1, blinding, commitment2);

    BOOST_CHECK(!zk::VerifyRangeProof(proof, commitment2));
}

BOOST_AUTO_TEST_CASE(bulletproofs_rewind)
{
    // Test that we can rewind the proof to recover value and blinding factor
    CAmount value = 50000;
    uint256 blinding;
    GetStrongRandBytes(blinding.begin(), 32);

    uint256 nonce;
    GetStrongRandBytes(nonce.begin(), 32);

    zk::Commitment commitment;
    zk::GenerateCommitment(value, blinding, commitment);

    zk::RangeProof proof;
    BOOST_CHECK(zk::GenRangeProof(value, blinding, nonce, commitment, proof));

    // Verify first
    BOOST_CHECK(zk::VerifyRangeProof(proof, commitment));

    // Rewind
    CAmount value_out;
    uint256 blinding_out;
    BOOST_CHECK(zk::RewindRangeProof(proof, commitment, nonce, value_out, blinding_out));

    BOOST_CHECK_EQUAL(value, value_out);
    BOOST_CHECK(memcmp(blinding.begin(), blinding_out.begin(), 32) == 0);
}

BOOST_AUTO_TEST_SUITE_END()
