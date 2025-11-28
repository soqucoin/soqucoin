#include "crypto/latticefold/verifier.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <iostream>
#include <vector>

// Declaration of the helper from verifier.cpp (not in header, but we can link to it or copy logic for testing)
// Actually, EvalCheckFoldProof is likely not exported in header?
// Let's check verifier.h again.
// It is NOT in the class, it's a standalone function.
// We need to declare it here if it's not in the header.
// Or better, add it to verifier.h
extern bool EvalCheckFoldProof(const std::vector<unsigned char>& vchProof) noexcept;

BOOST_FIXTURE_TEST_SUITE(latticefold_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(proof_parsing_bounds)
{
    // Min size is 656 bytes
    std::vector<unsigned char> vchSmall(655, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vchSmall));

    std::vector<unsigned char> vchMin(656, 0);
    // It will pass size check but fail parsing because 0 bytes aren't valid field elements/hashes likely,
    // or it might pass parsing but fail verification.
    // EvalCheckFoldProof returns false if VerifyDilithiumBatch fails.
    // We expect it to return false (invalid proof), but NOT crash.
    BOOST_CHECK(!EvalCheckFoldProof(vchMin));

    // Max size is 10000
    std::vector<unsigned char> vchLarge(10001, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vchLarge));
}

BOOST_AUTO_TEST_CASE(proof_structure_check)
{
    // Construct a proof with valid structure but invalid data
    // Header: 176 bytes
    // Footer: 480 bytes
    // Sumcheck: 8 rounds * 64 elements * 16 bytes = 8192 bytes
    // Total = 176 + 480 + 8192 = 8848 bytes

    std::vector<unsigned char> vch(8848, 0);

    // Set sumcheck bytes to be valid multiple of 16
    // The function checks if sumcheck_elements == 512.
    // (8848 - 176 - 480) / 16 = 8192 / 16 = 512.
    // So this size is exactly correct for 8 rounds.

    // It should parse correctly and call VerifyDilithiumBatch.
    // VerifyDilithiumBatch will fail because data is all zeros (invalid commitments etc).
    BOOST_CHECK(!EvalCheckFoldProof(vch));

    // Try a size that is valid multiple of 16 but wrong element count
    // e.g. 7 rounds = 7 * 64 * 16 = 7168 bytes
    // Total = 176 + 480 + 7168 = 7824 bytes
    std::vector<unsigned char> vchWrongRounds(7824, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vchWrongRounds));
}

BOOST_AUTO_TEST_SUITE_END()
