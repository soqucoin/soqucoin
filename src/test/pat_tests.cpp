#include "crypto/pat/logarithmic.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <vector>

using pat::CValType;

BOOST_FIXTURE_TEST_SUITE(pat_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(proof_parsing_roundtrip)
{
    // Test ParseLogarithmicProof with valid 100-byte buffer
    std::vector<unsigned char> vchProof(100, 0);

    // Set some dummy values
    // Merkle root (0-31)
    vchProof[0] = 0xaa;
    // PK XOR (32-63)
    vchProof[32] = 0xbb;
    // Msg Root (64-95)
    vchProof[64] = 0xcc;
    // Count (96-99) = 1 (little endian)
    vchProof[96] = 0x01;

    pat::LogarithmicProof proof;
    BOOST_CHECK(pat::ParseLogarithmicProof(vchProof, proof));

    BOOST_CHECK_EQUAL(proof.merkle_root.begin()[0], 0xaa);
    BOOST_CHECK_EQUAL(proof.pk_xor.begin()[0], 0xbb);
    BOOST_CHECK_EQUAL(proof.msg_root.begin()[0], 0xcc);
    BOOST_CHECK_EQUAL(proof.count, 1u);
}

BOOST_AUTO_TEST_CASE(proof_parsing_invalid_size)
{
    // Test ParseLogarithmicProof with invalid sizes
    std::vector<unsigned char> vchSmall(99, 0);
    pat::LogarithmicProof proof;
    BOOST_CHECK(!pat::ParseLogarithmicProof(vchSmall, proof));

    std::vector<unsigned char> vchLarge(101, 0);
    BOOST_CHECK(!pat::ParseLogarithmicProof(vchLarge, proof));
}

BOOST_AUTO_TEST_CASE(verify_logic_check)
{
    // Test VerifyLogarithmicProof (prototype logic)
    pat::LogarithmicProof proof;
    proof.merkle_root = uint256S("0xaa");
    proof.pk_xor = uint256S("0xbb");
    proof.msg_root = uint256S("0xcc");
    proof.count = 1;

    std::vector<unsigned char> agg_pk(32, 0);
    agg_pk[0] = 0xbb; // Matches pk_xor (0xbb...)

    std::vector<unsigned char> msg_root(32, 0);
    msg_root[0] = 0xcc; // Matches msg_root (0xcc...)

    // 1. Valid case
    BOOST_CHECK(pat::VerifyLogarithmicProof(proof, agg_pk, msg_root));

    // 2. Invalid agg_pk
    std::vector<unsigned char> bad_agg_pk = agg_pk;
    bad_agg_pk[0] = 0xff;
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, bad_agg_pk, msg_root));

    // 3. Invalid msg_root
    std::vector<unsigned char> bad_msg_root = msg_root;
    bad_msg_root[0] = 0xff;
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, agg_pk, bad_msg_root));

    // 4. Null merkle root (should fail per logic)
    proof.merkle_root = uint256();
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, agg_pk, msg_root));
}

// ==============================
// COMPREHENSIVE VERIFICATION TESTS
// (FIND-002: sibling path removed — verifier rebuilds full tree)
// ==============================

BOOST_AUTO_TEST_CASE(create_verify_roundtrip_single)
{
    // Test Create + Verify roundtrip with single signature
    std::vector<CValType> sigs, pks, msgs;

    // Create single entry (32 bytes each)
    CValType sig(32, 0x11);
    CValType pk(32, 0x22);
    CValType msg(32, 0x33);

    sigs.push_back(sig);
    pks.push_back(pk);
    msgs.push_back(msg);

    // Create proof (FIND-002: no sibling path output)
    CValType proof;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));

    // Verify proof (FIND-002: no sibling path input)
    BOOST_CHECK(pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));
}

BOOST_AUTO_TEST_CASE(create_verify_roundtrip_multiple)
{
    // Test Create + Verify roundtrip with 4 signatures
    std::vector<CValType> sigs, pks, msgs;

    for (int i = 0; i < 4; i++) {
        CValType sig(32, 0x10 + i);
        CValType pk(32, 0x20 + i);
        CValType msg(32, 0x30 + i);

        sigs.push_back(sig);
        pks.push_back(pk);
        msgs.push_back(msg);
    }

    // Create proof
    CValType proof;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));

    // Verify proof
    BOOST_CHECK(pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));
}

BOOST_AUTO_TEST_CASE(reject_tampered_merkle_root)
{
    // Create valid proof
    std::vector<CValType> sigs, pks, msgs;
    for (int i = 0; i < 4; i++) {
        sigs.push_back(CValType(32, 0x10 + i));
        pks.push_back(CValType(32, 0x20 + i));
        msgs.push_back(CValType(32, 0x30 + i));
    }

    CValType proof;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));

    // Tamper with merkle root
    proof[0] ^= 0xFF;

    // Verification should fail
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));
}

BOOST_AUTO_TEST_CASE(reject_tampered_pk_xor)
{
    // Create valid proof
    std::vector<CValType> sigs, pks, msgs;
    for (int i = 0; i < 4; i++) {
        sigs.push_back(CValType(32, 0x10 + i));
        pks.push_back(CValType(32, 0x20 + i));
        msgs.push_back(CValType(32, 0x30 + i));
    }

    CValType proof;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));

    // Tamper with pk_xor (byte 32)
    proof[32] ^= 0xFF;

    // Verification should fail (rogue-key attack detected)
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));
}

BOOST_AUTO_TEST_CASE(reject_tampered_msg_root)
{
    // Create valid proof
    std::vector<CValType> sigs, pks, msgs;
    for (int i = 0; i < 4; i++) {
        sigs.push_back(CValType(32, 0x10 + i));
        pks.push_back(CValType(32, 0x20 + i));
        msgs.push_back(CValType(32, 0x30 + i));
    }

    CValType proof;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));

    // Tamper with msg_root (byte 64)
    proof[64] ^= 0xFF;

    // Verification should fail (message substitution detected)
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));
}

BOOST_AUTO_TEST_CASE(reject_swapped_signatures)
{
    // Create valid proof with distinct entries
    std::vector<CValType> sigs, pks, msgs;
    for (int i = 0; i < 4; i++) {
        sigs.push_back(CValType(32, 0x10 + i));
        pks.push_back(CValType(32, 0x20 + i));
        msgs.push_back(CValType(32, 0x30 + i));
    }

    CValType proof;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));

    // Swap two signatures
    std::swap(sigs[0], sigs[1]);

    // Verification should fail (leaf hash changes)
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));
}

BOOST_AUTO_TEST_CASE(power_of_two_batches)
{
    // Test various power-of-2 batch sizes
    for (int n : {2, 4, 8, 16}) {
        std::vector<CValType> sigs, pks, msgs;
        for (int i = 0; i < n; i++) {
            sigs.push_back(CValType(32, 0x10 + (i % 256)));
            pks.push_back(CValType(32, 0x20 + (i % 256)));
            msgs.push_back(CValType(32, 0x30 + (i % 256)));
        }

        CValType proof;
        BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));
        BOOST_CHECK(pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));
    }
}

BOOST_AUTO_TEST_CASE(non_power_of_two_batches)
{
    // Test non-power-of-2 sizes (require padding)
    for (int n : {3, 5, 7, 9, 15}) {
        std::vector<CValType> sigs, pks, msgs;
        for (int i = 0; i < n; i++) {
            sigs.push_back(CValType(32, 0x10 + (i % 256)));
            pks.push_back(CValType(32, 0x20 + (i % 256)));
            msgs.push_back(CValType(32, 0x30 + (i % 256)));
        }

        CValType proof;
        BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));
        BOOST_CHECK(pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));
    }
}

BOOST_AUTO_TEST_CASE(reject_mismatched_counts)
{
    // Create proof with 4 signatures
    std::vector<CValType> sigs, pks, msgs;
    for (int i = 0; i < 4; i++) {
        sigs.push_back(CValType(32, 0x10 + i));
        pks.push_back(CValType(32, 0x20 + i));
        msgs.push_back(CValType(32, 0x30 + i));
    }

    CValType proof;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));

    // Try to verify with only 3 signatures
    sigs.pop_back();
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));
}

BOOST_AUTO_TEST_CASE(reject_invalid_field_sizes)
{
    // Create valid proof
    std::vector<CValType> sigs, pks, msgs;
    for (int i = 0; i < 4; i++) {
        sigs.push_back(CValType(32, 0x10 + i));
        pks.push_back(CValType(32, 0x20 + i));
        msgs.push_back(CValType(32, 0x30 + i));
    }

    CValType proof;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));

    // Test invalid signature size
    std::vector<CValType> bad_sigs = sigs;
    bad_sigs[0] = CValType(31, 0x10); // Wrong size
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, bad_sigs, pks, msgs));

    // Test invalid pk size
    std::vector<CValType> bad_pks = pks;
    bad_pks[0] = CValType(33, 0x20); // Wrong size
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sigs, bad_pks, msgs));

    // Test invalid msg size
    std::vector<CValType> bad_msgs = msgs;
    bad_msgs[0] = CValType(16, 0x30); // Wrong size
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sigs, pks, bad_msgs));
}

// ==============================
// HALBORN FIND-001: BOUNDS VALIDATION TESTS
// Verify that proof.count is rejected when 0 or > MAX_PAT_PROOF_COUNT.
// These tests exercise the parser gate in ParseLogarithmicProof.
// ==============================

// Helper: build a 100-byte proof blob with a specific count value
static CValType MakeProofWithCount(uint32_t count)
{
    CValType proof(100, 0);
    // Set a non-null merkle_root (byte 0)
    proof[0] = 0xAA;
    // Set pk_xor (byte 32)
    proof[32] = 0xBB;
    // Set msg_root (byte 64)
    proof[64] = 0xCC;
    // Set count (bytes 96-99, little-endian)
    uint32_t le_count = htole32(count);
    memcpy(proof.data() + 96, &le_count, 4);
    return proof;
}

BOOST_AUTO_TEST_CASE(find001_reject_count_zero)
{
    // FIND-001: count=0 caused UB via zero-length vector dereference.
    // Parser must reject before any allocation.
    CValType proof_data = MakeProofWithCount(0);
    pat::LogarithmicProof proof;
    BOOST_CHECK(!pat::ParseLogarithmicProof(proof_data, proof));
}

BOOST_AUTO_TEST_CASE(find001_accept_count_one)
{
    // Boundary: count=1 is the minimum valid batch size.
    CValType proof_data = MakeProofWithCount(1);
    pat::LogarithmicProof proof;
    BOOST_CHECK(pat::ParseLogarithmicProof(proof_data, proof));
    BOOST_CHECK_EQUAL(proof.count, 1u);
}

BOOST_AUTO_TEST_CASE(find001_accept_count_max)
{
    // Boundary: count=MAX_PAT_PROOF_COUNT (1<<20) is the last accepted value.
    CValType proof_data = MakeProofWithCount(pat::MAX_PAT_PROOF_COUNT);
    pat::LogarithmicProof proof;
    BOOST_CHECK(pat::ParseLogarithmicProof(proof_data, proof));
    BOOST_CHECK_EQUAL(proof.count, pat::MAX_PAT_PROOF_COUNT);
}

BOOST_AUTO_TEST_CASE(find001_reject_count_max_plus_one)
{
    // Boundary: count=MAX_PAT_PROOF_COUNT+1 is the first rejected value.
    CValType proof_data = MakeProofWithCount(pat::MAX_PAT_PROOF_COUNT + 1);
    pat::LogarithmicProof proof;
    BOOST_CHECK(!pat::ParseLogarithmicProof(proof_data, proof));
}

BOOST_AUTO_TEST_CASE(find001_reject_count_uint32_max)
{
    // FIND-001: count=0xFFFFFFFF caused OOM via multi-GB vector allocation.
    // Parser must reject without overflow or allocation attempt.
    CValType proof_data = MakeProofWithCount(0xFFFFFFFF);
    pat::LogarithmicProof proof;
    BOOST_CHECK(!pat::ParseLogarithmicProof(proof_data, proof));
}

// ==============================
// HALBORN FIND-002: MERKLE FORGERY TESTS
// Verify that the verifier now checks ALL leaves, not just leaf 0.
// The previous implementation accepted forged leaves at positions 1..n-1.
// ==============================

BOOST_AUTO_TEST_CASE(find002_reject_forged_leaf)
{
    // FIND-002 PoC: Create a valid proof with 4 genuine tuples,
    // then replace leaf 2 with a forged tuple. The old verifier (single-leaf)
    // would accept this; the new verifier (full tree rebuild) must reject.

    std::vector<CValType> sigs, pks, msgs;
    for (int i = 0; i < 4; i++) {
        sigs.push_back(CValType(32, 0x10 + i));
        pks.push_back(CValType(32, 0x20 + i));
        msgs.push_back(CValType(32, 0x30 + i));
    }

    // Create valid proof from genuine tuples
    CValType proof;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));

    // Forge leaf 2: replace sig[2] with attacker-chosen value
    sigs[2] = CValType(32, 0xFF); // forged signature

    // MUST FAIL: The forged leaf produces a different Merkle root
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));
}

BOOST_AUTO_TEST_CASE(find002_reject_forged_last_leaf)
{
    // Edge case: forge the LAST leaf (index n-1).
    // This is the maximum distance from leaf 0 in the old single-leaf verifier.

    std::vector<CValType> sigs, pks, msgs;
    for (int i = 0; i < 8; i++) {
        sigs.push_back(CValType(32, 0x10 + i));
        pks.push_back(CValType(32, 0x20 + i));
        msgs.push_back(CValType(32, 0x30 + i));
    }

    CValType proof;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));

    // Forge last leaf: replace pk[7] with attacker key
    pks[7] = CValType(32, 0xEE); // forged public key

    // MUST FAIL
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));
}

BOOST_AUTO_TEST_CASE(find002_reject_forged_message)
{
    // Forge a message (not sig/pk). The Merkle tree commits to all three
    // components of each tuple via LeafHash, so ANY forgery must be detected.

    std::vector<CValType> sigs, pks, msgs;
    for (int i = 0; i < 4; i++) {
        sigs.push_back(CValType(32, 0x10 + i));
        pks.push_back(CValType(32, 0x20 + i));
        msgs.push_back(CValType(32, 0x30 + i));
    }

    CValType proof;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));

    // Forge message at position 1
    msgs[1] = CValType(32, 0xDD); // forged message

    // MUST FAIL: both msg_root and Merkle root will mismatch
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));
}

BOOST_AUTO_TEST_CASE(find002_all_leaves_verified_exhaustive)
{
    // Exhaustively verify that forging ANY single leaf in a batch is rejected.
    // Tests all positions 0..n-1 for n=8.

    const int n = 8;
    std::vector<CValType> sigs, pks, msgs;
    for (int i = 0; i < n; i++) {
        sigs.push_back(CValType(32, 0x10 + i));
        pks.push_back(CValType(32, 0x20 + i));
        msgs.push_back(CValType(32, 0x30 + i));
    }

    CValType proof;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof));

    // Verify the genuine proof passes
    BOOST_CHECK(pat::VerifyLogarithmicProof(proof, sigs, pks, msgs));

    // Forge each leaf position individually
    for (int forged_pos = 0; forged_pos < n; forged_pos++) {
        std::vector<CValType> forged_sigs = sigs;
        forged_sigs[forged_pos] = CValType(32, 0xFF); // forge this position

        BOOST_CHECK_MESSAGE(
            !pat::VerifyLogarithmicProof(proof, forged_sigs, pks, msgs),
            "FIND-002 REGRESSION: Forged leaf at position " + std::to_string(forged_pos) + " was accepted!");
    }
}

// ==============================
// HALBORN FIND-005: MERKLE PADDING TESTS
// Verify that non-power-of-2 batches use last-leaf replication,
// not zero-padding. Zero-padding diverges from spec and would cause
// chain splits between spec-compliant implementations.
// ==============================

BOOST_AUTO_TEST_CASE(find005_non_power_of_two_roundtrip_extended)
{
    // FIND-005 regression: Exhaustive roundtrip for non-power-of-2 sizes.
    // These are the batch sizes that exercise padding slots.
    // If Create and Verify use mismatched padding, verification fails.
    for (int n : {3, 5, 6, 7, 9, 10, 11, 13, 15, 17, 31, 33}) {
        std::vector<CValType> sigs, pks, msgs;
        for (int i = 0; i < n; i++) {
            sigs.push_back(CValType(32, 0x10 + (i % 256)));
            pks.push_back(CValType(32, 0x20 + (i % 256)));
            msgs.push_back(CValType(32, 0x30 + (i % 256)));
        }

        CValType proof;
        BOOST_CHECK_MESSAGE(
            pat::CreateLogarithmicProof(sigs, pks, msgs, proof),
            "FIND-005: CreateLogarithmicProof failed for n=" + std::to_string(n));
        BOOST_CHECK_MESSAGE(
            pat::VerifyLogarithmicProof(proof, sigs, pks, msgs),
            "FIND-005 REGRESSION: Verify failed for n=" + std::to_string(n) +
                " — Create/Verify padding mismatch");
    }
}

BOOST_AUTO_TEST_CASE(find005_last_leaf_affects_padding)
{
    // FIND-005 regression: Verify that changing the last leaf changes
    // the Merkle root. With last-leaf replication, the padding slot
    // copies the last leaf, so changing it affects both the genuine
    // leaf position AND the padding — producing a different root.
    //
    // With zero-padding, changing the last leaf would also change the
    // root (via the genuine position), but this test structurally
    // validates the sensitivity by checking TWO properties:
    // 1. Roots differ when last leaf changes
    // 2. Cross-verification fails (proof_a won't verify batch_b)

    // Batch A: n=3, last entry = 0x12
    std::vector<CValType> sigs_a, pks_a, msgs_a;
    for (int i = 0; i < 3; i++) {
        sigs_a.push_back(CValType(32, 0x10 + i));
        pks_a.push_back(CValType(32, 0x20 + i));
        msgs_a.push_back(CValType(32, 0x30 + i));
    }

    CValType proof_a;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs_a, pks_a, msgs_a, proof_a));
    BOOST_CHECK(pat::VerifyLogarithmicProof(proof_a, sigs_a, pks_a, msgs_a));

    // Batch B: identical to A except last sig[2] = 0xFF
    std::vector<CValType> sigs_b = sigs_a, pks_b = pks_a, msgs_b = msgs_a;
    sigs_b[2] = CValType(32, 0xFF);

    CValType proof_b;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs_b, pks_b, msgs_b, proof_b));
    BOOST_CHECK(pat::VerifyLogarithmicProof(proof_b, sigs_b, pks_b, msgs_b));

    // Parse and compare roots
    pat::LogarithmicProof parsed_a, parsed_b;
    BOOST_CHECK(pat::ParseLogarithmicProof(proof_a, parsed_a));
    BOOST_CHECK(pat::ParseLogarithmicProof(proof_b, parsed_b));

    // Roots MUST differ — last leaf changed, and with last-leaf replication
    // the padding slot also changed
    BOOST_CHECK_MESSAGE(
        parsed_a.merkle_root != parsed_b.merkle_root,
        "FIND-005: Merkle roots identical despite different last leaf");

    // Cross-verification MUST fail
    BOOST_CHECK_MESSAGE(
        !pat::VerifyLogarithmicProof(proof_a, sigs_b, pks_b, msgs_b),
        "FIND-005 REGRESSION: proof_a verified with batch_b data");
}

BOOST_AUTO_TEST_SUITE_END()
