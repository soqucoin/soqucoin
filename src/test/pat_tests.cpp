#include "crypto/pat/logarithmic.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <iostream>
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
    BOOST_CHECK_EQUAL(proof.count, 1);
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

    // Create proof
    CValType proof;
    std::vector<CValType> sibling_path;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path));

    // For n=1, depth=0, sibling_path should be empty
    BOOST_CHECK_EQUAL(sibling_path.size(), 0);

    // Verify proof
    BOOST_CHECK(pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs));
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
    std::vector<CValType> sibling_path;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path));

    // For n=4, tree_size=4, depth=2
    BOOST_CHECK_EQUAL(sibling_path.size(), 2);

    // Verify proof
    BOOST_CHECK(pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs));
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
    std::vector<CValType> sibling_path;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path));

    // Tamper with merkle root
    proof[0] ^= 0xFF;

    // Verification should fail
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs));
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
    std::vector<CValType> sibling_path;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path));

    // Tamper with pk_xor (byte 32)
    proof[32] ^= 0xFF;

    // Verification should fail (rogue-key attack detected)
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs));
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
    std::vector<CValType> sibling_path;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path));

    // Tamper with msg_root (byte 64)
    proof[64] ^= 0xFF;

    // Verification should fail (message substitution detected)
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs));
}

BOOST_AUTO_TEST_CASE(reject_wrong_sibling_path)
{
    // Create valid proof
    std::vector<CValType> sigs, pks, msgs;
    for (int i = 0; i < 4; i++) {
        sigs.push_back(CValType(32, 0x10 + i));
        pks.push_back(CValType(32, 0x20 + i));
        msgs.push_back(CValType(32, 0x30 + i));
    }

    CValType proof;
    std::vector<CValType> sibling_path;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path));

    // Tamper with sibling path
    if (sibling_path.size() > 0) {
        sibling_path[0][0] ^= 0xFF;
    }

    // Verification should fail
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs));
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
    std::vector<CValType> sibling_path;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path));

    // Swap two signatures
    std::swap(sigs[0], sigs[1]);

    // Verification should fail (leaf hash changes)
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs));
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
        std::vector<CValType> sibling_path;
        BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path));
        BOOST_CHECK(pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs));
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
        std::vector<CValType> sibling_path;
        BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path));
        BOOST_CHECK(pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs));
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
    std::vector<CValType> sibling_path;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path));

    // Try to verify with only 3 signatures
    sigs.pop_back();
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs));
}

BOOST_AUTO_TEST_CASE(reject_wrong_sibling_path_length)
{
    // Create proof
    std::vector<CValType> sigs, pks, msgs;
    for (int i = 0; i < 4; i++) {
        sigs.push_back(CValType(32, 0x10 + i));
        pks.push_back(CValType(32, 0x20 + i));
        msgs.push_back(CValType(32, 0x30 + i));
    }

    CValType proof;
    std::vector<CValType> sibling_path;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path));

    // Add extra element to sibling path
    sibling_path.push_back(CValType(32, 0xAA));
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, msgs));
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
    std::vector<CValType> sibling_path;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof, sibling_path));

    // Test invalid signature size
    std::vector<CValType> bad_sigs = sigs;
    bad_sigs[0] = CValType(31, 0x10); // Wrong size
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sibling_path, bad_sigs, pks, msgs));

    // Test invalid pk size
    std::vector<CValType> bad_pks = pks;
    bad_pks[0] = CValType(33, 0x20); // Wrong size
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sibling_path, sigs, bad_pks, msgs));

    // Test invalid msg size
    std::vector<CValType> bad_msgs = msgs;
    bad_msgs[0] = CValType(16, 0x30); // Wrong size
    BOOST_CHECK(!pat::VerifyLogarithmicProof(proof, sibling_path, sigs, pks, bad_msgs));
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

BOOST_AUTO_TEST_SUITE_END()
