// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// pat_canonical_ordering_tests.cpp — is PAT's canonical ordering total?
//
// crypto/pat/logarithmic.h claims: "Non-malleability: Canonical ordering
// prevents proof malleability — All inputs sorted by PatHash(message) before
// tree construction. Same batch always produces identical proof regardless of
// input order."
//
// That claim is load-bearing for the PAT block attestation (epic
// pat-completion-epic-xlab phase 3), where EVERY node recomputes the commitment
// from block data and compares it to the coinbase. If two nodes can derive
// different proofs from the same block, that is a chain split — the nh6m class,
// where a compiler or platform difference partitions the network.
//
// These tests measure the claim rather than restating it.

#include "crypto/pat/logarithmic.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

typedef std::vector<unsigned char> CValType;

BOOST_FIXTURE_TEST_SUITE(pat_canonical_ordering_tests, BasicTestingSetup)

static CValType Fixed(unsigned char b)
{
    return CValType(32, b);
}

static CValType ProofOver(const std::vector<CValType>& sigs,
                          const std::vector<CValType>& pks,
                          const std::vector<CValType>& msgs)
{
    CValType out;
    BOOST_REQUIRE(pat::CreateLogarithmicProof(sigs, pks, msgs, out));
    return out;
}

// CONTROL — with DISTINCT messages the ordering is total, so permuting the
// input must not change the proof. If this fails, the sort is not happening at
// all and the test below proves nothing.
BOOST_AUTO_TEST_CASE(distinct_messages_give_an_order_independent_proof)
{
    const CValType s0 = Fixed(0x11), s1 = Fixed(0x22);
    const CValType p0 = Fixed(0x33), p1 = Fixed(0x44);
    const CValType m0 = Fixed(0x55), m1 = Fixed(0x66);

    const CValType a = ProofOver({s0, s1}, {p0, p1}, {m0, m1});
    const CValType b = ProofOver({s1, s0}, {p1, p0}, {m1, m0});

    BOOST_CHECK_MESSAGE(a == b,
        "PAT produced different proofs for the same batch presented in a different "
        "order, even with distinct messages. The canonical sort is not working at all.");
}

// ⛔ THE GAP. Two signatures over the SAME message. The comparator keys on
// PatHash(message) alone, so these two entries compare equivalent, and nothing
// in the ordering decides which comes first — it is left to std::sort, whose
// treatment of equivalent elements is unspecified and differs by
// implementation.
//
// This test asserts the CURRENT behaviour (the proof tracks input order), so it
// records the gap as a standing fact rather than asserting the documented claim
// that does not hold. When the comparator is made total — tie-break on
// PatHash(pk), then PatHash(sig) — this test must be inverted to require
// equality, and the header claim becomes true as written.
//
// ⛔ Do not "fix" this by relying on std::sort being stable for small n. It is
// not stable, and the input sizes that matter here are block-sized.
BOOST_AUTO_TEST_CASE(duplicate_messages_break_the_canonical_ordering)
{
    const CValType s0 = Fixed(0x11), s1 = Fixed(0x22);
    const CValType p0 = Fixed(0x33), p1 = Fixed(0x44);
    const CValType m  = Fixed(0x55);   // the SAME message for both entries

    const CValType a = ProofOver({s0, s1}, {p0, p1}, {m, m});
    const CValType b = ProofOver({s1, s0}, {p1, p0}, {m, m});

    BOOST_CHECK_MESSAGE(a != b,
        "PAT now produces the same proof for a batch with duplicate messages "
        "presented in either order. That means the ordering has been made total "
        "(good, and required before the block attestation can ship) — invert this "
        "test to require equality and update crypto/pat/logarithmic.h. Epic "
        "pat-completion-epic-xlab, phase 3 canonical-ordering spec.");
}

// The consequence stated directly: with duplicate messages, the (sig, pk)
// pairing that lands in each Merkle leaf depends on presentation order. For a
// block-level attestation every node must derive the identical proof from the
// identical block, so the ordering has to decide this — not the caller, and not
// the standard library.
BOOST_AUTO_TEST_CASE(duplicate_message_pairing_is_decided_by_presentation_order)
{
    const CValType sA = Fixed(0xA1), sB = Fixed(0xB1);
    const CValType pA = Fixed(0xA2), pB = Fixed(0xB2);
    const CValType m  = Fixed(0xCC);

    // Same multiset of (sig, pk) pairs, same messages — only the order differs.
    const CValType forward  = ProofOver({sA, sB}, {pA, pB}, {m, m});
    const CValType backward = ProofOver({sB, sA}, {pB, pA}, {m, m});

    BOOST_CHECK_MESSAGE(forward != backward,
        "Duplicate-message batches are now order-independent. See "
        "duplicate_messages_break_the_canonical_ordering — both tests invert together.");
}

BOOST_AUTO_TEST_SUITE_END()
