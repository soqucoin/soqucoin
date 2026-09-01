// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// pat_canonical_ordering_tests.cpp — is PAT's canonical ordering total?
//
// crypto/pat/logarithmic.h claims: "Non-malleability: Canonical ordering
// prevents proof malleability. Same batch always produces identical proof
// regardless of input order."
//
// That claim is load-bearing for the PAT block attestation (epic
// pat-completion-epic-xlab phase 3), where EVERY node recomputes the commitment
// from block data and compares it to the coinbase. If two nodes can derive
// different proofs from the same block, that is a chain split — the nh6m class,
// where a compiler or platform difference partitions the network.
//
// These tests measure the claim rather than restating it. When first written
// they measured it FAILING, for batches containing duplicate messages: the sort
// key was PatHash(message) alone, so entries over the same message compared
// equivalent and std::sort — which is not stable and whose treatment of
// equivalent elements is unspecified — decided the result. The key is now the
// total triple (message, pubkey, signature) with the original position as a
// final tie-break, and these assertions were inverted to require the claim
// rather than record its failure. Bead pat-canonical-ordering-not-total-97dz.

#include "crypto/pat/logarithmic.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"

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

// ⛔ THE CASE THAT USED TO FAIL. Two signatures over the SAME message.
//
// Keying on PatHash(message) alone left these two entries comparing equivalent,
// and std::sort gives no guarantee about the relative order of equivalent
// elements — it is not stable, and implementations may differ. The proof
// therefore tracked presentation order. Now the key is the total triple
// (message, pubkey, signature), so the ordering itself decides.
//
// ⛔ Do not narrow the key back to the message. And do not "fix" a future
// variant of this by relying on std::sort being stable for small n — it is not
// stable, and the input sizes that matter here are block-sized.
BOOST_AUTO_TEST_CASE(duplicate_messages_still_give_an_order_independent_proof)
{
    const CValType s0 = Fixed(0x11), s1 = Fixed(0x22);
    const CValType p0 = Fixed(0x33), p1 = Fixed(0x44);
    const CValType m  = Fixed(0x55);   // the SAME message for both entries

    const CValType a = ProofOver({s0, s1}, {p0, p1}, {m, m});
    const CValType b = ProofOver({s1, s0}, {p1, p0}, {m, m});

    BOOST_CHECK_MESSAGE(a == b,
        "A batch with duplicate messages produced different proofs depending on "
        "presentation order. The canonical ordering is not total again, which is a "
        "chain-split vector for the block attestation: every node recomputes this "
        "from block data and compares it to the coinbase commitment. See "
        "CanonicalOrder in crypto/pat/logarithmic.cpp and bead "
        "pat-canonical-ordering-not-total-97dz.");
}

// The ordering sorts TUPLES, and must never sort the three field vectors
// independently — that would silently re-pair signatures with the wrong public
// keys while still producing a well-formed proof.
//
// So this batch is NOT a permutation: the multiset of tuples genuinely differs,
// {(sA,pA),(sB,pB)} against {(sB,pA),(sA,pB)}, with the same messages and the
// same pk and sig multisets. pk_agg and msg_root are identical across the two;
// only the leaves distinguish them. A proof that cannot tell these apart has
// lost the sig-to-pk binding.
BOOST_AUTO_TEST_CASE(different_pairings_are_not_conflated)
{
    const CValType sA = Fixed(0xA1), sB = Fixed(0xB1);
    const CValType pA = Fixed(0xA2), pB = Fixed(0xB2);
    const CValType m  = Fixed(0xCC);

    // Signatures swapped, public keys left alone, so the PAIRING changes.
    const CValType paired  = ProofOver({sA, sB}, {pA, pB}, {m, m});
    const CValType repaired = ProofOver({sB, sA}, {pA, pB}, {m, m});

    BOOST_CHECK_MESSAGE(paired != repaired,
        "Two batches that pair the same signatures with DIFFERENT public keys "
        "produced the same proof. The ordering is sorting the field vectors "
        "independently rather than sorting tuples, so the sig-to-pk binding is "
        "gone — a proof would then attest to a pairing nobody signed.");
}

// Fully identical tuples are the one case the (message, pubkey, signature) key
// cannot separate. That is harmless, and this pins it as such: identical tuples
// produce identical leaves at either position, so the tree is the same whichever
// way they land. The original-position tie-break exists so the PERMUTATION is
// decided too, and std::sort's handling of equivalent elements never enters the
// result at all.
//
// ⛔ The repeated tuple is permuted against a DISTINCT third tuple, so the two
// copies carry different original positions in each presentation and the
// positional tie-break is actually exercised. Permuting a batch of nothing but
// identical tuples is a no-op on the input, and a test built that way passes on
// any implementation whatsoever — it measures only that the function is
// deterministic across two calls.
BOOST_AUTO_TEST_CASE(fully_identical_tuples_are_order_independent)
{
    const CValType s  = Fixed(0x77), p  = Fixed(0x88), m  = Fixed(0x99);  // T, twice
    const CValType su = Fixed(0xA7), pu = Fixed(0xA8), mu = Fixed(0xA9);  // U, distinct

    // One multiset {T, T, U}, three genuinely different presentations of it.
    const CValType ttu = ProofOver({s, s, su}, {p, p, pu}, {m, m, mu});
    const CValType tut = ProofOver({s, su, s}, {p, pu, p}, {m, mu, m});
    const CValType utt = ProofOver({su, s, s}, {pu, p, p}, {mu, m, m});

    BOOST_CHECK_MESSAGE(ttu == tut && tut == utt,
        "A batch containing two identical tuples produced different proofs "
        "depending on where those copies sat in the input. The positional "
        "tie-break is leaking presentation order into the result, which it must "
        "never do — it exists only to make the key space totally ordered.");
}

// Create and Verify must derive the SAME order — they call one function for
// that reason. If they ever diverge, honest proofs stop verifying. Exercised
// with duplicate messages, which is precisely where a divergence would hide.
BOOST_AUTO_TEST_CASE(verify_accepts_a_proof_over_duplicate_messages)
{
    const CValType s0 = Fixed(0x11), s1 = Fixed(0x22);
    const CValType p0 = Fixed(0x33), p1 = Fixed(0x44);
    const CValType m  = Fixed(0x55);

    const std::vector<CValType> sigs = {s0, s1}, pks = {p0, p1}, msgs = {m, m};
    const CValType proof_data = ProofOver(sigs, pks, msgs);

    BOOST_CHECK_MESSAGE(
        pat::VerifyLogarithmicProof(proof_data, sigs, pks, msgs),
        "Verify rejected a proof that Create had just produced over the same "
        "batch. The two halves derive the canonical order differently — they must "
        "both go through CanonicalOrder.");
}

// ⛔ KNOWN-ANSWER VECTORS — the cross-build guard, and the reason this file is
// not just a set of self-consistency checks.
//
// Every test above compares two proofs computed by the SAME binary, so all of
// them pass on a build whose ordering is self-consistently wrong. What the
// canonical ordering actually has to guarantee is that a DIFFERENT build — a
// different compiler, standard library, or optimisation level — derives the
// same bytes. Only a fixed expected value can catch that, and this is what
// DL-PAT-COMPLETION-PLAN §8 item 5 means by "canonical ordering pinned by test
// vectors".
//
// The duplicate-message vector is the load-bearing one: it is the case whose
// result was previously left to std::sort, so it is the case where two standard
// libraries could disagree.
//
// ⚠️ These are NOT yet covered by the consensus digest. The digest absorbs PAT
// proof bytes, but only for batches built by BuildValidPatScript, whose messages
// are all distinct (0x70+i) — so its material never reaches the tie path and it
// did not move when the ordering was corrected. Closing that means adding a
// duplicate-message batch to the absorbed material, which moves the pin and owes
// an F4 sweep; it is deliberately folded into the single re-pin that the phase-3
// commitment work already requires. Until then, these vectors are what the F4
// cross-build evidence rests on for ordering. Bead
// pat-canonical-ordering-not-total-97dz.
//
// If one of these fails on a new platform, do NOT re-pin it to that platform's
// output. A mismatch here is the chain split, caught in a test instead of on the
// network.
BOOST_AUTO_TEST_CASE(canonical_ordering_matches_pinned_vectors)
{
    const CValType s0 = Fixed(0x11), s1 = Fixed(0x22);
    const CValType p0 = Fixed(0x33), p1 = Fixed(0x44);

    // n=2, DUPLICATE messages — the tie path.
    const CValType dup = ProofOver({s0, s1}, {p0, p1}, {Fixed(0x55), Fixed(0x55)});
    BOOST_CHECK_EQUAL(HexStr(dup),
        "564a9d9fa194497bcf35def39262940b1000e65c2a33fdb577c12abfa9cd442e"  // merkle_root
        "ae75f84cf35d9168cf43665240cc528d67b90245b19e9c284ca63111629d13b5"  // pk_agg
        "d810da4dd375788b0f35075eae37a990fd8bf2b16f63b30c6ea64eb2ae262efe"  // msg_root
        "02000000");                                                        // count

    // n=3, distinct messages — the ordinary path, so a regression that somehow
    // spared the tie case still shows up.
    const CValType distinct = ProofOver({s0, s1, Fixed(0x33)},
                                        {p0, p1, Fixed(0x66)},
                                        {Fixed(0x70), Fixed(0x71), Fixed(0x72)});
    BOOST_CHECK_EQUAL(HexStr(distinct),
        "4e3c0ab483e9eda42d9bc4f6474931a2af1dc3dd81fbc2260a27d9423c6163ba"
        "5bf38dce14af6f59116c5a65cbf12817f4818d6ed62793fc9d9121bbce5cf126"
        "8e19963d59b4965dc1297387cf0eb33618a6cb33063da0c7e5ab08499418de46"
        "03000000");
}

BOOST_AUTO_TEST_SUITE_END()
