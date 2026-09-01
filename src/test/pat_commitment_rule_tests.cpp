// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// pat_commitment_rule_tests.cpp — the PAT block-attestation consensus rule
// (doc/PAT_BLOCK_ATTESTATION.md §7), driven through real blocks.
//
// Every case here goes through ConnectBlock (via TestBlockValidity, fJustCheck)
// and pins its verdict by NAMED reject string, the same discipline as
// migration_rule_tests. The blocks come from the production miner path
// (BuildSolvedBlock -> CreateNewBlock -> GenerateCoinbaseCommitment), so the
// honest case exercises the real producer and the real validator against each
// other — the pair whose drift is the failure mode.
//
// Regtest posture: USDSOQ and BTCSOQ are active from height 0, so the attested
// set here is the fully-extended one. The activation BOUNDARY (v7 joining the
// set) is pinned at module level in pat_attestation_tests; these tests pin the
// block-level rule.

#include "chainparams.h"
#include "consensus/pat_attestation.h"
#include "consensus/validation.h"
#include "random.h"
#include "test/dilithium_chain_setup.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

namespace {

//! Arm the PAT mandatory-commitment height for the duration of a scope, and
//! always restore the never-mandatory default (0).
struct ScopedPatMandatoryHeight {
    explicit ScopedPatMandatoryHeight(int nHeight)
    {
        UpdateRegtestPatCommitmentMandatoryHeight(nHeight);
        SelectParams(CBaseChainParams::REGTEST);
    }
    ~ScopedPatMandatoryHeight()
    {
        UpdateRegtestPatCommitmentMandatoryHeight(0);
        SelectParams(CBaseChainParams::REGTEST);
    }
};

} // namespace

struct PatCommitmentChainSetup : public DilithiumChainSetup {
    //! A correctly-signed v1 spend of `cb`'s output 0. Its inclusion makes a
    //! block carry exactly one attested tuple.
    CMutableTransaction SpendTo(const CTransaction& cb)
    {
        const CAmount inVal = cb.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;
        CTxIn in;
        in.prevout = COutPoint(cb.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);
        CTxOut out;
        out.nValue = inVal - 10000;
        out.scriptPubKey = Spk(OP_1);
        tx.vout.push_back(out);
        SignInput(tx, 0, coinbaseSpk, inVal);
        return tx;
    }

    //! ConnectBlock (fJustCheck) verdict by reject string; "" = validated.
    //! PoW and merkle are skipped so tampered coinbases can be driven straight
    //! at the rule.
    std::string RejectReasonFor(const CBlock& block)
    {
        CValidationState st;
        LOCK(cs_main);
        if (TestBlockValidity(st, Params(), block, chainActive.Tip(), false, false))
            return std::string();
        return st.GetRejectReason();
    }

    //! Index of the (first) PAT commitment output in the coinbase, or -1.
    static int PatCommitmentIndex(const CBlock& block)
    {
        const CTransaction& cb = *block.vtx[0];
        for (size_t o = 0; o < cb.vout.size(); ++o) {
            uint256 ignored;
            if (patattest::ParseCommitmentScript(cb.vout[o].scriptPubKey, ignored))
                return (int)o;
        }
        return -1;
    }

    //! Return the block with its coinbase vout vector replaced.
    static CBlock WithCoinbaseVout(const CBlock& block, const std::vector<CTxOut>& vout)
    {
        CBlock modified = block;
        CMutableTransaction cbMut(*modified.vtx[0]);
        cbMut.vout = vout;
        modified.vtx[0] = MakeTransactionRef(std::move(cbMut));
        return modified;
    }

    static CTxOut CommitmentOut(const uint256& hash)
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = patattest::BuildCommitmentScript(hash);
        return out;
    }
};

BOOST_FIXTURE_TEST_SUITE(pat_commitment_rule_tests, PatCommitmentChainSetup)

// The honest path: the production miner emits the commitment and ConnectBlock
// accepts it. This is producer and validator run against each other, and it is
// the case every future block with spends exercises. Fails if either half
// drifts from the other in any tuple argument, the ordering, or the encoding.
BOOST_AUTO_TEST_CASE(miner_emits_commitment_and_it_validates)
{
    CBlock block = BuildSolvedBlock({SpendTo(coinbaseTxns[0])}, Spk(OP_1));

    BOOST_REQUIRE_MESSAGE(PatCommitmentIndex(block) != -1,
        "the production miner did not emit a PAT commitment for a block with an "
        "attested spend — the producer half of the optional-but-verified contract "
        "is not running");

    BOOST_CHECK_EQUAL(RejectReasonFor(block), "");
}

// A block with no attested spends must carry no commitment, and the miner must
// not emit one. Every coinbase-only block on the chain is this case.
BOOST_AUTO_TEST_CASE(miner_emits_nothing_for_an_empty_block)
{
    CBlock block = BuildSolvedBlock({}, Spk(OP_1));
    BOOST_CHECK_EQUAL(PatCommitmentIndex(block), -1);
    BOOST_CHECK_EQUAL(RejectReasonFor(block), "");
}

// Tampered commitment ⇒ bad-blk-pat-commitment. The byte flipped is inside the
// 32-byte hash, so the output still PARSES as a commitment — flipping the magic
// instead would make it invisible and the block would pass as commitment-less.
BOOST_AUTO_TEST_CASE(tampered_commitment_rejected)
{
    CBlock block = BuildSolvedBlock({SpendTo(coinbaseTxns[1])}, Spk(OP_1));
    const int idx = PatCommitmentIndex(block);
    BOOST_REQUIRE(idx != -1);

    std::vector<CTxOut> vout(block.vtx[0]->vout);
    vout[idx].scriptPubKey[10] ^= 0x01; // inside the hash bytes
    const CBlock tampered = WithCoinbaseVout(block, vout);

    BOOST_CHECK_EQUAL(RejectReasonFor(tampered), "bad-blk-pat-commitment");
}

// More than one commitment ⇒ bad-blk-pat-commitment-duplicate, even when the
// duplicate is byte-identical to the honest one. Exactly-one is a shape rule,
// not a correctness vote.
BOOST_AUTO_TEST_CASE(duplicate_commitment_rejected)
{
    CBlock block = BuildSolvedBlock({SpendTo(coinbaseTxns[2])}, Spk(OP_1));
    const int idx = PatCommitmentIndex(block);
    BOOST_REQUIRE(idx != -1);

    std::vector<CTxOut> vout(block.vtx[0]->vout);
    vout.push_back(vout[idx]); // identical second commitment
    const CBlock doubled = WithCoinbaseVout(block, vout);

    BOOST_CHECK_EQUAL(RejectReasonFor(doubled), "bad-blk-pat-commitment-duplicate");
}

// A decoy placed BEFORE the honest commitment must not win. This is the
// first-match hazard the spec forbids copying from the LatticeFold validator:
// under first-match-wins this block would be rejected as a MISMATCH against
// the decoy at best, or accepted at worst if a validator compared the decoy
// and a miner precomputed it; under the exactly-one rule it is rejected for
// carrying two, independent of order.
BOOST_AUTO_TEST_CASE(decoy_before_honest_commitment_rejected_as_duplicate)
{
    CBlock block = BuildSolvedBlock({SpendTo(coinbaseTxns[3])}, Spk(OP_1));
    const int idx = PatCommitmentIndex(block);
    BOOST_REQUIRE(idx != -1);

    uint256 decoyHash;
    GetRandBytes(decoyHash.begin(), 32);
    std::vector<CTxOut> vout(block.vtx[0]->vout);
    vout.insert(vout.begin() + idx, CommitmentOut(decoyHash)); // decoy first

    BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)),
                      "bad-blk-pat-commitment-duplicate");
}

// A commitment on a block with no attested spends ⇒ bad-blk-pat-commitment-empty.
// There is no attestation for such a block (spec §5), so there is nothing a
// commitment could correctly commit to.
BOOST_AUTO_TEST_CASE(commitment_on_empty_block_rejected)
{
    CBlock block = BuildSolvedBlock({}, Spk(OP_1));
    BOOST_REQUIRE_EQUAL(PatCommitmentIndex(block), -1);

    uint256 anyHash;
    GetRandBytes(anyHash.begin(), 32);
    std::vector<CTxOut> vout(block.vtx[0]->vout);
    vout.push_back(CommitmentOut(anyHash));

    BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)),
                      "bad-blk-pat-commitment-empty");
}

// The optional posture: a block with attested spends and NO commitment is
// valid before the mandatory height. This is the fail-safe half of
// optional-but-verified — a commitment-computation bug must not be able to
// halt the chain at genesis.
BOOST_AUTO_TEST_CASE(absent_commitment_accepted_before_mandatory_height)
{
    CBlock block = BuildSolvedBlock({SpendTo(coinbaseTxns[4])}, Spk(OP_1));
    const int idx = PatCommitmentIndex(block);
    BOOST_REQUIRE(idx != -1);

    std::vector<CTxOut> vout(block.vtx[0]->vout);
    vout.erase(vout.begin() + idx);

    BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)), "");
}

// The mandatory posture, all three verdicts under one armed height:
//   attested spends without a commitment  ⇒ bad-blk-missing-pat-commitment
//   attested spends with the commitment   ⇒ valid
//   no attested spends, no commitment     ⇒ valid (no obligation to satisfy)
BOOST_AUTO_TEST_CASE(mandatory_height_requires_the_commitment)
{
    ScopedPatMandatoryHeight armed(1); // every block past genesis

    CBlock block = BuildSolvedBlock({SpendTo(coinbaseTxns[5])}, Spk(OP_1));
    const int idx = PatCommitmentIndex(block);
    BOOST_REQUIRE(idx != -1);

    BOOST_CHECK_EQUAL(RejectReasonFor(block), "");

    std::vector<CTxOut> vout(block.vtx[0]->vout);
    vout.erase(vout.begin() + idx);
    BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)),
                      "bad-blk-missing-pat-commitment");

    const CBlock empty = BuildSolvedBlock({}, Spk(OP_1));
    BOOST_CHECK_EQUAL(RejectReasonFor(empty), "");
}

// The mandatory rule is height-gated, not retroactive: armed ABOVE the next
// block's height, an absent commitment is still the optional posture.
BOOST_AUTO_TEST_CASE(mandatory_height_in_the_future_changes_nothing)
{
    ScopedPatMandatoryHeight armed(1000000);

    CBlock block = BuildSolvedBlock({SpendTo(coinbaseTxns[6])}, Spk(OP_1));
    const int idx = PatCommitmentIndex(block);
    BOOST_REQUIRE(idx != -1);

    std::vector<CTxOut> vout(block.vtx[0]->vout);
    vout.erase(vout.begin() + idx);
    BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)), "");
}

BOOST_AUTO_TEST_SUITE_END()
