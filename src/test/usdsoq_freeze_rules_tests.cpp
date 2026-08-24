// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// usdsoq_freeze_rules_tests.cpp — name-pins the freeze rules added in the
// SOQ-I013/I015 batch.
//
// These three rejections shipped with a clean stagenet resync from genesis and
// no unit test. That resync proved they do not FALSELY fire on real history. It
// proved nothing about whether they fire CORRECTLY on a violating input, and
// absence of rejection is not evidence of enforcement. Bead r0vn's rule applies:
// a reject rule is not done until a test drives a failing input through
// ConnectBlock and observes THAT EXACT REJECT STRING.
//
//   bad-usdsoq-freeze-dead-target    freeze naming something that is not a live
//                                    USDSOQ UTXO. Was fail-open: skipped with a
//                                    log line, so the issuer believed a coin was
//                                    frozen when consensus had ignored the op.
//   bad-usdsoq-freeze-redundant      freeze of an already-frozen outpoint.
//   bad-usdsoq-unfreeze-redundant    unfreeze of an outpoint that is not frozen.
//
// The last two exist because DisconnectBlock inverts freeze ops blindly, with no
// record of prior state. A redundant FREEZE was a no-op inbound and an UNFREEZE
// outbound, so a reorg silently lifted a freeze that predated the block.
// Requiring a real state transition makes every op exactly one change, which
// makes the blind inversion exactly right.

#include "chainparams.h"
#include "consensus/usdsoq.h"
#include "consensus/validation.h"
#include "test/dilithium_chain_setup.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

struct UsdsoqFreezeRulesSetup : public DilithiumChainSetup {
    UsdsoqTestAuthority auth;

    //! OP_RETURN <"FREEZE"> <37-byte payload: op || txid || vout_le32>
    static CScript FreezeOpReturn(uint8_t op, const COutPoint& target)
    {
        std::vector<unsigned char> payload;
        payload.push_back(op);
        payload.insert(payload.end(), target.hash.begin(), target.hash.end());
        payload.push_back((unsigned char)(target.n & 0xff));
        payload.push_back((unsigned char)((target.n >> 8) & 0xff));
        payload.push_back((unsigned char)((target.n >> 16) & 0xff));
        payload.push_back((unsigned char)((target.n >> 24) & 0xff));
        std::vector<unsigned char> tag = {'F','R','E','E','Z','E'};
        CScript s;
        s << OP_RETURN << tag << payload;
        return s;
    }

    //! An authority tx carrying one freeze op. `prevMarker` chains it to the
    //! tracked authority UTXO; without it this is a bootstrap.
    CMutableTransaction BuildFreezeTx(const CTransaction& feeCoinbase, uint8_t op,
                                      const COutPoint& target,
                                      const COutPoint* prevMarker = nullptr)
    {
        const CAmount feeVal = feeCoinbase.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;

        unsigned int feeIdx = 0;
        if (prevMarker) {
            CTxIn m; m.prevout = *prevMarker; m.nSequence = CTxIn::SEQUENCE_FINAL;
            tx.vin.push_back(m);
            feeIdx = 1;
        }
        CTxIn f; f.prevout = COutPoint(feeCoinbase.GetHash(), 0);
        f.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(f);

        CTxOut mark; mark.nValue = 100000; mark.scriptPubKey = auth.MarkerSpk();
        tx.vout.push_back(mark);
        CTxOut opret; opret.nValue = 0; opret.scriptPubKey = FreezeOpReturn(op, target);
        tx.vout.push_back(opret);
        CTxOut chg; chg.nValue = feeVal - 110000; chg.scriptPubKey = Spk(OP_1);
        tx.vout.push_back(chg);

        SignInput(tx, feeIdx, coinbaseSpk, feeVal);
        auth.Sign(tx, 0, auth.MarkerSpk());
        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(usdsoq_freeze_rules_tests, UsdsoqFreezeRulesSetup)

// Reachability control. A freeze of a live v7 UTXO must connect, or every
// rejection below could be caused by something unrelated to the rule.
BOOST_AUTO_TEST_CASE(freezing_a_live_usdsoq_utxo_is_accepted)
{
    COutPoint v7 = SeedCoin(Spk(OP_7), 5 * COIN, 0xf1);
    CMutableTransaction tx = BuildFreezeTx(coinbaseTxns[0], FREEZE_OP_FREEZE, v7);
    BOOST_CHECK_MESSAGE(RejectReasonFor({tx}).empty(),
        "control: a freeze of a live v7 UTXO must connect");
}

// WAS FAIL-OPEN. A control that silently no-ops is worse than one that is
// absent, because it reports success to the issuer.
BOOST_AUTO_TEST_CASE(freezing_a_dead_target_is_rejected_by_name)
{
    COutPoint ghost(uint256S("00000000000000000000000000000000000000000000000000000000deadbeef"), 0);
    CMutableTransaction tx = BuildFreezeTx(coinbaseTxns[0], FREEZE_OP_FREEZE, ghost);
    BOOST_CHECK_EQUAL(RejectReasonFor({tx}), "bad-usdsoq-freeze-dead-target");
}

// Idempotency, freeze direction. Without this the undo silently lifts a freeze
// that predated the block.
BOOST_AUTO_TEST_CASE(refreezing_an_already_frozen_outpoint_is_rejected_by_name)
{
    COutPoint v7 = SeedCoin(Spk(OP_7), 5 * COIN, 0xf2);

    CMutableTransaction first = BuildFreezeTx(coinbaseTxns[0], FREEZE_OP_FREEZE, v7);
    CBlock b1 = CreateAndProcessBlock({first}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == b1.GetHash(),
        "the first freeze must connect before a redundant one means anything");

    COutPoint marker(first.GetHash(), 0);
    CMutableTransaction again = BuildFreezeTx(coinbaseTxns[1], FREEZE_OP_FREEZE, v7, &marker);
    BOOST_CHECK_EQUAL(RejectReasonFor({again}), "bad-usdsoq-freeze-redundant");
}

// Idempotency, unfreeze direction. Without this the undo silently FREEZES a
// coin that was never frozen.
BOOST_AUTO_TEST_CASE(unfreezing_a_non_frozen_outpoint_is_rejected_by_name)
{
    COutPoint v7 = SeedCoin(Spk(OP_7), 5 * COIN, 0xf3);
    CMutableTransaction tx = BuildFreezeTx(coinbaseTxns[0], FREEZE_OP_UNFREEZE, v7);
    BOOST_CHECK_EQUAL(RejectReasonFor({tx}), "bad-usdsoq-unfreeze-redundant");
}

// The round trip must still work: freeze, then unfreeze, then freeze again.
// Guards against the redundancy rules hardening into "you may only ever freeze
// an outpoint once".
BOOST_AUTO_TEST_CASE(freeze_unfreeze_freeze_round_trip_is_accepted)
{
    COutPoint v7 = SeedCoin(Spk(OP_7), 5 * COIN, 0xf4);

    CMutableTransaction t1 = BuildFreezeTx(coinbaseTxns[0], FREEZE_OP_FREEZE, v7);
    CBlock b1 = CreateAndProcessBlock({t1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());

    COutPoint m1(t1.GetHash(), 0);
    CMutableTransaction t2 = BuildFreezeTx(coinbaseTxns[1], FREEZE_OP_UNFREEZE, v7, &m1);
    CBlock b2 = CreateAndProcessBlock({t2}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == b2.GetHash(),
        "unfreezing a frozen outpoint must be accepted");

    COutPoint m2(t2.GetHash(), 0);
    CMutableTransaction t3 = BuildFreezeTx(coinbaseTxns[2], FREEZE_OP_FREEZE, v7, &m2);
    BOOST_CHECK_MESSAGE(RejectReasonFor({t3}).empty(),
        "re-freezing after an unfreeze is a real state transition and must be "
        "accepted — the rule is about redundancy, not about freezing once");
}

BOOST_AUTO_TEST_SUITE_END()
