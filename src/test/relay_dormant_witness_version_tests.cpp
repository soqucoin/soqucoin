// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// relay_dormant_witness_version_tests.cpp — relay and the mempool around the
// height at which a witness version begins, on a mined regtest chain with
// standardness required, as mainnet and stagenet require it.
//
// A witness version of 2 to 16 is dormant below the height of its deployment:
// a block takes a spend of an output of the version with nothing read. From
// the height the version's rules judge the spend. Two relay rules follow from
// that, and this file holds them.
//
//   The spend. A transaction that spends a 34-byte witness program of a
//   version whose bit is clear in the mask of the next block is refused at
//   relay, whatever its witness, with the reason "dormant-witness-version".
//   An input with no witness at all never reaches the rule: CheckTransaction
//   refuses the transaction first, in a block as at relay.
//
//   The mask read again. After the tip has moved back, the mempool holds no
//   transaction with an output the mask of the new next height refuses, and
//   no descendant of one.
//
// The cases use witness version 6 with its height A set on regtest for their
// own scope; one case walks versions 0 to 16. Neither rule is a rule on
// blocks: a block below A with a spend of a version 6 output connects, and
// one case holds that.
//
// Blocks are built two ways. HandBlock takes the transactions the case names,
// as a miner with its own policy would. StockBlock is the node's own template
// for the next block with its transactions as the node chose them.

#include "amount.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/merkle.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "key.h"
#include "miner.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "test/dilithium_chain_setup.h"
#include "test/test_bitcoin.h"
#include "test/testutil.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "uint256.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

const CAmount FEE = COIN;
const CAmount SEEDED = 10 * COIN;
const std::string ACCEPTED = "accepted";
const std::string MISSING_INPUTS = "missing-inputs";
const std::string DORMANT = "dormant-witness-version";
//! CheckTransaction's reason for a transaction with an input that has no witness.
const std::string NO_SIGNATURE = "bad-txns-requires-dilithium";

//! What a spend of a version 6 output carries as its witness.
enum Witness {
    NO_WITNESS,    //!< nothing
    ONE_ZERO_BYTE, //!< the one item 00, which no rule of the version accepts
    SIGNED,        //!< the satisfaction of the output's key-hash script
};

//! The three deployments a version 6 spend reads, at one height for the life
//! of the object.
struct V6BeginsAt {
    ScopedRegtestActivation gate, keyhash, controlflow;
    explicit V6BeginsAt(int height)
        : gate(Consensus::DEPLOYMENT_P2WSH_DILITHIUM, height),
          keyhash(Consensus::DEPLOYMENT_DILITHIUM_KEYHASH, height),
          controlflow(Consensus::DEPLOYMENT_V6_CONTROLFLOW, height) {}
};

//! Every deployment that sets a bit of the mask by height, at one height.
struct GatedVersionsBeginAt {
    V6BeginsAt v6;
    ScopedRegtestActivation v4, v5v7, v8v9, ctv, apo, csfs;
    explicit GatedVersionsBeginAt(int height)
        : v6(height),
          v4(Consensus::DEPLOYMENT_SOQUOBSCURA, height),
          v5v7(Consensus::DEPLOYMENT_USDSOQ, height),
          v8v9(Consensus::DEPLOYMENT_BTCSOQ, height),
          ctv(Consensus::DEPLOYMENT_CTV, height),
          apo(Consensus::DEPLOYMENT_APO, height),
          csfs(Consensus::DEPLOYMENT_CSFS, height) {}
};

//! Sets fRequireStandard for the life of the object and puts back what it found.
struct ScopedRequireStandard {
    const bool previous;
    explicit ScopedRequireStandard(bool value) : previous(fRequireStandard) { fRequireStandard = value; }
    ~ScopedRequireStandard() { fRequireStandard = previous; }
};

//! Turns the priority area of block assembly off for the life of the object,
//! then gives the option its default.
struct NoPriorityArea {
    NoPriorityArea() { ForceSetArg("-blockprioritysize", "0"); }
    ~NoPriorityArea() { ForceSetArg("-blockprioritysize", std::to_string(DEFAULT_BLOCK_PRIORITY_SIZE)); }
};

//! The node's template for the next block: its transactions, or the text of
//! what CreateNewBlock threw.
struct Template {
    bool built;
    std::string error;
    std::vector<uint256> txids; //!< without the coinbase

    bool Holds(const CMutableTransaction& tx) const
    {
        return std::find(txids.begin(), txids.end(), tx.GetHash()) != txids.end();
    }
};

struct RelayChainSetup : public DilithiumChainSetup {
    unsigned int salt;

    RelayChainSetup() : salt(0)
    {
        // Eight more blocks, so that the first eight coinbases are mature at
        // every tip a case reaches.
        for (int i = 0; i < 8; ++i)
            Advance();
    }

    ~RelayChainSetup() { mempool.clear(); }

    int Height() const
    {
        LOCK(cs_main);
        return chainActive.Height();
    }

    //! Solves a block. Each block gets a coinbase of its own, so that a block
    //! built on a tip after another at the same height was invalidated is a
    //! different block.
    void Solve(CBlock& block)
    {
        LOCK(cs_main);
        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
        ++salt;
        CMutableTransaction coinbase(*block.vtx[0]);
        coinbase.vin[0].scriptSig << valtype{0x72, (unsigned char)(salt >> 8), (unsigned char)salt};
        block.vtx[0] = MakeTransactionRef(std::move(coinbase));
        block.hashMerkleRoot = BlockMerkleRoot(block);
        while (!CheckProofOfWork(block.GetPoWHash(), block.nBits, Params().GetConsensus(0)))
            ++block.nNonce;
    }

    //! A block on the tip with the given transactions and no other. Its
    //! coinbase claims the subsidy alone.
    CBlock HandBlock(const std::vector<CMutableTransaction>& txns = std::vector<CMutableTransaction>())
    {
        LOCK(cs_main);
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(Params()).CreateNewBlock(coinbaseSpk, true);
        CBlock block = tmpl->block;
        CAmount templateFees = 0;
        for (size_t i = 1; i < tmpl->vTxFees.size(); ++i)
            templateFees += tmpl->vTxFees[i];
        block.vtx.resize(1);
        CMutableTransaction coinbase(*block.vtx[0]);
        coinbase.vout[0].nValue -= templateFees;
        coinbase.vout.erase(
            std::remove_if(coinbase.vout.begin(), coinbase.vout.end(),
                [](const CTxOut& o) {
                    return o.scriptPubKey.size() >= 38 &&
                           o.scriptPubKey[0] == OP_RETURN && o.scriptPubKey[1] == 0x24 &&
                           o.scriptPubKey[2] == 0xaa && o.scriptPubKey[3] == 0x21 &&
                           o.scriptPubKey[4] == 0xa9 && o.scriptPubKey[5] == 0xed;
                }),
            coinbase.vout.end());
        coinbase.vin[0].scriptWitness.stack.clear();
        block.vtx[0] = MakeTransactionRef(std::move(coinbase));
        for (const CMutableTransaction& tx : txns)
            block.vtx.push_back(MakeTransactionRef(tx));
        GenerateCoinbaseCommitment(block, chainActive.Tip(), Params().GetConsensus(0));
        Solve(block);
        return block;
    }

    //! The node's own template for the next block, solved.
    CBlock StockBlock()
    {
        LOCK(cs_main);
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(Params()).CreateNewBlock(coinbaseSpk, true);
        CBlock block = tmpl->block;
        Solve(block);
        return block;
    }

    Template NextTemplate()
    {
        Template t;
        t.built = false;
        try {
            std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(Params()).CreateNewBlock(coinbaseSpk, true);
            t.built = true;
            for (size_t i = 1; i < tmpl->block.vtx.size(); ++i)
                t.txids.push_back(tmpl->block.vtx[i]->GetHash());
        } catch (const std::runtime_error& e) {
            t.error = e.what();
        }
        return t;
    }

    //! Hands a block to the node. True when it is the new tip.
    bool Submit(const CBlock& block)
    {
        bool fNewBlock = false;
        ProcessNewBlock(Params(), std::make_shared<const CBlock>(block), true, &fNewBlock);
        LOCK(cs_main);
        return chainActive.Tip()->GetBlockHash() == block.GetHash();
    }

    //! One block further, holding the given transactions and no other.
    void Advance(const std::vector<CMutableTransaction>& txns = std::vector<CMutableTransaction>())
    {
        BOOST_REQUIRE_MESSAGE(Submit(HandBlock(txns)), "a block built by the case did not connect");
    }

    void InvalidateTip()
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_REQUIRE(InvalidateBlock(state, Params(), chainActive.Tip()));
    }

    //! The mempool's answer to a transaction: ACCEPTED, MISSING_INPUTS, or
    //! the reject reason.
    std::string Verdict(const CMutableTransaction& tx)
    {
        LOCK(cs_main);
        CValidationState state;
        bool fMissingInputs = false;
        if (AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), false, &fMissingInputs, nullptr, true, 0))
            return ACCEPTED;
        if (fMissingInputs)
            return MISSING_INPUTS;
        return state.GetRejectReason();
    }

    bool Unspent(const COutPoint& out)
    {
        LOCK(cs_main);
        const CCoins* coins = pcoinsTip->AccessCoins(out.hash);
        return coins && coins->IsAvailable(out.n);
    }

    //! The witnessScript of every version 6 output of this file: a key-hash
    //! check on the fixture's key.
    CScript KeyHashScript() const
    {
        valtype h(CSHA256::OUTPUT_SIZE);
        CSHA256().Write(coinbasePkBytes.data(), coinbasePkBytes.size()).Finalize(h.data());
        return CScript() << h << OP_CHECKDILITHIUMKEYHASH << OP_1;
    }

    CScript V6Output() const
    {
        const CScript ws = KeyHashScript();
        valtype h(CSHA256::OUTPUT_SIZE);
        CSHA256().Write(ws.data(), ws.size()).Finalize(h.data());
        return CScript() << OP_6 << h;
    }

    //! Coinbase n of the fixture paid into equal version 6 outputs.
    CMutableTransaction Fund(size_t n, unsigned int outputs = 1)
    {
        const CTransaction& cb = coinbaseTxns[n];
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        for (unsigned int i = 0; i < outputs; ++i)
            tx.vout.push_back(CTxOut((cb.vout[0].nValue - FEE) / outputs, V6Output()));
        SignInput(tx, 0, coinbaseSpk, cb.vout[0].nValue);
        return tx;
    }

    //! A spend of one version 6 output of this file to the fixture's key.
    CMutableTransaction Spend(const COutPoint& out, CAmount value, Witness witness, CAmount fee = FEE)
    {
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(out, CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout.push_back(CTxOut(value - fee, coinbaseSpk));
        if (witness == ONE_ZERO_BYTE)
            tx.vin[0].scriptWitness.stack.push_back(valtype(1, 0x00));
        if (witness == SIGNED) {
            const CScript ws = KeyHashScript();
            const uint256 sighash = SignatureHash(ws, CTransaction(tx), 0, SIGHASH_ALL, value, SIGVERSION_WITNESS_V0, nullptr);
            valtype sig;
            BOOST_REQUIRE(coinbaseKey.Sign(sighash, sig));
            sig.push_back((unsigned char)SIGHASH_ALL);
            tx.vin[0].scriptWitness.stack.push_back(sig);
            tx.vin[0].scriptWitness.stack.push_back(coinbasePkBytes);
            tx.vin[0].scriptWitness.stack.push_back(valtype(ws.begin(), ws.end()));
            tx.vin[0].scriptWitness.stack.push_back(PrefixedPubkey(coinbasePkBytes));
        }
        return tx;
    }

    CMutableTransaction Spend(const CMutableTransaction& funding, unsigned int n, Witness witness, CAmount fee = FEE)
    {
        return Spend(COutPoint(funding.GetHash(), n), funding.vout[n].nValue, witness, fee);
    }

    //! A spend of output 0 of a transaction that pays the fixture's key.
    CMutableTransaction SpendToKey(const CMutableTransaction& parent)
    {
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(parent.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout.push_back(CTxOut(parent.vout[0].nValue - FEE, coinbaseSpk));
        SignInput(tx, 0, coinbaseSpk, parent.vout[0].nValue);
        return tx;
    }
};

std::string WitnessName(Witness w)
{
    return w == ONE_ZERO_BYTE ? "the witness 00" : "a signed witness";
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(relay_dormant_witness_version_tests, RelayChainSetup)

// The tip moves back one block, from A-1 to A-2. Two transactions that fund a
// version 6 output were accepted at the tip A-1, where the next block is A,
// and one of them has a child that spends its output with a signed witness.
// At the tip A-2 the mask of the next block refuses their output: the mempool
// holds none of the three, a spend of the other output with the witness 00
// finds nothing to spend, and the node's template for block A-1 is empty.
BOOST_AUTO_TEST_CASE(a_funding_and_its_child_leave_the_mempool_when_the_tip_moves_back_one_block)
{
    BOOST_REQUIRE_MESSAGE(fRequireStandard, "the unit fixture applies standardness, as mainnet and stagenet do");
    const int A = Height() + 2;
    V6BeginsAt begins(A);
    Advance();
    BOOST_REQUIRE_EQUAL(Height(), A - 1);

    const CMutableTransaction withChild = Fund(0);
    const CMutableTransaction child = Spend(withChild, 0, SIGNED);
    const CMutableTransaction alone = Fund(1);
    BOOST_REQUIRE_EQUAL(Verdict(withChild), ACCEPTED);
    BOOST_REQUIRE_EQUAL(Verdict(child), ACCEPTED);
    BOOST_REQUIRE_EQUAL(Verdict(alone), ACCEPTED);

    InvalidateTip();
    BOOST_REQUIRE_EQUAL(Height(), A - 2);

    BOOST_CHECK_MESSAGE(!mempool.exists(withChild.GetHash()), "a funding accepted at the tip A-1 is in the mempool at the tip A-2");
    BOOST_CHECK_MESSAGE(!mempool.exists(child.GetHash()), "the child of that funding is in the mempool at the tip A-2");
    BOOST_CHECK_MESSAGE(!mempool.exists(alone.GetHash()), "the second funding is in the mempool at the tip A-2");

    const CMutableTransaction taking = Spend(alone, 0, ONE_ZERO_BYTE);
    BOOST_CHECK_EQUAL(Verdict(taking), MISSING_INPUTS);

    const Template next = NextTemplate();
    BOOST_REQUIRE_MESSAGE(next.built, next.error);
    BOOST_CHECK_MESSAGE(next.txids.empty(), "the template for block A-1 holds " << next.txids.size() << " transactions");

    const CBlock block = StockBlock();
    BOOST_REQUIRE(Submit(block));
    BOOST_REQUIRE_EQUAL(Height(), A - 1);
    BOOST_CHECK_MESSAGE(block.vtx.size() == 1, "block A-1 holds " << block.vtx.size() - 1 << " transactions beside its coinbase");
    BOOST_CHECK_MESSAGE(!mempool.exists(taking.GetHash()) && std::find_if(block.vtx.begin(), block.vtx.end(),
                            [&](const CTransactionRef& tx) { return tx->GetHash() == taking.GetHash(); }) == block.vtx.end(),
        "the spend with the witness 00 was mined in block A-1 or waits in the mempool");
}

// The tip moves back three blocks, from A to A-3. One funding was mined in
// block A and returns through the disconnection of that block, while the tip
// is still A-1. The other was accepted at the tip A and never mined. At the
// tip A-3 the mempool holds neither, the node's blocks A-2 and A-1 hold
// neither, and a spend of the first one's output with the witness 00 finds
// nothing to spend at the tip A-2.
BOOST_AUTO_TEST_CASE(a_funding_leaves_the_mempool_when_the_tip_moves_back_below_the_height_by_more)
{
    const int A = Height() + 3;
    V6BeginsAt begins(A);
    Advance();
    Advance();
    BOOST_REQUIRE_EQUAL(Height(), A - 1);

    const CMutableTransaction mined = Fund(0);
    BOOST_REQUIRE_EQUAL(Verdict(mined), ACCEPTED);
    BOOST_REQUIRE(Submit(StockBlock()));
    BOOST_REQUIRE_EQUAL(Height(), A);
    BOOST_REQUIRE(Unspent(COutPoint(mined.GetHash(), 0)));
    const CMutableTransaction unmined = Fund(1);
    BOOST_REQUIRE_EQUAL(Verdict(unmined), ACCEPTED);

    InvalidateTip();
    InvalidateTip();
    InvalidateTip();
    BOOST_REQUIRE_EQUAL(Height(), A - 3);

    BOOST_CHECK_MESSAGE(!mempool.exists(mined.GetHash()), "the funding mined in block A is in the mempool at the tip A-3");
    BOOST_CHECK_MESSAGE(!mempool.exists(unmined.GetHash()), "the funding accepted at the tip A is in the mempool at the tip A-3");

    const CBlock first = StockBlock();
    BOOST_REQUIRE(Submit(first));
    BOOST_REQUIRE_EQUAL(Height(), A - 2);
    BOOST_CHECK_MESSAGE(first.vtx.size() == 1, "block A-2 holds " << first.vtx.size() - 1 << " transactions beside its coinbase");
    BOOST_CHECK_MESSAGE(!Unspent(COutPoint(mined.GetHash(), 0)), "a version 6 output was mined in block A-2 from the node's own template");

    const CMutableTransaction taking = Spend(mined, 0, ONE_ZERO_BYTE);
    BOOST_CHECK_EQUAL(Verdict(taking), MISSING_INPUTS);
    const CBlock second = StockBlock();
    BOOST_REQUIRE(Submit(second));
    BOOST_REQUIRE_EQUAL(Height(), A - 1);
    BOOST_CHECK_MESSAGE(second.vtx.size() == 1, "block A-1 holds " << second.vtx.size() - 1 << " transactions beside its coinbase");
}

// A version 6 output confirmed three blocks below A, in a block the case
// built. While the next block is below A, relay refuses a spend of it with the
// witness 00 and with a signed witness. When the next block is A, the version
// judges the spend: the witness 00 is outside the version's witness figures
// and the signed one is accepted and mined in block A. A spend with no witness
// is refused by CheckTransaction at every height.
BOOST_AUTO_TEST_CASE(a_spend_of_a_dormant_output_is_refused_at_relay_until_the_next_block_is_the_height)
{
    BOOST_REQUIRE(fRequireStandard);
    const int A = Height() + 4;
    V6BeginsAt begins(A);
    const CMutableTransaction funding = Fund(0);
    BOOST_REQUIRE_EQUAL(Verdict(funding), "scriptpubkey");
    Advance({funding});
    BOOST_REQUIRE_EQUAL(Height(), A - 3);
    BOOST_REQUIRE(Unspent(COutPoint(funding.GetHash(), 0)));

    size_t relayed = 0;
    for (int next = A - 2; next < A; ++next) {
        BOOST_REQUIRE_EQUAL(Height(), next - 1);
        for (Witness w : {ONE_ZERO_BYTE, SIGNED}) {
            const std::string verdict = Verdict(Spend(funding, 0, w));
            BOOST_CHECK_MESSAGE(verdict == DORMANT,
                "a spend with " << WitnessName(w) << ", next block A" << next - A << ": \"" << verdict << "\"");
            relayed += mempool.size();
            mempool.clear();
        }
        BOOST_CHECK_EQUAL(Verdict(Spend(funding, 0, NO_WITNESS)), NO_SIGNATURE);
        Advance();
    }
    BOOST_CHECK_EQUAL(relayed, 0u);

    // The next block is A.
    BOOST_REQUIRE_EQUAL(Height(), A - 1);
    BOOST_CHECK_EQUAL(Verdict(Spend(funding, 0, ONE_ZERO_BYTE)), "bad-witness-nonstandard");
    BOOST_CHECK_EQUAL(Verdict(Spend(funding, 0, NO_WITNESS)), NO_SIGNATURE);
    BOOST_REQUIRE_EQUAL(mempool.size(), 0u);
    const CMutableTransaction signedSpend = Spend(funding, 0, SIGNED);
    BOOST_CHECK_EQUAL(Verdict(signedSpend), ACCEPTED);
    const CBlock block = StockBlock();
    BOOST_REQUIRE(Submit(block));
    BOOST_REQUIRE_EQUAL(Height(), A);
    BOOST_CHECK_EQUAL(block.vtx.size(), 2u);
    BOOST_CHECK(!Unspent(COutPoint(funding.GetHash(), 0)));
}

// The forward crossing. A version 6 output is confirmed two blocks below A. A
// spend of it with the witness 00, paid above the floor of block assembly, is
// sent at the tip A-2 and is not mined in block A-1. Relay refused it, so at
// the tip A-1 the node builds its template and block A connects.
BOOST_AUTO_TEST_CASE(the_node_builds_block_a_after_a_spend_that_fails_the_version_was_sent_below_the_height)
{
    const int A = Height() + 3;
    V6BeginsAt begins(A);
    const CMutableTransaction funding = Fund(0);
    Advance({funding});
    BOOST_REQUIRE_EQUAL(Height(), A - 2);

    const CMutableTransaction failing = Spend(funding, 0, ONE_ZERO_BYTE);
    BOOST_CHECK_EQUAL(Verdict(failing), DORMANT);
    Advance();
    BOOST_REQUIRE_EQUAL(Height(), A - 1);
    BOOST_REQUIRE(Unspent(COutPoint(funding.GetHash(), 0)));

    const Template next = NextTemplate();
    BOOST_CHECK_MESSAGE(next.built, "CreateNewBlock at the tip A-1 threw: " << next.error);
    if (next.built) {
        BOOST_CHECK(next.txids.empty());
        BOOST_CHECK(Submit(StockBlock()));
        BOOST_CHECK_EQUAL(Height(), A);
    }
}

// The same crossing where standardness is not required, as on testnet and
// regtest: neither rule applies there. The spend is accepted below A, and from
// the tip A-1 the node cannot build a template while its mempool holds it. A
// funding accepted at the tip A-1 stays when the tip moves back.
BOOST_AUTO_TEST_CASE(neither_rule_applies_where_standardness_is_not_required)
{
    ScopedRequireStandard off(false);
    const int A = Height() + 3;
    V6BeginsAt begins(A);
    const CMutableTransaction funding = Fund(0);
    Advance({funding});
    BOOST_REQUIRE_EQUAL(Height(), A - 2);

    const CMutableTransaction failing = Spend(funding, 0, ONE_ZERO_BYTE);
    BOOST_CHECK_EQUAL(Verdict(failing), ACCEPTED);
    Advance();
    BOOST_REQUIRE_EQUAL(Height(), A - 1);
    const Template next = NextTemplate();
    BOOST_CHECK(!next.built);
    BOOST_CHECK_MESSAGE(next.error.find("TestBlockValidity failed") != std::string::npos, next.error);
    mempool.clear();

    const CMutableTransaction second = Fund(1);
    BOOST_REQUIRE_EQUAL(Verdict(second), ACCEPTED);
    InvalidateTip();
    BOOST_REQUIRE_EQUAL(Height(), A - 2);
    BOOST_CHECK(mempool.exists(second.GetHash()));
}

// The forward crossing with a child. The spend with the witness 00 pays
// between the relay floor and the floor of block assembly, so no template
// takes it for its fee. The case turns the priority area of block assembly
// off: that area takes the first entry by priority whatever it pays, so it
// would take the one entry of this mempool. A child that pays for both, sent
// when the next block is A, would bring the spend into the template. Relay
// refused the parent, so the child has nothing to spend and the node builds
// block A.
BOOST_AUTO_TEST_CASE(a_child_cannot_carry_a_spend_sent_below_the_height_into_block_a)
{
    const int A = Height() + 3;
    V6BeginsAt begins(A);
    NoPriorityArea feeAlone;
    const CMutableTransaction funding = Fund(0);
    Advance({funding});
    BOOST_REQUIRE_EQUAL(Height(), A - 2);

    CMutableTransaction parent = Spend(funding, 0, ONE_ZERO_BYTE);
    const int64_t size = GetVirtualTransactionSize(CTransaction(parent));
    const CAmount lowFee = 3 * ::minRelayTxFeeRate.GetFee(size);
    BOOST_REQUIRE_MESSAGE(lowFee < CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE).GetFee(size),
        "three times the relay floor is not below the floor of block assembly");
    parent = Spend(funding, 0, ONE_ZERO_BYTE, lowFee);

    BOOST_CHECK_EQUAL(Verdict(parent), DORMANT);
    const Template before = NextTemplate();
    BOOST_REQUIRE_MESSAGE(before.built, before.error);
    BOOST_CHECK(!before.Holds(parent));
    Advance();
    BOOST_REQUIRE_EQUAL(Height(), A - 1);

    const CMutableTransaction child = SpendToKey(parent);
    BOOST_CHECK_EQUAL(Verdict(child), MISSING_INPUTS);
    const Template next = NextTemplate();
    BOOST_CHECK_MESSAGE(next.built, "CreateNewBlock at the tip A-1 threw: " << next.error);
    if (next.built) {
        BOOST_CHECK(next.txids.empty());
        BOOST_CHECK(Submit(StockBlock()));
        BOOST_CHECK_EQUAL(Height(), A);
    }
}

// Each witness version through the mempool, with an output of the version
// placed in the UTXO set and spent with the witness 00. With every gated
// deployment far above the tip, versions 2 to 16 get the one reason. With
// regtest's own heights, where versions 5 to 9 and 11 run, the spend of each of
// those is judged by its version and fails for a reason of its own. Version 0,
// a 20-byte program of version 6 and an output that is no witness program are
// never the rule's.
BOOST_AUTO_TEST_CASE(each_dormant_version_is_refused_with_one_reason)
{
    BOOST_REQUIRE(fRequireStandard);
    auto program = [](int version, size_t length) {
        return CScript() << (version == 0 ? OP_0 : (opcodetype)(OP_1 + version - 1)) << valtype(length, (unsigned char)version);
    };
    auto verdictOfASpend = [&](const CScript& spk, uint8_t tag) {
        const std::string verdict = Verdict(Spend(SeedCoin(spk, SEEDED, tag), SEEDED, ONE_ZERO_BYTE));
        BOOST_CHECK_MESSAGE(verdict != ACCEPTED, "a spend with the witness 00 was accepted, output " << HexStr(spk));
        mempool.clear();
        return verdict;
    };

    {
        GatedVersionsBeginAt far(Height() + 1000);
        for (int version = 2; version <= 16; ++version) {
            const std::string verdict = verdictOfASpend(program(version, 32), 0x20 + version);
            BOOST_CHECK_MESSAGE(verdict == DORMANT, "version " << version << ", dormant: \"" << verdict << "\"");
        }
        BOOST_CHECK(verdictOfASpend(program(0, 32), 0x40) != DORMANT);
        BOOST_CHECK(verdictOfASpend(program(6, 20), 0x41) != DORMANT);
        BOOST_CHECK(verdictOfASpend(CScript() << OP_TRUE, 0x42) != DORMANT);
    }

    for (int version : {5, 6, 7, 8, 9, 11}) {
        const std::string verdict = verdictOfASpend(program(version, 32), 0x60 + version);
        BOOST_CHECK_MESSAGE(verdict != DORMANT, "version " << version << ", running: \"" << verdict << "\"");
    }

    // Version 1 has no dormant state: a signed spend of a coinbase is accepted
    // under both settings.
    {
        GatedVersionsBeginAt far(Height() + 1000);
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(coinbaseTxns[0].GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout.push_back(CTxOut(coinbaseTxns[0].vout[0].nValue - FEE, coinbaseSpk));
        SignInput(tx, 0, coinbaseSpk, coinbaseTxns[0].vout[0].nValue);
        BOOST_CHECK_EQUAL(Verdict(tx), ACCEPTED);
    }
}

// Neither rule is a rule on blocks. A block below A that holds a spend of a
// version 6 output with the witness 00 connects, as before. A block at A with
// the same spend of a second output does not.
BOOST_AUTO_TEST_CASE(a_block_below_the_height_with_the_spend_connects)
{
    const int A = Height() + 3;
    V6BeginsAt begins(A);
    const CMutableTransaction funding = Fund(0, 2);
    Advance({funding});
    BOOST_REQUIRE_EQUAL(Height(), A - 2);

    const CMutableTransaction below = Spend(funding, 0, ONE_ZERO_BYTE);
    BOOST_CHECK(Submit(HandBlock({below})));
    BOOST_CHECK_EQUAL(Height(), A - 1);
    BOOST_CHECK(!Unspent(COutPoint(funding.GetHash(), 0)));

    const CMutableTransaction at = Spend(funding, 1, ONE_ZERO_BYTE);
    BOOST_CHECK(!Submit(HandBlock({at})));
    BOOST_CHECK_EQUAL(Height(), A - 1);
    BOOST_CHECK(Unspent(COutPoint(funding.GetHash(), 1)));
}

// What stays when the tip moves back. A signed spend of a confirmed version 6
// output, accepted when the next block was A, stays at the tip A-2: a block
// below A takes it with nothing read and a block from A takes it under the
// rules it was checked with. The node's block A-1 holds it. A funding stays
// while the next block is still at or above A.
BOOST_AUTO_TEST_CASE(what_the_mempool_keeps_when_the_tip_moves_back)
{
    const int A = Height() + 3;
    V6BeginsAt begins(A);
    const CMutableTransaction funding = Fund(0);
    Advance({funding});
    Advance();
    BOOST_REQUIRE_EQUAL(Height(), A - 1);

    const CMutableTransaction signedSpend = Spend(funding, 0, SIGNED);
    BOOST_REQUIRE_EQUAL(Verdict(signedSpend), ACCEPTED);
    InvalidateTip();
    BOOST_REQUIRE_EQUAL(Height(), A - 2);
    BOOST_CHECK(mempool.exists(signedSpend.GetHash()));

    const CBlock block = StockBlock();
    BOOST_CHECK_EQUAL(block.vtx.size(), 2u);
    BOOST_CHECK(Submit(block));
    BOOST_REQUIRE_EQUAL(Height(), A - 1);
    BOOST_CHECK(!Unspent(COutPoint(funding.GetHash(), 0)));
    BOOST_CHECK_EQUAL(mempool.size(), 0u);

    Advance();
    BOOST_REQUIRE_EQUAL(Height(), A);
    const CMutableTransaction second = Fund(1);
    BOOST_REQUIRE_EQUAL(Verdict(second), ACCEPTED);
    InvalidateTip();
    BOOST_REQUIRE_EQUAL(Height(), A - 1);
    BOOST_CHECK_MESSAGE(mempool.exists(second.GetHash()), "a funding left the mempool while the next block is A");
}

// A block below A that holds a spend of a version 6 output with the witness 00
// is disconnected. The spend does not return to the mempool: the path that
// puts a disconnected block's transactions back applies the relay rule.
BOOST_AUTO_TEST_CASE(a_spend_mined_below_the_height_does_not_return_when_its_block_is_disconnected)
{
    const int A = Height() + 4;
    V6BeginsAt begins(A);
    const CMutableTransaction funding = Fund(0);
    Advance({funding});
    const CMutableTransaction spend = Spend(funding, 0, ONE_ZERO_BYTE);
    Advance({spend});
    BOOST_REQUIRE_EQUAL(Height(), A - 2);
    BOOST_REQUIRE(!Unspent(COutPoint(funding.GetHash(), 0)));

    InvalidateTip();
    BOOST_REQUIRE_EQUAL(Height(), A - 3);
    BOOST_REQUIRE(Unspent(COutPoint(funding.GetHash(), 0)));
    BOOST_CHECK_MESSAGE(!mempool.exists(spend.GetHash()), "the spend returned to the mempool at the tip A-3");
}

BOOST_AUTO_TEST_SUITE_END()
