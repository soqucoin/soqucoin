// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// relay_dormant_witness_version_tests.cpp — relay and the mempool around the
// height at which a witness version begins, on a mined regtest chain with
// standardness required, as mainnet and stagenet require it.
//
// A witness version of 2 to 16 is dormant below the height of its deployment:
// a block runs no script for a spend of an output of version 3 to 16, and no
// block may create an output of version 2. From the height the version's rules
// judge the spend. Two relay rules follow from
// that, and this file holds them.
//
//   The spend. A transaction that spends a 34-byte witness program of a
//   version whose bit is clear in the mask of the next block is refused at
//   relay, whatever its witness, with the reason "dormant-witness-version".
//   A transaction whose one input has no witness and an empty scriptSig never
//   reaches the rule: CheckTransaction refuses it first, in a block as at
//   relay. An input with no witness whose scriptSig ends in a push that
//   begins with the byte 00 passes CheckTransaction and reaches the rule. So
//   does an input with no witness and an empty scriptSig in a transaction
//   that CheckTransaction passes for another input: one with an output
//   OP_5 <32 bytes> and an input of the authority witness layout.
//
//   The mask read again. After the tip has moved back, the mempool holds no
//   transaction with an output the mask of the new next height refuses, and
//   no descendant of one. That holds where a reorganisation or an
//   invalidation stops part way too, after a failed write of the chain state
//   among the stops. removeForReorg runs at those stops when the coins view
//   is the tip's, which it is unless that write failed.
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
#include "consensus/pat_attestation.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "init.h"
#include "key.h"
#include "miner.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "scheduler.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "test/dilithium_chain_setup.h"
#include "test/test_bitcoin.h"
#include "test/testutil.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "util.h"
#include "utilstrencodings.h"
#include "uint256.h"
#include "validation.h"
#include "validationinterface.h"
#include "versionbits.h"
#include "warnings.h"

#include <boost/signals2/connection.hpp>
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

//! The shutdown request of init.cpp, which a node sets when it cannot read a
//! block or write its chain state. The cases that reach those paths take the
//! request back.
extern std::atomic<bool> fRequestShutdown;

namespace {

typedef std::vector<unsigned char> valtype;

const CAmount FEE = COIN;
const CAmount SEEDED = 10 * COIN;
const std::string ACCEPTED = "accepted";
const std::string MISSING_INPUTS = "missing-inputs";
const std::string DORMANT = "dormant-witness-version";
//! CheckTransaction's reason for a transaction with an input that has no
//! witness and an empty scriptSig.
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

//! Regtest's version-bits deployment of witness version 3 with a start time
//! and a timeout for the life of the object, then with the figures it found.
//! The cache of version-bits states is emptied both times, since it holds
//! states by block index.
struct ScopedVersion3Deployment {
    const int64_t foundStart, foundTimeout;
    ScopedVersion3Deployment(int64_t start, int64_t timeout)
        : foundStart(Params().GetConsensus(0).vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime),
          foundTimeout(Params().GetConsensus(0).vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout)
    {
        UpdateRegtestBIP9Parameters(Consensus::DEPLOYMENT_LATTICEFOLD, start, timeout);
        versionbitscache.Clear();
    }
    ~ScopedVersion3Deployment()
    {
        UpdateRegtestBIP9Parameters(Consensus::DEPLOYMENT_LATTICEFOLD, foundStart, foundTimeout);
        versionbitscache.Clear();
    }
};

//! Records the height of the tip each time the mempool accepts one
//! transaction: AcceptToMemoryPool signals an accepted transaction with no
//! block, before it returns. The unit fixture has no receiver of validation
//! signals, so the object brings one for its own life; the signal is
//! delivered in the caller's thread and the scheduler runs nothing.
struct TipAtAcceptance : public CValidationInterface {
    const uint256 txid;
    std::vector<int> heights;
    CScheduler scheduler;

    explicit TipAtAcceptance(const uint256& txidIn) : txid(txidIn)
    {
        RegisterBackgroundSignalScheduler(scheduler);
        RegisterValidationInterface(this);
    }
    ~TipAtAcceptance()
    {
        UnregisterValidationInterface(this);
        UnregisterBackgroundSignalScheduler();
    }

    void SyncTransaction(const CTransaction& tx, const CBlockIndex* pindex, int posInBlock) override
    {
        if (pindex == nullptr && tx.GetHash() == txid)
            heights.push_back(chainActive.Height());
    }
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
    //! coinbase claims the subsidy alone. For a mempool that holds no spend
    //! of a version 1 output: the template's attestation commitment stays in
    //! the coinbase, and the block is invalid unless it holds the spends the
    //! template held.
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

    //! The mempool's answer with the two arguments a caller chooses, and the
    //! validation state the answer left.
    std::string VerdictAs(const CMutableTransaction& tx, bool fLimitFree, bool fOverrideMempoolLimit, CValidationState& state)
    {
        LOCK(cs_main);
        bool fMissingInputs = false;
        if (AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), fLimitFree, &fMissingInputs, nullptr, fOverrideMempoolLimit, 0))
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

    //! Coinbase n of the fixture paid into equal outputs: each of version 6,
    //! or with changeFirst the first to the fixture's key and the rest of
    //! version 6.
    CMutableTransaction Fund(size_t n, unsigned int outputs = 1, bool changeFirst = false)
    {
        const CTransaction& cb = coinbaseTxns[n];
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        for (unsigned int i = 0; i < outputs; ++i)
            tx.vout.push_back(CTxOut((cb.vout[0].nValue - FEE) / outputs, changeFirst && i == 0 ? coinbaseSpk : V6Output()));
        SignInput(tx, 0, coinbaseSpk, cb.vout[0].nValue);
        return tx;
    }

    //! Coinbase n of the fixture paid into two equal outputs: the first of
    //! version 6, the second to the fixture's key.
    CMutableTransaction FundChangeLast(size_t n)
    {
        const CTransaction& cb = coinbaseTxns[n];
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout.push_back(CTxOut((cb.vout[0].nValue - FEE) / 2, V6Output()));
        tx.vout.push_back(CTxOut((cb.vout[0].nValue - FEE) / 2, coinbaseSpk));
        SignInput(tx, 0, coinbaseSpk, cb.vout[0].nValue);
        return tx;
    }

    //! Coinbase n of the fixture paid to the fixture's key.
    CMutableTransaction SpendFixtureCoinbase(size_t n)
    {
        const CTransaction& cb = coinbaseTxns[n];
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout.push_back(CTxOut(cb.vout[0].nValue - FEE, coinbaseSpk));
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

    //! A spend of the coinbase of the block at a height of the active chain,
    //! to the fixture's key.
    CMutableTransaction SpendCoinbaseOfBlock(int height)
    {
        CBlock block;
        {
            LOCK(cs_main);
            BOOST_REQUIRE(ReadBlockFromDisk(block, chainActive[height], Params().GetConsensus(height)));
        }
        const CTransaction& cb = *block.vtx[0];
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout.push_back(CTxOut(cb.vout[0].nValue - FEE, coinbaseSpk));
        SignInput(tx, 0, coinbaseSpk, cb.vout[0].nValue);
        return tx;
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

//! A backend of the coins view whose write throws while it is armed, before
//! it reads what it was given, so that the view's cache stays as it was.
struct FailingCoinsBackend : public CCoinsViewBacked {
    bool armed;
    int failed;
    explicit FailingCoinsBackend(CCoinsView* view) : CCoinsViewBacked(view), armed(false), failed(0) {}
    bool BatchWrite(CCoinsMap& mapCoins, const uint256& hashBlock) override
    {
        if (armed) {
            ++failed;
            throw std::runtime_error("the case fails this write of the coin database");
        }
        return CCoinsViewBacked::BatchWrite(mapCoins, hashBlock);
    }
};

//! For its life, the next write of the chain state fails from a moment the
//! case names by one of two fields. afterDisconnectionTo: from the signal
//! DisconnectTip gives once the tip has moved back to that block, so the
//! write fails inside the disconnection of that block, after the view took
//! the disconnection and before the tip moves. inConnectionOf: from the
//! signal ConnectTip gives for the block it has checked, so the write fails
//! after the view took the block's coins and before the tip moves. The object
//! also makes that write due: FlushStateToDisk writes when the cache is over
//! nCoinCacheUsage plus the room the mempool leaves, compared as a signed
//! figure, and the object puts the first below zero. It is a receiver of
//! validation signals with a scheduler of its own, as TipAtAcceptance is.
struct FailedChainStateWrite : public CValidationInterface {
    FailingCoinsBackend backend;
    CScheduler scheduler;
    const size_t foundCacheUsage;
    const CBlockIndex* afterDisconnectionTo;
    uint256 inConnectionOf;

    FailedChainStateWrite() : backend(pcoinsdbview), foundCacheUsage(nCoinCacheUsage), afterDisconnectionTo(nullptr)
    {
        {
            LOCK(cs_main);
            pcoinsTip->SetBackend(backend);
        }
        RegisterBackgroundSignalScheduler(scheduler);
        RegisterValidationInterface(this);
    }
    ~FailedChainStateWrite()
    {
        UnregisterValidationInterface(this);
        UnregisterBackgroundSignalScheduler();
        nCoinCacheUsage = foundCacheUsage;
        LOCK(cs_main);
        pcoinsTip->SetBackend(*pcoinsdbview);
    }

    void Arm()
    {
        backend.armed = true;
        nCoinCacheUsage = static_cast<size_t>(int64_t(-2000000000));
    }
    void SyncTransaction(const CTransaction&, const CBlockIndex* pindex, int) override
    {
        if (afterDisconnectionTo != nullptr && pindex == afterDisconnectionTo)
            Arm();
    }
    void BlockChecked(const CBlock& block, const CValidationState& state) override
    {
        if (state.IsValid() && block.GetHash() == inConnectionOf)
            Arm();
    }
};

//! Two branches from one block, for the cases in which a reorganisation or an
//! invalidation stops part way. Y, of five blocks, is built first and
//! invalidated. X, of four, is the node's: its fourth block is block A, the
//! first that runs version 6, and holds a funding. With Y valid again the
//! node moves to it, from the tip A to the tip A+1.
//!
//! A case of this fixture ends where a node would stop, and some end with a
//! coins view that is not the tip's. The fixture takes back the node's
//! request for its shutdown and its warning, puts the mempool checks back on,
//! and prints none of the node's messages for its user: one handler that
//! prints nothing takes the place of those the fixtures so far connected, and
//! the next fixture connects the printing handler again.
struct TwoBranchSetup : public RelayChainSetup {
    int below, A;
    CBlockIndex* y[6]; //!< y[1] to y[5], the longer branch
    CBlockIndex* x[5]; //!< x[1] to x[4], the node's branch
    CMutableTransaction funding;
    std::unique_ptr<V6BeginsAt> begins;
    boost::signals2::scoped_connection quiet;

    TwoBranchSetup() : below(0), A(0)
    {
        uiInterface.ThreadSafeMessageBox.disconnect_all_slots();
        quiet = uiInterface.ThreadSafeMessageBox.connect(
            [](const std::string&, const std::string&, unsigned int) { return false; });
    }
    ~TwoBranchSetup()
    {
        fRequestShutdown = false;
        SetMiscWarning("");
        mempool.setSanityCheck(1.0);
    }

    typedef std::vector<std::vector<CMutableTransaction> > BlocksOfTransactions;

    //! yTxns[i] are the transactions of block Y(i+1), xTxns[i] of block
    //! X(i+1) for X1 to X3. The funding spends coinbase 0 of the fixture.
    void Build(const BlocksOfTransactions& yTxns = BlocksOfTransactions(), const BlocksOfTransactions& xTxns = BlocksOfTransactions())
    {
        below = Height();
        A = below + 4;
        begins.reset(new V6BeginsAt(A));
        for (size_t i = 0; i < 5; ++i)
            Advance(i < yTxns.size() ? yTxns[i] : std::vector<CMutableTransaction>());
        {
            LOCK(cs_main);
            for (int i = 1; i <= 5; ++i)
                y[i] = chainActive[below + i];
            CValidationState state;
            BOOST_REQUIRE(InvalidateBlock(state, Params(), y[1]));
        }
        BOOST_REQUIRE_EQUAL(Height(), below);
        mempool.clear();
        for (size_t i = 0; i < 3; ++i)
            Advance(i < xTxns.size() ? xTxns[i] : std::vector<CMutableTransaction>());
        BOOST_REQUIRE_EQUAL(Height(), A - 1);
        funding = Fund(0);
        BOOST_REQUIRE_EQUAL(Verdict(funding), ACCEPTED);
        BOOST_REQUIRE(Submit(StockBlock()));
        BOOST_REQUIRE_EQUAL(Height(), A);
        LOCK(cs_main);
        for (int i = 1; i <= 4; ++i)
            x[i] = chainActive[below + i];
        BOOST_REQUIRE(x[1] != y[1]);
    }

    //! A spend of coinbase n of the fixture and of output 0 of a transaction
    //! that pays the fixture's key.
    CMutableTransaction SpendFixtureCoinbaseAnd(size_t n, const CMutableTransaction& parent)
    {
        const CTransaction& cb = coinbaseTxns[n];
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vin.push_back(CTxIn(COutPoint(parent.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout.push_back(CTxOut(cb.vout[0].nValue + parent.vout[0].nValue - FEE, coinbaseSpk));
        SignInput(tx, 0, coinbaseSpk, cb.vout[0].nValue);
        SignInput(tx, 1, coinbaseSpk, parent.vout[0].nValue);
        return tx;
    }

    //! A spend of the newest coinbase that block A+1 may spend.
    CMutableTransaction YoungCoinbaseSpend()
    {
        return SpendCoinbaseOfBlock(A + 1 - Params().GetConsensus(A + 1).nCoinbaseMaturity);
    }

    bool ViewIsAt(const CBlockIndex* index)
    {
        LOCK(cs_main);
        return pcoinsTip->GetBestBlock() == index->GetBlockHash();
    }
    bool TipIs(const CBlockIndex* index)
    {
        LOCK(cs_main);
        return chainActive.Tip() == index;
    }

    //! Finding its way to Y, the node stops at the tip A-1, on either early
    //! return of ActivateBestChainStep, and the two calls there read that
    //! tip: the next block is A.
    //!
    //! The first return: the undo data of block X3, the block at A-1, is
    //! marked absent, so block A alone is disconnected. The second: block Y4,
    //! the block at A of the longer branch, is pointed past the end of its
    //! file, so the four blocks of X are disconnected and Y1 to Y3 connected.
    //!
    //! The mempool holds the funding of block A once that block has gone, a
    //! spend of the newest coinbase block A may spend, a spend of the newest
    //! that block A+1 may spend, and a transaction with a relative lock of
    //! two blocks on an output mined in block X3, which block A+1 may hold
    //! and block A may not. The first two stay and the node's template for
    //! block A holds them. The last two leave. Then, with the block index as
    //! it was, the reorganisation completes.
    void StopsAtTheTipBelowTheHeight(bool failsToConnect)
    {
        const CMutableTransaction mined = SpendFixtureCoinbase(2);
        BlocksOfTransactions xTxns(3);
        xTxns[2].push_back(mined);
        Build(BlocksOfTransactions(), xTxns);
        const int maturity = Params().GetConsensus(A + 1).nCoinbaseMaturity;
        const CMutableTransaction matureAtA = SpendCoinbaseOfBlock(A - maturity);
        const CMutableTransaction young = YoungCoinbaseSpend();
        CMutableTransaction locked;
        locked.nVersion = 2;
        locked.vin.push_back(CTxIn(COutPoint(mined.GetHash(), 0), CScript(), 2));
        locked.vout.push_back(CTxOut(mined.vout[0].nValue - FEE, coinbaseSpk));
        SignInput(locked, 0, coinbaseSpk, mined.vout[0].nValue);
        BOOST_REQUIRE_EQUAL(Verdict(matureAtA), ACCEPTED);
        BOOST_REQUIRE_EQUAL(Verdict(young), ACCEPTED);
        BOOST_REQUIRE_EQUAL(Verdict(locked), ACCEPTED);

        const unsigned int dataPos = y[4]->nDataPos;
        {
            LOCK(cs_main);
            if (failsToConnect)
                y[4]->nDataPos = 0x7fffffff;
            else
                x[3]->nStatus &= ~BLOCK_HAVE_UNDO;
            BOOST_REQUIRE(ResetBlockFailureFlags(y[1]));
        }
        CValidationState stopped;
        BOOST_CHECK(!ActivateBestChain(stopped, Params()));
        BOOST_CHECK(!stopped.IsInvalid());
        BOOST_REQUIRE_MESSAGE(TipIs(failsToConnect ? y[3] : x[3]), "the tip is at A" << Height() - A);
        BOOST_CHECK(ViewIsAt(failsToConnect ? y[3] : x[3]));
        BOOST_CHECK_EQUAL(ShutdownRequested(), failsToConnect);
        fRequestShutdown = false;

        BOOST_CHECK_MESSAGE(mempool.exists(funding.GetHash()),
            "a funding left the mempool where the reorganisation stopped at the tip A-1, whose next block is A");
        BOOST_CHECK_MESSAGE(mempool.exists(matureAtA.GetHash()), "a spend of a coinbase that block A may spend left the mempool");
        BOOST_CHECK_MESSAGE(!mempool.exists(young.GetHash()), "a spend of a coinbase that block A may not spend is in the mempool");
        BOOST_CHECK_MESSAGE(!mempool.exists(locked.GetHash()), "a transaction whose relative lock block A does not meet is in the mempool");
        BOOST_CHECK_EQUAL(mempool.exists(mined.GetHash()), failsToConnect);
        const Template next = NextTemplate();
        BOOST_CHECK_MESSAGE(next.built, next.error);
        BOOST_CHECK(next.Holds(funding));
        BOOST_CHECK(next.Holds(matureAtA));

        {
            LOCK(cs_main);
            y[4]->nDataPos = dataPos;
            x[3]->nStatus |= BLOCK_HAVE_UNDO;
        }
        CValidationState completed;
        BOOST_CHECK(ActivateBestChain(completed, Params()));
        BOOST_CHECK(TipIs(y[5]));
    }

    //! What the three cases of a failed write of the chain state hold once
    //! the function has returned. The removal ran: the funding of block A,
    //! which returned on the way, has left. removeForReorg did not: the entry
    //! that spends a coinbase and an output the view no longer holds is in
    //! the mempool, and so is the spend of a coinbase that is not mature for
    //! the next block.
    void CheckTheMempoolAfterTheFailedWrite(const FailedChainStateWrite& failure, const CMutableTransaction& entry, const CMutableTransaction& young)
    {
        BOOST_CHECK_EQUAL(failure.backend.failed, 1);
        BOOST_CHECK(ShutdownRequested());
        BOOST_CHECK_MESSAGE(!mempool.exists(funding.GetHash()), "a funding is in the mempool after a stop at a tip whose next block is below the height");
        BOOST_CHECK_MESSAGE(mempool.exists(entry.GetHash()),
            "removeForReorg ran with a coins view that is not the tip's: the entry that spends a coinbase and an output the view does not hold has left");
        BOOST_CHECK_MESSAGE(mempool.exists(young.GetHash()),
            "removeForReorg ran with a coins view that is not the tip's: the spend of a coinbase that is not mature has left");
    }

    //! The first early return of ActivateBestChainStep after a failed write.
    //! Block X2 holds a transaction; the mempool holds an entry that spends a
    //! coinbase and that transaction's output. Blocks A and X3 are
    //! disconnected, and the write fails inside the disconnection of X2: the
    //! tip is still X2, and the view is at X1 and without that output.
    void FirstEarlyReturnAfterAFailedWrite(bool mempoolChecks)
    {
        mempool.setSanityCheck(mempoolChecks ? 1.0 : 0.0);
        const CMutableTransaction mined = SpendFixtureCoinbase(2);
        BlocksOfTransactions xTxns(3);
        xTxns[1].push_back(mined);
        Build(BlocksOfTransactions(), xTxns);
        const CMutableTransaction entry = SpendFixtureCoinbaseAnd(3, mined);
        const CMutableTransaction young = YoungCoinbaseSpend();
        BOOST_REQUIRE_EQUAL(Verdict(entry), ACCEPTED);
        BOOST_REQUIRE_EQUAL(Verdict(young), ACCEPTED);

        FailedChainStateWrite failure;
        failure.afterDisconnectionTo = x[2];
        {
            LOCK(cs_main);
            BOOST_REQUIRE(ResetBlockFailureFlags(y[1]));
        }
        CValidationState stopped;
        BOOST_CHECK(!ActivateBestChain(stopped, Params()));
        BOOST_CHECK(stopped.IsError());
        BOOST_REQUIRE(TipIs(x[2]));
        BOOST_REQUIRE(ViewIsAt(x[1]));
        BOOST_CHECK(!Unspent(COutPoint(mined.GetHash(), 0)));
        CheckTheMempoolAfterTheFailedWrite(failure, entry, young);
    }

    //! The second early return after a failed write. A transaction is mined
    //! below the common ancestor, and block Y1 spends its one output; the
    //! mempool holds an entry that spends a coinbase and the same output. The
    //! four blocks of X are disconnected, and the write fails inside the
    //! connection of Y1: the tip is the common ancestor, and the view is at
    //! Y1 and without that output.
    void SecondEarlyReturnAfterAFailedWrite(bool mempoolChecks)
    {
        mempool.setSanityCheck(mempoolChecks ? 1.0 : 0.0);
        const CMutableTransaction mined = SpendFixtureCoinbase(2);
        Advance({mined});
        BlocksOfTransactions yTxns(1);
        yTxns[0].push_back(SpendToKey(mined));
        Build(yTxns);
        BOOST_REQUIRE(Unspent(COutPoint(mined.GetHash(), 0)));
        const CMutableTransaction entry = SpendFixtureCoinbaseAnd(3, mined);
        const CMutableTransaction young = YoungCoinbaseSpend();
        BOOST_REQUIRE_EQUAL(Verdict(entry), ACCEPTED);
        BOOST_REQUIRE_EQUAL(Verdict(young), ACCEPTED);

        FailedChainStateWrite failure;
        failure.inConnectionOf = y[1]->GetBlockHash();
        {
            LOCK(cs_main);
            BOOST_REQUIRE(ResetBlockFailureFlags(y[1]));
        }
        CValidationState stopped;
        BOOST_CHECK(!ActivateBestChain(stopped, Params()));
        BOOST_CHECK(stopped.IsError());
        BOOST_REQUIRE_EQUAL(Height(), below);
        BOOST_REQUIRE(ViewIsAt(y[1]));
        BOOST_CHECK(!Unspent(COutPoint(mined.GetHash(), 0)));
        CheckTheMempoolAfterTheFailedWrite(failure, entry, young);
    }

    //! The failure return of InvalidateBlock after a failed write: the state
    //! of the first early return, reached by the invalidation of block X1.
    void InvalidateBlockAfterAFailedWrite(bool mempoolChecks)
    {
        mempool.setSanityCheck(mempoolChecks ? 1.0 : 0.0);
        const CMutableTransaction mined = SpendFixtureCoinbase(2);
        BlocksOfTransactions xTxns(3);
        xTxns[1].push_back(mined);
        Build(BlocksOfTransactions(), xTxns);
        const CMutableTransaction entry = SpendFixtureCoinbaseAnd(3, mined);
        const CMutableTransaction young = YoungCoinbaseSpend();
        BOOST_REQUIRE_EQUAL(Verdict(entry), ACCEPTED);
        BOOST_REQUIRE_EQUAL(Verdict(young), ACCEPTED);

        FailedChainStateWrite failure;
        failure.afterDisconnectionTo = x[2];
        bool invalidated;
        {
            LOCK(cs_main);
            CValidationState state;
            invalidated = InvalidateBlock(state, Params(), x[1]);
        }
        BOOST_CHECK(!invalidated);
        BOOST_REQUIRE(TipIs(x[2]));
        BOOST_REQUIRE(ViewIsAt(x[1]));
        BOOST_CHECK(!Unspent(COutPoint(mined.GetHash(), 0)));
        CheckTheMempoolAfterTheFailedWrite(failure, entry, young);
    }
};

std::string WitnessName(Witness w)
{
    return w == ONE_ZERO_BYTE ? "the witness 00" : "a signed witness";
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(relay_dormant_witness_version_tests, RelayChainSetup)

// The tip moves back one block, from A-1 to A-2. Two transactions that fund a
// version 6 output were accepted at the tip A-1, where the next block is A.
// One of them has a child that spends its output with a signed witness. The
// second pays its change first and the version 6 output second, and a third
// pays the version 6 output first and its change second.
// At the tip A-2 the mask of the next block refuses their output: the mempool
// holds none of the four, a spend of the other output with the witness 00
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
    const CMutableTransaction alone = Fund(1, 2, true);
    BOOST_REQUIRE_EQUAL(Verdict(withChild), ACCEPTED);
    BOOST_REQUIRE_EQUAL(Verdict(child), ACCEPTED);
    BOOST_REQUIRE_EQUAL(Verdict(alone), ACCEPTED);
    const CMutableTransaction changeLast = FundChangeLast(2);
    BOOST_REQUIRE_EQUAL(Verdict(changeLast), ACCEPTED);

    InvalidateTip();
    BOOST_REQUIRE_EQUAL(Height(), A - 2);
    BOOST_CHECK_MESSAGE(!mempool.exists(changeLast.GetHash()), "a funding whose version 6 output is followed by its change is in the mempool at the tip A-2");

    BOOST_CHECK_MESSAGE(!mempool.exists(withChild.GetHash()), "a funding accepted at the tip A-1 is in the mempool at the tip A-2");
    BOOST_CHECK_MESSAGE(!mempool.exists(child.GetHash()), "the child of that funding is in the mempool at the tip A-2");
    BOOST_CHECK_MESSAGE(!mempool.exists(alone.GetHash()), "the second funding is in the mempool at the tip A-2");

    const CMutableTransaction taking = Spend(alone, 1, ONE_ZERO_BYTE);
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
// is still A: it is judged with the mask of block A+1, and at the tip A-1 it
// is in the mempool, since the next block is A. The other was accepted at the
// tip A and never mined. At the
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

    {
        TipAtAcceptance returned(mined.GetHash());
        InvalidateTip();
        BOOST_REQUIRE_EQUAL(Height(), A - 1);
        BOOST_REQUIRE_EQUAL(returned.heights.size(), 1u);
        BOOST_CHECK_MESSAGE(returned.heights[0] == A, "the funding of block A returned while the tip was A" << returned.heights[0] - A);
        BOOST_CHECK_MESSAGE(mempool.exists(mined.GetHash()), "the funding of block A is not in the mempool at the tip A-1");
    }
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
// and the signed one is accepted and mined in block A. The spend the case
// builds with no witness and an empty scriptSig, its one input, is refused by
// CheckTransaction at every height.
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
    mempool.clear();

    // A spend of a dormant version 11 output is refused here by the script
    // check, under the flag relay carries for a witness version held for a
    // later rule, and not by the relay rule.
    GatedVersionsBeginAt far(Height() + 1000);
    const COutPoint v11 = SeedCoin(CScript() << OP_11 << valtype(32, 0x0b), SEEDED, 0x51);
    BOOST_CHECK_EQUAL(Verdict(Spend(v11, SEEDED, ONE_ZERO_BYTE)),
        "non-mandatory-script-verify-flag (Witness version reserved for soft-fork upgrades)");
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

// The refusal is the same however the transaction arrives. Relay calls
// AcceptToMemoryPool with fLimitFree true and fOverrideMempoolLimit false,
// sendrawtransaction with both false, and the path that puts a disconnected
// block's transactions back with false and true. Each gets the reason, the
// reject code of a non-standard transaction, no score, and a state that is
// not marked as possible corruption.
BOOST_AUTO_TEST_CASE(the_spend_rule_does_not_read_how_the_transaction_arrived)
{
    BOOST_REQUIRE(fRequireStandard);
    GatedVersionsBeginAt far(Height() + 1000);
    const COutPoint out = SeedCoin(V6Output(), SEEDED, 0x52);
    const CMutableTransaction spend = Spend(out, SEEDED, SIGNED);
    struct Caller {
        const char* name;
        bool fLimitFree, fOverrideMempoolLimit;
    };
    for (const Caller& caller : {Caller{"relay", true, false}, Caller{"sendrawtransaction", false, false}, Caller{"a disconnected block", false, true}}) {
        CValidationState state;
        const std::string verdict = VerdictAs(spend, caller.fLimitFree, caller.fOverrideMempoolLimit, state);
        BOOST_CHECK_MESSAGE(verdict == DORMANT, caller.name << ": \"" << verdict << "\"");
        int nDoS = -1;
        BOOST_CHECK_MESSAGE(state.IsInvalid(nDoS), caller.name);
        BOOST_CHECK_MESSAGE(nDoS == 0, caller.name << ": score " << nDoS);
        BOOST_CHECK_MESSAGE(state.GetRejectCode() == REJECT_NONSTANDARD, caller.name << ": code " << state.GetRejectCode());
        BOOST_CHECK_MESSAGE(!state.CorruptionPossible(), caller.name);
        BOOST_CHECK_EQUAL(mempool.size(), 0u);
    }
}

// The checks of a transaction that run before the rule keep their reasons for
// a spend of a dormant output: the scriptSig of each input must be push-only
// (IsStandardTx), and a relative lock must be met (CheckSequenceLocks). The
// rule comes before the checks of the previous output's form, of the witness
// and of the script.
BOOST_AUTO_TEST_CASE(the_checks_that_run_before_the_spend_rule_keep_their_reasons)
{
    BOOST_REQUIRE(fRequireStandard);
    GatedVersionsBeginAt far(Height() + 1000);
    const COutPoint out = SeedCoin(CScript() << OP_11 << valtype(32, 0x0b), SEEDED, 0x53);

    CMutableTransaction notPushOnly = Spend(out, SEEDED, ONE_ZERO_BYTE);
    notPushOnly.vin[0].scriptSig = CScript() << OP_NOP;
    BOOST_CHECK_EQUAL(Verdict(notPushOnly), "scriptsig-not-pushonly");

    CMutableTransaction locked = Spend(out, SEEDED, ONE_ZERO_BYTE);
    locked.vin[0].nSequence = 0x0000ffff;
    BOOST_CHECK_EQUAL(Verdict(locked), "non-BIP68-final");

    BOOST_CHECK_EQUAL(Verdict(Spend(out, SEEDED, ONE_ZERO_BYTE)), DORMANT);
    BOOST_CHECK_EQUAL(mempool.size(), 0u);
}

// An input with no witness reaches the rule when its scriptSig ends in a push
// that begins with the byte 00: CheckTransaction reads that push where it
// finds no witness. With an empty scriptSig CheckTransaction refuses the
// transaction the case builds, whose one input it is. While the next block is
// below A, relay refuses the first form
// with the rule's reason and a block that holds it connects. When the next
// block is A the version judges it: relay refuses it for another reason, and
// a block that holds it does not connect.
BOOST_AUTO_TEST_CASE(an_input_with_no_witness_and_a_scriptsig_that_ends_in_a_push_of_00_reaches_the_rule)
{
    BOOST_REQUIRE(fRequireStandard);
    const int A = Height() + 4;
    V6BeginsAt begins(A);
    const CMutableTransaction funding = Fund(0, 2);
    Advance({funding});
    BOOST_REQUIRE_EQUAL(Height(), A - 3);

    auto noWitness = [&](unsigned int n, const CScript& scriptSig) {
        CMutableTransaction tx = Spend(funding, n, NO_WITNESS);
        tx.vin[0].scriptSig = scriptSig;
        return tx;
    };
    const CScript push00 = CScript() << valtype(1, 0x00);
    BOOST_REQUIRE_EQUAL(HexStr(push00), "0100");
    const CMutableTransaction empty = noWitness(0, CScript());
    const CMutableTransaction pushed = noWitness(0, push00);
    BOOST_REQUIRE(!CTransaction(pushed).HasWitness());
    {
        CValidationState refused, passed;
        BOOST_CHECK(!CheckTransaction(CTransaction(empty), refused));
        BOOST_CHECK_EQUAL(refused.GetRejectReason(), NO_SIGNATURE);
        BOOST_CHECK_MESSAGE(CheckTransaction(CTransaction(pushed), passed), passed.GetRejectReason());
    }

    BOOST_CHECK_EQUAL(Verdict(empty), NO_SIGNATURE);
    BOOST_CHECK_EQUAL(Verdict(pushed), DORMANT);
    BOOST_REQUIRE_EQUAL(mempool.size(), 0u);
    BOOST_CHECK(Submit(HandBlock({pushed})));
    BOOST_REQUIRE_EQUAL(Height(), A - 2);
    BOOST_CHECK(!Unspent(COutPoint(funding.GetHash(), 0)));

    Advance();
    BOOST_REQUIRE_EQUAL(Height(), A - 1);
    const CMutableTransaction atTheHeight = noWitness(1, push00);
    const std::string verdict = Verdict(atTheHeight);
    BOOST_CHECK_MESSAGE(verdict != DORMANT && verdict != ACCEPTED && verdict != NO_SIGNATURE, "next block A: \"" << verdict << "\"");
    BOOST_REQUIRE_EQUAL(mempool.size(), 0u);
    BOOST_CHECK(!Submit(HandBlock({atTheHeight})));
    BOOST_CHECK_EQUAL(Height(), A - 1);
    BOOST_CHECK(Unspent(COutPoint(funding.GetHash(), 1)));
}

// An input with no witness and an empty scriptSig reaches the rule in a
// transaction that CheckTransaction passes for another input: where the
// transaction has an output OP_5 <32 bytes> and one input whose witness has
// the authority layout (six items, the third the byte 55, the fifth of 2,420
// bytes), CTransaction::HasDilithiumSignatures answers for the whole
// transaction before it reads another input. The output is standard on
// regtest, where version 5 runs. While the next block is below A, relay gives
// the rule's reason. The transaction is no authority transaction, and a block
// that holds it is refused by the authority rule.
BOOST_AUTO_TEST_CASE(an_input_with_no_witness_and_an_empty_scriptsig_reaches_the_rule_beside_an_input_of_the_authority_layout)
{
    BOOST_REQUIRE(fRequireStandard);
    const int A = Height() + 4;
    V6BeginsAt begins(A);
    const CMutableTransaction funding = Fund(0);
    Advance({funding});
    BOOST_REQUIRE_EQUAL(Height(), A - 3);

    const CTransaction& cb = coinbaseTxns[2];
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    tx.vin.push_back(CTxIn(COutPoint(funding.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    tx.vout.push_back(CTxOut(10 * COIN, CScript() << OP_5 << valtype(32, 0x05)));
    tx.vout.push_back(CTxOut(cb.vout[0].nValue + funding.vout[0].nValue - 10 * COIN - FEE, coinbaseSpk));
    SignInput(tx, 0, coinbaseSpk, cb.vout[0].nValue);
    tx.vin[0].scriptWitness.stack.push_back(valtype(1, 0x55));
    tx.vin[0].scriptWitness.stack.push_back(valtype(32, 0x01));
    tx.vin[0].scriptWitness.stack.push_back(valtype(2420, 0x02));
    tx.vin[0].scriptWitness.stack.push_back(valtype(1, 0x03));
    BOOST_REQUIRE_EQUAL(tx.vin[0].scriptWitness.stack.size(), 6u);
    BOOST_REQUIRE(tx.vin[1].scriptWitness.IsNull());
    BOOST_REQUIRE(tx.vin[1].scriptSig.empty());

    const CMutableTransaction alone = Spend(funding, 0, NO_WITNESS);
    {
        CValidationState refused, passed;
        BOOST_CHECK(!CheckTransaction(CTransaction(alone), refused));
        BOOST_CHECK_EQUAL(refused.GetRejectReason(), NO_SIGNATURE);
        BOOST_CHECK_MESSAGE(CheckTransaction(CTransaction(tx), passed), passed.GetRejectReason());
    }
    BOOST_CHECK_EQUAL(Verdict(alone), NO_SIGNATURE);
    BOOST_CHECK_EQUAL(Verdict(tx), DORMANT);
    BOOST_CHECK_EQUAL(mempool.size(), 0u);
    BOOST_CHECK_EQUAL(RejectReasonFor({tx}), "bad-usdsoq-authority-unavailable");
}

// HandBlock and the attestation commitment. With no spend of a version 1
// output in the mempool the template has no commitment and the block is valid.
// With one in the mempool the template commits to it, and the commitment stays
// in the coinbase HandBlock builds: the block is valid when it holds the spend
// and is refused when it does not.
BOOST_AUTO_TEST_CASE(a_hand_block_keeps_the_attestation_commitment_of_the_template)
{
    auto commitments = [](const CBlock& block) {
        uint256 committed;
        return patattest::FindCommitments(*block.vtx[0], committed);
    };
    auto verdict = [](const CBlock& block) {
        LOCK(cs_main);
        CValidationState state;
        return TestBlockValidity(state, Params(), block, chainActive.Tip(), true, true) ? std::string("valid") : state.GetRejectReason();
    };
    const CBlock empty = HandBlock();
    BOOST_CHECK_EQUAL(commitments(empty), 0);
    BOOST_CHECK_EQUAL(verdict(empty), "valid");

    const CMutableTransaction spend = SpendFixtureCoinbase(0);
    BOOST_REQUIRE_EQUAL(Verdict(spend), ACCEPTED);

    const CBlock without = HandBlock();
    BOOST_CHECK_EQUAL(without.vtx.size(), 1u);
    BOOST_CHECK_EQUAL(commitments(without), 1);
    BOOST_CHECK_EQUAL(verdict(without), "bad-blk-pat-commitment-empty");
    const CBlock with = HandBlock({spend});
    BOOST_CHECK_EQUAL(commitments(with), 1);
    BOOST_CHECK_EQUAL(verdict(with), "valid");
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

// The same removal on the path of a reorganisation, ActivateBestChainStep. On
// regtest every block has the same work, so a branch the node moves to is
// never lower than the one it leaves; the case moves the height of the version
// instead of the tip. Two blocks stand at one height. The node is on the
// first, with a funding in its mempool. Made to prefer the second, it
// reorganises and keeps the funding, since the next block still runs the
// version. With the version's height then set above the chain, it reorganises
// back to the first block, and the funding leaves the mempool.
BOOST_AUTO_TEST_CASE(a_reorganisation_applies_the_mask_of_the_new_next_block)
{
    const CBlock first = HandBlock();
    const CBlock second = HandBlock();
    BOOST_REQUIRE(first.GetHash() != second.GetHash());
    BOOST_REQUIRE(Submit(first));
    BOOST_REQUIRE(!Submit(second));

    auto prefer = [&](const CBlock& block) {
        CBlockIndex* index;
        {
            LOCK(cs_main);
            BOOST_REQUIRE(mapBlockIndex.count(block.GetHash()));
            index = mapBlockIndex[block.GetHash()];
        }
        CValidationState state;
        BOOST_REQUIRE(PreciousBlock(state, Params(), index));
        LOCK(cs_main);
        BOOST_REQUIRE(chainActive.Tip() == index);
    };

    const CMutableTransaction funding = Fund(0);
    BOOST_REQUIRE_EQUAL(Verdict(funding), ACCEPTED);
    prefer(second);
    BOOST_CHECK_MESSAGE(mempool.exists(funding.GetHash()), "a funding left the mempool in a reorganisation at a height where the version runs");

    V6BeginsAt later(Height() + 10);
    prefer(first);
    BOOST_CHECK_MESSAGE(!mempool.exists(funding.GetHash()), "a funding is in the mempool after a reorganisation to a tip whose next block is below the height");
}

// A reorganisation that ends where the next block is A keeps a funding, though
// the block after the common ancestor is below A. The common ancestor is at
// A-2 and two blocks stand at A-1. The node is on the first, with a funding
// accepted there, and is made to prefer the second. The removal reads the mask
// of the block after the new tip, which is A.
BOOST_AUTO_TEST_CASE(a_reorganisation_reads_the_mask_of_the_block_after_the_new_tip)
{
    const int A = Height() + 2;
    V6BeginsAt begins(A);
    const CBlock first = HandBlock();
    const CBlock second = HandBlock();
    BOOST_REQUIRE(first.GetHash() != second.GetHash());
    BOOST_REQUIRE(Submit(first));
    BOOST_REQUIRE(!Submit(second));
    BOOST_REQUIRE_EQUAL(Height(), A - 1);

    const CMutableTransaction funding = Fund(0);
    BOOST_REQUIRE_EQUAL(Verdict(funding), ACCEPTED);
    CBlockIndex* index;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mapBlockIndex.count(second.GetHash()));
        index = mapBlockIndex[second.GetHash()];
    }
    CValidationState state;
    BOOST_REQUIRE(PreciousBlock(state, Params(), index));
    {
        LOCK(cs_main);
        BOOST_REQUIRE(chainActive.Tip() == index);
    }
    BOOST_REQUIRE_EQUAL(Height(), A - 1);
    BOOST_CHECK_MESSAGE(mempool.exists(funding.GetHash()), "a funding left the mempool in a reorganisation whose new next block is A");
}

// InvalidateBlock stops part way when a block cannot be disconnected: the
// case marks the undo data of block A-3 as absent and invalidates that block
// from the tip A, where block A holds a funding. Blocks A, A-1 and A-2 are
// disconnected before the failure and the funding returned on the way. At the
// tip A-3 the removal runs before the function returns. The coins view is that
// tip's, so removeForReorg runs too: a spend of the newest coinbase that block
// A+1 may spend leaves.
BOOST_AUTO_TEST_CASE(the_removal_runs_when_invalidateblock_stops_part_way)
{
    const int A = Height() + 4;
    V6BeginsAt begins(A);
    Advance();
    Advance();
    Advance();
    BOOST_REQUIRE_EQUAL(Height(), A - 1);
    const CMutableTransaction funding = Fund(0);
    BOOST_REQUIRE_EQUAL(Verdict(funding), ACCEPTED);
    BOOST_REQUIRE(Submit(StockBlock()));
    BOOST_REQUIRE_EQUAL(Height(), A);
    const CMutableTransaction young = SpendCoinbaseOfBlock(A + 1 - Params().GetConsensus(A + 1).nCoinbaseMaturity);
    BOOST_REQUIRE_EQUAL(Verdict(young), ACCEPTED);

    bool invalidated;
    {
        LOCK(cs_main);
        CBlockIndex* noUndo = chainActive[A - 3];
        noUndo->nStatus &= ~BLOCK_HAVE_UNDO;
        CValidationState state;
        invalidated = InvalidateBlock(state, Params(), noUndo);
        noUndo->nStatus |= BLOCK_HAVE_UNDO;
    }
    BOOST_CHECK(!invalidated);
    BOOST_CHECK_EQUAL(Height(), A - 3);
    BOOST_CHECK_MESSAGE(!mempool.exists(funding.GetHash()), "a funding is in the mempool after InvalidateBlock stopped at a tip whose next block is below the height");
    BOOST_CHECK_MESSAGE(!mempool.exists(young.GetHash()), "a spend of a coinbase that is not mature for the next block is in the mempool after InvalidateBlock stopped");
}

// A reorganisation stops part way, in the two ways ActivateBestChainStep can
// stop after it has disconnected a block. The node is on a branch whose block
// A holds a funding, and a longer branch from the ancestor at A-4 becomes
// valid again.
//
// A block cannot be disconnected: the case marks the undo data of the first
// block of the node's branch as absent, so blocks A, A-1 and A-2 are
// disconnected, the funding returns on the way, and the fourth disconnection
// fails at the tip A-3.
//
// A block cannot be connected for a reason other than its validity: the case
// points the first block of the longer branch at a place past the end of its
// file, so all four blocks are disconnected and the read fails at the tip
// A-4. The node asks for its own shutdown on that path, and the case takes the
// request back.
//
// Either way the mempool does not hold the funding and the node's template
// for the next block is without it. removeForReorg runs on both paths too: an
// ordinary spend of the newest coinbase that block A+1 may spend leaves the
// mempool, since that coinbase is not mature for the block after the tip where
// the reorganisation stops. It runs with the lock-time flags: the block at A-1
// holds a transaction, and one that spends its output with a relative lock of
// two blocks is accepted at the tip A. Where the reorganisation stops the
// first has returned to the mempool and the second, whose lock the next block
// does not meet, has left. With the block index as it was, the reorganisation
// completes.
BOOST_AUTO_TEST_CASE(the_removal_runs_when_a_reorganisation_stops_part_way)
{
    // Every fixture of the unit binary connects the handler that prints a
    // node's message for its user, and none disconnects it, so the message
    // for the unreadable block would be printed once for each fixture so far.
    // For this case one handler that prints nothing takes their place. The
    // next fixture connects the printing handler again.
    uiInterface.ThreadSafeMessageBox.disconnect_all_slots();
    boost::signals2::scoped_connection quiet(uiInterface.ThreadSafeMessageBox.connect(
        [](const std::string&, const std::string&, unsigned int) { return false; }));

    for (const bool failsToConnect : {false, true}) {
        const std::string way = failsToConnect ? "a block that cannot be read" : "a block that cannot be disconnected";
        const int below = Height();
        const int A = below + 4;
        V6BeginsAt begins(A);
        for (int i = 0; i < 5; ++i)
            Advance();
        CBlockIndex* longer;
        {
            LOCK(cs_main);
            longer = chainActive[below + 1];
            CValidationState state;
            BOOST_REQUIRE(InvalidateBlock(state, Params(), longer));
        }
        BOOST_REQUIRE_EQUAL(Height(), below);
        const CMutableTransaction mined = SpendFixtureCoinbase(failsToConnect ? 3 : 2);
        Advance();
        Advance();
        Advance({mined});
        BOOST_REQUIRE_EQUAL(Height(), A - 1);
        const CMutableTransaction funding = Fund(failsToConnect ? 1 : 0);
        BOOST_REQUIRE_EQUAL(Verdict(funding), ACCEPTED);
        BOOST_REQUIRE(Submit(StockBlock()));
        BOOST_REQUIRE_EQUAL(Height(), A);
        const CMutableTransaction young = SpendCoinbaseOfBlock(A + 1 - Params().GetConsensus(A + 1).nCoinbaseMaturity);
        BOOST_REQUIRE_EQUAL(Verdict(young), ACCEPTED);
        CMutableTransaction locked;
        locked.nVersion = 2;
        locked.vin.push_back(CTxIn(COutPoint(mined.GetHash(), 0), CScript(), 2));
        locked.vout.push_back(CTxOut(mined.vout[0].nValue - FEE, coinbaseSpk));
        SignInput(locked, 0, coinbaseSpk, mined.vout[0].nValue);
        BOOST_REQUIRE_EQUAL(Verdict(locked), ACCEPTED);

        CBlockIndex* noUndo;
        const unsigned int dataPos = longer->nDataPos;
        {
            LOCK(cs_main);
            noUndo = chainActive[below + 1];
            BOOST_REQUIRE(noUndo != longer);
            if (failsToConnect)
                longer->nDataPos = 0x7fffffff;
            else
                noUndo->nStatus &= ~BLOCK_HAVE_UNDO;
            BOOST_REQUIRE(ResetBlockFailureFlags(longer));
        }
        BOOST_REQUIRE(!ShutdownRequested());
        CValidationState stopped;
        BOOST_CHECK_MESSAGE(!ActivateBestChain(stopped, Params()), way);
        BOOST_CHECK_MESSAGE(!stopped.IsInvalid(), way);
        BOOST_CHECK_MESSAGE(Height() == (failsToConnect ? A - 4 : A - 3), way << ": the tip is A" << Height() - A);
        BOOST_CHECK_MESSAGE(ShutdownRequested() == failsToConnect, way);
        fRequestShutdown = false;
        SetMiscWarning("");
        BOOST_CHECK_MESSAGE(!mempool.exists(funding.GetHash()),
            way << ": a funding is in the mempool after a reorganisation stopped at a tip whose next block is below the height");
        BOOST_CHECK_MESSAGE(!mempool.exists(young.GetHash()),
            way << ": a spend of a coinbase that is not mature for the next block is in the mempool");
        BOOST_CHECK_MESSAGE(mempool.exists(mined.GetHash()), way << ": the transaction of the block at A-1 did not return to the mempool");
        BOOST_CHECK_MESSAGE(!mempool.exists(locked.GetHash()),
            way << ": a transaction whose relative lock the next block does not meet is in the mempool");
        const Template next = NextTemplate();
        BOOST_CHECK_MESSAGE(next.built, way << ": " << next.error);
        BOOST_CHECK_MESSAGE(!next.Holds(funding), way << ": the template for the next block holds the funding");

        {
            LOCK(cs_main);
            longer->nDataPos = dataPos;
            noUndo->nStatus |= BLOCK_HAVE_UNDO;
        }
        CValidationState completed;
        BOOST_CHECK_MESSAGE(ActivateBestChain(completed, Params()), way);
        BOOST_CHECK_MESSAGE(Height() == A + 1, way << ": the tip is A" << Height() - A);
        BOOST_CHECK(!mempool.exists(funding.GetHash()));
        // The blocks of the next run are built by hand, for a mempool that
        // holds no spend of a version 1 output.
        mempool.clear();
    }
}

// What the calls at the two early returns are given: the tip the step has
// reached, the height of the block after it and the lock-time flags. Each run
// stops at the tip A-1, where a funding and a spend of a coinbase mature at A
// stay and a spend of a coinbase mature at A+1 and a transaction with a
// relative lock that block A does not meet leave
// (TwoBranchSetup::StopsAtTheTipBelowTheHeight).
BOOST_FIXTURE_TEST_CASE(the_first_early_return_reads_the_tip_where_the_reorganisation_stopped, TwoBranchSetup)
{
    StopsAtTheTipBelowTheHeight(false);
}

BOOST_FIXTURE_TEST_CASE(the_second_early_return_reads_the_tip_where_the_reorganisation_stopped, TwoBranchSetup)
{
    StopsAtTheTipBelowTheHeight(true);
}

// A write of the chain state fails inside a disconnection or a connection, and
// the function returns with a coins view that is one block behind the tip or
// one block ahead of it. At each of the three returns that follow, the two
// early returns of ActivateBestChainStep and the failure return of
// InvalidateBlock, the removal of outputs of a dormant version runs, since it
// reads the tip alone, and removeForReorg does not, since it reads the view:
// given that view with mempool checks on, it stops the process by an assertion
// on an entry that spends a coinbase and an output the view no longer holds,
// and with the checks off it removes that entry. Mempool checks are on by
// default on regtest and off on the other networks, and each return has a case
// for either setting.
BOOST_FIXTURE_TEST_CASE(the_first_early_return_after_a_failed_write_of_the_chain_state, TwoBranchSetup)
{
    FirstEarlyReturnAfterAFailedWrite(true);
}

BOOST_FIXTURE_TEST_CASE(the_first_early_return_after_a_failed_write_of_the_chain_state_with_mempool_checks_off, TwoBranchSetup)
{
    FirstEarlyReturnAfterAFailedWrite(false);
}

BOOST_FIXTURE_TEST_CASE(the_second_early_return_after_a_failed_write_of_the_chain_state, TwoBranchSetup)
{
    SecondEarlyReturnAfterAFailedWrite(true);
}

BOOST_FIXTURE_TEST_CASE(the_second_early_return_after_a_failed_write_of_the_chain_state_with_mempool_checks_off, TwoBranchSetup)
{
    SecondEarlyReturnAfterAFailedWrite(false);
}

BOOST_FIXTURE_TEST_CASE(invalidateblock_after_a_failed_write_of_the_chain_state, TwoBranchSetup)
{
    InvalidateBlockAfterAFailedWrite(true);
}

BOOST_FIXTURE_TEST_CASE(invalidateblock_after_a_failed_write_of_the_chain_state_with_mempool_checks_off, TwoBranchSetup)
{
    InvalidateBlockAfterAFailedWrite(false);
}

// The one test of a dormant program, over every version and length. With an
// empty mask versions 2 to 16 are dormant and versions 0 and 1 are not. A set
// bit clears its own version and no other. A program of another length, a
// 34-byte script that is no program and a script that is no witness program
// are never dormant.
BOOST_AUTO_TEST_CASE(the_dormant_test_reads_the_version_the_length_and_the_bit)
{
    auto program = [](int version, size_t length) {
        return CScript() << (version == 0 ? OP_0 : (opcodetype)(OP_1 + version - 1)) << valtype(length, 0x11);
    };
    WitnessVersionMask every = 0;
    for (int version = 0; version <= 16; ++version)
        every |= WitnessVersionBit(version);

    for (int version = 0; version <= 16; ++version) {
        const CScript spk = program(version, 32);
        BOOST_REQUIRE_EQUAL(spk.size(), 34u);
        BOOST_CHECK_MESSAGE(IsDormantWitnessProgram(spk, 0) == (version >= 2), "version " << version << ", empty mask");
        BOOST_CHECK_MESSAGE(!IsDormantWitnessProgram(spk, every), "version " << version << ", every bit set");
        for (int bit = 0; bit <= 16; ++bit) {
            const bool dormant = IsDormantWitnessProgram(spk, WitnessVersionBit(bit));
            BOOST_CHECK_MESSAGE(dormant == (version >= 2 && bit != version), "version " << version << ", bit " << bit);
        }
        for (size_t length = 2; length <= 40; ++length) {
            if (length != 32)
                BOOST_CHECK_MESSAGE(!IsDormantWitnessProgram(program(version, length), 0),
                    "version " << version << ", a program of " << length << " bytes");
        }
    }

    // 34 bytes that begin with OP_6 and are no push of 32 bytes.
    CScript notAProgram = CScript() << OP_6 << OP_DROP;
    notAProgram.insert(notAProgram.end(), 32, (unsigned char)OP_NOP);
    BOOST_REQUIRE_EQUAL(notAProgram.size(), 34u);
    BOOST_CHECK(!IsDormantWitnessProgram(notAProgram, 0));
    BOOST_CHECK(!IsDormantWitnessProgram(CScript() << OP_TRUE, 0));
    BOOST_CHECK(!IsDormantWitnessProgram(CScript(), 0));
    BOOST_CHECK(!IsDormantWitnessProgram(CScript() << OP_RETURN << valtype(32, 0x11), 0));
    // 35 bytes: a version opcode, a push of 32 bytes and one opcode more.
    const CScript longer = CScript() << OP_6 << valtype(32, 0x11) << OP_DROP;
    BOOST_REQUIRE_EQUAL(longer.size(), 35u);
    BOOST_CHECK(!IsDormantWitnessProgram(longer, 0));

    // The input rule over a view: one dormant previous output among the
    // inputs is enough, at any position, and a coinbase has none.
    CCoinsView base;
    CCoinsViewCache view(&base);
    auto coin = [&](unsigned char tag, const CScript& spk) {
        uint256 txid;
        txid.begin()[0] = tag;
        CCoinsModifier c = view.ModifyCoins(txid);
        c->vout.resize(1);
        c->vout[0] = CTxOut(SEEDED, spk);
        return COutPoint(txid, 0);
    };
    const COutPoint plain = coin(1, coinbaseSpk);
    const COutPoint v6 = coin(2, program(6, 32));
    const COutPoint v9 = coin(3, program(9, 32));
    auto spending = [](const std::vector<COutPoint>& outs) {
        CMutableTransaction tx;
        for (const COutPoint& out : outs)
            tx.vin.push_back(CTxIn(out));
        tx.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
        return CTransaction(tx);
    };
    const WitnessVersionMask six = WitnessVersionBit(6);
    BOOST_CHECK(!SpendsDormantWitnessProgram(spending({plain}), view, 0));
    BOOST_CHECK(SpendsDormantWitnessProgram(spending({v6}), view, 0));
    BOOST_CHECK(!SpendsDormantWitnessProgram(spending({v6}), view, six));
    BOOST_CHECK(SpendsDormantWitnessProgram(spending({plain, v6}), view, 0));
    BOOST_CHECK(SpendsDormantWitnessProgram(spending({v6, plain}), view, 0));
    BOOST_CHECK(!SpendsDormantWitnessProgram(spending({plain, v6}), view, six));
    BOOST_CHECK(SpendsDormantWitnessProgram(spending({plain, v6, v9}), view, six));
    BOOST_CHECK(!SpendsDormantWitnessProgram(spending({plain, v6, v9}), view, six | WitnessVersionBit(9)));
    BOOST_CHECK(!SpendsDormantWitnessProgram(coinbaseTxns[0], view, 0));
}

// The mask as one function. For each deployment that sets a bit by height, and
// for a height A on each of regtest's three tiers of parameters (below 10, 10
// to 19, from 20), the bit of each version the deployment governs equals
// DeploymentActiveAtHeight for the block after pindexPrev, at the four blocks
// around A. Version 11 runs when any one of its three deployments does.
// Versions 0, 1, 2, 10 and 12 to 16 have no bit: version 10 has none when the
// two deployments it is allocated to both run. With no block before, the
// height is 0. Bit 3 follows the version-bits state for the block after
// pindexPrev, read over block indexes the case makes: regtest's own figures
// never begin, and with a start time the bit is set from the first block of
// the period after the one that locked in.
BOOST_AUTO_TEST_CASE(the_mask_follows_each_deployment_at_its_height_on_every_tier)
{
    struct Gate {
        Consensus::DeploymentPos pos;
        std::vector<int> versions;
    };
    const std::vector<Gate> gates = {
        {Consensus::DEPLOYMENT_SOQUOBSCURA, {4}},
        {Consensus::DEPLOYMENT_USDSOQ, {5, 7}},
        {Consensus::DEPLOYMENT_P2WSH_DILITHIUM, {6}},
        {Consensus::DEPLOYMENT_BTCSOQ, {8, 9}},
        {Consensus::DEPLOYMENT_CTV, {11}},
        {Consensus::DEPLOYMENT_APO, {11}},
        {Consensus::DEPLOYMENT_CSFS, {11}},
    };
    WitnessVersionMask never = ~(WitnessVersionMask)0;
    for (int version = 3; version <= 11; ++version)
        if (version != 10)
            never &= ~WitnessVersionBit(version);

    LOCK(cs_main);
    BOOST_REQUIRE(chainActive.Height() > 120);
    const int FAR = chainActive.Height() + 1000;
    size_t read = 0;
    for (const Gate& gate : gates) {
        for (int A : {5, 15, 100}) {
            // Every gated deployment far above, then this one at A.
            GatedVersionsBeginAt far(FAR);
            ScopedRegtestActivation at(gate.pos, A);
            for (int next = A - 2; next <= A + 1; ++next) {
                const Consensus::Params& cons = Params().GetConsensus(next);
                const bool active = Consensus::DeploymentActiveAtHeight(next, cons, gate.pos);
                BOOST_CHECK_EQUAL(active, next >= A);
                const WitnessVersionMask mask = NextBlockWitnessVersionMask(chainActive[next - 1]);
                WitnessVersionMask expected = 0;
                if (active)
                    for (int version : gate.versions)
                        expected |= WitnessVersionBit(version);
                BOOST_CHECK_MESSAGE(mask == expected, "deployment " << gate.pos << " at " << A << ", block " << next
                    << ": mask " << mask << ", expected " << expected);
                BOOST_CHECK_EQUAL(mask & never, 0u);
                ++read;
            }
        }
    }
    BOOST_CHECK_EQUAL(read, gates.size() * 3 * 4);

    for (int A : {5, 15, 100}) {
        GatedVersionsBeginAt far(FAR);
        ScopedRegtestActivation usdsoq(Consensus::DEPLOYMENT_USDSOQ, A);
        ScopedRegtestActivation soquobscura(Consensus::DEPLOYMENT_SOQUOBSCURA, A);
        BOOST_CHECK_EQUAL(NextBlockWitnessVersionMask(chainActive[A - 2]), 0u);
        BOOST_CHECK_EQUAL(NextBlockWitnessVersionMask(chainActive[A - 1]),
            WitnessVersionBit(4) | WitnessVersionBit(5) | WitnessVersionBit(7));
    }

    // Regtest's own heights: versions 5 to 9 and 11 from the first block, for
    // the block after the tip and for block 0, which has no block before it.
    const WitnessVersionMask regtest = WitnessVersionBit(5) | WitnessVersionBit(6) | WitnessVersionBit(7) |
                                       WitnessVersionBit(8) | WitnessVersionBit(9) | WitnessVersionBit(11);
    BOOST_CHECK_EQUAL(NextBlockWitnessVersionMask(chainActive.Tip()), regtest);
    BOOST_CHECK_EQUAL(NextBlockWitnessVersionMask(nullptr), regtest);

    // A deployment at height 1: not in block 0, in block 1.
    {
        ScopedRegtestActivation at(Consensus::DEPLOYMENT_P2WSH_DILITHIUM, 1);
        BOOST_CHECK_EQUAL(NextBlockWitnessVersionMask(nullptr) & WitnessVersionBit(6), 0u);
        BOOST_CHECK_EQUAL(NextBlockWitnessVersionMask(chainActive[0]) & WitnessVersionBit(6), WitnessVersionBit(6));
    }

    // Bit 3. Three periods of block indexes that all signal the deployment:
    // defined in the first period, started in the second, locked in in the
    // third, active from the first block after it.
    const Consensus::Params& cons = Params().GetConsensus(0);
    const int window = cons.nMinerConfirmationWindow;
    const int32_t signalling = VERSIONBITS_TOP_BITS | (1 << cons.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit);
    std::vector<CBlockIndex> made(3 * window);
    for (int i = 0; i < 3 * window; ++i) {
        made[i].nHeight = i;
        made[i].pprev = i ? &made[i - 1] : nullptr;
        made[i].nTime = 1500000000 + i;
        made[i].nVersion = signalling;
        made[i].BuildSkip();
    }
    const CBlockIndex* lastOfTheLockedInPeriod = &made[3 * window - 1];
    versionbitscache.Clear();
    BOOST_CHECK_EQUAL(NextBlockWitnessVersionMask(lastOfTheLockedInPeriod), regtest);
    {
        ScopedVersion3Deployment begins(1, Consensus::BIP9Deployment::NO_TIMEOUT);
        BOOST_CHECK_EQUAL(NextBlockWitnessVersionMask(lastOfTheLockedInPeriod->pprev), regtest);
        BOOST_CHECK_EQUAL(NextBlockWitnessVersionMask(lastOfTheLockedInPeriod), regtest | WitnessVersionBit(3));
    }
    BOOST_CHECK_EQUAL(NextBlockWitnessVersionMask(lastOfTheLockedInPeriod), regtest);
    versionbitscache.Clear();
}

BOOST_AUTO_TEST_SUITE_END()
