// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// witness_v11_chain_tests.cpp — witness version 11 on a mined regtest chain:
// what relay accepts, what a block accepts, and what each charges.
//
// The script layer is covered by witness_v11_script_tests.cpp. This file funds
// outputs of the version in mined blocks and spends them through
// AcceptToMemoryPool and through ConnectBlock, under each of the eight
// combinations of the version's three deployments (ctv, apo, csfs), which the
// cases set on regtest for their own scope.
//
// An input of the version has one of four outcomes under a combination:
//
//   dormant    none of the three is active. The input succeeds in a block with
//              nothing read. Relay refuses it.
//   hooked     the version runs and the input leaves through an upgrade hook
//              (a sub-version or a reserved byte) or passes a key-hash check on
//              a key of an undefined type. It succeeds in a block. Relay
//              refuses it.
//   evaluated  the script runs and passes. Relay and a block accept it.
//   failed     the script runs and fails. Relay and a block refuse it.
//
// Relay refuses a dormant or hooked input with the reason
// "non-mandatory-script-verify-flag", naming the script error, and does not
// score the peer that sent it. It refuses a failed input with
// "mandatory-script-verify-flag-failed" and scores the peer.

#include "test/dilithium_chain_setup.h"

#include "consensus/params.h"
#include "hash.h"
#include "policy/policy.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "txmempool.h"

#include <boost/test/unit_test.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

//! The three deployments of witness version 11. Bit i of a combination is
//! V11_DEPLOYMENTS[i].
const Consensus::DeploymentPos V11_DEPLOYMENTS[3] = {
    Consensus::DEPLOYMENT_CTV, Consensus::DEPLOYMENT_APO, Consensus::DEPLOYMENT_CSFS};
const int CTV = 1;
const int APO = 2;
const int CSFS = 4;
const int ALL_THREE = CTV | APO | CSFS;

const CAmount FEE = COIN;

//! For the life of the object, the regtest heights of the three deployments:
//! a deployment whose bit is set in `mask` begins at `nHeight`, and one whose
//! bit is clear is withdrawn. Each height found is put back.
struct ScopedV11Deployments {
    std::unique_ptr<ScopedRegtestActivation> held[3];
    explicit ScopedV11Deployments(int mask, int nHeight = 0)
    {
        for (int i = 0; i < 3; ++i) {
            held[i].reset(new ScopedRegtestActivation(
                V11_DEPLOYMENTS[i], (mask & (1 << i)) ? nHeight : Consensus::BIP9Deployment::NOT_SCHEDULED));
        }
    }
};

valtype Sha256(const valtype& data)
{
    valtype h(32);
    CSHA256().Write(data.data(), data.size()).Finalize(h.data());
    return h;
}

//! The committed item: the sub-version byte and the script.
valtype CommittedItem(const CScript& script, unsigned char subversion = 0xc0)
{
    valtype item(1, subversion);
    item.insert(item.end(), script.begin(), script.end());
    return item;
}

//! OP_11 and the SHA-256 of the committed item.
CScript OutputFor(const valtype& committedItem)
{
    return CScript() << OP_11 << Sha256(committedItem);
}

const valtype TRAILER(1, 0x00);

//! The template hash OP_CHECKTEMPLATEVERIFY compares, written out from its
//! fields for a transaction whose scriptSigs are empty: the version, the lock
//! time, the number of inputs, the hash of the sequences, the number of
//! outputs, the hash of the outputs and the input's index.
valtype TemplateHash(const CMutableTransaction& tx, uint32_t nIn)
{
    auto le32 = [](CSHA256& h, uint32_t v) {
        const unsigned char b[4] = {(unsigned char)v, (unsigned char)(v >> 8), (unsigned char)(v >> 16), (unsigned char)(v >> 24)};
        h.Write(b, 4);
    };
    auto le64 = [](CSHA256& h, uint64_t v) {
        unsigned char b[8];
        for (int i = 0; i < 8; ++i)
            b[i] = (unsigned char)(v >> (8 * i));
        h.Write(b, 8);
    };
    CSHA256 sequences;
    for (const CTxIn& in : tx.vin) {
        BOOST_REQUIRE(in.scriptSig.empty());
        le32(sequences, in.nSequence);
    }
    unsigned char sequencesHash[32];
    sequences.Finalize(sequencesHash);
    CSHA256 outputs;
    for (const CTxOut& out : tx.vout) {
        le64(outputs, (uint64_t)out.nValue);
        le32(outputs, (uint32_t)out.scriptPubKey.size());
        outputs.Write(out.scriptPubKey.data(), out.scriptPubKey.size());
    }
    unsigned char outputsHash[32];
    outputs.Finalize(outputsHash);

    CSHA256 h;
    le32(h, (uint32_t)tx.nVersion);
    le32(h, tx.nLockTime);
    le32(h, (uint32_t)tx.vin.size());
    h.Write(sequencesHash, 32);
    le32(h, (uint32_t)tx.vout.size());
    h.Write(outputsHash, 32);
    le32(h, nIn);
    valtype result(32);
    h.Finalize(result.data());
    return result;
}

//! A script of exactly `size` bytes that leaves one true item.
CScript ScriptOfSize(size_t size)
{
    BOOST_REQUIRE(size >= 4);
    CScript s;
    size_t rest = size - 1;
    if (rest % 2 == 1) {
        s << valtype(1, 0xaa) << OP_DROP;  // three bytes
        rest -= 3;
    }
    for (size_t i = 0; i < rest / 2; ++i)
        s << OP_1 << OP_DROP;
    s << OP_1;
    BOOST_REQUIRE_EQUAL(s.size(), size);
    return s;
}

//! `n` times OP_DROP, then OP_1: a script that takes `n` satisfaction items.
CScript DropScript(size_t n)
{
    CScript s;
    for (size_t i = 0; i < n; ++i)
        s << OP_DROP;
    s << OP_1;
    return s;
}

std::string NonMandatory(ScriptError e)
{
    return std::string("non-mandatory-script-verify-flag (") + ScriptErrorString(e) + ")";
}

std::string Mandatory(ScriptError e)
{
    return std::string("mandatory-script-verify-flag-failed (") + ScriptErrorString(e) + ")";
}

//! What relay answered for one transaction.
struct RelayResult {
    bool accepted;
    std::string reason;  //!< the reject reason, empty when accepted
    int nDoS;            //!< the score given to the sending peer
    int64_t sigOpCost;   //!< the figure the mempool recorded, when accepted
};

struct Coin {
    COutPoint outpoint;
    CAmount value;
};

struct WitnessV11ChainSetup : public DilithiumChainSetup {
    size_t nextCoinbase;
    CKey stranger;
    valtype ownerItem;     //!< the key item of the fixture's key: 0x00 and the key
    valtype strangerItem;

    WitnessV11ChainSetup() : nextCoinbase(0)
    {
        BOOST_REQUIRE_MESSAGE(fRequireStandard, "the unit fixture applies standardness, as mainnet and stagenet do");
        stranger.MakeNewKey(true);
        const CPubKey pub = stranger.GetPubKey();
        ownerItem = PrefixedPubkey(coinbasePkBytes);
        strangerItem = PrefixedPubkey(valtype(pub.begin(), pub.end()));
        BOOST_REQUIRE_EQUAL(ownerItem.size(), 1313u);
    }

    int NextHeight()
    {
        LOCK(cs_main);
        return chainActive.Height() + 1;
    }

    //! The value each of `n` outputs gets from the next funding.
    CAmount NextEach(size_t n) const
    {
        BOOST_REQUIRE(nextCoinbase < coinbaseTxns.size());
        return (coinbaseTxns[nextCoinbase].vout[0].nValue - FEE) / (CAmount)n;
    }

    //! A transaction that pays one mature coinbase to the given outputs in
    //! equal parts, signed and not yet relayed or mined.
    CMutableTransaction FundingTx(const std::vector<CScript>& spks)
    {
        const CAmount each = NextEach(spks.size());
        const CTransaction& cb = coinbaseTxns[nextCoinbase++];
        CMutableTransaction F;
        F.nVersion = 2;
        F.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        for (const CScript& spk : spks)
            F.vout.push_back(CTxOut(each, spk));
        SignInput(F, 0, coinbaseSpk, cb.vout[0].nValue);
        return F;
    }

    //! Funds the given outputs in one mined block and returns one coin an output.
    std::vector<Coin> Fund(const std::vector<CScript>& spks)
    {
        const CMutableTransaction F = FundingTx(spks);
        const CBlock b = CreateAndProcessBlock(std::vector<CMutableTransaction>(1, F), coinbaseSpk);
        BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == b.GetHash(), "the funding block must connect");
        std::vector<Coin> coins;
        for (size_t i = 0; i < F.vout.size(); ++i)
            coins.push_back(Coin{COutPoint(F.GetHash(), (uint32_t)i), F.vout[i].nValue});
        return coins;
    }

    //! A transaction that spends `coin` to the fixture's key, with no witness yet.
    CMutableTransaction SpendTx(const Coin& coin) const
    {
        CMutableTransaction S;
        S.nVersion = 2;
        S.vin.push_back(CTxIn(coin.outpoint, CScript(), CTxIn::SEQUENCE_FINAL));
        S.vout.push_back(CTxOut(coin.value - FEE, coinbaseSpk));
        return S;
    }

    //! The spend of `coin` with the witness [satisfaction items] [committed item] [trailer].
    CMutableTransaction Spend(const Coin& coin, const std::vector<valtype>& satisfaction, const valtype& committed,
                              const valtype& trailer = TRAILER) const
    {
        CMutableTransaction S = SpendTx(coin);
        S.vin[0].scriptWitness.stack = satisfaction;
        S.vin[0].scriptWitness.stack.push_back(committed);
        S.vin[0].scriptWitness.stack.push_back(trailer);
        return S;
    }

    //! A signature item of witness version 11 by `key` for the one input of the
    //! spend of `coin`, over `script`.
    valtype Sign(const CKey& key, const CScript& script, const Coin& coin) const
    {
        const uint256 message = SignatureHash(script, CTransaction(SpendTx(coin)), 0, SIGHASH_ALL, coin.value,
                                              SIGVERSION_WITNESS_V11, nullptr, 0x00);
        valtype sig;
        BOOST_REQUIRE(key.Sign(message, sig));
        sig.push_back((unsigned char)SIGHASH_ALL);
        return sig;
    }

    //! A signature of `key` over a message taken from the stack.
    valtype SignMessage(const CKey& key, const valtype& message) const
    {
        valtype sig;
        BOOST_REQUIRE(key.Sign(Hash(message.begin(), message.end()), sig));
        return sig;
    }

    //! Relays one transaction and empties the mempool again.
    RelayResult Relay(const CMutableTransaction& mtx)
    {
        RelayResult r = {false, std::string(), 0, -1};
        const CTransactionRef tx = MakeTransactionRef(mtx);
        {
            LOCK(cs_main);
            CValidationState st;
            r.accepted = AcceptToMemoryPool(mempool, st, tx, false, nullptr, nullptr, true, 0);
            if (!r.accepted) {
                r.reason = st.GetRejectReason();
                st.IsInvalid(r.nDoS);
            }
        }
        if (r.accepted) {
            LOCK(mempool.cs);
            CTxMemPool::txiter it = mempool.mapTx.find(tx->GetHash());
            BOOST_REQUIRE(it != mempool.mapTx.end());
            r.sigOpCost = it->GetSigOpCost();
        }
        mempool.clear();
        return r;
    }

    //! What a block at `nHeight` charges for `tx`: the flags the count reads
    //! for an input of the version are the three deployment flags, taken here
    //! from each deployment's height.
    int64_t BlockCharge(const CMutableTransaction& tx, int nHeight)
    {
        LOCK(cs_main);
        const Consensus::Params& cons = Params().GetConsensus(nHeight);
        unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        if (Consensus::DeploymentActiveAtHeight(nHeight, cons, Consensus::DEPLOYMENT_CTV))
            flags |= SCRIPT_VERIFY_CTV;
        if (Consensus::DeploymentActiveAtHeight(nHeight, cons, Consensus::DEPLOYMENT_APO))
            flags |= SCRIPT_VERIFY_APO;
        if (Consensus::DeploymentActiveAtHeight(nHeight, cons, Consensus::DEPLOYMENT_CSFS))
            flags |= SCRIPT_VERIFY_CSFS;
        CCoinsViewCache view(pcoinsTip);
        return GetTransactionSigOpCost(CTransaction(tx), view, flags);
    }

    //! Mines a block that holds `tx` and requires it to become the tip.
    void Connect(const CMutableTransaction& tx)
    {
        const CBlock b = CreateAndProcessBlock(std::vector<CMutableTransaction>(1, tx), coinbaseSpk);
        BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == b.GetHash(), "the block must connect");
    }
};

//! The outcome of an input whose script the version reads.
enum Outcome {
    EVALUATED,  //!< the script runs and passes
    FAILED,     //!< the script runs and fails, or is refused before it runs
    HOOKED,     //!< the input leaves through a sub-version or a reserved byte
    HOOKED_KEY, //!< the script runs and a key-hash check passes on a key of an undefined type
};

struct Verdict {
    Outcome outcome;
    ScriptError error;  //!< the script error relay names; SCRIPT_ERR_OK for EVALUATED
};

//! One spend and what it does while the version runs.
struct Entry {
    std::string name;
    CMutableTransaction tx;
    //! The verdict under a combination with at least one deployment active.
    std::function<Verdict(int)> running;
    //! The key-hash checks and OP_CHECKSIGFROMSTACK bytes the count finds in
    //! the script under a combination, when the input does not leave through
    //! a sub-version or a reserved byte.
    std::function<int64_t(int)> checks;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(witness_v11_chain_tests, WitnessV11ChainSetup)

// An output of the version is standard to create exactly where the version
// runs at the next block: with any of its three deployments active, and not
// with the three withdrawn. A 20-byte program under OP_11 and an output of
// witness version 12 are not standard in any of the eight states.
BOOST_AUTO_TEST_CASE(an_output_is_standard_to_create_exactly_where_the_version_runs)
{
    const CScript v11 = OutputFor(CommittedItem(CScript() << OP_1));
    const CScript shortProgram = CScript() << OP_11 << valtype(20, 0x01);
    const CScript v12 = CScript() << OP_12 << valtype(32, 0x01);
    const CMutableTransaction toV11 = FundingTx(std::vector<CScript>(1, v11));
    const CMutableTransaction toShort = FundingTx(std::vector<CScript>(1, shortProgram));
    const CMutableTransaction toV12 = FundingTx(std::vector<CScript>(1, v12));

    for (int mask = 0; mask < 8; ++mask) {
        ScopedV11Deployments deployments(mask);
        const RelayResult created = Relay(toV11);
        if (mask == 0) {
            BOOST_CHECK_MESSAGE(!created.accepted && created.reason == "scriptpubkey" && created.nDoS == 0,
                "with the three withdrawn, a transaction that creates an output of the version must be refused "
                "as non-standard; accepted " << created.accepted << ", reason '" << created.reason << "'");
        } else {
            BOOST_CHECK_MESSAGE(created.accepted,
                "combination " << mask << ": a transaction that creates an output of the version must be "
                "accepted at relay; refused with '" << created.reason << "'");
        }
        for (const CMutableTransaction* other : {&toShort, &toV12}) {
            const RelayResult r = Relay(*other);
            BOOST_CHECK_MESSAGE(!r.accepted && r.reason == "scriptpubkey",
                "combination " << mask << ": an output that is not OP_11 and 32 bytes must stay non-standard; "
                "accepted " << r.accepted << ", reason '" << r.reason << "'");
        }
        // In a block the output is valid to create in every state.
        BOOST_CHECK_MESSAGE(BlockIsValid(std::vector<CMutableTransaction>(1, toV11)),
            "combination " << mask << ": a block that creates an output of the version must be valid");
    }
}

// With the three deployments withdrawn, the state mainnet ships in, an output
// of the version is spent in a block by anyone, with any witness. Relay refuses
// each such spend by the script flag, names the dormant version and does not
// score the peer. With the three active the same spends are refused in a block
// and at relay.
BOOST_AUTO_TEST_CASE(a_spend_of_a_dormant_output_is_refused_at_relay_and_valid_in_a_block)
{
    const CScript script = CScript() << Sha256(ownerItem) << OP_CHECKDILITHIUMKEYHASH << OP_1;
    const valtype committed = CommittedItem(script);
    const std::vector<Coin> coins = Fund(std::vector<CScript>(2, OutputFor(committed)));
    const Coin& coin = coins[0];

    // Three spends by someone who holds no key of the output: one witness
    // item; the committed item with no satisfaction; the stranger's own key
    // and a signature made with it.
    CMutableTransaction oneItem = SpendTx(coin);
    oneItem.vin[0].scriptWitness.stack.push_back(TRAILER);
    const CMutableTransaction noSatisfaction = Spend(coin, {}, committed);
    const CMutableTransaction strangersKey = Spend(coin, {Sign(stranger, script, coin), strangerItem}, committed);
    const CMutableTransaction* attempts[] = {&oneItem, &noSatisfaction, &strangersKey};

    {
        ScopedV11Deployments withdrawn(0);
        for (const CMutableTransaction* attempt : attempts) {
            const RelayResult r = Relay(*attempt);
            BOOST_CHECK_MESSAGE(!r.accepted, "a spend of a dormant output must be refused at relay");
            BOOST_CHECK_MESSAGE(r.reason == NonMandatory(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM),
                "the refusal must be the script flag's and name the dormant version; got '" << r.reason << "'");
            BOOST_CHECK_MESSAGE(r.nDoS == 0, "the sending peer must not be scored; got " << r.nDoS);
            BOOST_CHECK_MESSAGE(BlockIsValid(std::vector<CMutableTransaction>(1, *attempt)),
                "a spend of a dormant output must be valid in a block");
            BOOST_CHECK_EQUAL(BlockCharge(*attempt, NextHeight()), 0);
        }
    }

    // The three active: the same three spends of the same coin.
    const std::string activeReasons[] = {
        "bad-witness-nonstandard",
        Mandatory(SCRIPT_ERR_INVALID_STACK_OPERATION),
        Mandatory(SCRIPT_ERR_CHECKDILITHIUMKEYHASH),
    };
    for (size_t i = 0; i < 3; ++i) {
        const RelayResult r = Relay(*attempts[i]);
        BOOST_CHECK_MESSAGE(!r.accepted && r.reason == activeReasons[i],
            "attempt " << i << " with the three active: accepted " << r.accepted << ", reason '" << r.reason << "'");
        BOOST_CHECK_MESSAGE(!BlockIsValid(std::vector<CMutableTransaction>(1, *attempts[i])),
            "attempt " << i << " must be refused in a block with the three active");
    }

    // The owner's spend is accepted at relay and connects.
    const Coin& second = coins[1];
    const CMutableTransaction owners = Spend(second, {Sign(coinbaseKey, script, second), ownerItem}, committed);
    const RelayResult r = Relay(owners);
    BOOST_CHECK_MESSAGE(r.accepted, "the owner's spend must be accepted at relay; refused with '" << r.reason << "'");
    BOOST_CHECK_EQUAL(r.sigOpCost, 1);
    Connect(owners);
}

// Each upgrade hook: the spend is refused at relay by the script flag with the
// hook's own error and no score for the peer, and a block that holds it
// connects.
BOOST_AUTO_TEST_CASE(each_hook_is_refused_at_relay_and_connects_in_a_block)
{
    const valtype later(40, 0x05);  // a key item of a type this release does not define
    const CScript reservedScript = CScript() << OP_1 << static_cast<opcodetype>(0xbb);
    const CScript laterKeyScript = CScript() << Sha256(later) << OP_CHECKDILITHIUMKEYHASH << OP_1;
    const valtype otherSubversion = CommittedItem(CScript() << OP_1, 0xc1);
    const CScript ctvScript = CScript() << valtype(32, 0x99) << OP_CHECKTEMPLATEVERIFY;

    const std::vector<Coin> coins = Fund({
        OutputFor(CommittedItem(reservedScript)),
        OutputFor(CommittedItem(laterKeyScript)),
        OutputFor(otherSubversion),
        OutputFor(CommittedItem(ctvScript)),
    });

    struct Hook {
        const char* name;
        CMutableTransaction tx;
        ScriptError error;
        int combination;
    };
    const Hook hooks[] = {
        {"a reserved byte", Spend(coins[0], {}, CommittedItem(reservedScript)), SCRIPT_ERR_DISCOURAGE_RESERVED_OPCODE, ALL_THREE},
        {"a key of an undefined type", Spend(coins[1], {valtype(), later}, CommittedItem(laterKeyScript)),
            SCRIPT_ERR_DISCOURAGE_UNKNOWN_KEYTYPE, ALL_THREE},
        {"another sub-version", Spend(coins[2], {valtype(3, 0x07)}, otherSubversion, valtype(5, 0x00)),
            SCRIPT_ERR_DISCOURAGE_UNKNOWN_SUBVERSION, ALL_THREE},
        // OP_CHECKTEMPLATEVERIFY while its deployment is withdrawn and the
        // version runs on the two others: the byte is reserved.
        {"a byte whose deployment is inactive", Spend(coins[3], {}, CommittedItem(ctvScript)),
            SCRIPT_ERR_DISCOURAGE_RESERVED_OPCODE, APO | CSFS},
    };

    for (const Hook& hook : hooks) {
        ScopedV11Deployments deployments(hook.combination);
        const RelayResult r = Relay(hook.tx);
        BOOST_CHECK_MESSAGE(!r.accepted, hook.name << ": the spend must be refused at relay");
        BOOST_CHECK_MESSAGE(r.reason == NonMandatory(hook.error),
            hook.name << ": the refusal must be the script flag's with the hook's own error; got '" << r.reason << "'");
        BOOST_CHECK_MESSAGE(r.nDoS == 0, hook.name << ": the sending peer must not be scored; got " << r.nDoS);
        {
            LOCK(mempool.cs);
            BOOST_CHECK_EQUAL(mempool.size(), 0u);
        }
        Connect(hook.tx);
    }
}

// Over a set of spends and the eight combinations of the three deployments:
// relay accepts a spend only where a block accepts it, the figure the mempool
// records is the figure the block charges, a spend valid with a set of
// deployments active is valid with every subset, and the count of an input is
// zero exactly where it is dormant or leaves through a sub-version or a
// reserved byte.
BOOST_AUTO_TEST_CASE(relay_accepts_only_what_a_block_accepts_under_every_combination)
{
    const valtype ownerHash = Sha256(ownerItem);
    const valtype later(33, 0x09);
    const valtype message = {'p', 'r', 'i', 'c', 'e'};
    const valtype otherMessage = {'p', 'r', 'i', 'c', 'f'};

    const CScript keyScript = CScript() << ownerHash << OP_CHECKDILITHIUMKEYHASH << OP_1;
    const CScript twoKeyScript = CScript() << ownerHash << OP_CHECKDILITHIUMKEYHASH << ownerHash << OP_CHECKDILITHIUMKEYHASH << OP_1;
    const CScript csfsScript = CScript() << OP_CHECKSIGFROMSTACK << OP_1;
    const CScript csfsKeyScript = CScript() << OP_CHECKSIGFROMSTACK << ownerHash << OP_CHECKDILITHIUMKEYHASH << OP_1;
    const CScript reservedScript = CScript() << OP_1 << static_cast<opcodetype>(0xcc);
    const CScript laterKeyScript = CScript() << Sha256(later) << OP_CHECKDILITHIUMKEYHASH << OP_1;
    const CScript trueScript = CScript() << OP_1;
    const CScript dupScript = CScript() << OP_1 << OP_DUP << OP_DROP;

    // The template of a spend: every coin of this case has one value, so one
    // template hash serves, whatever output is spent.
    const size_t nCoins = 14;
    const CAmount each = NextEach(nCoins);
    const valtype rightTemplate = TemplateHash(SpendTx(Coin{COutPoint(), each}), 0);
    valtype wrongTemplate = rightTemplate;
    wrongTemplate[0] ^= 0x01;
    const CScript ctvScript = CScript() << rightTemplate << OP_CHECKTEMPLATEVERIFY;
    const CScript wrongCtvScript = CScript() << wrongTemplate << OP_CHECKTEMPLATEVERIFY;

    const CScript scripts[nCoins] = {
        keyScript, keyScript, ctvScript, wrongCtvScript, csfsScript, csfsScript, reservedScript,
        laterKeyScript, trueScript /* under sub-version 0x01 */, trueScript, trueScript, twoKeyScript, csfsKeyScript, dupScript,
    };
    std::vector<valtype> committed;
    std::vector<CScript> outputs;
    for (size_t i = 0; i < nCoins; ++i) {
        committed.push_back(CommittedItem(scripts[i], i == 8 ? 0x01 : 0xc0));
        outputs.push_back(OutputFor(committed.back()));
    }
    const std::vector<Coin> coins = Fund(outputs);
    BOOST_REQUIRE_EQUAL(coins[0].value, each);

    const valtype csfsSig = SignMessage(coinbaseKey, message);
    auto always = [](Outcome o, ScriptError e) { return [o, e](int) { return Verdict{o, e}; }; };
    auto gatedBy = [](int bit, Outcome o, ScriptError e) {
        return [bit, o, e](int mask) {
            return (mask & bit) ? Verdict{o, e} : Verdict{HOOKED, SCRIPT_ERR_DISCOURAGE_RESERVED_OPCODE};
        };
    };
    auto count = [](int64_t n) { return [n](int) { return n; }; };

    CMutableTransaction withScriptSig = Spend(coins[10], {}, committed[10]);
    withScriptSig.vin[0].scriptSig = CScript() << OP_0;

    const std::vector<Entry> entries = {
        {"the owner's key and signature",
            Spend(coins[0], {Sign(coinbaseKey, keyScript, coins[0]), ownerItem}, committed[0]),
            always(EVALUATED, SCRIPT_ERR_OK), count(1)},
        {"a stranger's key and signature",
            Spend(coins[1], {Sign(stranger, keyScript, coins[1]), strangerItem}, committed[1]),
            always(FAILED, SCRIPT_ERR_CHECKDILITHIUMKEYHASH), count(1)},
        {"the template of the spend",
            Spend(coins[2], {}, committed[2]),
            gatedBy(CTV, EVALUATED, SCRIPT_ERR_OK), count(0)},
        {"another template",
            Spend(coins[3], {}, committed[3]),
            gatedBy(CTV, FAILED, SCRIPT_ERR_CHECKTEMPLATEVERIFY), count(0)},
        {"a signed message",
            Spend(coins[4], {csfsSig, message, ownerItem}, committed[4]),
            gatedBy(CSFS, EVALUATED, SCRIPT_ERR_OK), count(1)},
        {"a signature over another message",
            Spend(coins[5], {csfsSig, otherMessage, ownerItem}, committed[5]),
            gatedBy(CSFS, FAILED, SCRIPT_ERR_CHECKSIGFROMSTACK), count(1)},
        {"a reserved byte",
            Spend(coins[6], {}, committed[6]),
            always(HOOKED, SCRIPT_ERR_DISCOURAGE_RESERVED_OPCODE), count(0)},
        {"a key of an undefined type",
            Spend(coins[7], {valtype(), later}, committed[7]),
            always(HOOKED_KEY, SCRIPT_ERR_DISCOURAGE_UNKNOWN_KEYTYPE), count(1)},
        {"another sub-version",
            Spend(coins[8], {}, committed[8]),
            always(HOOKED, SCRIPT_ERR_DISCOURAGE_UNKNOWN_SUBVERSION), count(0)},
        {"a trailer of two bytes",
            Spend(coins[9], {}, committed[9], valtype(2, 0x00)),
            always(FAILED, SCRIPT_ERR_WITNESS_V11_TRAILER), count(0)},
        {"a scriptSig that is not empty",
            withScriptSig,
            always(FAILED, SCRIPT_ERR_WITNESS_MALLEATED), count(0)},
        {"two key-hash checks",
            Spend(coins[11], {Sign(coinbaseKey, twoKeyScript, coins[11]), ownerItem, Sign(coinbaseKey, twoKeyScript, coins[11]), ownerItem}, committed[11]),
            always(EVALUATED, SCRIPT_ERR_OK), count(2)},
        {"a signed message and a key-hash check",
            Spend(coins[12], {Sign(coinbaseKey, csfsKeyScript, coins[12]), ownerItem, csfsSig, message, ownerItem}, committed[12]),
            gatedBy(CSFS, EVALUATED, SCRIPT_ERR_OK), count(2)},
        {"an opcode outside the set",
            Spend(coins[13], {}, committed[13]),
            always(FAILED, SCRIPT_ERR_DISALLOWED_OPCODE), count(0)},
    };
    BOOST_REQUIRE_EQUAL(entries.size(), nCoins);

    for (const Entry& e : entries) {
        bool valid[8];
        for (int mask = 0; mask < 8; ++mask) {
            ScopedV11Deployments deployments(mask);
            const std::string where = e.name + ", combination " + std::to_string(mask);
            const int nNext = NextHeight();

            // What the case states for this combination.
            const bool dormant = (mask == 0);
            const Verdict v = dormant ? Verdict{HOOKED, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM} : e.running(mask);
            const bool expectValid = (v.outcome != FAILED);
            const bool expectRelay = (v.outcome == EVALUATED);
            const int64_t expectCharge = (dormant || v.outcome == HOOKED) ? 0 : e.checks(mask);

            valid[mask] = BlockIsValid(std::vector<CMutableTransaction>(1, e.tx));
            BOOST_CHECK_MESSAGE(valid[mask] == expectValid,
                where << ": valid in a block " << valid[mask] << ", expected " << expectValid);

            const int64_t charge = BlockCharge(e.tx, nNext);
            BOOST_CHECK_MESSAGE(charge == expectCharge,
                where << ": a block charges " << charge << " sigops, expected " << expectCharge);

            const RelayResult r = Relay(e.tx);
            BOOST_CHECK_MESSAGE(r.accepted == expectRelay,
                where << ": accepted at relay " << r.accepted << " ('" << r.reason << "'), expected " << expectRelay);
            if (r.accepted) {
                BOOST_CHECK_MESSAGE(valid[mask], where << ": accepted at relay and refused in a block");
                BOOST_CHECK_MESSAGE(r.sigOpCost == charge,
                    where << ": the mempool records " << r.sigOpCost << " sigops and the block charges " << charge);
            }
            if (!expectRelay && expectValid) {
                BOOST_CHECK_MESSAGE(r.reason == NonMandatory(v.error) && r.nDoS == 0,
                    where << ": expected the script flag's refusal with no score; got '" << r.reason << "', score " << r.nDoS);
            }
            if (!expectRelay && !expectValid) {
                BOOST_CHECK_MESSAGE(r.reason == Mandatory(v.error) && r.nDoS == 100,
                    where << ": expected a refusal that scores the peer; got '" << r.reason << "', score " << r.nDoS);
            }
        }
        for (int larger = 0; larger < 8; ++larger) {
            for (int smaller = 0; smaller < 8; ++smaller) {
                if ((smaller & larger) != smaller)
                    continue;
                BOOST_CHECK_MESSAGE(!valid[larger] || valid[smaller],
                    e.name << ": valid in a block with combination " << larger << " and refused with its subset " << smaller);
            }
        }
    }
}

// The mempool prices and checks for the block a transaction can next enter,
// and a block reads the deployments at its own height. With the three
// deployments beginning at the next block, the tip's flags charge a spend of
// two key-hash checks nothing and the next block charges two; relay accepts
// the spend and an output of the version, the template carries the block's
// figure, and that block refuses a spend by someone who holds no key. With
// the three beginning one block later, the next block is still dormant: relay
// refuses the spend and the output, and the block accepts the stranger's spend.
BOOST_AUTO_TEST_CASE(relay_reads_the_deployments_at_the_next_block_and_not_at_the_tip)
{
    const valtype ownerHash = Sha256(ownerItem);
    const CScript script = CScript() << ownerHash << OP_CHECKDILITHIUMKEYHASH << ownerHash << OP_CHECKDILITHIUMKEYHASH << OP_1;
    const valtype committed = CommittedItem(script);
    const std::vector<Coin> coins = Fund(std::vector<CScript>(1, OutputFor(committed)));
    const Coin& coin = coins[0];
    const CMutableTransaction S =
        Spend(coin, {Sign(coinbaseKey, script, coin), ownerItem, Sign(coinbaseKey, script, coin), ownerItem}, committed);
    // The same coin spent by someone who holds no key of it.
    const CMutableTransaction stolen =
        Spend(coin, {Sign(stranger, script, coin), strangerItem, Sign(stranger, script, coin), strangerItem}, committed);
    const CMutableTransaction creates = FundingTx(std::vector<CScript>(1, OutputFor(committed)));
    const int nTip = NextHeight() - 1;

    {
        // One block below the first block of the version.
        ScopedV11Deployments later(ALL_THREE, nTip + 2);
        BOOST_CHECK_EQUAL(BlockCharge(S, nTip + 1), 0);
        // The next block is the last in which the version is dormant: it
        // accepts the stranger's spend.
        BOOST_CHECK_MESSAGE(BlockIsValid(std::vector<CMutableTransaction>(1, stolen)),
            "one block below the version's height a block must accept any spend of the output");
        const RelayResult theft = Relay(stolen);
        BOOST_CHECK_MESSAGE(!theft.accepted && theft.reason == NonMandatory(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM),
            "one block below the version's height relay must refuse the stranger's spend as dormant; accepted "
            << theft.accepted << ", reason '" << theft.reason << "'");
        const RelayResult spend = Relay(S);
        BOOST_CHECK_MESSAGE(!spend.accepted && spend.reason == NonMandatory(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM),
            "one block below the version's height a spend must be refused as dormant; accepted " << spend.accepted
            << ", reason '" << spend.reason << "'");
        const RelayResult output = Relay(creates);
        BOOST_CHECK_MESSAGE(!output.accepted && output.reason == "scriptpubkey",
            "one block below the version's height an output must be non-standard; accepted " << output.accepted
            << ", reason '" << output.reason << "'");
        BOOST_CHECK(BlockIsValid(std::vector<CMutableTransaction>(1, S)));
    }
    {
        // The next block is the first block of the version.
        ScopedV11Deployments next(ALL_THREE, nTip + 1);
        BOOST_REQUIRE_EQUAL(BlockCharge(S, nTip), 0);
        const int64_t blockCharge = BlockCharge(S, nTip + 1);
        BOOST_CHECK_EQUAL(blockCharge, 2);

        // A block reads the deployments at its own height: the first block of
        // the version refuses the stranger's spend, and so does relay, with a
        // score for the peer.
        BOOST_CHECK_MESSAGE(!BlockIsValid(std::vector<CMutableTransaction>(1, stolen)),
            "the first block of the version must refuse the stranger's spend");
        const RelayResult theft = Relay(stolen);
        BOOST_CHECK_MESSAGE(!theft.accepted && theft.reason == Mandatory(SCRIPT_ERR_CHECKDILITHIUMKEYHASH) && theft.nDoS == 100,
            "where the next block runs the version relay must refuse the stranger's spend and score the peer; accepted "
            << theft.accepted << ", reason '" << theft.reason << "', score " << theft.nDoS);

        const RelayResult output = Relay(creates);
        BOOST_CHECK_MESSAGE(output.accepted,
            "an output must be standard where the next block runs the version; refused with '" << output.reason << "'");

        {
            LOCK(cs_main);
            CValidationState st;
            const bool ok = AcceptToMemoryPool(mempool, st, MakeTransactionRef(S), false, nullptr, nullptr, true, 0);
            BOOST_REQUIRE_MESSAGE(ok, "the spend must be accepted where the next block runs the version; got: " << FormatStateMessage(st));
        }
        {
            LOCK(mempool.cs);
            CTxMemPool::txiter it = mempool.mapTx.find(S.GetHash());
            BOOST_REQUIRE(it != mempool.mapTx.end());
            BOOST_CHECK_EQUAL(it->GetSigOpCost(), blockCharge);
        }
        // The template builds, which runs the miner's own validity check, and
        // carries the recorded figure.
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(Params()).CreateNewBlock(coinbaseSpk, true);
        BOOST_REQUIRE(tmpl);
        BOOST_REQUIRE_EQUAL(tmpl->block.vtx.size(), 2u);
        BOOST_CHECK(tmpl->block.vtx[1]->GetHash() == S.GetHash());
        BOOST_CHECK_EQUAL(tmpl->vTxSigOpsCost[1], blockCharge);
        mempool.clear();
        BOOST_CHECK(BlockIsValid(std::vector<CMutableTransaction>(1, S)));
    }
}

// The figures. A script that is evaluated is held in a block to 10,000 bytes
// and to 1,000 satisfaction items of 2,421 bytes; relay holds an input of the
// running version to a committed item of 3,601 bytes and to 100 satisfaction
// items, each item other than the committed item 80 bytes at most or of the
// length of a signature (2,420, or 2,421 with its hash type byte) or of a key
// item (1,313). An input that leaves through a hook is outside the block's
// figures and is refused at relay all the same.
BOOST_AUTO_TEST_CASE(an_item_over_each_figure_is_refused_and_a_hooked_script_is_outside_the_figures)
{
    CScript bigReserved = ScriptOfSize(10001);
    bigReserved << static_cast<opcodetype>(0xbb);

    const valtype committedItems[] = {
        CommittedItem(DropScript(1)),         // 0: one satisfaction item
        CommittedItem(DropScript(100)),       // 1
        CommittedItem(DropScript(101)),       // 2
        CommittedItem(DropScript(1000)),      // 3
        CommittedItem(DropScript(1001)),      // 4
        CommittedItem(ScriptOfSize(3600)),    // 5: a committed item of 3,601 bytes
        CommittedItem(ScriptOfSize(3601)),    // 6
        CommittedItem(ScriptOfSize(10000)),   // 7
        CommittedItem(ScriptOfSize(10001)),   // 8
        CommittedItem(bigReserved),           // 9: over the size, with a reserved byte
        CommittedItem(ScriptOfSize(10001), 0xc1),  // 10: over the size, under another sub-version
    };
    std::vector<CScript> outputs;
    for (const valtype& item : committedItems)
        outputs.push_back(OutputFor(item));
    const std::vector<Coin> coins = Fund(outputs);

    struct Row {
        const char* name;
        CMutableTransaction tx;
        bool validInBlock;
        bool acceptedAtRelay;
    };
    const valtype one(1, 0x01);
    const std::vector<valtype> overEveryFigure(1001, valtype(2422, 0x01));
    const Row rows[] = {
        {"an item of 80 bytes", Spend(coins[0], {valtype(80, 0x01)}, committedItems[0]), true, true},
        {"an item of 81 bytes", Spend(coins[0], {valtype(81, 0x01)}, committedItems[0]), true, false},
        {"an item of 1,312 bytes", Spend(coins[0], {valtype(1312, 0x01)}, committedItems[0]), true, false},
        {"an item of 1,313 bytes", Spend(coins[0], {valtype(1313, 0x01)}, committedItems[0]), true, true},
        {"an item of 2,420 bytes", Spend(coins[0], {valtype(2420, 0x01)}, committedItems[0]), true, true},
        {"an item of 2,421 bytes", Spend(coins[0], {valtype(2421, 0x01)}, committedItems[0]), true, true},
        {"an item of 2,422 bytes", Spend(coins[0], {valtype(2422, 0x01)}, committedItems[0]), false, false},
        {"100 satisfaction items", Spend(coins[1], std::vector<valtype>(100, one), committedItems[1]), true, true},
        {"101 satisfaction items", Spend(coins[2], std::vector<valtype>(101, one), committedItems[2]), true, false},
        {"1,000 satisfaction items", Spend(coins[3], std::vector<valtype>(1000, one), committedItems[3]), true, false},
        {"1,001 satisfaction items", Spend(coins[4], std::vector<valtype>(1001, one), committedItems[4]), false, false},
        {"a committed item of 3,601 bytes", Spend(coins[5], {}, committedItems[5]), true, true},
        {"a committed item of 3,602 bytes", Spend(coins[6], {}, committedItems[6]), true, false},
        {"a script of 10,000 bytes", Spend(coins[7], {}, committedItems[7]), true, false},
        {"a script of 10,001 bytes", Spend(coins[8], {}, committedItems[8]), false, false},
        {"over every figure beside a reserved byte", Spend(coins[9], overEveryFigure, committedItems[9]), true, false},
        {"over every figure under another sub-version", Spend(coins[10], overEveryFigure, committedItems[10]), true, false},
    };

    for (const Row& row : rows) {
        BOOST_CHECK_MESSAGE(BlockIsValid(std::vector<CMutableTransaction>(1, row.tx)) == row.validInBlock,
            row.name << ": valid in a block must be " << row.validInBlock);
        const RelayResult r = Relay(row.tx);
        BOOST_CHECK_MESSAGE(r.accepted == row.acceptedAtRelay,
            row.name << ": accepted at relay " << r.accepted << " ('" << r.reason << "'), expected " << row.acceptedAtRelay);
        if (!r.accepted && row.validInBlock) {
            BOOST_CHECK_MESSAGE(r.nDoS == 0, row.name << ": a spend a block accepts must not score the peer; got " << r.nDoS);
        }
    }

    // With the three withdrawn relay applies none of its figures to the
    // version, and the script flag refuses the spend.
    {
        ScopedV11Deployments withdrawn(0);
        const RelayResult r = Relay(rows[1].tx);
        BOOST_CHECK_MESSAGE(!r.accepted && r.reason == NonMandatory(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM),
            "an input over a relay figure, dormant: accepted " << r.accepted << ", reason '" << r.reason << "'");
    }
}

BOOST_AUTO_TEST_SUITE_END()
