// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// dilithium_chain_setup.h — a regtest chain fixture that drives REAL blocks
// through ConnectBlock, shared by the consensus reject-path suites.
//
// Four near-identical copies of this fixture already exist
// (usdsoq_v7_conservation_harness, freeze_registry_harness,
// btcsoq_lifecycle_harness, and one inside usdsoq_v10_reject_path). This header
// exists so the count stops growing; the pre-existing three are deliberately
// left alone rather than churned.
//
// Two capabilities here are load-bearing and are the reason several consensus
// rules went untested for so long:
//
//   * RejectReasonFor(). ProcessNewBlock returns a bool, so a test built on it
//     can only assert that the tip did not move — which passes for the WRONG
//     reject exactly as happily as for the right one. Driving the block through
//     TestBlockValidity yields the CValidationState and therefore the exact
//     string that bead r0vn requires.
//   * SeedCoin(). Drops a mature, spendable coin of an ARBITRARY witness version
//     straight into the UTXO set, so a test can spend an output type that policy
//     would never relay and consensus would never let a block create.

#ifndef BITCOIN_TEST_DILITHIUM_CHAIN_SETUP_H
#define BITCOIN_TEST_DILITHIUM_CHAIN_SETUP_H

#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "key.h"
#include "miner.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "test/test_bitcoin.h"
#include "txdb.h"
#include "uint256.h"
#include "validation.h"

#include "consensus/usdsoq.h"   // CUSDSOQAuthority, ComputeAuthorityKeyHash

extern "C" {
#include "crypto/dilithium/api.h"
}

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>
#include <vector>

//! Regtest coinbase maturity (chainparams: 60 * 4).
static const int DILITHIUM_CHAIN_MATURITY = 240;

//! OP_N <32-byte program> — the one shape every Soqucoin witness version uses.
inline CScript MakeWitnessSpk(opcodetype version, const std::vector<unsigned char>& rawPubkey)
{
    uint256 pkHash;
    CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(pkHash.begin());
    CScript spk;
    spk << version << std::vector<unsigned char>(pkHash.begin(), pkHash.end());
    return spk;
}

//! ML-DSA-44 public keys are 0x00-prefixed on the witness stack (FIPS 204 Table 3).
inline std::vector<unsigned char> PrefixedPubkey(const std::vector<unsigned char>& rawPubkey)
{
    std::vector<unsigned char> out;
    out.reserve(rawPubkey.size() + 1);
    out.push_back(0x00);
    out.insert(out.end(), rawPubkey.begin(), rawPubkey.end());
    return out;
}

//! A real 2-of-3 ML-DSA-44 USDSOQ authority, installed into the consensus
//! global for the lifetime of the object.
//!
//! SOQ-I009: before that fix, the USDSOQ harnesses ran with NO authority
//! configured and relied on ConnectBlock falling straight through
//! `isAuthorityTx && g_usdsoq_authority.IsInitialized()` — i.e. they exercised
//! the authority money path with the authority verifier switched off, which is
//! precisely the state that made forged markers profitable on mainnet. That
//! fall-through is now a hard default-deny, so a test that wants an authority
//! transaction has to bring a real authority and real signatures. This helper
//! is the USDSOQ twin of the fixture already used by
//! btcsoq_lifecycle_harness_tests.
struct UsdsoqTestAuthority {
    std::vector<std::vector<uint8_t>> pks;
    std::vector<std::vector<uint8_t>> sks;

    UsdsoqTestAuthority()
    {
        for (int i = 0; i < 3; i++) {
            std::vector<uint8_t> pk(pqcrystals_dilithium2_PUBLICKEYBYTES);
            std::vector<uint8_t> sk(pqcrystals_dilithium2_SECRETKEYBYTES);
            BOOST_REQUIRE_EQUAL(pqcrystals_dilithium2_ref_keypair(pk.data(), sk.data()), 0);
            pks.push_back(pk);
            sks.push_back(sk);
        }
        LOCK(cs_main);
        g_usdsoq_supply.Reset();
        g_usdsoq_authority_outpoint.SetNull();
        BOOST_REQUIRE(g_usdsoq_authority.Initialize(pks, 2));
    }

    ~UsdsoqTestAuthority()
    {
        LOCK(cs_main);
        g_usdsoq_supply.Reset();
        g_usdsoq_authority_outpoint.SetNull();
    }

    //! The canonical marker script OP_5 <SHA256(concat(pubkeys))>. ConnectBlock
    //! reconstructs exactly this when the tracked authority UTXO has already
    //! been spent by UpdateCoins, so chained authority txs must use it.
    CScript MarkerSpk() const
    {
        uint256 kh = ComputeAuthorityKeyHash(pks);
        CScript s;
        s << OP_5 << std::vector<unsigned char>(kh.begin(), kh.end());
        return s;
    }

    static std::vector<uint8_t> SignWith(const uint256& msg, const std::vector<uint8_t>& sk)
    {
        std::vector<uint8_t> sig(pqcrystals_dilithium2_BYTES);
        size_t siglen = 0;
        BOOST_REQUIRE_EQUAL(pqcrystals_dilithium2_ref_signature(
            sig.data(), &siglen, msg.begin(), 32, nullptr, 0, sk.data()), 0);
        sig.resize(siglen);
        BOOST_REQUIRE_EQUAL(sig.size(), (size_t)DILITHIUM_SIG_SIZE);
        return sig;
    }

    //! Attach the M-of-N authority witness to `authIdx`, signing over
    //! `scriptCode` exactly as ConnectBlock recomputes it (SIGHASH_ALL,
    //! amount 0, BIP143). Layout matches the documented authority stack:
    //!   [0] payout_sig  [1] payout_pk  [2] 0x55 tag  [3] payload
    //!   [4..] auth sigs  [last] authority_set
    void Sign(CMutableTransaction& tx, unsigned int authIdx, const CScript& scriptCode) const
    {
        CTransaction ctx(tx);
        uint256 h = SignatureHash(scriptCode, ctx, authIdx, SIGHASH_ALL,
                                  CAmount(0), SIGVERSION_WITNESS_V0, nullptr);
        std::vector<std::vector<unsigned char>>& w = tx.vin[authIdx].scriptWitness.stack;
        w.clear();
        w.push_back(std::vector<unsigned char>{0x00});   // [0] payout_sig placeholder
        w.push_back(std::vector<unsigned char>{0x00});   // [1] payout_pk placeholder
        w.push_back(std::vector<unsigned char>{0x55});   // [2] authority tag
        w.push_back(std::vector<unsigned char>{0x00});   // [3] payload placeholder
        std::vector<uint8_t> s0 = SignWith(h, sks[0]);
        std::vector<uint8_t> s1 = SignWith(h, sks[1]);
        w.push_back(std::vector<unsigned char>(s0.begin(), s0.end()));
        w.push_back(std::vector<unsigned char>(s1.begin(), s1.end()));
        w.push_back(std::vector<unsigned char>{0x00});   // [last] authority_set placeholder
    }
};

struct DilithiumChainSetup : public TestingSetup {
    CKey coinbaseKey;
    CScript coinbaseSpk;
    std::vector<unsigned char> coinbasePkBytes;
    std::vector<CTransaction> coinbaseTxns;

    DilithiumChainSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        coinbaseKey.MakeNewKey(true);
        CPubKey pk = coinbaseKey.GetPubKey();   // local first — never .GetPubKey().begin() inline
        BOOST_REQUIRE(pk.IsValid());
        coinbasePkBytes.assign(pk.begin(), pk.end());
        BOOST_REQUIRE_EQUAL(coinbasePkBytes.size(), 1312u);
        coinbaseSpk = Spk(OP_1);
        BOOST_REQUIRE_EQUAL(coinbaseSpk.size(), 34u);

        // Dilithium v1 coinbase: regtest sets dilithiumOnlyHeight = 0, so a
        // legacy P2PK coinbase (what TestChain240Setup would mine) is rejected.
        for (int i = 0; i < DILITHIUM_CHAIN_MATURITY; i++) {
            CBlock b = CreateAndProcessBlock({}, coinbaseSpk);
            BOOST_REQUIRE_MESSAGE(b.vtx.size() > 0, "block must have coinbase");
            coinbaseTxns.push_back(*b.vtx[0]);
        }
    }

    //! scriptPubKey of the given witness version, owned by coinbaseKey.
    CScript Spk(opcodetype version) const { return MakeWitnessSpk(version, coinbasePkBytes); }

    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& spk)
    {
        CBlock block = BuildSolvedBlock(txns, spk);
        std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(block);
        bool fNewBlock = false;
        ProcessNewBlock(Params(), shared, true, &fNewBlock);
        return block;
    }

    //! Solve a block on top of the tip WITHOUT connecting it.
    CBlock BuildSolvedBlock(const std::vector<CMutableTransaction>& txns, const CScript& spk)
    {
        const CChainParams& cp = Params();
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(cp).CreateNewBlock(spk, true);
        BOOST_REQUIRE_MESSAGE(tmpl != nullptr, "CreateNewBlock must not return nullptr");
        CBlock& block = tmpl->block;
        block.vtx.resize(1);
        {
            // Drop the witness commitment CreateNewBlock generated for the EMPTY
            // template, then regenerate it over our actual vtx set.
            CMutableTransaction coinbaseMut(*block.vtx[0]);
            coinbaseMut.vout.erase(
                std::remove_if(coinbaseMut.vout.begin(), coinbaseMut.vout.end(),
                    [](const CTxOut& o) {
                        return o.scriptPubKey.size() >= 38 &&
                               o.scriptPubKey[0] == OP_RETURN && o.scriptPubKey[1] == 0x24 &&
                               o.scriptPubKey[2] == 0xaa && o.scriptPubKey[3] == 0x21 &&
                               o.scriptPubKey[4] == 0xa9 && o.scriptPubKey[5] == 0xed;
                    }),
                coinbaseMut.vout.end());
            coinbaseMut.vin[0].scriptWitness.stack.clear();
            block.vtx[0] = MakeTransactionRef(std::move(coinbaseMut));
        }
        for (const CMutableTransaction& tx : txns)
            block.vtx.push_back(MakeTransactionRef(tx));
        GenerateCoinbaseCommitment(block, chainActive.Tip(), cp.GetConsensus(0));
        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
        while (!CheckProofOfWork(block.GetPoWHash(), block.nBits, cp.GetConsensus(0)))
            ++block.nNonce;
        return block;
    }

    //! Run a solved block through the full ConnectBlock path and return the
    //! reject reason, or "" if it validated. THE assertion primitive for r0vn.
    std::string RejectReasonFor(const std::vector<CMutableTransaction>& txns)
    {
        CBlock B = BuildSolvedBlock(txns, coinbaseSpk);
        CValidationState st;
        bool ok;
        {
            LOCK(cs_main);
            ok = TestBlockValidity(st, Params(), B, chainActive.Tip(), true, true);
        }
        if (ok) return std::string();
        BOOST_TEST_MESSAGE("reject: " << st.GetRejectReason()
            << (st.GetDebugMessage().empty() ? "" : " | " + st.GetDebugMessage()));
        return st.GetRejectReason();
    }

    //! Raw validity of a solved block.
    //!
    //! RejectReasonFor() cannot express "rejected with no reason", and that is
    //! exactly what a SCRIPT failure inside a block produces: ConnectBlock
    //! queues script checks and reports `control.Wait()` failure as
    //! `state.DoS(100, false)` with an empty reject string (inherited from
    //! upstream). So a rule enforced in VerifyScript is invisible to the r0vn
    //! assertion primitive — it reads identically to "the block was fine".
    //! Use this when the expected rejection comes from script verification
    //! rather than from a named ConnectBlock rule.
    bool BlockIsValid(const std::vector<CMutableTransaction>& txns)
    {
        CBlock B = BuildSolvedBlock(txns, coinbaseSpk);
        CValidationState st;
        LOCK(cs_main);
        return TestBlockValidity(st, Params(), B, chainActive.Tip(), true, true);
    }

    //! Seed a mature, spendable coin of an arbitrary witness version into the UTXO
    //! set. pcoinsTip is modified directly: an intermediate CCoinsViewCache would
    //! flush its unset hashBlock over the tip's and trip ConnectBlock's assertion.
    COutPoint SeedCoin(const CScript& spk, CAmount value, uint8_t tag)
    {
        uint256 txid;
        txid.begin()[0] = tag;   // distinct txid per seeded coin
        {
            LOCK(cs_main);
            CCoinsModifier c = pcoinsTip->ModifyCoins(txid);
            c->Clear();
            c->fCoinBase = false;
            c->nHeight   = 1;    // mature, non-coinbase
            c->nVersion  = 2;
            c->vout.resize(1);
            c->vout[0].nValue       = value;
            c->vout[0].scriptPubKey = spk;
        }
        return COutPoint(txid, 0);
    }

    //! BIP143 witness-v0 signature over scriptCode, stack = [sig, 0x00||pubkey].
    void SignInput(CMutableTransaction& tx, unsigned int idx, const CScript& scriptCode, CAmount amount)
    {
        CTransaction ctxForSign(tx);
        uint256 sighash = SignatureHash(scriptCode, ctxForSign, idx, SIGHASH_ALL,
                                        amount, SIGVERSION_WITNESS_V0, nullptr);
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(coinbaseKey.Sign(sighash, sig));
        sig.push_back((unsigned char)SIGHASH_ALL);
        tx.vin[idx].scriptWitness.stack.clear();
        tx.vin[idx].scriptWitness.stack.push_back(sig);
        tx.vin[idx].scriptWitness.stack.push_back(PrefixedPubkey(coinbasePkBytes));
    }
};

#endif // BITCOIN_TEST_DILITHIUM_CHAIN_SETUP_H
