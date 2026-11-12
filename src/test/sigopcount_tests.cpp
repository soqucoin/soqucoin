// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validation.h"
#include "pubkey.h"
#include "key.h"
#include "script/script.h"
#include "script/standard.h"
#include "uint256.h"
#include "test/test_bitcoin.h"

#include <vector>

#include <boost/foreach.hpp>
#include <boost/test/unit_test.hpp>

// Helpers:
static std::vector<unsigned char>
Serialize(const CScript& s)
{
    std::vector<unsigned char> sSerialized(s.begin(), s.end());
    return sSerialized;
}

BOOST_FIXTURE_TEST_SUITE(sigopcount_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(GetSigOpCount)
{
    // Test CScript::GetSigOpCount()
    CScript s1;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 0U);
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 0U);

    uint160 dummy;
    s1 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 2U);
    s1 << OP_IF << OP_CHECKSIG << OP_ENDIF;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 3U);
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 21U);

    CScript p2sh = GetScriptForDestination(CScriptID(s1));
    CScript scriptSig;
    scriptSig << OP_0 << Serialize(s1);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig), 3U);

    std::vector<CPubKey> keys;
    for (int i = 0; i < 3; i++)
    {
        CKey k;
        k.MakeNewKey(true);
        keys.push_back(k.GetPubKey());
    }
    CScript s2 = GetScriptForMultisig(1, keys);
    BOOST_CHECK_EQUAL(s2.GetSigOpCount(true), 3U);
    BOOST_CHECK_EQUAL(s2.GetSigOpCount(false), 20U);

    p2sh = GetScriptForDestination(CScriptID(s2));
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(true), 0U);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(false), 0U);
    CScript scriptSig2;
    scriptSig2 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << Serialize(s2);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig2), 3U);
}

/**
 * Verifies script execution of the zeroth scriptPubKey of tx output and
 * zeroth scriptSig and witness of tx input.
 */
ScriptError VerifyWithFlag(const CTransaction& output, const CMutableTransaction& input, int flags)
{
    ScriptError error;
    CTransaction inputi(input);
    bool ret = VerifyScript(inputi.vin[0].scriptSig, output.vout[0].scriptPubKey, &inputi.vin[0].scriptWitness, flags, TransactionSignatureChecker(&inputi, 0, output.vout[0].nValue), &error);
    BOOST_CHECK((ret == true) == (error == SCRIPT_ERR_OK));

    return error;
}

/**
 * Builds a creationTx from scriptPubKey and a spendingTx from scriptSig
 * and witness such that spendingTx spends output zero of creationTx.
 * Also inserts creationTx's output into the coins view.
 */
void BuildTxs(CMutableTransaction& spendingTx, CCoinsViewCache& coins, CMutableTransaction& creationTx, const CScript& scriptPubKey, const CScript& scriptSig, const CScriptWitness& witness)
{
    creationTx.nVersion = 1;
    creationTx.vin.resize(1);
    creationTx.vin[0].prevout.SetNull();
    creationTx.vin[0].scriptSig = CScript();
    creationTx.vout.resize(1);
    creationTx.vout[0].nValue = 1;
    creationTx.vout[0].scriptPubKey = scriptPubKey;

    spendingTx.nVersion = 1;
    spendingTx.vin.resize(1);
    spendingTx.vin[0].prevout.hash = creationTx.GetHash();
    spendingTx.vin[0].prevout.n = 0;
    spendingTx.vin[0].scriptSig = scriptSig;
    spendingTx.vin[0].scriptWitness = witness;
    spendingTx.vout.resize(1);
    spendingTx.vout[0].nValue = 1;
    spendingTx.vout[0].scriptPubKey = CScript();

    coins.ModifyCoins(creationTx.GetHash())->FromTx(creationTx, 0);
}

BOOST_AUTO_TEST_CASE(GetTxSigOpCost)
{
    // Transaction creates outputs
    CMutableTransaction creationTx;
    // Transaction that spends outputs and whose
    // sig op cost is going to be tested
    CMutableTransaction spendingTx;

    // Create utxo set
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    // Create key
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    // Default flags
    int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;

    // Multisig script (legacy counting)
    {
        CScript scriptPubKey = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        // Do not use a valid signature to avoid using wallet operations.
        CScript scriptSig = CScript() << OP_0 << OP_0;

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, CScriptWitness());
        // Legacy counting only includes signature operations in scriptSigs and scriptPubKeys
        // of a transaction and does not take the actual executed sig operations into account.
        // spendingTx in itself does not contain a signature operation.
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags), 0);
        // creationTx contains two signature operations in its scriptPubKey, but legacy counting
        // is not accurate.
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(creationTx), coins, flags), MAX_PUBKEYS_PER_MULTISIG * WITNESS_SCALE_FACTOR);
        // VerifyScript accepts witness programs and OP_RETURN outputs only; a bare
        // multisig output is refused before any script runs.
        BOOST_CHECK_EQUAL(VerifyWithFlag(creationTx, spendingTx, flags), SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO);
    }

    // Multisig nested in P2SH
    {
        CScript redeemScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript scriptPubKey = GetScriptForDestination(CScriptID(redeemScript));
        CScript scriptSig = CScript() << OP_0 << OP_0 << ToByteVector(redeemScript);

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, CScriptWitness());
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags), 2 * WITNESS_SCALE_FACTOR);
        // A P2SH output is refused the same way.
        BOOST_CHECK_EQUAL(VerifyWithFlag(creationTx, spendingTx, flags), SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO);
    }

    // Witness v0 program of 20 bytes. GetScriptForWitness derives one from a
    // pay-to-pubkey script with a key of 33 to 65 bytes only, so the program is
    // written out here.
    {
        CScript scriptPubKey = CScript() << OP_0 << ToByteVector(uint160());
        CScript scriptSig = CScript();
        CScriptWitness scriptWitness;
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags), 1);
        // No signature operations if we don't verify the witness.
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags & ~SCRIPT_VERIFY_WITNESS), 0);
        // VerifyScript accepts witness programs of 32 bytes only.
        BOOST_CHECK_EQUAL(VerifyWithFlag(creationTx, spendingTx, flags), SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO);

        // Witness versions 1 to 5 cost one signature operation per input.
        BOOST_CHECK(scriptPubKey[0] == 0x00);
        for (int version = 1; version <= 5; version++) {
            scriptPubKey[0] = 0x50 + version;
            BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
            const int64_t cost = GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags);
            BOOST_CHECK_MESSAGE(cost == 1, "witness version " << version << " costs " << cost << " signature operations, expected 1");
        }

        // The sig op cost for an unallocated witness version is zero.
        scriptPubKey[0] = 0x60;
        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags), 0);
        scriptPubKey[0] = 0x00;
        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);

        // The witness of a coinbase transaction is not taken into account.
        spendingTx.vin[0].prevout.SetNull();
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags), 0);
    }

    // Witness v0 program of 20 bytes nested in P2SH. CountWitnessSigOps reads a
    // witness program in the scriptPubKey only, and the redeem script holds no
    // signature operation.
    {
        CScript scriptSig = CScript() << OP_0 << ToByteVector(uint160());
        CScript scriptPubKey = GetScriptForDestination(CScriptID(scriptSig));
        scriptSig = CScript() << ToByteVector(scriptSig);
        CScriptWitness scriptWitness;
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags), 0);
        BOOST_CHECK_EQUAL(VerifyWithFlag(creationTx, spendingTx, flags), SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO);
    }

    // Witness v0 program of 32 bytes. The count of 2 below pins how the counter
    // reads this output form: it takes the last witness item as a script and
    // counts its signature opcodes (script/interpreter.cpp:1206-1218).
    // VerifyScript reads the same form as a single-key output whose last
    // witness item is the public key (script/interpreter.cpp:2056-2083), and
    // refuses this three-item witness. The count is unrelated to what
    // verification runs. Tracked as bead gbc4f.
    {
        CScript witnessScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript scriptPubKey = GetScriptForWitness(witnessScript);
        CScript scriptSig = CScript();
        CScriptWitness scriptWitness;
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));
        scriptWitness.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags), 2);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags & ~SCRIPT_VERIFY_WITNESS), 0);
        // A witness of three items does not match a v0 program of 32 bytes.
        BOOST_CHECK_EQUAL(VerifyWithFlag(creationTx, spendingTx, flags), SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }

    // Witness v0 program of 32 bytes nested in P2SH
    {
        CScript witnessScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript redeemScript = GetScriptForWitness(witnessScript);
        CScript scriptPubKey = GetScriptForDestination(CScriptID(redeemScript));
        CScript scriptSig = CScript() << ToByteVector(redeemScript);
        CScriptWitness scriptWitness;
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));
        scriptWitness.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags), 0);
        BOOST_CHECK_EQUAL(VerifyWithFlag(creationTx, spendingTx, flags), SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO);
    }
}

BOOST_AUTO_TEST_SUITE_END()
