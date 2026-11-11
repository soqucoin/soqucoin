// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021-2022 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include "policy/policy.h"

#include "validation.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/foreach.hpp>

    /**
     * Check transaction inputs to mitigate two
     * potential denial-of-service attacks:
     * 
     * 1. scriptSigs with extra data stuffed into them,
     *    not consumed by scriptPubKey (or P2SH script)
     * 2. P2SH scripts with a crazy number of expensive
     *    CHECKSIG/CHECKMULTISIG operations
     *
     * Why bother? To avoid denial-of-service attacks; an attacker
     * can submit a standard HASH... OP_EQUAL transaction,
     * which will get accepted into blocks. The redemption
     * script can be anything; an attacker could use a very
     * expensive-to-check-upon-redemption script like:
     *   DUP CHECKSIG DROP ... repeated 100 times... OP_1
     */

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType, WitnessVersionMask activeWitnessVersions)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    // Standard only where the script layer has a spend path. Solver still names
    // the classical forms (pay-to-pubkey, pay-to-pubkey-hash, pay-to-script-hash,
    // bare multisig) and both witness v0 forms, but VerifyScript refuses every
    // scriptPubKey that is neither OP_RETURN nor a version opcode followed by a
    // 32-byte push (SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO), and reads a 32-byte
    // v0 program as the SHA256 of an ML-DSA-44 public key, which a witness script
    // hash is not. Relayed, each would confirm as an output nobody can spend. A
    // form Solver names later stays non-standard until it is listed here. Policy
    // only: a block may still create these outputs. Bead trp6.
    switch (whichType) {
    case TX_NULL_DATA:
        if (!fAcceptDatacarrier || scriptPubKey.size() > nMaxDatacarrierBytes)
            return false;
        break;
    case TX_WITNESS_V1_SCRIPTHASH:
    case TX_WITNESS_V5_AUTHORITY:
    case TX_WITNESS_V6_COVENANT:
    case TX_WITNESS_V7_USDSOQ:
    case TX_WITNESS_V8_BTCSOQ:
    case TX_WITNESS_V9_BTCSOQ_AUTHORITY:
        break;
    default:
        return false;
    }

    // Reject witness versions v2-v16 at the policy layer UNLESS their consensus
    // rules are active on this chain right now.
    //
    // These programs are consensus-valid-as-anyone-can-spend until their soft fork
    // activates. Relaying one before then is not a soft failure, it is a fund-loss
    // path: the output confirms and anybody may then spend it.
    // Reference: BIP141 section 4 — prevents premature output creation.
    //
    // This previously carved out v5-v9 UNCONDITIONALLY, which was correct on
    // stagenet (where those deployments are ALWAYS_ACTIVE) and wrong on mainnet
    // (where every one of them is nStartTime=0/nTimeout=0 or NOT_SCHEDULED). The
    // effect on mainnet was that v5-v9 outputs were relay-standard AND
    // anyone-can-spend simultaneously. Gating on the live activation state makes
    // policy track consensus on the OUTPUT side, which is the same policy-equals-
    // consensus rule already applied to the INPUT side after live bug daf9fd85.
    //
    // Deliberately a POLICY change, not a consensus one: tightening consensus here
    // would turn each future activation into a hard fork.
    if (scriptPubKey.size() == 34 &&
        scriptPubKey[0] >= 0x52 && scriptPubKey[0] <= 0x60 &&  // OP_2 through OP_16
        scriptPubKey[1] == 32) {
        const int witnessVersion = scriptPubKey[0] - 0x50;      // OP_N encodes N
        if (!(activeWitnessVersions & WitnessVersionBit(witnessVersion))) {
            return false;
        }
    }

    return true;
}

bool IsStandardTx(const CTransaction& tx, std::string& reason, WitnessVersionMask activeWitnessVersions)
{
    if (tx.nVersion > CTransaction::MAX_STANDARD_VERSION || tx.nVersion < 1) {
        reason = "version";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_WEIGHT mitigates CPU exhaustion attacks.
    unsigned int sz = GetTransactionWeight(tx);
    if (sz >= MAX_STANDARD_TX_WEIGHT) {
        reason = "tx-size";
        return false;
    }

    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys (remember the 520 byte limit on redeemScript size). That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)+3=1627
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not
        // considered standard.
        if (txin.scriptSig.size() > 1650) {
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
    }

    unsigned int nDataOut = 0;
    txnouttype whichType;
    BOOST_FOREACH(const CTxOut& txout, tx.vout) {
        if (!::IsStandard(txout.scriptPubKey, whichType, activeWitnessVersions)) {
            reason = "scriptpubkey";
            return false;
        }

        if (whichType == TX_NULL_DATA)
            nDataOut++;
        else if (whichType == TX_WITNESS_V5_AUTHORITY) {
            // Authority marker outputs are 0-value by design — not dust.
            // They serve as on-chain audit trail for USDSOQ operations.
        } else if (whichType == TX_WITNESS_V9_BTCSOQ_AUTHORITY) {
            // Same rule for the BTCSOQ authority marker (0-value by design).
        } else if (txout.IsDust(nHardDustLimit)) {
            reason = "dust";
            return false;
        }

        // SOQ-ARCH-003: Relay-policy enforcement of UTXO_COST_PER_BYTE.
        // Rejects outputs whose value < UTXO_COST_PER_BYTE × serialized_size
        // at the mempool level, preventing "mempool poison" TXs that pass the
        // dust limit but fail ConnectBlock's consensus UTXO cost enforcement.
        // Without this, such TXs sit in the mempool forever — every block
        // template includes them, every block attempt fails, and mining stalls.
        // Exemptions mirror ConnectBlock's UTXO-cost exemption list exactly:
        //   - Unspendable outputs (OP_RETURN) — not in UTXO set
        //   - USDSOQ authority markers (OP_5, 0-value by design)
        //   - BTCSOQ authority markers (OP_9 <32>, 0-value by design)
        // NOTE: v8 BTCSOQ holdings are NOT exempt — they carry sat-denominated
        // value and are subject to the same UTXO-cost floor as any output,
        // matching ConnectBlock exactly (open product question recorded in
        // bead uen6: 6500/byte ⇒ ~279,500-sat minimum per v8 UTXO on nets
        // where UTXO_COST is active; mainnet ships it NOT_SCHEDULED).
        if (!txout.scriptPubKey.IsUnspendable() &&
            !(txout.scriptPubKey.size() == 34 && txout.scriptPubKey[0] == 0x55) &&
            !(txout.scriptPubKey.size() == 34 && txout.scriptPubKey[0] == 0x59 &&
              txout.scriptPubKey[1] == 32)) {
            size_t nOutputSize = ::GetSerializeSize(txout, SER_NETWORK, PROTOCOL_VERSION);
            CAmount nMinUtxoValue = UTXO_COST_PER_BYTE * static_cast<CAmount>(nOutputSize);
            if (txout.nValue < nMinUtxoValue) {
                reason = "utxo-cost-per-byte";
                return false;
            }
        }
    }

    // only one OP_RETURN txout is permitted
    if (nDataOut > 1) {
        reason = "multi-op-return";
        return false;
    }

    return true;
}

bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CTxOut& prev = mapInputs.GetOutputFor(tx.vin[i]);

        std::vector<std::vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            std::vector<std::vector<unsigned char> > stack;
            // convert the scriptSig into a stack, so we can inspect the redeemScript
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SIGVERSION_BASE))
                return false;
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            if (subscript.GetSigOpCount(true) > MAX_P2SH_SIGOPS) {
                return false;
            }
        }
    }

    return true;
}

bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs, WitnessVersionMask activeWitnessVersions)
{
    if (tx.IsCoinBase())
        return true; // Coinbases are skipped

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        // We don't care if witness for this input is empty, since it must not be bloated.
        // If the script is invalid without witness, it would be caught sooner or later during validation.
        if (tx.vin[i].scriptWitness.IsNull())
            continue;

        const CTxOut &prev = mapInputs.GetOutputFor(tx.vin[i]);

        // get the scriptPubKey corresponding to this input:
        CScript prevScript = prev.scriptPubKey;

        if (prevScript.IsPayToScriptHash()) {
            std::vector <std::vector<unsigned char> > stack;
            // If the scriptPubKey is P2SH, we try to extract the redeemScript casually by converting the scriptSig
            // into a stack. We do not check IsPushOnly nor compare the hash as these will be done later anyway.
            // If the check fails at this stage, we know that this txid must be a bad one.
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SIGVERSION_BASE))
                return false;
            if (stack.empty())
                return false;
            prevScript = CScript(stack.back().begin(), stack.back().end());
        }

        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;

        // Non-witness program must not be associated with any witness
        if (!prevScript.IsWitnessProgram(witnessversion, witnessprogram))
            return false;

        // Check P2WSH standard limits
        if (witnessversion == 0 && witnessprogram.size() == 32) {
            if (tx.vin[i].scriptWitness.stack.back().size() > MAX_STANDARD_P2WSH_SCRIPT_SIZE)
                return false;
            size_t sizeWitnessStack = tx.vin[i].scriptWitness.stack.size() - 1;
            if (sizeWitnessStack > MAX_STANDARD_P2WSH_STACK_ITEMS)
                return false;
            for (unsigned int j = 0; j < sizeWitnessStack; j++) {
                if (tx.vin[i].scriptWitness.stack[j].size() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
                    return false;
            }
        }

        // Check P2WSH-Dilithium (witness v6) standard limits while the v6 rules are active.
        // The witness is [satisfaction items...] [witnessScript] [trailer].
        if (witnessversion == 6 && witnessprogram.size() == 32 && (activeWitnessVersions & WitnessVersionBit(6))) {
            const std::vector<std::vector<unsigned char> >& stack = tx.vin[i].scriptWitness.stack;
            if (stack.size() < 2)
                return false;
            // The satisfaction items come first, so their number is the witnessScript's index
            const size_t nSatisfactionItems = stack.size() - 2;
            if (stack[nSatisfactionItems].size() > MAX_STANDARD_V6_SCRIPT_SIZE)
                return false;
            if (nSatisfactionItems > MAX_STANDARD_V6_SATISFACTION_ITEMS)
                return false;
            // Every item other than the witnessScript, the trailer included
            for (size_t j = 0; j < stack.size(); j++) {
                if (j == nSatisfactionItems)
                    continue;
                const size_t itemSize = stack[j].size();
                if (itemSize > MAX_STANDARD_V6_ITEM_SIZE &&
                    itemSize != STANDARD_V6_SIGNATURE_SIZE && itemSize != STANDARD_V6_SIGNATURE_SIZE + 1 &&
                    itemSize != STANDARD_V6_PUBKEY_SIZE && itemSize != STANDARD_V6_PUBKEY_SIZE + 1)
                    return false;
            }
        }
    }
    return true;
}

CFeeRate incrementalRelayFee = CFeeRate(DEFAULT_INCREMENTAL_RELAY_FEE);
unsigned int nBytesPerSigOp = DEFAULT_BYTES_PER_SIGOP;
CAmount nDustLimit = DEFAULT_DUST_LIMIT;
CAmount nHardDustLimit = DEFAULT_HARD_DUST_LIMIT;

int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost)
{
    return (std::max(nWeight, nSigOpCost * nBytesPerSigOp) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
}

int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost)
{
    return GetVirtualTransactionSize(GetTransactionWeight(tx), nSigOpCost);
}
