// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

#include "crypto/binius/verifier.h"
#include <script/interpreter.h>


#include "hash.h"
#include "primitives/transaction.h"
#include "zk/bulletproofs.h"
#include <crypto/latticefold/verifier.h>
#include <crypto/pat/logarithmic.h>
#include <crypto/ripemd160.h>
#include <crypto/sha1.h>
#include <crypto/sha256.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>

#include <cstring>

using namespace std;

typedef vector<unsigned char> valtype;

namespace
{

inline bool set_success(ScriptError* ret)
{
    if (ret)
        *ret = SCRIPT_ERR_OK;
    return true;
}

inline bool set_error(ScriptError* ret, const ScriptError serror)
{
    if (ret)
        *ret = serror;
    return false;
}

} // namespace

bool CastToBool(const valtype& vch)
{
    for (unsigned int i = 0; i < vch.size(); i++) {
        if (vch[i] != 0) {
            // Can be negative zero
            if (i == vch.size() - 1 && vch[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.  There are no loops.
 */
#define stacktop(i) (stack.at(stack.size() + (i)))
#define altstacktop(i) (altstack.at(altstack.size() + (i)))
static inline void popstack(vector<valtype>& stack)
{
    if (stack.empty())
        throw runtime_error("popstack(): stack empty");
    stack.pop_back();
}

// Removed legacy DER helpers as they are no longer used

bool CheckSignatureEncoding(const vector<unsigned char>& vchSig, unsigned int flags, ScriptError* serror)
{
    if (vchSig.size() == 0) {
        return true;
    }

    // Soqucoin only permits ML-DSA (Dilithium) signatures and public keys
    return set_error(serror, SCRIPT_ERR_SIG_DER);
}


bool EvalScript(vector<vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror)
{
    if (serror) *serror = SCRIPT_ERR_OK;

    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    static const CScriptNum bnFalse(0);
    static const CScriptNum bnTrue(1);
    static const valtype vchFalse(0);
    static const valtype vchZero(0);
    static const valtype vchTrue(1, 1);

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    opcodetype opcode;
    valtype vchPushValue;
    CScriptNum bn(0);
    vector<valtype> altstack;
    set_success(serror);

    try {
        while (pc < pend) {
            bool fExec = true;

            if (!script.GetOp(pc, opcode, vchPushValue))
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);

            if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

            if (opcode > OP_16) {
                //
                // Execution
                //
                if (fExec) {
                    if (opcode == OP_CHECKBATCHSIG) {
                        // OP_CHECKBATCHSIG logic remains the same
                        valtype proof_data = stacktop(-3);
                        valtype agg_pk = stacktop(-2);
                        valtype msg_root = stacktop(-1);

                        const uint256 dummy;
                        if (agg_pk.size() != dummy.size() || msg_root.size() != dummy.size()) {
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }

                        const uint256 aggregate_pk(agg_pk);
                        const uint256 message_root_uint(msg_root);
                        sangria::BatchProof proof;
                        proof.proof_data = proof_data;
                        proof.batch_size = proof_data.empty() ? 0 : 1;
                        proof.message_root = message_root_uint;

                        if (!sangria::VerifyBatch(proof, aggregate_pk, message_root_uint)) {
                            return set_error(serror, SCRIPT_ERR_BATCH_VERIFICATION_FAILED);
                        }

                        popstack(stack);
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(valtype(1, 1)); // true
                    } else if (opcode == OP_CHECKPATAGG) {
                        // SECURITY NOTE (Halborn FIND-006): Simple-mode verification removed.
                        // Only full-mode (with witness data) is accepted in consensus.
                        // Stack layout: <sigs...> <pks...> <msgs...> <count> <proof> <agg_pk> <msg_root>
                        // NOTE (FIND-002): sibling_path removed from stack layout.

                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        valtype proof_data = stacktop(-3);
                        valtype agg_pk = stacktop(-2);
                        valtype msg_root = stacktop(-1);

                        // 1. Parse LogarithmicProof from proof_data
                        pat::LogarithmicProof proof;
                        if (!pat::ParseLogarithmicProof(proof_data, proof)) {
                            return set_error(serror, SCRIPT_ERR_PAT_VERIFICATION_FAILED);
                        }


                        // 3. Check for Full Verification (Witness Data)
                        uint32_t n = proof.count;

                        // SECURITY (Halborn FIND-001): Consensus-layer bounds check.
                        // Prevents integer overflow in required_items calculation and
                        // OOM from attacker-crafted count values. Defense-in-depth:
                        // ParseLogarithmicProof already rejects, but the opcode handler
                        // must not trust upstream gates for consensus-critical code.
                        if (n == 0 || n > pat::MAX_PAT_PROOF_COUNT) {
                            return set_error(serror, SCRIPT_ERR_PAT_VERIFICATION_FAILED);
                        }

                        // Required items: 3 (base) + 1 (count) + 3*n (witness triples)
                        // NOTE (FIND-002): sibling_path removed — verifier rebuilds full tree
                        size_t required_items = 4 + 3 * static_cast<size_t>(n);

                        if (stack.size() < required_items) {
                            // SECURITY NOTE (Halborn FIND-006): Insufficient witness data.
                            // Simple-mode (3-item stack) is no longer accepted in consensus.
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }

                        // Full Mode: Verify witness data
                        try {
                            // Extract count (sanity check)
                            valtype count_blob = stacktop(-4);
                            if (count_blob.size() == 4) {
                                uint32_t stack_n;
                                memcpy(&stack_n, count_blob.data(), 4);
                                stack_n = le32toh(stack_n);
                                if (stack_n != n) {
                                    return set_error(serror, SCRIPT_ERR_PAT_VERIFICATION_FAILED);
                                }
                            }

                            // Cast n to int to prevent unsigned arithmetic overflow
                            // in stacktop() index calculations. Without this cast,
                            // -(5 + n + i) wraps to ~4B for uint32_t n.
                            const int sn = static_cast<int>(n);

                            std::vector<valtype> w_sigs, w_pks, w_msgs;
                            w_msgs.reserve(n);
                            w_pks.reserve(n);
                            w_sigs.reserve(n);

                            // Extract msgs (indices -5 to -(4+n))
                            for (int i = 0; i < sn; i++) {
                                w_msgs.push_back(stacktop(-(5 + i)));
                            }

                            // Extract pks (indices -(5+n) to -(4+2*n))
                            for (int i = 0; i < sn; i++) {
                                w_pks.push_back(stacktop(-(5 + sn + i)));
                            }

                            // Extract sigs (indices -(5+2*n) to -(4+3*n))
                            for (int i = 0; i < sn; i++) {
                                w_sigs.push_back(stacktop(-(5 + 2 * sn + i)));
                            }

                            if (!pat::VerifyLogarithmicProof(proof_data, w_sigs, w_pks, w_msgs)) {
                                return set_error(serror, SCRIPT_ERR_PAT_VERIFICATION_FAILED);
                            }

                            // Pop all items
                            for (size_t i = 0; i < required_items; i++) {
                                popstack(stack);
                            }
                        } catch (const std::exception& e) {
                            return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
                        }

                        stack.push_back(valtype(1, 1)); // true
                    } else if (opcode == OP_CHECKFOLDPROOF) {
                        if (stack.size() < 1) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        const valtype& vchProof = stacktop(-1);

                        // Consensus gating
                        // Check flag instead of direct height check
                        if (!(flags & SCRIPT_VERIFY_LATTICEFOLD)) {
                            return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                        }

                        if (!EvalCheckFoldProof(vchProof)) {
                            return set_error(serror, SCRIPT_ERR_CHECKFOLDPROOF_FAILED);
                        }

                        popstack(stack);
                        stack.push_back(valtype(1, 1)); // true
                    } else if (opcode == 0xfb) {        // OP_CHECKDILITHIUMSIG
                        // Single ML-DSA-44 verify
                        if (stack.size() < 2) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        valtype sig = stacktop(-2);
                        valtype pubkey = stacktop(-1);

                        // We need the message hash. In standard CheckSig, it's calculated.
                        // Here we are in an opcode. We need to calculate the sighash.
                        // Use the checker to validate.

                        // Note: This is a simplified implementation.
                        // Real implementation would need to handle sighash type from sig.
                        if (!checker.CheckSig(sig, pubkey, script, sigversion)) {
                            return set_error(serror, SCRIPT_ERR_SIG_DER); // Or SCRIPT_ERR_DILITHIUM_FAIL
                        }

                        popstack(stack);
                        popstack(stack);
                        stack.push_back(valtype(1, 1)); // true
                    }
                }
            } else {
                //
                // Push value
                //
                if (fExec) {
                    if (opcode == OP_0)
                        stack.push_back(vchFalse);
                    else if (opcode >= OP_1 && opcode <= OP_16) {
                        CScriptNum bn((int)opcode - (int)(OP_1 - 1));
                        stack.push_back(bn.getvch());
                    } else
                        stack.push_back(vchPushValue);
                }
            }
        }
    } catch (...) {
        return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    }

    if (!stack.empty())
        return set_success(serror);

    return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
}


size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags)
{
    return 0;
}

PrecomputedTransactionData::PrecomputedTransactionData(const CTransaction& tx)
{
    // Precompute hashPrevouts (BIP143 step 2)
    // Double SHA256 of the serialization of all input outpoints
    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const auto& txin : tx.vin) {
            ss << txin.prevout;
        }
        hashPrevouts = ss.GetHash();
    }

    // Precompute hashSequence (BIP143 step 3)
    // Double SHA256 of the serialization of all input sequence values
    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const auto& txin : tx.vin) {
            ss << txin.nSequence;
        }
        hashSequence = ss.GetHash();
    }

    // Precompute hashOutputs (BIP143 step 8)
    // Double SHA256 of the serialization of all outputs
    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const auto& txout : tx.vout) {
            ss << txout;
        }
        hashOutputs = ss.GetHash();
    }
}

// BIP143 Signature Hash Implementation
// Implements the witness program signature hash algorithm as specified in BIP143
// This ensures signatures commit to: version, prevouts, sequences, outpoint, scriptCode,
// amount, sequence, outputs, locktime, and hashtype
uint256 SignatureHash(const CScript& scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType, const CAmount& amount, SigVersion sigversion, const PrecomputedTransactionData* cache)
{
    // Validate input index
    if (nIn >= txTo.vin.size()) {
        // Return a hash that will never match any signature
        return uint256::ONE;
    }

    if (sigversion == SIGVERSION_WITNESS_V0) {
        // BIP143 signature hash algorithm for witness v0
        uint256 hashPrevouts;
        uint256 hashSequence;
        uint256 hashOutputs;

        // Step 2: hashPrevouts
        // If ANYONECANPAY is not set, use precomputed or compute fresh
        if (!(nHashType & SIGHASH_ANYONECANPAY)) {
            if (cache) {
                hashPrevouts = cache->hashPrevouts;
            } else {
                CHashWriter ss(SER_GETHASH, 0);
                for (const auto& txin : txTo.vin) {
                    ss << txin.prevout;
                }
                hashPrevouts = ss.GetHash();
            }
        }
        // else hashPrevouts remains zero (uint256 default)

        // Step 3: hashSequence
        // If ANYONECANPAY, SINGLE, or NONE are not set, use precomputed or compute fresh
        if (!(nHashType & SIGHASH_ANYONECANPAY) &&
            (nHashType & 0x1f) != SIGHASH_SINGLE &&
            (nHashType & 0x1f) != SIGHASH_NONE) {
            if (cache) {
                hashSequence = cache->hashSequence;
            } else {
                CHashWriter ss(SER_GETHASH, 0);
                for (const auto& txin : txTo.vin) {
                    ss << txin.nSequence;
                }
                hashSequence = ss.GetHash();
            }
        }
        // else hashSequence remains zero

        // Step 8: hashOutputs
        if ((nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
            // SIGHASH_ALL: hash all outputs
            if (cache) {
                hashOutputs = cache->hashOutputs;
            } else {
                CHashWriter ss(SER_GETHASH, 0);
                for (const auto& txout : txTo.vout) {
                    ss << txout;
                }
                hashOutputs = ss.GetHash();
            }
        } else if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn < txTo.vout.size()) {
            // SIGHASH_SINGLE: hash only the output at the same index
            CHashWriter ss(SER_GETHASH, 0);
            ss << txTo.vout[nIn];
            hashOutputs = ss.GetHash();
        }
        // else (SIGHASH_NONE or SINGLE with no corresponding output) hashOutputs remains zero

        // Compute the sighash preimage per BIP143:
        // 1. nVersion (4 bytes)
        // 2. hashPrevouts (32 bytes)
        // 3. hashSequence (32 bytes)
        // 4. outpoint being spent (32+4 bytes)
        // 5. scriptCode (serialized as scripts are)
        // 6. amount (8 bytes)
        // 7. nSequence of the input (4 bytes)
        // 8. hashOutputs (32 bytes)
        // 9. nLockTime (4 bytes)
        // 10. sighash type (4 bytes, little-endian)
        CHashWriter ss(SER_GETHASH, 0);
        ss << txTo.nVersion;
        ss << hashPrevouts;
        ss << hashSequence;
        ss << txTo.vin[nIn].prevout;
        ss << *(CScriptBase*)(&scriptCode);
        ss << amount;
        ss << txTo.vin[nIn].nSequence;
        ss << hashOutputs;
        ss << txTo.nLockTime;
        ss << nHashType;

        return ss.GetHash();
    }

    // SIGVERSION_BASE: Legacy sighash (pre-SegWit)
    // We still support this for compatibility, but Soqucoin primarily uses witness v0
    // Create a copy of the transaction for modification
    CMutableTransaction txTmp(txTo);

    // Blank out other inputs' signatures
    for (auto& in : txTmp.vin) {
        in.scriptSig.clear();
    }
    // Set the scriptCode for the input being signed
    txTmp.vin[nIn].scriptSig = scriptCode;

    // Handle SIGHASH types
    if ((nHashType & 0x1f) == SIGHASH_NONE) {
        // Signing input but not outputs
        txTmp.vout.clear();
        // Let other inputs update their sequence
        for (unsigned int i = 0; i < txTmp.vin.size(); i++) {
            if (i != nIn) {
                txTmp.vin[i].nSequence = 0;
            }
        }
    } else if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
        // Sign only the output at the same index
        if (nIn >= txTmp.vout.size()) {
            // SIGHASH_SINGLE bug: return 1 as hash
            return uint256::ONE;
        }
        txTmp.vout.resize(nIn + 1);
        for (unsigned int i = 0; i < nIn; i++) {
            txTmp.vout[i].SetNull();
        }
        // Let other inputs update their sequence
        for (unsigned int i = 0; i < txTmp.vin.size(); i++) {
            if (i != nIn) {
                txTmp.vin[i].nSequence = 0;
            }
        }
    }

    // SIGHASH_ANYONECANPAY: only sign this input
    if (nHashType & SIGHASH_ANYONECANPAY) {
        txTmp.vin.resize(1);
        txTmp.vin[0] = txTo.vin[nIn];
        txTmp.vin[0].scriptSig = scriptCode;
    }

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp;
    ss << nHashType;
    return ss.GetHash();
}

// Strict post-quantum script verification — ECDSA paths completely removed
// Only OP_CHECKDILITHIUMSIG (0xfb), OP_CHECKPATAGG (0xfd), OP_CHECKFOLDPROOF (0xfc) are allowed
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror)
{
    // Enforce Dilithium Output Type (OP_0 or OP_1 <32-byte hash>)
    // Witness v0 = OP_0, Witness v1 = OP_1 (Dilithium)
    bool is_dilithium = (scriptPubKey.size() == 34 &&
                         (scriptPubKey[0] == OP_0 || scriptPubKey[0] == OP_1) &&
                         scriptPubKey[1] == 32);
    bool is_op_return = (scriptPubKey.size() > 0 && scriptPubKey[0] == OP_RETURN);

    if (!is_dilithium && !is_op_return) {
        return set_error(serror, SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO);
    }

    if (is_op_return) {
        // Check for Confidential Transaction (v1): OP_RETURN <commitment> <proof>
        // Commitment is 33 bytes, Proof is ~2660 bytes
        // Total script size: 1 + 1 (push 32) + 32 + 3 (push 1200) + 1200 = ~1237 bytes
        // We verify the proof if present
        if (scriptPubKey.size() > 1000) { // Heuristic check
            // Extract commitment and proof
            // Script: OP_RETURN <32-byte-commitment> <1200-byte-proof>
            // Parsing:
            // [0] = OP_RETURN
            // [1] = 0x21 (33 bytes)
            // [2..33] = commitment
            // [34..36] = push opcode for 1200 bytes (e.g. 0x4d 0xb0 0x04)
            // [37..] = proof

            CScript::const_iterator pc = scriptPubKey.begin();
            opcodetype opcode;
            std::vector<unsigned char> vch;

            // OP_RETURN
            if (!scriptPubKey.GetOp(pc, opcode, vch) || opcode != OP_RETURN) return set_error(serror, SCRIPT_ERR_OP_RETURN);

            // Commitment
            std::vector<unsigned char> commitmentData;
            if (!scriptPubKey.GetOp(pc, opcode, commitmentData) || commitmentData.size() != 33) return set_error(serror, SCRIPT_ERR_OP_RETURN);

            // Proof
            std::vector<unsigned char> proofData;
            if (!scriptPubKey.GetOp(pc, opcode, proofData) || proofData.size() < 100) return set_error(serror, SCRIPT_ERR_OP_RETURN);

            // Verify Range Proof
            zk::Commitment comm(commitmentData);
            zk::RangeProof proof(proofData);

            if (!zk::VerifyRangeProof(proof, comm)) {
                return set_error(serror, SCRIPT_ERR_ZKPROOF_FAILED);
            }
            return set_success(serror);
        }
        return set_error(serror, SCRIPT_ERR_OP_RETURN);
    }

    // Dilithium verification
    if (!witness || witness->stack.size() != 2) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }

    const valtype& sig = witness->stack[0];
    const valtype& pubkey = witness->stack[1];

    // For Dilithium witness v1, the pubkey in the witness stack is prefixed with 0x00
    // (NIST FIPS 204 Table 3 requirement). We need to strip this prefix before hashing
    // to compare with the witness program.
    const unsigned char* pubkeyData = pubkey.data();
    size_t pubkeySize = pubkey.size();

    // Check if this is a 0x00-prefixed Dilithium pubkey (1313 bytes)
    if (pubkey.size() == 1313 && pubkey[0] == 0x00) {
        // Skip the 0x00 prefix for hashing
        pubkeyData = pubkey.data() + 1;
        pubkeySize = pubkey.size() - 1;
    } else {
    }

    // Verify pubkey hash matches scriptPubKey
    uint256 hash;
    CSHA256().Write(pubkeyData, pubkeySize).Finalize(hash.begin());

    if (memcmp(hash.begin(), scriptPubKey.data() + 2, 32) != 0) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }

    // Verify signature
    // Use SIGVERSION_WITNESS_V0 for now as it provides witness sighash structure
    if (!checker.CheckSig(sig, pubkey, scriptSig, SIGVERSION_WITNESS_V0)) {
        return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
    }

    return set_success(serror);
}


bool TransactionSignatureChecker::VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const
{
    return vchPubKey.Verify(sighash, vchSig);
}

bool TransactionSignatureChecker::CheckSig(const std::vector<unsigned char>& vchSigIn, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
{
    // For Dilithium witness v1 signatures, the public key in the witness stack
    // is prefixed with 0x00 (NIST FIPS 204 Table 3 requirement).
    // We need to strip this prefix before creating the CPubKey object.
    std::vector<unsigned char> vchPubKeyActual = vchPubKey;

    // Check if this is a Dilithium pubkey (prefixed with 0x00 and size is 1313)
    if (vchPubKey.size() == 1313 && vchPubKey[0] == 0x00) {
        // Strip the 0x00 prefix to get the actual 1312-byte Dilithium pubkey
        vchPubKeyActual = std::vector<unsigned char>(vchPubKey.begin() + 1, vchPubKey.end());
    }

    CPubKey pubkey(vchPubKeyActual);
    if (!pubkey.IsValid()) {
        return false;
    }

    // Hash type is one byte tacked on to the end of the signature
    if (vchSigIn.empty()) {
        return false;
    }
    int nHashType = vchSigIn.back();
    std::vector<unsigned char> vchSig(vchSigIn.begin(), vchSigIn.end() - 1);

    uint256 sighash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion, txdata);

    if (!VerifySignature(vchSig, pubkey, sighash)) {
        return false;
    }

    return true;
}

bool TransactionSignatureChecker::CheckLockTime(const CScriptNum& nLockTime) const
{
    // There are two kinds of nLockTime: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nLockTime < LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nLockTime being tested is the same as
    // the nLockTime in the transaction.
    if (!((txTo->nLockTime < LOCKTIME_THRESHOLD && nLockTime < LOCKTIME_THRESHOLD) ||
            (txTo->nLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD)))
        return false;

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple integer one.
    if (nLockTime > (int64_t)txTo->nLockTime)
        return false;

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been
    // finalized by setting nSequence to maxint. The
    // CHECKLOCKTIMEVERIFY opcode execution fails in this case.
    if (txTo->vin[nIn].nSequence == CTxIn::SEQUENCE_FINAL)
        return false;

    return true;
}

bool TransactionSignatureChecker::CheckSequence(const CScriptNum& nSequence) const
{
    // Relative lock times are supported by comparing the passed
    // in operand to the sequence number of the input.
    if (nSequence < 0)
        return false;

    // The lock time feature can be disabled and thus
    // CHECKSEQUENCEVERIFY bypassed if the sequence number of
    // the input is set to maxint. The CHECKSEQUENCEVERIFY
    // opcode execution fails in this case.
    if (txTo->vin[nIn].nSequence == CTxIn::SEQUENCE_FINAL)
        return false;

    // Mask off any bits that do not have consensus-enforced meaning
    // before doing the integer comparisons
    const uint32_t nLockTimeMask = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const uint32_t nSequenceMasked = txTo->vin[nIn].nSequence & nLockTimeMask;
    const uint32_t nSequenceIn = nSequence.getint64() & nLockTimeMask;

    // There are two kinds of nSequence: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nSequence being tested is the same as
    // the nSequence in the transaction.
    if (!((nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceIn < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
            (nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceIn >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)))
        return false;

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple integer one.
    if (nSequenceIn > nSequenceMasked)
        return false;

    return true;
}
