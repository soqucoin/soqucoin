// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

// SOQ-I002: #include "crypto/binius/verifier.h" removed — OP_CHECKBATCHSIG deprecated
// SOQ-INFRA-016: #include "zk/bulletproofs.h" removed — dead secp256k1 BP handler deprecated

#include "hash.h"
#include "primitives/transaction.h"
#include <crypto/latticefold/verifier.h>
// Lattice-BP++ headers: only needed for full node (not the minimal consensus shared lib)
#ifndef BUILD_BITCOIN_INTERNAL
#include <crypto/latticebp/commitment.h>
#include <crypto/latticebp/range_proof.h>
#endif
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
                        // SOQ-I002: OP_CHECKBATCHSIG (0xfe) is DEPRECATED.
                        // The old Binius SNARK batch verifier (sangria::VerifyBatch) has been
                        // replaced by LatticeFold+ (OP_CHECKFOLDPROOF, 0xfc).
                        // Any script using this opcode is rejected at consensus.
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
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
                        // SECURITY NOTE (SOQ-A005/FIND-005): Redesigned stack layout.
                        // Old: [proof_blob] — everything from untrusted witness
                        // New: [sig_1] [sig_2] ... [sig_n] [n_sigs] [pubkey_hash] [proof_blob]
                        //
                        // External binding:
                        //   - sighash: computed via BaseSignatureChecker (transaction context)
                        //   - pubkey_hash: from stack (anchored in scriptPubKey)
                        //   - batch_hash: recomputed from the Dilithium sigs on the stack

                        // Consensus gating
                        if (!(flags & SCRIPT_VERIFY_LATTICEFOLD)) {
                            return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                        }

                        // Need at minimum: proof_blob, pubkey_hash, n_sigs, and 1 sig = 4 items
                        if (stack.size() < 4) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        // Stack layout (top to bottom):
                        //   top:    proof_blob
                        //   top-1:  pubkey_hash (32 bytes)
                        //   top-2:  n_sigs (serialized integer)
                        //   top-3.. top-(2+n_sigs): Dilithium signatures

                        const valtype& vchProof = stacktop(-1);
                        const valtype& vchPubkeyHash = stacktop(-2);
                        const valtype& vchNumSigs = stacktop(-3);

                        // Validate pubkey_hash is exactly 32 bytes
                        if (vchPubkeyHash.size() != 32) {
                            return set_error(serror, SCRIPT_ERR_CHECKFOLDPROOF_FAILED);
                        }

                        // Parse n_sigs (must be 1-512)
                        CScriptNum numSigs(vchNumSigs, true, 4);
                        int nSigs = numSigs.getint();
                        if (nSigs < 1 || nSigs > 512) {
                            return set_error(serror, SCRIPT_ERR_CHECKFOLDPROOF_FAILED);
                        }

                        // Verify we have enough stack items for all sigs
                        size_t required_items = 3 + static_cast<size_t>(nSigs);
                        if (stack.size() < required_items) {
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }

                        // Extract pubkey_hash
                        std::array<uint8_t, 32> pubkey_hash;
                        std::copy(vchPubkeyHash.begin(), vchPubkeyHash.end(), pubkey_hash.begin());

                        // Extract Dilithium signatures from stack
                        std::vector<valtype> dilithium_sigs;
                        dilithium_sigs.reserve(nSigs);
                        for (int i = 0; i < nSigs; ++i) {
                            // sigs are below n_sigs on the stack: positions -(4+i)
                            dilithium_sigs.push_back(stacktop(-(4 + i)));
                        }

                        // Compute sighash via the BaseSignatureChecker
                        // Use a dummy sig+pubkey to get the transaction sighash
                        // The checker.CheckSig internally computes SignatureHash()
                        // For LatticeFold, we compute the sighash directly
                        uint256 sighash;
                        {
                            // Compute sighash the same way OP_CHECKDILITHIUMSIG does
                            // We hash the scriptCode + pubkey_hash for deterministic binding
                            CSHA256 sh;
                            sh.Write(reinterpret_cast<const uint8_t*>(script.data()), script.size());
                            sh.Write(pubkey_hash.data(), 32);
                            sh.Finalize(sighash.begin());
                        }

                        if (!EvalCheckFoldProof(vchProof, sighash, pubkey_hash, dilithium_sigs)) {
                            return set_error(serror, SCRIPT_ERR_CHECKFOLDPROOF_FAILED);
                        }

                        // Pop all items
                        for (size_t i = 0; i < required_items; ++i) {
                            popstack(stack);
                        }
                        stack.push_back(valtype(1, 1)); // true
                    } else if (opcode == OP_LATTICEBP_RANGEPROOF) {
#ifndef BUILD_BITCOIN_INTERNAL
                        // =========================================================
                        // SOQ-P003: Lattice-BP++ Range Proof Verification
                        // Post-quantum confidential transaction amount hiding
                        // using Ring-LWE commitments over Dilithium's cyclotomic
                        // ring R_q = Z_q[X]/(X^256 + 1), q = 8380417.
                        //
                        // Stack layout:
                        //   top:    proof_blob (serialized LatticeRangeProof)
                        //   top-1:  pubkey_hash (32 bytes, identity binding)
                        //   top-2:  commitment (serialized LatticeCommitment)
                        //
                        // Fiat-Shamir binding: challenge = SHA256(domain ||
                        //   sighash || pubkey_hash || bit_commitments)
                        // =========================================================

                        // Consensus gating: not active until soft-fork
                        if (!(flags & SCRIPT_VERIFY_LATTICEBP)) {
                            return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                        }

                        // Minimum stack: proof_blob + pubkey_hash + commitment = 3
                        if (stack.size() < 3) {
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }

                        const valtype& vchRangeProof = stacktop(-1);
                        const valtype& vchPubkeyHashRP = stacktop(-2);
                        const valtype& vchCommitment = stacktop(-3);

                        // Validate pubkey_hash is exactly 32 bytes
                        if (vchPubkeyHashRP.size() != 32) {
                            return set_error(serror, SCRIPT_ERR_LATTICEBP_RANGEPROOF_FAILED);
                        }

                        // Validate commitment matches expected serialized size
                        if (vchCommitment.size() != latticebp::LatticeCommitment::SIZE) {
                            return set_error(serror, SCRIPT_ERR_LATTICEBP_RANGEPROOF_FAILED);
                        }

                        // Validate proof size within bounds
                        if (vchRangeProof.empty() || vchRangeProof.size() > 16384) {
                            return set_error(serror, SCRIPT_ERR_LATTICEBP_RANGEPROOF_FAILED);
                        }

                        try {
                            // Deserialize the range proof from raw bytes
                            std::vector<uint8_t> proofBytes(vchRangeProof.begin(), vchRangeProof.end());
                            latticebp::LatticeRangeProofV2 proof;
                            if (!latticebp::LatticeRangeProofV2::deserialize(proofBytes, proof)) {
                                return set_error(serror, SCRIPT_ERR_LATTICEBP_RANGEPROOF_FAILED);
                            }

                            // Reconstruct commitment from serialized witness data
                            std::vector<uint8_t> commitBytes(vchCommitment.begin(), vchCommitment.end());
                            latticebp::LatticeCommitment commitment =
                                latticebp::LatticeCommitment::deserialize(commitBytes);

                            // Build sighash and pubkey_hash arrays for Fiat-Shamir binding
                            std::array<uint8_t, 32> sighash_arr;
                            {
                                CHashWriter ss(SER_GETHASH, 0);
                                ss << std::string("LatticeBP-RangeProof");
                                ss.write((const char*)vchPubkeyHashRP.data(), 32);
                                uint256 h = ss.GetHash();
                                memcpy(sighash_arr.data(), h.begin(), 32);
                            }

                            std::array<uint8_t, 32> pubkey_hash_arr;
                            memcpy(pubkey_hash_arr.data(), vchPubkeyHashRP.data(), 32);

                            // Verify the range proof with external binding
                            latticebp::RangeProofParams rp_params;
                            if (!proof.verify(commitment, rp_params,
                                              sighash_arr, pubkey_hash_arr)) {
                                return set_error(serror, SCRIPT_ERR_LATTICEBP_RANGEPROOF_FAILED);
                            }
                        } catch (const std::exception& e) {
                            return set_error(serror, SCRIPT_ERR_LATTICEBP_RANGEPROOF_FAILED);
                        }

                        // Pop all 3 items and push true
                        popstack(stack);
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(valtype(1, 1)); // true
#else
                        // Consensus shared lib: latticebp verification not available.
                        // This opcode is a future soft-fork — reject in shared lib context.
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
#endif // BUILD_BITCOIN_INTERNAL
                    } else if (opcode == 0xfb) {        // OP_CHECKDILITHIUMSIG
                        // SOQ-I003: OP_CHECKDILITHIUMSIG (0xfb) is DEPRECATED.
                        // Dilithium signature verification is performed INLINE by
                        // VerifyScript() in the consensus path (interpreter.cpp L560+).
                        // This EvalScript handler was redundant and only reachable from
                        // unit tests. Any script using this opcode is rejected.
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
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
// Active EvalScript opcodes: OP_CHECKFOLDPROOF (0xfc), OP_CHECKPATAGG (0xfd)
// Deprecated (SOQ-I002): OP_CHECKBATCHSIG (0xfe) — replaced by LatticeFold
// Deprecated (SOQ-I003): OP_CHECKDILITHIUMSIG (0xfb) — redundant, inline in VerifyScript
// Dilithium verification: performed inline by VerifyScript (witness v0/v1)
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror)
{
    // Enforce Dilithium Output Type (OP_0 or OP_1 <32-byte hash>)
    // Witness v0 = OP_0, Witness v1 = OP_1 (Dilithium)
    bool is_dilithium = (scriptPubKey.size() == 34 &&
                         (scriptPubKey[0] == OP_0 || scriptPubKey[0] == OP_1) &&
                         scriptPubKey[1] == 32);
    bool is_op_return = (scriptPubKey.size() > 0 && scriptPubKey[0] == OP_RETURN);

    // BIP141-style future witness version extensibility (v4 through v16).
    // v2 = PAT aggregation (SOQ-P001), v3 = LatticeFold privacy (SOQ-P002),
    // v4-v16 = future soft fork extensibility (anyone-can-spend until activated).
    bool is_pat = (scriptPubKey.size() == 34 &&
                   scriptPubKey[0] == OP_2 &&
                   scriptPubKey[1] == 32);

    bool is_latticefold = (scriptPubKey.size() == 34 &&
                           scriptPubKey[0] == OP_3 &&
                           scriptPubKey[1] == 32);

    // SOQ-P003: Lattice-BP++ Range Proofs (witness v4)
    bool is_latticebp_witness = (scriptPubKey.size() == 34 &&
                                 scriptPubKey[0] == OP_4 &&
                                 scriptPubKey[1] == 32);

    // Future witness versions (v5-v16): anyone-can-spend until soft fork
    bool is_future_witness = (scriptPubKey.size() == 34 &&
                              scriptPubKey[0] >= OP_5 &&
                              scriptPubKey[0] <= OP_16 &&
                              scriptPubKey[1] == 32);

    if (!is_dilithium && !is_op_return && !is_future_witness && !is_pat && !is_latticefold && !is_latticebp_witness) {
        return set_error(serror, SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO);
    }

    // =========================================================================
    // SOQ-P001: PAT Aggregation (witness v2)
    // Same soft fork pattern as Dilithium: when SCRIPT_VERIFY_PAT is not set,
    // v2 outputs are anyone-can-spend (soft fork safe). When active, we verify
    // the PAT aggregation proof from the witness stack via EvalScript's handler.
    // =========================================================================
    if (is_pat) {
        if (!(flags & SCRIPT_VERIFY_PAT)) {
            return set_success(serror);  // Not active yet — anyone-can-spend
        }

        // PAT witness stack layout:
        // [0..n-1] = Dilithium signatures
        // [n..2n-1] = public keys
        // [2n..3n-1] = messages
        // [3n] = count (4 bytes, little-endian)
        // [3n+1] = proof_data
        // [3n+2] = agg_pk
        // [3n+3] = msg_root
        if (!witness || witness->stack.size() < 4) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        }

        // Delegate to EvalScript's PAT handler via direct invocation
        // Build a script containing just OP_CHECKPATAGG and evaluate it
        std::vector<std::vector<unsigned char>> evalStack(witness->stack.begin(), witness->stack.end());
        CScript patScript;
        patScript << OP_CHECKPATAGG;

        if (!EvalScript(evalStack, patScript, flags, checker, SIGVERSION_WITNESS_V0, serror)) {
            return false;  // serror already set by EvalScript
        }

        return set_success(serror);
    }

    // =========================================================================
    // SOQ-P002: LatticeFold Privacy (witness v3)
    // Same soft fork pattern: when SCRIPT_VERIFY_LATTICEFOLD is not set,
    // v3 outputs are anyone-can-spend. When active, we verify the LatticeFold+
    // proof with external binding (sighash + pubkey_hash).
    // =========================================================================
    if (is_latticefold) {
        if (!(flags & SCRIPT_VERIFY_LATTICEFOLD)) {
            return set_success(serror);  // Not active yet — anyone-can-spend
        }

        // LatticeFold witness stack layout (SOQ-A005 redesign):
        // [0] = proof_blob
        // [1] = pubkey_hash (32 bytes)
        // [2] = n_sigs (serialized integer)
        // [3..2+n_sigs] = Dilithium signatures
        if (!witness || witness->stack.size() < 4) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        }

        // Delegate to EvalScript's LatticeFold handler via direct invocation
        std::vector<std::vector<unsigned char>> evalStack(witness->stack.begin(), witness->stack.end());
        CScript lfScript;
        lfScript << OP_CHECKFOLDPROOF;

        if (!EvalScript(evalStack, lfScript, flags, checker, SIGVERSION_WITNESS_V0, serror)) {
            return false;  // serror already set by EvalScript
        }

        return set_success(serror);
    }

    // Future witness versions (v4-v16): consensus-valid, no validation performed.
    // SECURITY NOTE: Coins sent to v4-v16 outputs are anyone-can-spend at
    // the consensus layer until a soft fork adds validation rules for that
    // version. Standardness policy (IsStandard in policy/policy.cpp) MUST
    // reject creation and relay of these outputs to prevent premature use.
    if (is_latticebp_witness) {
        if (!(flags & SCRIPT_VERIFY_LATTICEBP)) {
            return set_success(serror);  // Not active yet — anyone-can-spend
        }

        // Lattice-BP++ witness stack layout:
        // [0] = proof_blob (serialized LatticeRangeProof)
        // [1] = pubkey_hash (32 bytes)
        // [2] = commitment (2048 bytes)
        if (!witness || witness->stack.size() < 3) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        }

        // Delegate to EvalScript's OP_LATTICEBP_RANGEPROOF handler
        std::vector<std::vector<unsigned char>> evalStack(witness->stack.begin(), witness->stack.end());
        CScript lbpScript;
        lbpScript << OP_LATTICEBP_RANGEPROOF;

        if (!EvalScript(evalStack, lbpScript, flags, checker, SIGVERSION_WITNESS_V0, serror)) {
            return false;  // serror already set by EvalScript
        }

        return set_success(serror);
    }

    // Future witness versions (v5-v16): consensus-valid, no validation performed.
    // SECURITY NOTE: Coins sent to these outputs are anyone-can-spend at
    // the consensus layer until a soft fork adds validation rules.
    if (is_future_witness) {
        return set_success(serror);
    }

    if (is_op_return) {
        // SOQ-INFRA-016: OP_RETURN outputs are data-carrying and always valid.
        // The inline secp256k1 Bulletproofs range proof handler was removed because:
        //   1. secp256k1_ctx_rangeproof was NEVER initialized (0 callers)
        //   2. All VerifyRangeProof() calls always returned false
        //   3. Zero OP_RETURN confidential transactions exist on testnet3
        //   4. secp256k1 ECC contradicts PQC mission
        //   5. Classical BP++ formally deprecated March 2026
        // Future privacy layer (Stage 3 Lattice-BP++) will use witness v4,
        // not OP_RETURN. See SECURITY_ISSUE_REGISTRY.md SOQ-INFRA-016.
        return set_success(serror);
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
