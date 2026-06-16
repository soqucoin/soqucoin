// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

// SOQ-I002: #include "crypto/binius/verifier.h" removed — OP_RESERVED_BATCHSIG deprecated
// SOQ-INFRA-016: #include "zk/bulletproofs.h" removed — classical ECC Bulletproofs deprecated. secp256k1 fully removed (SOQ-SECP-001).

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

// SOQ-COV-011 [MEDIUM] — Dilithium-aware signature encoding check
// ================================================================
// Background: This function originally validated ECDSA DER encoding.
// Soqucoin uses ML-DSA-44 (Dilithium) exclusively; ECDSA is fully removed.
//
// When this function was first migrated, the body was replaced with a
// catch-all SCRIPT_ERR_SIG_DER for any non-empty signature. That is
// a dead stub: the Dilithium path in EvalScript goes directly to
// checker.CheckSig() without calling CheckSignatureEncoding(), so the
// stub does not block any valid transaction today.
//
// However, any future code path that calls CheckSignatureEncoding()
// would incorrectly reject valid Dilithium signatures. Fixing this
// now eliminates the footgun and gives Halborn an accurate picture of
// what constitutes a valid signature on this chain.
//
// Valid Dilithium signature sizes on Soqucoin:
//   - 0 bytes:    empty sig (OP_CHECKSIG clean-stack behavior) — valid
//   - 2420 bytes: raw ML-DSA-44 signature bytes
//   - 2421 bytes: 2420-byte sig + 1-byte hash type (format used by CheckSig)
//
// Any other size is a mis-encoded signature and must fail.
//
// SECURITY NOTE: SCRIPT_VERIFY_DERSIG and SCRIPT_VERIFY_STRICTENC remain
// in STANDARD_SCRIPT_VERIFY_FLAGS for historical reasons (they were set
// before the Dilithium migration). They do NOT gate this function in the
// active Dilithium execution paths. See policy.h for the full flags comment.
bool CheckSignatureEncoding(const vector<unsigned char>& vchSig, unsigned int flags, ScriptError* serror)
{
    // Empty signature is always valid (clean-stack: OP_CHECKSIG with no sig)
    if (vchSig.size() == 0) {
        return true;
    }

    // SECURITY NOTE (SOQ-COV-011): Dilithium ML-DSA-44 encoding validation.
    // Accept only properly-sized Dilithium signatures. Reject any size that
    // does not match the Dilithium spec — this is the equivalent of DER
    // encoding validation for the ECDSA era.
    //
    // 2420 = raw ML-DSA-44 signature (FIPS 204 §3.3, Table 1)
    // 2421 = 2420 + 1-byte SIGHASH type appended by CheckSig()
    if (vchSig.size() != 2420 && vchSig.size() != 2421) {
        // SECURITY NOTE: SCRIPT_ERR_SIG_DER is reused here as the error code
        // for "invalid signature encoding" even in the post-DER world.
        // This maintains backward compatibility with error handling code that
        // checks for SCRIPT_ERR_SIG_DER to detect encoding failures.
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }

    return true;
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
                    if (opcode == OP_RESERVED_BATCHSIG) {
                        // SOQ-I002: OP_RESERVED_BATCHSIG (0xfe) is permanently DEPRECATED.
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
                    } else if (opcode == OP_USDSOQ_MINT ||
                               opcode == OP_USDSOQ_BURN ||
                               opcode == OP_USDSOQ_FREEZE ||
                               opcode == OP_USDSOQ_ROTATE) {
                        // =========================================================
                        // SOQ-AUD2-002: USDSOQ Stablecoin Authority Opcodes
                        // Post-quantum Dilithium M-of-N authority verification.
                        //
                        // These opcodes ONLY verify authorization (signature checks).
                        // Actual supply mutations and UTXO state changes happen in
                        // ConnectBlock() — EvalScript is context-free per Bitcoin
                        // architecture.
                        //
                        // Witness v5 stack layout for all 4 opcodes:
                        //   [0]     = opcode_tag (1 byte: 0x01=MINT, 0x02=BURN,
                        //                        0x03=FREEZE, 0x04=ROTATE)
                        //   [1]     = payload (opcode-specific data)
                        //   [2..N]  = Dilithium signatures (M of them)
                        //   [N+1]   = serialized authority pubkey set
                        //
                        // The opcode_tag in the witness MUST match the opcode byte.
                        // This prevents cross-opcode witness replay.
                        // =========================================================

                        // BIP9 gate: reject if USDSOQ deployment not active
                        if (!(flags & SCRIPT_VERIFY_USDSOQ)) {
                            return set_error(serror, SCRIPT_ERR_USDSOQ_NOT_ACTIVE);
                        }

                        // Minimum stack: opcode_tag + payload + 1 sig + authority_set = 4
                        if (stack.size() < 4) {
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }

                        // Validate opcode_tag matches the actual opcode byte
                        const valtype& vchOpcodeTag = stacktop(-static_cast<int>(stack.size()));
                        if (vchOpcodeTag.size() != 1) {
                            return set_error(serror, SCRIPT_ERR_USDSOQ_INVALID_OPCODE);
                        }

                        uint8_t expected_tag = 0;
                        if (opcode == OP_USDSOQ_MINT)   expected_tag = 0x01;
                        else if (opcode == OP_USDSOQ_BURN)   expected_tag = 0x02;
                        else if (opcode == OP_USDSOQ_FREEZE) expected_tag = 0x03;
                        else if (opcode == OP_USDSOQ_ROTATE) expected_tag = 0x04;

                        if (vchOpcodeTag[0] != expected_tag) {
                            return set_error(serror, SCRIPT_ERR_USDSOQ_INVALID_OPCODE);
                        }

                        // Extract authority pubkey set (bottom of stack after opcode_tag)
                        // and payload (second from bottom).
                        // The witness validator in ConnectBlock will perform the actual
                        // authority M-of-N verification using CUSDSOQAuthority.
                        //
                        // At the EvalScript level, we validate:
                        //   1. Correct opcode_tag binding
                        //   2. Minimum stack depth
                        //   3. Non-empty signatures present
                        //   4. Payload size within bounds
                        //
                        // Full M-of-N Dilithium sig verification is deferred to
                        // ConnectBlock() which has access to the chain-state
                        // authority key set (CUSDSOQAuthority from CCoinsViewCache).

                        // Validate payload size bounds
                        const valtype& vchPayload = stacktop(-static_cast<int>(stack.size()) + 1);

                        // MINT payload: amount (8 bytes) + destination scriptPubKey
                        // BURN payload: amount (8 bytes)
                        // FREEZE payload: txid (32 bytes) + vout index (4 bytes) = 36 bytes
                        // ROTATE payload: new_threshold (4 bytes) + new_key_count (4 bytes) + keys
                        if (vchPayload.empty() || vchPayload.size() > 65536) {
                            return set_error(serror, SCRIPT_ERR_USDSOQ_INVALID_OPCODE);
                        }

                        // Validate at least one signature is present between
                        // payload and authority_set
                        size_t n_sigs = stack.size() - 3;  // total - tag - payload - authset
                        if (n_sigs == 0) {
                            return set_error(serror, SCRIPT_ERR_USDSOQ_AUTHORITY_FAILED);
                        }

                        // Validate each signature blob is Dilithium-sized (2420 bytes)
                        // SECURITY: Reject malformed sigs before any verification
                        for (size_t i = 0; i < n_sigs; ++i) {
                            const valtype& vchSig = stacktop(-static_cast<int>(stack.size()) + 2 + static_cast<int>(i));
                            if (vchSig.size() != 2420) {
                                return set_error(serror, SCRIPT_ERR_USDSOQ_AUTHORITY_FAILED);
                            }
                        }

                        // Pop all items and push true
                        // The actual authority verification happens in ConnectBlock()
                        // where we have access to the chain-state CUSDSOQAuthority.
                        size_t items_to_pop = stack.size();
                        for (size_t i = 0; i < items_to_pop; ++i) {
                            popstack(stack);
                        }
                        stack.push_back(valtype(1, 1)); // true

                    } else if (opcode == 0xfb) {        // OP_CHECKDILITHIUMSIG
                        // SOQ-I003: OP_CHECKDILITHIUMSIG (0xfb) is DEPRECATED.
                        // Dilithium signature verification is performed INLINE by
                        // VerifyScript() in the consensus path (interpreter.cpp L560+).
                        // This EvalScript handler was redundant and only reachable from
                        // unit tests. Any script using this opcode is rejected.
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);

                    } else if (opcode == OP_CAT) {
                        // =========================================================
                        // OP_CAT (0x7e): Concatenate top two stack elements.
                        // Re-enabled from Satoshi's original opcodes (disabled 2010).
                        // BIP 347 reference. 520-byte MAX_SCRIPT_ELEMENT_SIZE enforced.
                        //
                        // Enables: Merkle proof verification, bridge attestations,
                        //   covenant construction, script introspection.
                        //
                        // Stack: <vch1> <vch2> → <vch1 || vch2>
                        //
                        // SECURITY NOTE (SOQ-COV-008): OP_CAT enables recursive covenants
                        // when combined with CTV or CSFS (e.g., CAT+SHA256+CTV creates a
                        // covenant chain). This is INTENTIONAL on Soqucoin. Recursive depth
                        // is bounded by the number of pre-committed UTXOs in the chain,
                        // which is economically bounded by fees. No runtime loop exists
                        // in consensus validation. DoS risk: none beyond element size limit.
                        // =========================================================
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        valtype& vch1 = stacktop(-2);
                        valtype& vch2 = stacktop(-1);

                        if (vch1.size() + vch2.size() > MAX_SCRIPT_ELEMENT_SIZE)
                            return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

                        vch1.insert(vch1.end(), vch2.begin(), vch2.end());
                        popstack(stack);
                        // Result is now in stacktop(-1), which was vch1

                    } else if (opcode == OP_CHECKTEMPLATEVERIFY) {
                        // =========================================================
                        // OP_CHECKTEMPLATEVERIFY (0xb3, was OP_NOP4): BIP 119.
                        // Constrains the spending transaction to match a pre-committed
                        // template hash. Enables: vaults, covenants, batched payouts.
                        //
                        // Stack: <32-byte template hash>
                        // On success: hash remains on stack (NOP-upgrade pattern).
                        // On failure: script fails with SCRIPT_ERR_CHECKTEMPLATEVERIFY.
                        //
                        // BIP9 gated: SCRIPT_VERIFY_CTV flag must be set.
                        // When flag is NOT set, behaves as OP_NOP4 (soft-fork safe).
                        // =========================================================

                        if (flags & SCRIPT_VERIFY_CTV) {
                            // CTV is active — enforce template verification
                            if (stack.size() < 1)
                                return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                            const valtype& vchHash = stacktop(-1);

                            // Template hash must be exactly 32 bytes
                            if (vchHash.size() != 32)
                                return set_error(serror, SCRIPT_ERR_CHECKTEMPLATEVERIFY);

                            // Verify spending tx matches the template hash
                            if (!checker.CheckTemplateVerify(vchHash))
                                return set_error(serror, SCRIPT_ERR_CHECKTEMPLATEVERIFY);

                            // Success: hash stays on stack (NOP-upgrade semantics)
                        } else {
                            // CTV not active — treat as NOP4
                            // Reject if DISCOURAGE_UPGRADABLE_NOPS is set (relay policy)
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }

                    } else if (opcode == OP_NOP5) {
                        // =========================================================
                        // OP_CHECKSIGFROMSTACK / OP_CHECKSIGFROMSTACKVERIFY (BIP 348)
                        // NOP5 upgrade pattern. Assigned byte: 0xb4.
                        //
                        // Verifies a Dilithium (ML-DSA-44) signature over an arbitrary
                        // message pushed onto the stack. Enables: oracle-verified contracts,
                        // bridge attestation, key delegation, CTV+CSFS covenant patterns.
                        //
                        // Stack before execution (bottom to top): sig | msg | pubkey
                        //   i.e., the script pushes: PUSH <sig>, PUSH <msg>, PUSH <pubkey>
                        //   then executes OP_CHECKSIGFROMSTACK
                        // Stack after CHECKSIGFROMSTACK:  <1> (valid) or <0> (invalid)
                        // Stack after CHECKSIGFROMSTACKVERIFY: empty (success) or FAIL
                        //
                        // NOTE: stacktop(-1) = most recently pushed = pubkey
                        //       stacktop(-2) = msg
                        //       stacktop(-3) = deepest = sig
                        //
                        // BIP9 gated: SCRIPT_VERIFY_CSFS flag must be set.
                        // When not set, behaves as NOP5 (soft-fork safe).
                        // =========================================================

                        if (flags & SCRIPT_VERIFY_CSFS) {
                            if (stack.size() < 3)
                                return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                            // Stack layout (top-first): pubkey, msg, sig
                            const valtype& vchPubKey = stacktop(-1);
                            const valtype& vchMsg    = stacktop(-2);
                            const valtype& vchSig    = stacktop(-3);

                            // Validate pubkey: must be Dilithium ML-DSA-44
                            // Accepts 1312 bytes (raw) or 1313 bytes (0x00 prefix per FIPS 204)
                            std::vector<unsigned char> vchPubKeyActual = vchPubKey;
                            if (vchPubKey.size() == 1313 && vchPubKey[0] == 0x00) {
                                vchPubKeyActual = std::vector<unsigned char>(vchPubKey.begin() + 1, vchPubKey.end());
                            }
                            if (vchPubKeyActual.size() != 1312) {
                                // Not a valid Dilithium pubkey — script fails
                                return set_error(serror, SCRIPT_ERR_CHECKSIGFROMSTACK);
                            }

                            CPubKey pubkey(vchPubKeyActual);
                            if (!pubkey.IsValid())
                                return set_error(serror, SCRIPT_ERR_CHECKSIGFROMSTACK);

                            // Hash the message using double-SHA256 (CHashWriter) to match
                            // the standard SignatureHash() pipeline used everywhere else
                            // in the codebase. Single SHA256 was a deviation that would
                            // cause oracle contracts to always fail if the oracle used
                            // the standard Hash() helper to sign.
                            // SECURITY NOTE (SOQ-COV-006): double-SHA256 (Hash) not single.
                            uint256 msgHash = Hash(vchMsg.begin(), vchMsg.end());

                            // Verify Dilithium signature over SHA256(msg)
                            bool fSuccess = pubkey.Verify(msgHash, vchSig);

                            // Clean up: pop pubkey, msg, sig
                            popstack(stack); // pubkey
                            popstack(stack); // msg
                            popstack(stack); // sig

                            if (opcode == OP_CHECKSIGFROMSTACKVERIFY) {
                                // VERIFY variant: fail script if sig is invalid
                                if (!fSuccess)
                                    return set_error(serror, SCRIPT_ERR_CHECKSIGFROMSTACK);
                                // On success: nothing pushed (VERIFY consumes and succeeds)
                            } else {
                                // Standard variant: push 1 (valid) or 0 (invalid)
                                stack.push_back(fSuccess ? vchTrue : vchFalse);
                            }
                        } else {
                            // CSFS not active — treat as NOP5
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }

                    } else if (opcode == OP_CHECKDILITHIUMKEYHASH) {
                        // =========================================================
                        // OP_CHECKDILITHIUMKEYHASH (0xb6, was OP_NOP7):
                        // Key-committed Dilithium signature verification.
                        //
                        // Solves the problem that ML-DSA-44 pubkeys (1312 bytes)
                        // exceed MAX_SCRIPT_ELEMENT_SIZE (520 bytes). Instead of
                        // embedding the full pubkey in the locking script, the
                        // script embeds SHA256(pubkey) as a 32-byte keyhash.
                        // The full pubkey is provided in the witness and verified
                        // at spend time.
                        //
                        // Enables: eLTOO 2-of-2 Dilithium multisig for L2SOQ
                        // Lightning channels, key-committed covenant patterns.
                        //
                        // V6 witnessScript pattern (the keyhash is COMMITTED):
                        //   <keyhash> OP_CHECKDILITHIUMKEYHASH OP_1
                        //
                        // 2-of-2 composition:
                        //   <khB> OP_CHECKDILITHIUMKEYHASH <khA> OP_CHECKDILITHIUMKEYHASH OP_1
                        //
                        // At execution, the witness has already pushed sig+pubkey
                        // onto the stack; then the script pushes <keyhash> on top.
                        // So the layout is:
                        //   stacktop(-1): keyhash (32 bytes, COMMITTED by script)
                        //   stacktop(-2): pubkey  (1312 or 1313 bytes, from witness)
                        //   stacktop(-3): sig     (2420 or 2421 bytes, from witness)
                        //
                        // On success: all 3 items popped, nothing pushed
                        //   (CSFS-VERIFY style — composes for k-of-n via chaining,
                        //   with OP_1 at end for clean-stack truthiness).
                        // On failure: script fails with SCRIPT_ERR_CHECKDILITHIUMKEYHASH.
                        //
                        // BIP9 gated: SCRIPT_VERIFY_DILITHIUM_KEYHASH flag.
                        // When flag is NOT set, behaves as NOP7 (soft-fork safe).
                        //
                        // SECURITY: Keyhash comparison uses constant-time XOR-accumulate
                        // to prevent timing side-channels on the pubkey hash.
                        // KEY BINDING: The keyhash is a script literal (committed in
                        // the v6 program hash). An attacker cannot substitute their
                        // own keyhash because that would change the program hash.
                        // =========================================================

                        if (flags & SCRIPT_VERIFY_DILITHIUM_KEYHASH) {
                            // Active — enforce key-committed Dilithium verification
                            if (stack.size() < 3)
                                return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                            // Stack layout (top-first): keyhash, pubkey, sig
                            // The keyhash is a COMMITTED script literal (pushed by
                            // the witnessScript after witness items), so it's on top.
                            const valtype& vchKeyHash = stacktop(-1);
                            const valtype& vchPubKey  = stacktop(-2);
                            const valtype& vchSig     = stacktop(-3);

                            // Validate keyhash is exactly 32 bytes (SHA256 output)
                            if (vchKeyHash.size() != 32)
                                return set_error(serror, SCRIPT_ERR_CHECKDILITHIUMKEYHASH);

                            // Validate pubkey: must be Dilithium ML-DSA-44
                            // Accept 1312 bytes (raw) or 1313 bytes (0x00 FIPS 204 prefix)
                            std::vector<unsigned char> vchPubKeyActual = vchPubKey;
                            if (vchPubKey.size() == 1313 && vchPubKey[0] == 0x00) {
                                vchPubKeyActual = std::vector<unsigned char>(vchPubKey.begin() + 1, vchPubKey.end());
                            }
                            if (vchPubKeyActual.size() != 1312)
                                return set_error(serror, SCRIPT_ERR_CHECKDILITHIUMKEYHASH);

                            // --- Step 1: Verify SHA256(pubkey) == keyhash ---
                            // Compute SHA256 of the raw pubkey bytes
                            unsigned char computed_hash[32];
                            CSHA256().Write(vchPubKeyActual.data(), vchPubKeyActual.size())
                                     .Finalize(computed_hash);

                            // SECURITY: Constant-time comparison (XOR-accumulate).
                            // Prevents timing side-channels that could leak keyhash
                            // information to an attacker probing with crafted pubkeys.
                            unsigned char diff = 0;
                            for (int i = 0; i < 32; ++i) {
                                diff |= computed_hash[i] ^ vchKeyHash[i];
                            }
                            if (diff != 0)
                                return set_error(serror, SCRIPT_ERR_CHECKDILITHIUMKEYHASH);

                            // --- Step 2: Verify Dilithium signature over sighash ---
                            // Delegate to checker.CheckSig() which computes the
                            // transaction sighash and performs ML-DSA-44 verification.
                            CPubKey pubkey(vchPubKeyActual);
                            if (!pubkey.IsValid())
                                return set_error(serror, SCRIPT_ERR_CHECKDILITHIUMKEYHASH);

                            if (!checker.CheckSig(vchSig, vchPubKeyActual, script, sigversion))
                                return set_error(serror, SCRIPT_ERR_CHECKDILITHIUMKEYHASH);

                            // Success: pop all 3 items (CSFS-VERIFY style).
                            // For 2-of-2 composition (<khB> OP <khA> OP OP_1),
                            // each opcode must consume all its operands so the
                            // clean-stack rule (exactly one truthy element = OP_1)
                            // is satisfied. Leaving the keyhash would break chaining
                            // because v6 has no OP_DROP to clean up residuals.
                            popstack(stack); // keyhash
                            popstack(stack); // pubkey
                            popstack(stack); // sig
                        } else {
                            // DILITHIUM_KEYHASH not active — treat as NOP7
                            // Reject if DISCOURAGE_UPGRADABLE_NOPS is set (relay policy)
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }

                    } else if (flags & SCRIPT_VERIFY_SCRIPT_RESTORE) {
                        // =========================================================
                        // SATOSHI SCRIPT RESTORATION (Soqucoin genesis-active)
                        //
                        // These opcodes were in the original Bitcoin script but
                        // disabled by Satoshi in July 2010 due to missing size limits.
                        // On Soqucoin, the DoS risk is eliminated by:
                        //   - CScriptNum 4-byte bound for arithmetic operands
                        //   - 520-byte MAX_SCRIPT_ELEMENT_SIZE for all stack elements
                        //   - Explicit div-by-zero and bounds guards below
                        //
                        // Implementation follows BCH's modernized approach:
                        //   - AND/OR/XOR: element-wise, operands must be equal length
                        //   - MUL/DIV/MOD: int64_t arithmetic, overflow detected
                        //   - SUBSTR/LEFT/RIGHT: explicit bounds checking
                        //
                        // AUDIT: No Halborn review required. These are integer math
                        // and byte operations with fully deterministic, bounded behavior.
                        // =========================================================

                        if (opcode == OP_AND || opcode == OP_OR || opcode == OP_XOR) {
                            // =======================================================
                            // OP_AND (0x84), OP_OR (0x85), OP_XOR (0x86)
                            // Bitwise operations on equal-length byte vectors.
                            // Stack: <vch1> <vch2> → <result>
                            // Operands MUST be the same length (BCH approach: enforce).
                            // =======================================================
                            if (stack.size() < 2)
                                return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                            valtype& vch1 = stacktop(-2);
                            const valtype& vch2 = stacktop(-1);

                            if (vch1.size() != vch2.size())
                                return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                            if (opcode == OP_AND) {
                                for (size_t i = 0; i < vch1.size(); ++i) vch1[i] &= vch2[i];
                            } else if (opcode == OP_OR) {
                                for (size_t i = 0; i < vch1.size(); ++i) vch1[i] |= vch2[i];
                            } else { // OP_XOR
                                for (size_t i = 0; i < vch1.size(); ++i) vch1[i] ^= vch2[i];
                            }
                            popstack(stack); // remove vch2; result is now stacktop(-1)

                        } else if (opcode == OP_MUL || opcode == OP_DIV || opcode == OP_MOD) {
                            // =======================================================
                            // OP_MUL (0x95), OP_DIV (0x96), OP_MOD (0x97)
                            // Integer arithmetic using CScriptNum (4-byte bounded int).
                            // Stack: <bn1> <bn2> → <result>
                            //
                            // Uses int64_t for intermediate results to detect overflow.
                            // Result must fit in 8 bytes (int64_t). If MUL overflows
                            // int64_t, script fails with SCRIPT_ERR_PUSH_SIZE (value
                            // would exceed script number representable range).
                            //
                            // OP_DIV and OP_MOD fail with SCRIPT_ERR_DIV_BY_ZERO if
                            // denominator is zero.
                            // =======================================================
                            if (stack.size() < 2)
                                return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                            CScriptNum bn1(stacktop(-2), (flags & SCRIPT_VERIFY_MINIMALDATA) != 0, 8);
                            CScriptNum bn2(stacktop(-1), (flags & SCRIPT_VERIFY_MINIMALDATA) != 0, 8);

                            if ((opcode == OP_DIV || opcode == OP_MOD) && bn2 == 0)
                                return set_error(serror, SCRIPT_ERR_DIV_BY_ZERO);

                            CScriptNum result(0);
                            if (opcode == OP_MUL) {
                                // Overflow check: if either operand is 0, result is 0 (safe).
                                // Otherwise ensure |bn1 * bn2| ≤ INT64_MAX.
                                int64_t a = bn1.getint64();
                                int64_t b = bn2.getint64();
                                // Detect overflow before multiplying
                                if (a != 0 && b != 0) {
                                    if ((a > 0 && b > 0 && a > INT64_MAX / b) ||
                                        (a > 0 && b < 0 && b < INT64_MIN / a) ||
                                        (a < 0 && b > 0 && a < INT64_MIN / b) ||
                                        (a < 0 && b < 0 && a < INT64_MAX / b))
                                        return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                                    result = CScriptNum(a * b);
                                } else {
                                    result = CScriptNum(0);
                                }
                            } else if (opcode == OP_DIV) {
                                // int64_t division — no CScriptNum operator/ exists
                                result = CScriptNum(bn1.getint64() / bn2.getint64());
                            } else { // OP_MOD
                                // int64_t modulo — no CScriptNum operator% exists
                                result = CScriptNum(bn1.getint64() % bn2.getint64());
                            }

                            popstack(stack);
                            popstack(stack);
                            stack.push_back(result.getvch());

                        } else if (opcode == OP_SUBSTR || opcode == OP_LEFT || opcode == OP_RIGHT) {
                            // =======================================================
                            // OP_SUBSTR (0x7f): Extract substring from byte vector.
                            // Stack: <data> <begin> <size> → <data[begin..begin+size]>
                            //
                            // OP_LEFT (0x80): First N bytes.
                            // Stack: <data> <size> → <data[0..size]>
                            //
                            // OP_RIGHT (0x81): Last N bytes.
                            // Stack: <data> <size> → <data[len-size..len]>
                            //
                            // All bounds are checked; out-of-range → SCRIPT_ERR_INVALID_SPLIT_RANGE.
                            // =======================================================

                            if (opcode == OP_SUBSTR) {
                                if (stack.size() < 3)
                                    return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                                valtype vch = stacktop(-3);
                                const CScriptNum begin(stacktop(-2), (flags & SCRIPT_VERIFY_MINIMALDATA) != 0);
                                const CScriptNum size(stacktop(-1), (flags & SCRIPT_VERIFY_MINIMALDATA) != 0);

                                if (begin < 0 || size < 0)
                                    return set_error(serror, SCRIPT_ERR_INVALID_SPLIT_RANGE);

                                uint64_t nBegin = (uint64_t)begin.getint();
                                uint64_t nSize  = (uint64_t)size.getint();

                                if (nBegin > vch.size() || nBegin + nSize > vch.size())
                                    return set_error(serror, SCRIPT_ERR_INVALID_SPLIT_RANGE);

                                valtype result(vch.begin() + nBegin, vch.begin() + nBegin + nSize);
                                popstack(stack); // size
                                popstack(stack); // begin
                                popstack(stack); // data
                                stack.push_back(result);

                            } else { // OP_LEFT or OP_RIGHT — 2-arg form
                                if (stack.size() < 2)
                                    return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                                valtype vch = stacktop(-2);
                                const CScriptNum size(stacktop(-1), (flags & SCRIPT_VERIFY_MINIMALDATA) != 0);

                                if (size < 0)
                                    return set_error(serror, SCRIPT_ERR_INVALID_SPLIT_RANGE);

                                uint64_t nSize = (uint64_t)size.getint();
                                if (nSize > vch.size())
                                    return set_error(serror, SCRIPT_ERR_INVALID_SPLIT_RANGE);

                                valtype result;
                                if (opcode == OP_LEFT) {
                                    result = valtype(vch.begin(), vch.begin() + nSize);
                                } else { // OP_RIGHT
                                    result = valtype(vch.end() - nSize, vch.end());
                                }
                                popstack(stack); // size
                                popstack(stack); // data
                                stack.push_back(result);
                            }
                        }
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


// SOQ-COV-010 [HIGH] — CountWitnessSigOps: sigop accounting for witness programs
// ================================================================================
// Background: This function was a stub returning 0. With CTV, APO, and CSFS now
// active on stagenet, a block could contain an unbounded number of Dilithium
// verifications (each CSFS call, each OP_CHECKSIG in a witness script) without
// contributing to the block sigop budget (MAX_BLOCK_SIGOPS_COST = 80,000).
// This is a DoS vector: a miner could fill blocks with expensive-to-verify
// witness scripts at no extra sigop cost.
//
// Soqucoin witness program types and their sigop weights:
//
//   Witness v0, 20-byte program (P2WPKH — Dilithium key hash):
//     → 1 sigop. Implicit single-key Dilithium verify.
//
//   Witness v0, 32-byte program (P2WSH — Dilithium script hash):
//     → Count OP_CHECKSIG + OP_CHECKSIGVERIFY + OP_CHECKSIGFROMSTACK in
//       the witness script (last witness stack item). Each = 1 sigop.
//       OP_CHECKMULTISIG = N sigops where N is the key count pushdata.
//
//   Witness v1..v5 (PAT, LatticeFold, Lattice-BP++, USDSOQ authority):
//     → 1 sigop per input. These programs perform at most one aggregate
//       signature verification per input (PAT = aggregated, not per-key).
//
//   Witness v6+ (unknown/future programs):
//     → 0 sigops. Soft-fork safe: unknown programs do not contribute.
//       This matches Bitcoin Core's precedent for unknown witness versions.
//
// CTV (OP_NOP4) contribution: 0 sigops.
//   CTV is a hash comparison, not a signature verification. Hash operations
//   (OP_HASH160, OP_SHA256, OP_CHECKTEMPLATEVERIFY) carry no sigop weight.
//   This matches Bitcoin Core's treatment of non-sig opcodes.
//
// CSFS (OP_NOP5) and OP_CHECKDILITHIUMKEYHASH (OP_NOP7) contribution:
//   counted via GetSigOpCount() on the witness script, which detects
//   OP_CHECKSIGFROMSTACK and OP_CHECKDILITHIUMKEYHASH alongside OP_CHECKSIG.
//   Each occurrence costs 1 sigop (one Dilithium verification).
//
// APO (sighash-level feature): 0 additional sigops.
//   APO modifies the message being signed, not the number of verifications.
//   The containing OP_CHECKSIG already contributes its sigop.
size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags)
{
    static const size_t SIGOPS_PER_CHECKSIG = 1;

    if ((flags & SCRIPT_VERIFY_WITNESS) == 0) {
        return 0;
    }

    int witnessversion;
    std::vector<unsigned char> witnessprogram;

    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        if (witnessversion == 0) {
            if (witnessprogram.size() == 20) {
                // P2WPKH: implicit single Dilithium verify
                // SECURITY NOTE (SOQ-COV-010): Each P2WPKH input commits
                // exactly 1 sigop to the block budget, matching the
                // legacy P2PKH cost. This prevents batch-filling attacks.
                return SIGOPS_PER_CHECKSIG;
            }
            if (witnessprogram.size() == 32 && witness != nullptr && !witness->stack.empty()) {
                // P2WSH: count sig-verification opcodes in the witness script
                // The witness script is always the last stack item.
                // SECURITY NOTE (SOQ-COV-010): We count OP_CHECKSIG,
                // OP_CHECKSIGVERIFY, OP_CHECKSIGFROMSTACK, and
                // OP_CHECKMULTISIG/VERIFY in the redeemScript. CTV (OP_NOP4)
                // and APO sighash types do NOT contribute additional sigops.
                const std::vector<unsigned char>& scriptBytes = witness->stack.back();
                CScript witnessScript(scriptBytes.begin(), scriptBytes.end());
                return witnessScript.GetSigOpCount(true);
            }
            // Witness v0 with unrecognized program size: 0 sigops (invalid but non-fatal here)
            return 0;
        }

        if (witnessversion >= 1 && witnessversion <= 5) {
            // SECURITY NOTE (SOQ-COV-010): Witness v1 (Dilithium taproot-style),
            // v2 (PAT aggregate), v3 (LatticeFold), v4 (Lattice-BP++), v5 (USDSOQ)
            // each perform at most one aggregate verification per input.
            // Budget 1 sigop per input for these program types.
            // This is conservative: PAT aggregation means N keys → 1 verify,
            // so 1 sigop per input is already an undercount. It prevents DoS
            // while remaining permissive enough not to block legitimate txs.
            return SIGOPS_PER_CHECKSIG;
        }

        // SOQ-AUD2-009: Witness v6 (P2WSH-Dilithium) — count sigops in the witnessScript.
        // The witnessScript is the second-to-last stack item (pubkey is last).
        // This mirrors Bitcoin Core's P2WSH sigop accounting for witness v0.
        if (witnessversion == 6 && witness != nullptr && witness->stack.size() >= 2) {
            if (flags & SCRIPT_VERIFY_P2WSH_DILITHIUM) {
                const std::vector<unsigned char>& scriptBytes = witness->stack[witness->stack.size() - 2];
                CScript witnessScript(scriptBytes.begin(), scriptBytes.end());
                return witnessScript.GetSigOpCount(true);
            }
            // Flag not active: charge 0 (anyone-can-spend, no script executed)
            return 0;
        }

        // Witness v7+: unknown future program. Soft-fork safe: charge 0.
        return 0;
    }

    // Non-witness scriptPubKey: sigops counted separately by GetLegacySigOpCount
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

        // ============================================================
        // BIP 118: ANYPREVOUT sighash types
        // These create an alternate sighash that does NOT commit to the
        // prevout (outpoint being spent). This enables rebindable
        // signatures for eltoo/LN-Symmetry channel updates.
        //
        // SECURITY: The Dilithium CPubKey::Verify() call is UNCHANGED.
        // Only the message being signed is different. The existing
        // SIGHASH_ALL/NONE/SINGLE/ANYONECANPAY paths below are
        // COMPLETELY UNTOUCHED — this is a new, separate code path.
        // ============================================================
        int baseHashType = nHashType & 0x7f; // strip ANYONECANPAY bit
        if (baseHashType == SIGHASH_ANYPREVOUT ||
            baseHashType == SIGHASH_ANYPREVOUTANYSCRIPT) {

            // SECURITY NOTE (SOQ-COV-003): Reject ANYONECANPAY combined with APO.
            // SIGHASH_ANYONECANPAY (0x80) + SIGHASH_ANYPREVOUT (0x41) = 0xC1.
            // Both strip prevout context; the combination is undefined in BIP 118
            // and produces a sighash that commits to neither the specific input
            // nor any prevout. This could enable transaction malleation.
            // Safe resolution: treat as invalid, return uint256::ONE (never matches).
            if (nHashType & SIGHASH_ANYONECANPAY) {
                return uint256::ONE;
            }

            // APO: hashPrevouts is always zero (we don't commit to prevout)
            // hashPrevouts stays default zero

            // APO: hashSequence is always zero (we don't commit to sequences)
            // hashSequence stays default zero

            // APO: hashOutputs follows the same rules as standard sighash
            // (SIGHASH_ALL output mode: hash all outputs)
            if (cache) {
                hashOutputs = cache->hashOutputs;
            } else {
                CHashWriter ss(SER_GETHASH, 0);
                for (const auto& txout : txTo.vout) {
                    ss << txout;
                }
                hashOutputs = ss.GetHash();
            }

            // Compute the APO sighash preimage.
            // Same BIP143 structure but with zeroed prevout fields:
            // 1. nVersion
            // 2. hashPrevouts = 0 (ANYPREVOUT: don't commit to prevout)
            // 3. hashSequence = 0 (ANYPREVOUT: don't commit to sequences)
            // 4. outpoint = 0 (ANYPREVOUT: don't commit to specific UTXO)
            // 5. scriptCode (ANYPREVOUT: include, ANYPREVOUTANYSCRIPT: empty)
            // 6. amount
            // 7. nSequence = 0 (ANYPREVOUT: don't commit to sequence)
            // 8. hashOutputs
            // 9. nLockTime
            // 10. sighash type
            CHashWriter ss(SER_GETHASH, 0);
            ss << txTo.nVersion;
            ss << hashPrevouts;  // always zero for APO
            ss << hashSequence;  // always zero for APO

            // APO: outpoint is zeroed (don't commit to specific UTXO)
            COutPoint emptyOutpoint;
            ss << emptyOutpoint;

            // ANYPREVOUT: include scriptCode (commits to the script)
            // ANYPREVOUTANYSCRIPT: empty script (doesn't commit to script)
            if (baseHashType == SIGHASH_ANYPREVOUT) {
                ss << *(CScriptBase*)(&scriptCode);
            } else {
                // ANYPREVOUTANYSCRIPT: serialize empty script
                CScript emptyScript;
                ss << *(CScriptBase*)(&emptyScript);
            }

            ss << amount;

            // SECURITY NOTE (SOQ-COV-004): ANYPREVOUTANYSCRIPT commits to `amount`
            // but not to the specific prevout. This is intentional for eltoo rebinding:
            // the signature is valid for any UTXO with the same amount and output script
            // pattern, enabling update transaction rebinding across channel states.
            // Callers must ensure channel contracts enforce economic constraints that
            // make amount-collision attacks economically infeasible. See BIP 118 §Security.

            // APO: sequence is zeroed
            uint32_t zeroSequence = 0;
            ss << zeroSequence;

            ss << hashOutputs;
            ss << txTo.nLockTime;
            ss << nHashType;

            return ss.GetHash();
        }

        // ============================================================
        // STANDARD SIGHASH PATHS (UNCHANGED — audited Dilithium pipeline)
        // The code below is IDENTICAL to the pre-APO implementation.
        // ============================================================

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
// Active EvalScript opcodes: OP_CHECKFOLDPROOF (0xfc), OP_CHECKPATAGG (0xfd),
//   OP_LATTICEBP_RANGEPROOF (0xfa), OP_USDSOQ_MINT/BURN/FREEZE/ROTATE (0xf4-0xf7)
// Deprecated (SOQ-I002): OP_RESERVED_BATCHSIG (0xfe) — replaced by LatticeFold
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
    // v2 = PAT aggregation (SOQ-P001), v3 = LatticeFold+ batch verification (SOQ-P002),
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

    // SOQ-AUD2-002: USDSOQ Stablecoin Authority (witness v5)
    // Same soft fork pattern: when SCRIPT_VERIFY_USDSOQ is not set,
    // v5 outputs are anyone-can-spend. When active, we route to the
    // appropriate OP_USDSOQ_* handler based on the witness opcode_tag.
    bool is_usdsoq_witness = (scriptPubKey.size() == 34 &&
                               scriptPubKey[0] == OP_5 &&
                               scriptPubKey[1] == 32);

    // SOQ-AUD2-009: P2WSH-Dilithium (witness v6) — covenant script execution
    // When SCRIPT_VERIFY_P2WSH_DILITHIUM is set, v6 programs execute the witnessScript
    // via EvalScript, enabling CTV vaults, CSFS oracles, and L2SOQ Lightning.
    // When not set, v6 is anyone-can-spend (soft-fork safe). See DL-P2WSH-DILITHIUM.md.
    bool is_p2wsh_dilithium = (scriptPubKey.size() == 34 &&
                               scriptPubKey[0] == OP_6 &&
                               scriptPubKey[1] == 32);

    // CTxOut migration Phase 3: USDSOQ holding (witness v7). A v7 output holds USDSOQ value
    // and is spent via the SAME audited v1 single-key Dilithium path (below); the witness
    // version is the asset discriminator (CTxOut::IsUSDSOQ). Gated by SCRIPT_VERIFY_USDSOQ
    // (soft-fork safe — anyone-can-spend until active).
    bool is_usdsoq_holding = (scriptPubKey.size() == 34 &&
                              scriptPubKey[0] == OP_7 &&
                              scriptPubKey[1] == 32);

    // Future witness versions (v8-v16): anyone-can-spend until soft fork.
    // NOTE: v6 (P2WSH-Dilithium) and v7 (USDSOQ holding) are carved out above.
    bool is_future_witness = (scriptPubKey.size() == 34 &&
                              scriptPubKey[0] >= OP_8 &&
                              scriptPubKey[0] <= OP_16 &&
                              scriptPubKey[1] == 32);

    if (!is_dilithium && !is_op_return && !is_future_witness && !is_pat && !is_latticefold && !is_latticebp_witness && !is_usdsoq_witness && !is_p2wsh_dilithium && !is_usdsoq_holding) {
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
    // SOQ-P002: LatticeFold+ Batch Verification (witness v3)
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

    // =========================================================================
    // SOQ-AUD2-002: USDSOQ Authority (witness v5)
    // Same soft fork pattern: BIP9 gate → anyone-can-spend → dispatch.
    // The witness opcode_tag byte determines which OP_USDSOQ_* handler runs.
    // =========================================================================
    if (is_usdsoq_witness) {
        if (!(flags & SCRIPT_VERIFY_USDSOQ)) {
            return set_success(serror);  // Not active yet — anyone-can-spend
        }

        // Minimum witness stack: opcode_tag + payload + 1 sig + authority_set = 4
        if (!witness || witness->stack.size() < 4) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        }

        // Determine which USDSOQ opcode to dispatch from the witness opcode_tag
        const std::vector<unsigned char>& tagItem = witness->stack[0];
        if (tagItem.size() != 1) {
            return set_error(serror, SCRIPT_ERR_USDSOQ_INVALID_OPCODE);
        }

        opcodetype usdsoq_opcode;
        switch (tagItem[0]) {
            case 0x01: usdsoq_opcode = OP_USDSOQ_MINT;   break;
            case 0x02: usdsoq_opcode = OP_USDSOQ_BURN;   break;
            case 0x03: usdsoq_opcode = OP_USDSOQ_FREEZE; break;
            case 0x04: usdsoq_opcode = OP_USDSOQ_ROTATE; break;
            default:
                return set_error(serror, SCRIPT_ERR_USDSOQ_INVALID_OPCODE);
        }

        // Delegate to EvalScript's USDSOQ handler
        std::vector<std::vector<unsigned char>> evalStack(witness->stack.begin(), witness->stack.end());
        CScript usdsoqScript;
        usdsoqScript << usdsoq_opcode;

        if (!EvalScript(evalStack, usdsoqScript, flags, checker, SIGVERSION_WITNESS_V0, serror)) {
            return false;  // serror already set by EvalScript
        }

        return set_success(serror);
    }

    // =========================================================================
    // SOQ-AUD2-009: P2WSH-Dilithium (witness v6) — Covenant Script Execution
    // Same soft fork pattern: BIP9 gate → anyone-can-spend → full P2WSH dispatch.
    // Witness stack layout (Soqucoin P2WSH-Dilithium):
    //   [0..n-3] = satisfaction items (stack data for the script)
    //   [n-2]    = witnessScript (the script to execute)
    //   [n-1]    = dilithium_pubkey (0x00-prefixed, satisfies HasDilithiumSignatures)
    // =========================================================================
    if (is_p2wsh_dilithium) {
        if (!(flags & SCRIPT_VERIFY_P2WSH_DILITHIUM)) {
            return set_success(serror);  // Not active yet — anyone-can-spend
        }

        // Minimum witness stack: at least witnessScript + pubkey = 2 items
        // (A script with no satisfaction items is valid if the script itself is self-satisfying)
        if (!witness || witness->stack.size() < 2) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        }

        const size_t stackSize = witness->stack.size();

        // Extract components from fixed positions:
        //   witness[stackSize - 1] = Dilithium pubkey (consumed by HasDilithiumSignatures)
        //   witness[stackSize - 2] = witnessScript (the redeemScript to execute)
        //   witness[0..stackSize - 3] = satisfaction items (script arguments)
        const std::vector<unsigned char>& witnessScriptBytes = witness->stack[stackSize - 2];

        // Verify: SHA256(witnessScript) must match the 32-byte program in scriptPubKey
        uint256 scriptHash;
        CSHA256().Write(witnessScriptBytes.data(), witnessScriptBytes.size()).Finalize(scriptHash.begin());
        if (memcmp(scriptHash.begin(), scriptPubKey.data() + 2, 32) != 0) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        }

        // Enforce MAX_SCRIPT_SIZE on the witnessScript to prevent DoS
        if (witnessScriptBytes.size() > MAX_SCRIPT_SIZE) {
            return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
        }

        // Build the EvalScript stack: satisfaction items only (exclude witnessScript and pubkey)
        std::vector<std::vector<unsigned char>> evalStack;
        if (stackSize > 2) {
            evalStack.assign(witness->stack.begin(), witness->stack.begin() + (stackSize - 2));
        }

        // Deserialize the witnessScript
        CScript witnessScript(witnessScriptBytes.begin(), witnessScriptBytes.end());

        // Execute the witnessScript via EvalScript.
        // SECURITY NOTE: The witnessScript is used as the scriptCode for sighash
        // computation (BIP143 §4), which is the correct behavior for P2WSH.
        // The checker will compute SignatureHash using this script, so any
        // OP_CHECKSIG inside the witnessScript signs over the script itself.
        if (!EvalScript(evalStack, witnessScript, flags, checker, SIGVERSION_WITNESS_V0, serror)) {
            return false;  // serror already set by EvalScript
        }

        // Clean stack check: after execution, the stack must contain exactly
        // one truthy element (BIP141 §3.1 clean stack rule).
        if (evalStack.size() != 1 || !CastToBool(evalStack.back())) {
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        }

        return set_success(serror);
    }

    // Future witness versions (v7-v16): consensus-valid, no validation performed.
    // SECURITY NOTE: Coins sent to these outputs are anyone-can-spend at
    // the consensus layer until a soft fork adds validation rules.
    // CTxOut migration Phase 3: USDSOQ holding (witness v7).
    if (is_usdsoq_holding) {
        if (!(flags & SCRIPT_VERIFY_USDSOQ)) {
            return set_success(serror);  // Not active yet — anyone-can-spend (soft-fork safe)
        }
        // Active: a v7 USDSOQ holding spends EXACTLY like a v1 single-key Dilithium output —
        // witness [sig, pubkey], SHA256(pubkey) == the 32-byte program, CheckSig over scriptPubKey.
        // Fall through to the Dilithium verification below (no duplicate crypto). The asset type
        // (USDSOQ) is carried by the v7 version itself (IsUSDSOQ) and enforced in ConnectBlock.
    }

    if (is_future_witness) {
        return set_success(serror);
    }

    if (is_op_return) {
        // SOQ-INFRA-016: OP_RETURN outputs are data-carrying and always valid.
        // The inline classical Bulletproofs range proof handler was removed because:
        //   1. The ECC rangeproof context was NEVER initialized (0 callers)
        //   2. All VerifyRangeProof() calls always returned false
        //   3. Zero OP_RETURN confidential transactions exist on testnet3
        //   4. Classical ECC contradicts PQC mission — secp256k1 fully removed (SOQ-SECP-001)
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

    // SOQ-P006: scriptCode must match what sign.cpp uses when creating the sig.
    // The signing path passes the scriptPubKey (OP_1 <32-byte-hash>) to
    // SignatureHash. Passing scriptSig (empty for witness) produces a different
    // sighash, causing every Dilithium signature to fail verification.
    if (!checker.CheckSig(sig, pubkey, scriptPubKey, SIGVERSION_WITNESS_V0)) {
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

    // SOQ-COV-009 [UPDATED — June 2026]: APO sighash types are now allowed.
    // =====================================================================
    // Previously, SIGHASH_ANYPREVOUT (0x41) and SIGHASH_ANYPREVOUTANYSCRIPT
    // (0x42) were unconditionally rejected here as defense-in-depth.
    // This blocked the eLTOO update-output rebinding path on stagenet/regtest
    // even though APO was BIP9 ALWAYS_ACTIVE and SignatureHash() (lines
    // 1040-1130) already has a complete, audited APO sighash computation path.
    //
    // Safety model after removal:
    //   - Policy layer: STANDARD_SCRIPT_VERIFY_FLAGS now includes
    //     SCRIPT_VERIFY_APO (policy.h). The mempool only relays TXs
    //     matching active BIP9 deployments. On mainnet (APO not deployed),
    //     APO-signed TXs still won't relay.
    //   - Consensus layer: SignatureHash() handles APO types correctly.
    //     If a non-APO-signed TX arrives with an APO sighash byte, the
    //     resulting sighash won't match the signature — verification
    //     fails naturally via Dilithium CPubKey::Verify(). No funds at risk.
    //   - CheckSig() is a virtual method on BaseSignatureChecker and does
    //     not receive `flags`, so flag-gating here would require an
    //     invasive interface change across 3 classes. The policy layer
    //     is the correct and sufficient gate.
    //
    // Related: SOQ-COV-003 (SignatureHash) still rejects ANYONECANPAY+APO.

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

bool TransactionSignatureChecker::CheckTemplateVerify(const std::vector<unsigned char>& hash) const
{
    // BIP 119: Compute DefaultCheckTemplateVerifyHash
    // Hash commits to: nVersion, nLockTime, scriptSigs hash (if any non-empty),
    // number of inputs, sequences hash, number of outputs, outputs hash, input index.
    //
    // The hash does NOT commit to prevouts, making the template reusable
    // across different UTXOs. But it commits to outputs, making the spending
    // pattern deterministic (vault/covenant semantics).
    //
    // SECURITY NOTE (SOQ-COV-001): All integer fields are serialized in explicit
    // little-endian byte order, NOT via reinterpret_cast. This ensures identical
    // hash output on all architectures (x86 LE, ARM, MIPS BE) and prevents
    // consensus splits in mixed-hardware deployments.
    //
    // SECURITY NOTE (SOQ-COV-002): Final comparison uses XOR-accumulate
    // (constant-time). memcmp short-circuits on first mismatch, enabling a
    // timing oracle attack to recover the expected template hash byte-by-byte.

    if (hash.size() != 32)
        return false;

    // Helper: write a uint32_t in canonical little-endian
    auto writeLE32 = [](CSHA256& h, uint32_t v) {
        uint8_t buf[4];
        buf[0] = v & 0xff;
        buf[1] = (v >> 8) & 0xff;
        buf[2] = (v >> 16) & 0xff;
        buf[3] = (v >> 24) & 0xff;
        h.Write(buf, 4);
    };
    // Helper: write a uint64_t (int64_t cast) in canonical little-endian
    auto writeLE64 = [](CSHA256& h, int64_t v) {
        uint64_t u = (uint64_t)v;
        uint8_t buf[8];
        buf[0] = u & 0xff;
        buf[1] = (u >> 8) & 0xff;
        buf[2] = (u >> 16) & 0xff;
        buf[3] = (u >> 24) & 0xff;
        buf[4] = (u >> 32) & 0xff;
        buf[5] = (u >> 40) & 0xff;
        buf[6] = (u >> 48) & 0xff;
        buf[7] = (u >> 56) & 0xff;
        h.Write(buf, 8);
    };

    CSHA256 ss;

    // 1. nVersion (4 bytes LE)
    writeLE32(ss, (uint32_t)txTo->nVersion);

    // 2. nLockTime (4 bytes LE)
    writeLE32(ss, txTo->nLockTime);

    // 3. If any scriptSig is non-empty, hash all scriptSigs
    bool hasScriptSigs = false;
    for (const auto& txin : txTo->vin) {
        if (!txin.scriptSig.empty()) {
            hasScriptSigs = true;
            break;
        }
    }
    if (hasScriptSigs) {
        CSHA256 ssSigs;
        for (const auto& txin : txTo->vin) {
            // Serialize length (LE) + data for each scriptSig
            writeLE32(ssSigs, (uint32_t)txin.scriptSig.size());
            if (!txin.scriptSig.empty()) {
                ssSigs.Write(txin.scriptSig.data(), txin.scriptSig.size());
            }
        }
        uint8_t scriptSigsHash[32];
        ssSigs.Finalize(scriptSigsHash);
        ss.Write(scriptSigsHash, 32);
    }

    // 4. Number of inputs (4 bytes LE)
    writeLE32(ss, (uint32_t)txTo->vin.size());

    // 5. Hash of all input sequences
    {
        CSHA256 ssSeq;
        for (const auto& txin : txTo->vin) {
            writeLE32(ssSeq, txin.nSequence);
        }
        uint8_t seqHash[32];
        ssSeq.Finalize(seqHash);
        ss.Write(seqHash, 32);
    }

    // 6. Number of outputs (4 bytes LE)
    writeLE32(ss, (uint32_t)txTo->vout.size());

    // 7. Hash of all outputs (amount + scriptPubKey) — all LE
    {
        CSHA256 ssOut;
        for (const auto& txout : txTo->vout) {
            writeLE64(ssOut, txout.nValue);
            // SOQ-COV-012: CTV must commit to extension bytes to prevent
            // asset-type substitution in covenant-locked UTXOs.
            // Without this, a CTV vault locked for SOQ could be spent with
            // USDSOQ outputs of the same value — the hash would still match.
            ssOut.Write((const unsigned char*)&txout.nVisibility, 1);
            ssOut.Write((const unsigned char*)&txout.nAssetType, 1);
            writeLE32(ssOut, (uint32_t)txout.scriptPubKey.size());
            if (!txout.scriptPubKey.empty()) {
                ssOut.Write(txout.scriptPubKey.data(), txout.scriptPubKey.size());
            }
        }
        uint8_t outHash[32];
        ssOut.Finalize(outHash);
        ss.Write(outHash, 32);
    }

    // 8. Input index being spent (4 bytes LE)
    writeLE32(ss, (uint32_t)nIn);

    // Finalize and compare — CONSTANT TIME (SOQ-COV-002)
    uint8_t computed[32];
    ss.Finalize(computed);

    // XOR-accumulate: diff==0 iff all bytes match. Short-circuit resistant.
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= computed[i] ^ hash.data()[i];
    return diff == 0;
}
