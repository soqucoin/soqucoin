// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

#include "crypto/binius/verifier.h"
#include <script/interpreter.h>

#include "primitives/transaction.h"
#include "util.h"
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

    error("Soqucoin only permits ML-DSA (Dilithium) signatures and public keys");
    return set_error(serror, SCRIPT_ERR_SIG_DER);
}

bool static CheckPubKeyEncoding(const valtype& vchPubKey, unsigned int flags, const SigVersion& sigversion, ScriptError* serror)
{
    if (vchPubKey.empty() || vchPubKey[0] != 0x00) {
        error("Soqucoin only permits ML-DSA (Dilithium) signatures and public keys");
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    }

    return true;
}

bool static CheckMinimalPush(const valtype& data, opcodetype opcode)
{
    if (data.size() == 0) {
        if (opcode != OP_0) return false;
    } else if (data.size() == 1) {
        if (opcode != OP_1NEGATE && opcode != OP_1 && opcode != (opcodetype)data[0]) return false;
    } else if (opcode == OP_PUSHDATA1) {
        if (data.size() <= 75) return false;
    } else if (opcode == OP_PUSHDATA2) {
        if (data.size() <= 255) return false;
    } else if (opcode == OP_PUSHDATA4) {
        if (data.size() <= 65535) return false;
    }
    return true;
}

bool EvalScript(vector<vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror)
{
    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    static const CScriptNum bnFalse(0);
    static const CScriptNum bnTrue(1);
    static const valtype vchFalse(0);
    static const valtype vchZero(0);
    static const valtype vchTrue(1, 1);

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    opcodetype opcode;
    valtype vchPushValue;
    CScriptNum bn(0);
    vector<valtype> altstack;
    set_success(serror);

    try {
        while (pc < pend) {
            bool fExec = !stack.empty();

            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue))
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

            // Note how OP_RESERVED does not count towards the opcode limit.
            if (opcode > OP_16) {
                //
                // Execution
                //
                if (fExec) {
                    if (opcode == OP_CHECKBATCHSIG) {
                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

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
                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        valtype proof_data = stacktop(-3);
                        valtype agg_pk = stacktop(-2);
                        valtype msg_root = stacktop(-1);

                        // Parse LogarithmicProof from proof_data
                        // For now, we use the stub
                        pat::LogarithmicProof proof;
                        // TODO: Parse proof_data into proof struct

                        if (!pat::VerifyLogarithmicProof(proof, agg_pk, msg_root)) {
                            return set_error(serror, SCRIPT_ERR_PAT_VERIFICATION_FAILED);
                        }

                        popstack(stack);
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(valtype(1, 1)); // true
                    } else if (opcode == OP_CHECKFOLDPROOF) {
                        if (stack.size() < 1) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        const valtype& vchProof = stacktop(-1);
                        if (!EvalCheckFoldProof(vchProof)) return set_error(serror, SCRIPT_ERR_CHECKFOLDPROOF_FAILED);
                        stack.pop_back();
                        stack.push_back(valtype(1, 1)); // true
                    }
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

unsigned int WitnessSigOps(int witnessversion, const std::vector<unsigned char>& witnessprogram, const CScriptWitness& witness, unsigned int flags)
{
    return 0;
}
