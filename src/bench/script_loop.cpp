// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// script_loop.cpp — the time the script loop of witness versions 6 and 11
// takes on four shapes, and the time of a transaction's precomputed data.
// At the merge of witness version 11 the time of each of the four grew with
// the square of its size: the loop read the nesting of conditionals from end
// to end at every opcode, and each input that executed
// OP_CHECKTEMPLATEVERIFY hashed the sequences and the outputs of its
// transaction, and its scriptSigs where one was present.
//
//   ScriptLoopNestedConditionals             one script of 10,000 bytes that
//                                            nests 3,333 conditionals, each
//                                            of them taken.
//   ScriptLoopTemplateChecksRelay            a transaction of 2,126 inputs and
//                                            2,140 outputs, each input one
//                                            OP_CHECKTEMPLATEVERIFY. Spent as
//                                            witness version 11, each input
//                                            with a committed item of 35
//                                            bytes and its trailer, it weighs
//                                            799,716 units of the 800,000 a
//                                            standard transaction may.
//   ScriptLoopTemplateChecksBlock            the same shape at 10,600 inputs
//                                            and 10,690 outputs: 3,990,538
//                                            units of the 4,000,000 a block
//                                            may.
//   ScriptLoopTemplateChecksBlockScriptSig   the block shape's inputs with one
//                                            output, and the bytes of its
//                                            outputs in the scriptSig of one
//                                            more input, which is not
//                                            evaluated.
//   ScriptLoopPrecomputedData                the precomputed data of the block
//                                            shape's transaction, built once.
//                                            A node builds the data at relay
//                                            and in a block, and in a block
//                                            whose scripts it checks at least
//                                            twice for a transaction other
//                                            than the coinbase.
//   ScriptLoopTemplateParts                  the part of that work that the
//                                            template hash adds.
//
// A template check is timed as validation runs it: the transaction's
// precomputed data is built once, and each input gets a checker of its own
// that holds it. The operand is not the transaction's template hash, so each
// check fails after the hash is computed and compared, which is the work of
// a check that passes.
//
// Run them with: bench_soqucoin ScriptLoop

#include "bench.h"

#include "amount.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "uint256.h"

#include <cassert>
#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

const unsigned int FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_SCRIPT_RESTORE |
                           SCRIPT_VERIFY_P2WSH_DILITHIUM | SCRIPT_VERIFY_V6_CONTROLFLOW |
                           SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_APO | SCRIPT_VERIFY_CSFS;

//! A transaction of `inputs` inputs and `outputs` outputs of a 34-byte script
//! each. When `scriptSigBytes` is not zero it has one input more, the last,
//! whose scriptSig holds that many bytes.
CTransaction TemplateTx(size_t inputs, size_t outputs, size_t scriptSigBytes)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    for (size_t i = 0; i < inputs; ++i) {
        CTxIn in;
        in.prevout = COutPoint(uint256S("0x1111111111111111111111111111111111111111111111111111111111111111"), static_cast<uint32_t>(i));
        tx.vin.push_back(in);
    }
    if (scriptSigBytes > 0) {
        CTxIn in;
        in.prevout = COutPoint(uint256S("0x2222222222222222222222222222222222222222222222222222222222222222"), 0);
        const valtype bytes(scriptSigBytes, 0x51);
        in.scriptSig = CScript(bytes.begin(), bytes.end());
        tx.vin.push_back(in);
    }
    for (size_t i = 0; i < outputs; ++i)
        tx.vout.push_back(CTxOut(COIN, CScript() << OP_1 << valtype(32, 0x22)));
    return CTransaction(tx);
}

void TemplateChecks(benchmark::State& state, size_t inputs, size_t outputs, size_t scriptSigBytes)
{
    const CTransaction tx = TemplateTx(inputs, outputs, scriptSigBytes);
    const CScript script = CScript() << valtype(32, 0x07) << OP_CHECKTEMPLATEVERIFY;
    while (state.KeepRunning()) {
        const PrecomputedTransactionData txdata(tx);
        for (size_t i = 0; i < inputs; ++i) {
            const TransactionSignatureChecker checker(&tx, static_cast<unsigned int>(i), CAmount(0), txdata);
            std::vector<valtype> stack;
            ScriptError error = SCRIPT_ERR_OK;
            const bool ok = EvalScript(stack, script, FLAGS, checker, SIGVERSION_WITNESS_V11, &error);
            assert(!ok && error == SCRIPT_ERR_CHECKTEMPLATEVERIFY);
        }
    }
}

} // namespace

static void ScriptLoopNestedConditionals(benchmark::State& state)
{
    CScript script;
    for (int i = 0; i < 3333; ++i)
        script << OP_1 << OP_IF;
    for (int i = 0; i < 3333; ++i)
        script << OP_ENDIF;
    script << OP_1;
    assert(script.size() == 10000);
    while (state.KeepRunning()) {
        std::vector<valtype> stack;
        ScriptError error = SCRIPT_ERR_OK;
        const bool ok = EvalScript(stack, script, FLAGS, BaseSignatureChecker(), SIGVERSION_WITNESS_V0, &error);
        assert(ok && stack.size() == 1);
    }
}

static void ScriptLoopTemplateChecksRelay(benchmark::State& state)
{
    TemplateChecks(state, 2126, 2140, 0);
}

static void ScriptLoopTemplateChecksBlock(benchmark::State& state)
{
    TemplateChecks(state, 10600, 10690, 0);
}

static void ScriptLoopTemplateChecksBlockScriptSig(benchmark::State& state)
{
    TemplateChecks(state, 10600, 1, 459670);
}

static void ScriptLoopPrecomputedData(benchmark::State& state)
{
    const CTransaction tx = TemplateTx(10600, 10690, 0);
    while (state.KeepRunning()) {
        const PrecomputedTransactionData txdata(tx);
        assert(!txdata.templateParts.fHasScriptSigs);
    }
}

static void ScriptLoopTemplateParts(benchmark::State& state)
{
    const CTransaction tx = TemplateTx(10600, 10690, 0);
    while (state.KeepRunning()) {
        const TemplateHashParts parts(tx);
        assert(!parts.fHasScriptSigs);
    }
}

BENCHMARK(ScriptLoopNestedConditionals);
BENCHMARK(ScriptLoopPrecomputedData);
BENCHMARK(ScriptLoopTemplateParts);
BENCHMARK(ScriptLoopTemplateChecksRelay);
BENCHMARK(ScriptLoopTemplateChecksBlock);
BENCHMARK(ScriptLoopTemplateChecksBlockScriptSig);
