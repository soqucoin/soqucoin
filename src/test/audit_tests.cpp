#include "chainparams.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_bitcoin.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(audit_tests, BasicTestingSetup)

// Helper to create a dummy proof of given size
std::vector<unsigned char> CreateDummyProof(size_t size)
{
    return std::vector<unsigned char>(size, 0xaa);
}

BOOST_AUTO_TEST_CASE(op_checkfoldproof_tests)
{
    // Test OP_CHECKFOLDPROOF (0xfc)
    // Prototype status:
    // 1. Checks stack size >= 1
    // 2. Checks proof size 1280 <= size <= 1536
    // 3. Calls EvalCheckFoldProof (which fails on dummy data)

    // Switch to REGTEST to ensure opcode is active (activation height = 0)
    SelectParams(CBaseChainParams::REGTEST);

    // We removed direct chainActive dependency in interpreter.cpp
    // Now we need to pass SCRIPT_VERIFY_LATTICEFOLD flag to EvalScript
    unsigned int flags = SCRIPT_VERIFY_LATTICEFOLD;

    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    // printf("DEBUG: SCRIPT_ERR_INVALID_STACK_OPERATION = %d\n", SCRIPT_ERR_INVALID_STACK_OPERATION);
    // printf("DEBUG: SCRIPT_ERR_CHECKFOLDPROOF_FAILED = %d\n", SCRIPT_ERR_CHECKFOLDPROOF_FAILED);

    // Case 1: Empty stack
    {
        CScript script = CScript() << OP_CHECKFOLDPROOF;
        std::vector<std::vector<unsigned char> > stack;
        BOOST_CHECK(!EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // Case 2: Invalid proof size (too small)
    {
        CScript script = CScript() << OP_CHECKFOLDPROOF;
        std::vector<std::vector<unsigned char> > stack;
        stack.push_back(CreateDummyProof(100)); // < 1280
        BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CHECKFOLDPROOF_FAILED);
    }

    // Case 3: Valid proof size, but invalid proof content (EvalCheckFoldProof fails)
    {
        CScript script = CScript() << OP_CHECKFOLDPROOF;
        std::vector<std::vector<unsigned char> > stack;
        stack.push_back(CreateDummyProof(1280)); // Valid size
        BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CHECKFOLDPROOF_FAILED);
    }
}

BOOST_AUTO_TEST_CASE(op_checkpatagg_tests)
{
    // Test OP_CHECKPATAGG (0xfd)
    // Prototype status:
    // 1. Checks stack size >= 3
    // 2. Calls VerifyLogarithmicProof (prototype checks XOR binding)

    ScriptError serror;
    BaseSignatureChecker checker;
    unsigned int flags = SCRIPT_VERIFY_LATTICEFOLD;

    // Construct valid inputs for the prototype verifier
    // proof_data: 32 bytes root || 32 bytes xor || 32 bytes msg_root || 4 bytes count
    // Total 100 bytes
    std::vector<unsigned char> proof_data(100, 0);
    std::vector<unsigned char> agg_pk(32, 0x11);
    std::vector<unsigned char> msg_root(32, 0x22);

    // Set proof.pk_xor (bytes 32-64) to match agg_pk
    std::copy(agg_pk.begin(), agg_pk.end(), proof_data.begin() + 32);

    // Set proof.msg_root (bytes 64-96) to match msg_root
    std::copy(msg_root.begin(), msg_root.end(), proof_data.begin() + 64);

    // Set proof.merkle_root (bytes 0-31) to non-zero (otherwise IsNull() fails)
    proof_data[0] = 0x01;

    // Case 1: Success (Prototype consistency check passes)
    {
        CScript script = CScript() << OP_CHECKPATAGG;
        std::vector<std::vector<unsigned char> > stack;
        stack.push_back(proof_data);
        stack.push_back(agg_pk);
        stack.push_back(msg_root);

        bool result = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
        BOOST_CHECK(result);
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        if (stack.size() > 0)
            BOOST_CHECK(stack.back()[0] == 1); // Returns true
    }

    // Case 2: Failure (XOR binding mismatch)
    {
        std::vector<unsigned char> bad_agg_pk = agg_pk;
        bad_agg_pk[0] ^= 0xff; // Corrupt it

        CScript script = CScript() << OP_CHECKPATAGG;
        std::vector<std::vector<unsigned char> > stack;
        stack.push_back(proof_data);
        stack.push_back(bad_agg_pk);
        stack.push_back(msg_root);

        BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_PAT_VERIFICATION_FAILED);
    }

    // Case 3: Failure (Empty msg_root)
    {
        CScript script = CScript() << OP_CHECKPATAGG;
        std::vector<std::vector<unsigned char> > stack;
        stack.push_back(proof_data);
        stack.push_back(agg_pk);
        stack.push_back(std::vector<unsigned char>()); // Empty

        BOOST_CHECK(!EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_PAT_VERIFICATION_FAILED);
    }
}

BOOST_AUTO_TEST_CASE(op_checkdilithiumsig_tests)
{
    // Test OP_CHECKDILITHIUMSIG (0xfb)
    // 1. Checks stack size >= 2
    // 2. Calls checker.CheckSig

    ScriptError serror;
    BaseSignatureChecker checker; // Default checker returns false for CheckSig

    std::vector<unsigned char> sig(100, 0xaa);
    std::vector<unsigned char> pubkey(100, 0xbb);

    // Case 1: Execution (fails CheckSig because dummy checker returns false)
    {
        CScript script = CScript() << OP_CHECKDILITHIUMSIG;
        std::vector<std::vector<unsigned char> > stack;
        stack.push_back(sig);
        stack.push_back(pubkey);

        BOOST_CHECK(!EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror));
        // We expect SCRIPT_ERR_SIG_DER or whatever we returned on failure
        // In my implementation: return set_error(serror, SCRIPT_ERR_SIG_DER);
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_DER);
    }

    // Case 2: Invalid stack
    {
        CScript script = CScript() << OP_CHECKDILITHIUMSIG;
        std::vector<std::vector<unsigned char> > stack;
        stack.push_back(sig); // Only 1 item
        BOOST_CHECK(!EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }
}

BOOST_AUTO_TEST_SUITE_END()
