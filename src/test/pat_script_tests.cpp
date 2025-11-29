#include "crypto/pat/logarithmic.h"
#include "random.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_FIXTURE_TEST_SUITE(pat_script_tests, BasicTestingSetup)

// Helper to create random 32-byte vector
static std::vector<unsigned char> GetRandHashVec()
{
    uint256 hash;
    GetRandBytes(hash.begin(), 32);
    return std::vector<unsigned char>(hash.begin(), hash.end());
}

static bool CastToBool(const std::vector<unsigned char>& vch)
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

BOOST_AUTO_TEST_CASE(pat_opcode_simple_mode)
{
    // Test Simple Mode: <proof> <agg_pk> <msg_root> OP_CHECKPATAGG

    // 1. Create synthetic data
    std::vector<std::vector<unsigned char> > sigs, pks, msgs;
    sigs.push_back(GetRandHashVec());
    pks.push_back(GetRandHashVec());
    msgs.push_back(GetRandHashVec());

    // 2. Create proof
    std::vector<unsigned char> proof_data;
    std::vector<std::vector<unsigned char> > sibling_path;
    BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof_data, sibling_path));

    // 3. Parse proof to get expected roots
    pat::LogarithmicProof proof;
    BOOST_CHECK(pat::ParseLogarithmicProof(proof_data, proof));

    std::vector<unsigned char> agg_pk(proof.pk_xor.begin(), proof.pk_xor.end());
    std::vector<unsigned char> msg_root(proof.msg_root.begin(), proof.msg_root.end());

    // 4. Construct Script
    CScript script;
    script << proof_data << agg_pk << msg_root << OP_CHECKPATAGG;

    // 5. Execute
    BaseSignatureChecker checker;
    ScriptError serror;
    std::vector<std::vector<unsigned char> > stack;
    bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

    BOOST_CHECK_MESSAGE(result, ScriptErrorString(serror));
    BOOST_CHECK(serror == SCRIPT_ERR_OK);
    // EvalScript returns true if script executed without error.
    // We also need to check if the top of stack is true.
    BOOST_CHECK(!stack.empty());
    if (!stack.empty()) {
        BOOST_CHECK(CastToBool(stack.back()));
    }

    // 6. Test Failure (Bad Msg Root)
    std::vector<unsigned char> bad_msg_root = msg_root;
    bad_msg_root[0] ^= 0xFF;

    CScript scriptFail;
    scriptFail << proof_data << agg_pk << bad_msg_root << OP_CHECKPATAGG;

    stack.clear();
    result = EvalScript(stack, scriptFail, 0, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK(serror == SCRIPT_ERR_PAT_VERIFICATION_FAILED);
}

BOOST_AUTO_TEST_CASE(pat_opcode_simple_mode_comprehensive)
{
    // Test multiple scenarios for Simple Mode to ensure robustness

    // Scenario 1: n=1 (single signature)
    {
        std::vector<std::vector<unsigned char> > sigs, pks, msgs;
        sigs.push_back(GetRandHashVec());
        pks.push_back(GetRandHashVec());
        msgs.push_back(GetRandHashVec());

        std::vector<unsigned char> proof_data;
        std::vector<std::vector<unsigned char> > sibling_path;
        BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof_data, sibling_path));

        pat::LogarithmicProof proof;
        BOOST_CHECK(pat::ParseLogarithmicProof(proof_data, proof));

        std::vector<unsigned char> agg_pk(proof.pk_xor.begin(), proof.pk_xor.end());
        std::vector<unsigned char> msg_root(proof.msg_root.begin(), proof.msg_root.end());

        CScript script;
        script << proof_data << agg_pk << msg_root << OP_CHECKPATAGG;

        BaseSignatureChecker checker;
        ScriptError serror;
        std::vector<std::vector<unsigned char> > stack;
        bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

        BOOST_CHECK_MESSAGE(result, "n=1 test failed: " + std::string(ScriptErrorString(serror)));
        BOOST_CHECK(serror == SCRIPT_ERR_OK);
        BOOST_CHECK(!stack.empty() && CastToBool(stack.back()));
    }

    // Scenario 2: n=4 (power of 2)
    {
        std::vector<std::vector<unsigned char> > sigs, pks, msgs;
        for (int i = 0; i < 4; i++) {
            sigs.push_back(GetRandHashVec());
            pks.push_back(GetRandHashVec());
            msgs.push_back(GetRandHashVec());
        }

        std::vector<unsigned char> proof_data;
        std::vector<std::vector<unsigned char> > sibling_path;
        BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof_data, sibling_path));

        pat::LogarithmicProof proof;
        BOOST_CHECK(pat::ParseLogarithmicProof(proof_data, proof));

        std::vector<unsigned char> agg_pk(proof.pk_xor.begin(), proof.pk_xor.end());
        std::vector<unsigned char> msg_root(proof.msg_root.begin(), proof.msg_root.end());

        CScript script;
        script << proof_data << agg_pk << msg_root << OP_CHECKPATAGG;

        BaseSignatureChecker checker;
        ScriptError serror;
        std::vector<std::vector<unsigned char> > stack;
        bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

        BOOST_CHECK_MESSAGE(result, "n=4 test failed: " + std::string(ScriptErrorString(serror)));
        BOOST_CHECK(serror == SCRIPT_ERR_OK);
        BOOST_CHECK(!stack.empty() && CastToBool(stack.back()));
    }

    // Scenario 3: n=7 (non-power of 2)
    {
        std::vector<std::vector<unsigned char> > sigs, pks, msgs;
        for (int i = 0; i < 7; i++) {
            sigs.push_back(GetRandHashVec());
            pks.push_back(GetRandHashVec());
            msgs.push_back(GetRandHashVec());
        }

        std::vector<unsigned char> proof_data;
        std::vector<std::vector<unsigned char> > sibling_path;
        BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof_data, sibling_path));

        pat::LogarithmicProof proof;
        BOOST_CHECK(pat::ParseLogarithmicProof(proof_data, proof));

        std::vector<unsigned char> agg_pk(proof.pk_xor.begin(), proof.pk_xor.end());
        std::vector<unsigned char> msg_root(proof.msg_root.begin(), proof.msg_root.end());

        CScript script;
        script << proof_data << agg_pk << msg_root << OP_CHECKPATAGG;

        BaseSignatureChecker checker;
        ScriptError serror;
        std::vector<std::vector<unsigned char> > stack;
        bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

        BOOST_CHECK_MESSAGE(result, "n=7 test failed: " + std::string(ScriptErrorString(serror)));
        BOOST_CHECK(serror == SCRIPT_ERR_OK);
        BOOST_CHECK(!stack.empty() && CastToBool(stack.back()));
    }

    // Scenario 4: Tampered pk_xor should fail
    {
        std::vector<std::vector<unsigned char> > sigs, pks, msgs;
        sigs.push_back(GetRandHashVec());
        pks.push_back(GetRandHashVec());
        msgs.push_back(GetRandHashVec());

        std::vector<unsigned char> proof_data;
        std::vector<std::vector<unsigned char> > sibling_path;
        BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof_data, sibling_path));

        pat::LogarithmicProof proof;
        BOOST_CHECK(pat::ParseLogarithmicProof(proof_data, proof));

        std::vector<unsigned char> agg_pk(proof.pk_xor.begin(), proof.pk_xor.end());
        std::vector<unsigned char> msg_root(proof.msg_root.begin(), proof.msg_root.end());

        // Tamper with agg_pk
        agg_pk[0] ^= 0xFF;

        CScript script;
        script << proof_data << agg_pk << msg_root << OP_CHECKPATAGG;

        BaseSignatureChecker checker;
        ScriptError serror;
        std::vector<std::vector<unsigned char> > stack;
        bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

        BOOST_CHECK_MESSAGE(!result, "Tampered pk_xor should fail");
        BOOST_CHECK(serror == SCRIPT_ERR_PAT_VERIFICATION_FAILED);
    }

    // Scenario 5: Tampered msg_root should fail
    {
        std::vector<std::vector<unsigned char> > sigs, pks, msgs;
        sigs.push_back(GetRandHashVec());
        pks.push_back(GetRandHashVec());
        msgs.push_back(GetRandHashVec());

        std::vector<unsigned char> proof_data;
        std::vector<std::vector<unsigned char> > sibling_path;
        BOOST_CHECK(pat::CreateLogarithmicProof(sigs, pks, msgs, proof_data, sibling_path));

        pat::LogarithmicProof proof;
        BOOST_CHECK(pat::ParseLogarithmicProof(proof_data, proof));

        std::vector<unsigned char> agg_pk(proof.pk_xor.begin(), proof.pk_xor.end());
        std::vector<unsigned char> msg_root(proof.msg_root.begin(), proof.msg_root.end());

        // Tamper with msg_root
        msg_root[0] ^= 0xFF;

        CScript script;
        script << proof_data << agg_pk << msg_root << OP_CHECKPATAGG;

        BaseSignatureChecker checker;
        ScriptError serror;
        std::vector<std::vector<unsigned char> > stack;
        bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

        BOOST_CHECK_MESSAGE(!result, "Tampered msg_root should fail");
        BOOST_CHECK(serror == SCRIPT_ERR_PAT_VERIFICATION_FAILED);
    }
}

BOOST_AUTO_TEST_SUITE_END()
