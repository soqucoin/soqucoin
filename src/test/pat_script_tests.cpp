// HALBORN FIND-006: All tests rewritten to use full-mode (witness) stacks.
// Simple-mode (3-item stack) is no longer accepted in consensus.
#include "crypto/pat/logarithmic.h"
#include "random.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

using namespace std;
typedef std::vector<unsigned char> valtype;

BOOST_FIXTURE_TEST_SUITE(pat_script_tests, BasicTestingSetup)

// Helper to create random 32-byte vector
static valtype GetRandHashVec()
{
    uint256 hash;
    GetRandBytes(hash.begin(), 32);
    return valtype(hash.begin(), hash.end());
}

static bool CastToBool(const valtype& vch)
{
    for (unsigned int i = 0; i < vch.size(); i++) {
        if (vch[i] != 0) {
            if (i == vch.size() - 1 && vch[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

// Helper: Build a full-mode OP_CHECKPATAGG script with witness data.
// Stack layout: <sigs...> <pks...> <msgs...> <count_le32> <proof> <agg_pk> <msg_root>
static CScript BuildFullModeScript(
    const std::vector<valtype>& sigs,
    const std::vector<valtype>& pks,
    const std::vector<valtype>& msgs,
    const valtype& proof_data,
    const valtype& agg_pk,
    const valtype& msg_root)
{
    CScript script;
    uint32_t n = sigs.size();

    // Push sigs (bottom of stack)
    for (uint32_t i = 0; i < n; i++)
        script << sigs[i];

    // Push pks
    for (uint32_t i = 0; i < n; i++)
        script << pks[i];

    // Push msgs
    for (uint32_t i = 0; i < n; i++)
        script << msgs[i];

    // Push count as 4-byte LE
    valtype count_blob(4);
    memcpy(count_blob.data(), &n, 4);
    script << count_blob;

    // Push proof, agg_pk, msg_root (top of stack)
    script << proof_data << agg_pk << msg_root;

    script << OP_CHECKPATAGG;
    return script;
}

// Helper: Create proof and extract agg_pk/msg_root from proof structure
struct ProofBundle {
    valtype proof_data;
    valtype agg_pk;
    valtype msg_root;
};

static ProofBundle CreateProofBundle(
    const std::vector<valtype>& sigs,
    const std::vector<valtype>& pks,
    const std::vector<valtype>& msgs)
{
    ProofBundle bundle;
    BOOST_REQUIRE(pat::CreateLogarithmicProof(sigs, pks, msgs, bundle.proof_data));

    pat::LogarithmicProof proof;
    BOOST_REQUIRE(pat::ParseLogarithmicProof(bundle.proof_data, proof));

    bundle.agg_pk.assign(proof.pk_agg.begin(), proof.pk_agg.end());
    bundle.msg_root.assign(proof.msg_root.begin(), proof.msg_root.end());
    return bundle;
}

// ==============================
// HALBORN FIND-006: FULL-MODE VERIFICATION TESTS
// ==============================

BOOST_AUTO_TEST_CASE(pat_opcode_full_mode)
{
    // Test Full Mode: n=1 — valid proof with correct witness
    std::vector<valtype> sigs, pks, msgs;
    sigs.push_back(GetRandHashVec());
    pks.push_back(GetRandHashVec());
    msgs.push_back(GetRandHashVec());

    ProofBundle b = CreateProofBundle(sigs, pks, msgs);
    CScript script = BuildFullModeScript(sigs, pks, msgs, b.proof_data, b.agg_pk, b.msg_root);

    BaseSignatureChecker checker;
    ScriptError serror;
    std::vector<valtype> stack;
    bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

    BOOST_CHECK_MESSAGE(result, "Full-mode n=1: " + std::string(ScriptErrorString(serror)));
    BOOST_CHECK(serror == SCRIPT_ERR_OK);
    BOOST_CHECK(!stack.empty() && CastToBool(stack.back()));

    // Tampered witness sig should fail (full-mode verifies witness data)
    std::vector<valtype> bad_sigs = sigs;
    bad_sigs[0][0] ^= 0xFF;
    CScript scriptFail = BuildFullModeScript(bad_sigs, pks, msgs, b.proof_data, b.agg_pk, b.msg_root);

    stack.clear();
    result = EvalScript(stack, scriptFail, 0, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK(serror == SCRIPT_ERR_PAT_VERIFICATION_FAILED);
}

BOOST_AUTO_TEST_CASE(pat_opcode_full_mode_comprehensive)
{
    // Scenario 1: n=1
    {
        std::vector<valtype> sigs, pks, msgs;
        sigs.push_back(GetRandHashVec());
        pks.push_back(GetRandHashVec());
        msgs.push_back(GetRandHashVec());

        ProofBundle b = CreateProofBundle(sigs, pks, msgs);
        CScript script = BuildFullModeScript(sigs, pks, msgs, b.proof_data, b.agg_pk, b.msg_root);

        BaseSignatureChecker checker;
        ScriptError serror;
        std::vector<valtype> stack;
        bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

        BOOST_CHECK_MESSAGE(result, "n=1: " + std::string(ScriptErrorString(serror)));
        BOOST_CHECK(!stack.empty() && CastToBool(stack.back()));
    }

    // Scenario 2: n=4 (power of 2)
    {
        std::vector<valtype> sigs, pks, msgs;
        for (int i = 0; i < 4; i++) {
            sigs.push_back(GetRandHashVec());
            pks.push_back(GetRandHashVec());
            msgs.push_back(GetRandHashVec());
        }

        ProofBundle b = CreateProofBundle(sigs, pks, msgs);
        CScript script = BuildFullModeScript(sigs, pks, msgs, b.proof_data, b.agg_pk, b.msg_root);

        BaseSignatureChecker checker;
        ScriptError serror;
        std::vector<valtype> stack;
        bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

        BOOST_CHECK_MESSAGE(result, "n=4: " + std::string(ScriptErrorString(serror)));
        BOOST_CHECK(!stack.empty() && CastToBool(stack.back()));
    }

    // Scenario 3: n=7 (non-power of 2, exercises FIND-005 padding)
    {
        std::vector<valtype> sigs, pks, msgs;
        for (int i = 0; i < 7; i++) {
            sigs.push_back(GetRandHashVec());
            pks.push_back(GetRandHashVec());
            msgs.push_back(GetRandHashVec());
        }

        ProofBundle b = CreateProofBundle(sigs, pks, msgs);
        CScript script = BuildFullModeScript(sigs, pks, msgs, b.proof_data, b.agg_pk, b.msg_root);

        BaseSignatureChecker checker;
        ScriptError serror;
        std::vector<valtype> stack;
        bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

        BOOST_CHECK_MESSAGE(result, "n=7: " + std::string(ScriptErrorString(serror)));
        BOOST_CHECK(!stack.empty() && CastToBool(stack.back()));
    }

    // Scenario 4: Tampered witness pk should fail
    {
        std::vector<valtype> sigs, pks, msgs;
        sigs.push_back(GetRandHashVec());
        pks.push_back(GetRandHashVec());
        msgs.push_back(GetRandHashVec());

        ProofBundle b = CreateProofBundle(sigs, pks, msgs);

        // Tamper with a witness pk (not the header agg_pk)
        std::vector<valtype> bad_pks = pks;
        bad_pks[0][0] ^= 0xFF;

        CScript script = BuildFullModeScript(sigs, bad_pks, msgs, b.proof_data, b.agg_pk, b.msg_root);

        BaseSignatureChecker checker;
        ScriptError serror;
        std::vector<valtype> stack;
        bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

        BOOST_CHECK_MESSAGE(!result, "Tampered witness pk should fail");
        BOOST_CHECK(serror == SCRIPT_ERR_PAT_VERIFICATION_FAILED);
    }

    // Scenario 5: Tampered witness msg should fail
    {
        std::vector<valtype> sigs, pks, msgs;
        sigs.push_back(GetRandHashVec());
        pks.push_back(GetRandHashVec());
        msgs.push_back(GetRandHashVec());

        ProofBundle b = CreateProofBundle(sigs, pks, msgs);

        // Tamper with a witness msg (not the header msg_root)
        std::vector<valtype> bad_msgs = msgs;
        bad_msgs[0][0] ^= 0xFF;

        CScript script = BuildFullModeScript(sigs, pks, bad_msgs, b.proof_data, b.agg_pk, b.msg_root);

        BaseSignatureChecker checker;
        ScriptError serror;
        std::vector<valtype> stack;
        bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

        BOOST_CHECK_MESSAGE(!result, "Tampered witness msg should fail");
        BOOST_CHECK(serror == SCRIPT_ERR_PAT_VERIFICATION_FAILED);
    }
}

// ==============================
// HALBORN FIND-006: SIMPLE-MODE REJECTION TEST
// Verify that 3-item stack (old simple-mode) is now rejected.
// ==============================

BOOST_AUTO_TEST_CASE(find006_simple_mode_rejected)
{
    // Build a valid proof, then push ONLY the 3-item simple-mode stack.
    // This MUST fail with SCRIPT_ERR_INVALID_STACK_OPERATION.
    std::vector<valtype> sigs, pks, msgs;
    sigs.push_back(GetRandHashVec());
    pks.push_back(GetRandHashVec());
    msgs.push_back(GetRandHashVec());

    ProofBundle b = CreateProofBundle(sigs, pks, msgs);

    // Old simple-mode script: <proof> <agg_pk> <msg_root> OP_CHECKPATAGG
    CScript script;
    script << b.proof_data << b.agg_pk << b.msg_root << OP_CHECKPATAGG;

    BaseSignatureChecker checker;
    ScriptError serror;
    std::vector<valtype> stack;
    bool result = EvalScript(stack, script, 0, checker, SIGVERSION_BASE, &serror);

    BOOST_CHECK_MESSAGE(!result,
        "FIND-006 REGRESSION: Simple-mode (3-item stack) should be rejected");
    BOOST_CHECK_MESSAGE(serror == SCRIPT_ERR_INVALID_STACK_OPERATION,
        "Expected INVALID_STACK_OPERATION, got: " + std::string(ScriptErrorString(serror)));
}

BOOST_AUTO_TEST_SUITE_END()
