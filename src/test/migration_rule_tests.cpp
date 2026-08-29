// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// migration_rule_tests.cpp — tamper matrix for the genesis-migration one-shot
// allocation rule (DL-GENESIS-MIGRATION-IMPLEMENTATION §A, bead
// gm-consensus-rule-bxws).
//
// The rule: at exactly nHeight == nMigrationHeight (non-zero, hash set), the
// coinbase must carry the committed allocation outputs as vout[1..N] in
// committed order (a trailing segwit witness-commitment output is excluded
// from the committed range); their standard vector serialization must
// double-SHA256 to hashMigrationOutputs, their values must sum to exactly
// nMigrationTotal, and the miner's vout[0] stays bounded by subsidy + fees
// while the permitted coinbase total becomes subsidy + fees + nMigrationTotal.
// With null/0/0 constants the rule is INERT — behavior byte-for-byte unchanged.
//
// r0vn acceptance criterion: every reject case drives a failing block through
// ConnectBlock (via TestBlockValidity, which runs ConnectBlock in fJustCheck
// mode) and observes the EXACT reject string, never just an unmoved tip.
//
// ⚠️ These tests arm the rule by mutating the regtest singleton
// (UpdateRegtestMigrationParams). Every arming goes through the RAII guard
// below so the singleton is always restored to the inert null/0/0/{} state,
// even on assertion failure — a leaked arming would poison every later suite.
//
// Fixture shape borrowed from authority_skip_gate_tests.cpp.

#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "miner.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "uint256.h"
#include "validation.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace {

//! OP_1 <32-byte hash> — the witness-v1 shape the miner's Dilithium-only
//! coinbase check requires, and the shape real sq1 allocations will have.
static CScript V1Spk(unsigned char seed)
{
    return CScript() << OP_1 << std::vector<unsigned char>(32, seed);
}

static uint256 HashOutputs(const std::vector<CTxOut>& vOutputs)
{
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << vOutputs;
    return hasher.GetHash();
}

static CAmount SumOutputs(const std::vector<CTxOut>& vOutputs)
{
    CAmount total = 0;
    for (const CTxOut& out : vOutputs) total += out.nValue;
    return total;
}

//! Arms the regtest migration rule for one scope and ALWAYS disarms on exit.
struct MigrationArming {
    MigrationArming(const uint256& hashOutputs, CAmount nTotal, int nHeight,
                    const std::vector<CTxOut>& vOutputs)
    {
        UpdateRegtestMigrationParams(hashOutputs, nTotal, nHeight, vOutputs);
    }
    ~MigrationArming()
    {
        UpdateRegtestMigrationParams(uint256(), 0, 0, std::vector<CTxOut>());
    }
};

} // namespace

struct MigrationChainSetup : public TestingSetup {
    CScript minerSpk;
    std::vector<CTxOut> committed; // the canonical 3-output allocation fixture

    MigrationChainSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        minerSpk = V1Spk(0x01);
        // Values sit above the SOQ-ARCH-003 utxo-cost floor (6,500 sat/byte —
        // active from height 0 on regtest), as every real allocation does: the
        // snapshot tool's dust floor is 1 pSOQ = 1 SOQ = 10^8 sats, comfortably
        // over the ~2.8e5-sat minimum for a v1 output.
        committed.push_back(CTxOut(10 * COIN, V1Spk(0xA1)));
        committed.push_back(CTxOut(20 * COIN, V1Spk(0xA2)));
        committed.push_back(CTxOut(COIN / 2, V1Spk(0xA3)));
        // Past the regtest params-tree boundaries (digishield at 10, auxpow at
        // 20), so armed heights resolve through auxpowConsensus — the struct a
        // singleton mutation historically missed (bead tofg).
        for (int i = 0; i < 30; i++) {
            MineHonestBlock();
        }
    }

    //! Template straight from the production miner — this is also the §A3 test
    //! surface: at the armed height the template must already carry the
    //! committed outputs.
    CBlock BuildTemplateBlock()
    {
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(Params()).CreateNewBlock(minerSpk, true);
        BOOST_REQUIRE(tmpl != nullptr);
        return tmpl->block;
    }

    //! Runs ConnectBlock (fJustCheck) on the block as-is; returns the reject
    //! string, or "" if it validated. PoW and merkle are skipped so tampered,
    //! unsolved blocks can be driven straight at the rule. The migration
    //! rejects asserted below all carry their own named strings, so "" is
    //! unambiguous here (see authority_skip_gate_tests.cpp on the empty-string
    //! caveat for script-layer rules).
    std::string RejectReasonFor(const CBlock& block)
    {
        CValidationState st;
        LOCK(cs_main);
        if (TestBlockValidity(st, Params(), block, chainActive.Tip(), false, false)) return std::string();
        return st.GetRejectReason();
    }

    //! Solve and submit; returns whether the tip advanced to this block.
    bool MineBlock(CBlock& block)
    {
        const CChainParams& cp = Params();
        unsigned int extraNonce = 0;
        {
            LOCK(cs_main);
            IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
        }
        while (!CheckProofOfWork(block.GetPoWHash(), block.nBits, cp.GetConsensus(0)))
            ++block.nNonce;
        std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(block);
        bool fNewBlock = false;
        ProcessNewBlock(cp, shared, true, &fNewBlock);
        LOCK(cs_main);
        return chainActive.Tip()->GetBlockHash() == block.GetHash();
    }

    void MineHonestBlock()
    {
        CBlock block = BuildTemplateBlock();
        BOOST_REQUIRE(MineBlock(block));
    }

    int TipHeight()
    {
        LOCK(cs_main);
        return chainActive.Height();
    }

    //! Replace the coinbase vout vector, keeping everything else (witness
    //! commitment output positions are the caller's business — the committed
    //! range excludes only a TRAILING commitment output).
    static CBlock WithCoinbaseVout(const CBlock& block, const std::vector<CTxOut>& vout)
    {
        CBlock tampered = block;
        CMutableTransaction coinbaseMut(*tampered.vtx[0]);
        coinbaseMut.vout = vout;
        tampered.vtx[0] = MakeTransactionRef(std::move(coinbaseMut));
        return tampered;
    }
};

BOOST_FIXTURE_TEST_SUITE(migration_rule_tests, MigrationChainSetup)

// The inert guarantee, stated as a test: with null constants (the state every
// real network ships in), the template carries no allocation and validates.
BOOST_AUTO_TEST_CASE(inert_by_default)
{
    CBlock block = BuildTemplateBlock();
    // miner output + witness commitment only — nothing appended
    BOOST_CHECK_EQUAL(block.vtx[0]->vout.size(), 2U);
    BOOST_CHECK_EQUAL(RejectReasonFor(block), "");
}

// §A3 + §A2 honest path: at the armed height the production template carries
// miner + committed outputs (+ trailing commitment), in committed order, and
// the block both validates and connects.
BOOST_AUTO_TEST_CASE(honest_migration_block_accepted)
{
    const int H = TipHeight() + 1;
    MigrationArming arm(HashOutputs(committed), SumOutputs(committed), H, committed);

    CBlock block = BuildTemplateBlock();
    const CTransaction& coinbase = *block.vtx[0];
    BOOST_REQUIRE_EQUAL(coinbase.vout.size(), 2U + committed.size());
    for (size_t i = 0; i < committed.size(); i++) {
        BOOST_CHECK(coinbase.vout[1 + i] == committed[i]);
    }
    BOOST_CHECK_EQUAL(RejectReasonFor(block), "");
    BOOST_CHECK(MineBlock(block));
    BOOST_CHECK_EQUAL(TipHeight(), H);
}

// Tamper 1: one committed output missing.
BOOST_AUTO_TEST_CASE(tamper_missing_output)
{
    const int H = TipHeight() + 1;
    MigrationArming arm(HashOutputs(committed), SumOutputs(committed), H, committed);
    CBlock block = BuildTemplateBlock();
    std::vector<CTxOut> vout = block.vtx[0]->vout;
    vout.erase(vout.begin() + 2); // drop the second committed output
    BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)), "bad-cb-migration-outputs");
}

// Tamper 2: one committed amount altered (by a single sat, both directions).
BOOST_AUTO_TEST_CASE(tamper_altered_amount)
{
    const int H = TipHeight() + 1;
    MigrationArming arm(HashOutputs(committed), SumOutputs(committed), H, committed);
    CBlock block = BuildTemplateBlock();
    for (const CAmount delta : {CAmount(1), CAmount(-1)}) {
        std::vector<CTxOut> vout = block.vtx[0]->vout;
        vout[1].nValue += delta;
        BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)), "bad-cb-migration-outputs");
    }
}

// Tamper 3: committed outputs reordered (same set, same sum).
BOOST_AUTO_TEST_CASE(tamper_reordered_outputs)
{
    const int H = TipHeight() + 1;
    MigrationArming arm(HashOutputs(committed), SumOutputs(committed), H, committed);
    CBlock block = BuildTemplateBlock();
    std::vector<CTxOut> vout = block.vtx[0]->vout;
    std::swap(vout[1], vout[2]);
    BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)), "bad-cb-migration-outputs");
}

// Tamper 4: an extra output inserted inside the committed range. A zero-value
// OP_RETURN is the sharpest probe: unspendable outputs are exempt from the
// utxo-cost floor and zero value is invisible to every amount check, so ONLY
// the committed-vector hash can catch it.
BOOST_AUTO_TEST_CASE(tamper_extra_output_inside_range)
{
    const int H = TipHeight() + 1;
    MigrationArming arm(HashOutputs(committed), SumOutputs(committed), H, committed);
    CBlock block = BuildTemplateBlock();
    std::vector<CTxOut> vout = block.vtx[0]->vout;
    vout.insert(vout.begin() + 2, CTxOut(0, CScript() << OP_RETURN << std::vector<unsigned char>{0xEE}));
    BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)), "bad-cb-migration-outputs");
}

// Tamper 5 (amended for nMigrationHeight): the committed outputs at any height
// other than the armed one are just unlicensed coinbase inflation, and the
// pre-existing subsidy check rejects them. Driven at both H-1 and H+1.
BOOST_AUTO_TEST_CASE(tamper_outputs_at_wrong_height)
{
    const int H = TipHeight() + 2; // arm one block in the future
    MigrationArming arm(HashOutputs(committed), SumOutputs(committed), H, committed);

    // H-1: rule inert at this height, so a coinbase carrying the committed
    // outputs simply pays too much.
    {
        CBlock block = BuildTemplateBlock();
        std::vector<CTxOut> vout = block.vtx[0]->vout;
        vout.insert(vout.begin() + 1, committed.begin(), committed.end());
        BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)), "bad-cb-amount");
    }

    // Advance honestly through H-1 and H (the migration block itself).
    MineHonestBlock();
    BOOST_REQUIRE_EQUAL(TipHeight(), H - 1);
    {
        CBlock block = BuildTemplateBlock();
        BOOST_CHECK_EQUAL(RejectReasonFor(block), "");
        BOOST_REQUIRE(MineBlock(block));
    }
    BOOST_REQUIRE_EQUAL(TipHeight(), H);

    // H+1: the window is one block wide. Same outputs, same reject.
    {
        CBlock block = BuildTemplateBlock();
        BOOST_CHECK_EQUAL(block.vtx[0]->vout.size(), 2U); // template appends nothing past H
        std::vector<CTxOut> vout = block.vtx[0]->vout;
        vout.insert(vout.begin() + 1, committed.begin(), committed.end());
        BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)), "bad-cb-amount");
    }
}

// Tampers 6+7: value inflation on the migration block. Inflating a COMMITTED
// output is a hash mismatch (tamper 2 already pins that), so the interesting
// case is the MINER output: the committed set stays byte-identical and only
// vout[0] exceeds subsidy + fees.
BOOST_AUTO_TEST_CASE(tamper_miner_output_inflated)
{
    const int H = TipHeight() + 1;
    MigrationArming arm(HashOutputs(committed), SumOutputs(committed), H, committed);
    CBlock block = BuildTemplateBlock();
    std::vector<CTxOut> vout = block.vtx[0]->vout;
    vout[0].nValue += 1; // one sat above subsidy + fees
    BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)), "bad-cb-migration-miner-value");
}

// Tamper 8: armed-vs-null cross-check. The SAME block bytes flip verdict with
// the constants: the honest migration block is valid armed and inflation when
// null; the plain block is valid null and missing-outputs when armed.
BOOST_AUTO_TEST_CASE(tamper_armed_vs_null_crosscheck)
{
    const int H = TipHeight() + 1;

    CBlock migrationBlock, plainBlock;
    {
        MigrationArming arm(HashOutputs(committed), SumOutputs(committed), H, committed);
        migrationBlock = BuildTemplateBlock();
        BOOST_CHECK_EQUAL(RejectReasonFor(migrationBlock), "");
    }
    plainBlock = BuildTemplateBlock();
    BOOST_CHECK_EQUAL(RejectReasonFor(plainBlock), "");

    // Null constants: the migration block is unlicensed inflation.
    BOOST_CHECK_EQUAL(RejectReasonFor(migrationBlock), "bad-cb-amount");

    {
        MigrationArming arm(HashOutputs(committed), SumOutputs(committed), H, committed);
        // Armed: the plain block (miner + trailing commitment only) has no
        // committed range at all.
        BOOST_CHECK_EQUAL(RejectReasonFor(plainBlock), "bad-cb-migration-missing");
    }
}

// Tamper 9: hash set but the coinbase carries no committed outputs — just the
// miner output and the trailing witness commitment (which stays, both because
// an honest lazy miner would produce exactly this shape and because stripping
// it would trip the witness checks before the rule is ever reached).
BOOST_AUTO_TEST_CASE(tamper_miner_output_only)
{
    const int H = TipHeight() + 1;
    MigrationArming arm(HashOutputs(committed), SumOutputs(committed), H, committed);
    CBlock block = BuildTemplateBlock();
    std::vector<CTxOut> vout;
    vout.push_back(block.vtx[0]->vout.front()); // miner
    vout.push_back(block.vtx[0]->vout.back());  // witness commitment
    BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, vout)), "bad-cb-migration-missing");
}

// Tamper 10: armed constants internally inconsistent — nMigrationTotal does
// not equal the committed sum. The hash matches, the sum check fails closed:
// no block at H can ever validate under such constants.
BOOST_AUTO_TEST_CASE(tamper_total_mismatch)
{
    const int H = TipHeight() + 1;
    // The production miner would fail its own TestBlockValidity under the
    // inconsistent constants (that is the fail-loudly property §A3 promises),
    // so take the block from a consistent arming first. Sequential scopes, not
    // nested — the guard's destructor resets the singleton unconditionally.
    CBlock block;
    {
        MigrationArming consistent(HashOutputs(committed), SumOutputs(committed), H, committed);
        block = BuildTemplateBlock();
        BOOST_CHECK_EQUAL(RejectReasonFor(block), "");
    }
    MigrationArming arm(HashOutputs(committed), SumOutputs(committed) + 1, H, committed);
    BOOST_CHECK_EQUAL(RejectReasonFor(block), "bad-cb-migration-total");
}

// The witness-commitment seam: the committed range must exclude a TRAILING
// commitment output (the miner appends it after the allocation), but an
// impostor commitment-shaped output that is NOT trailing is inside the range
// and breaks the hash like any other insertion.
BOOST_AUTO_TEST_CASE(witness_commitment_exclusion)
{
    const int H = TipHeight() + 1;
    MigrationArming arm(HashOutputs(committed), SumOutputs(committed), H, committed);
    CBlock block = BuildTemplateBlock();
    const std::vector<CTxOut>& vout = block.vtx[0]->vout;

    // Structure sanity: [miner, committed..., commitment]
    BOOST_REQUIRE_EQUAL(vout.size(), 2U + committed.size());
    const CTxOut& commitment = vout.back();
    BOOST_REQUIRE(commitment.scriptPubKey.size() >= 38 && commitment.scriptPubKey[0] == OP_RETURN);

    // A second commitment-shaped output inserted INSIDE the committed range is
    // not excluded — hash mismatch.
    {
        std::vector<CTxOut> tampered = vout;
        tampered.insert(tampered.begin() + 1, CTxOut(0, commitment.scriptPubKey));
        BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, tampered)), "bad-cb-migration-outputs");
    }

    // Moving the real commitment INSIDE the range (so nothing trails) also
    // breaks the hash — exclusion applies to the trailing position only.
    {
        std::vector<CTxOut> tampered = vout;
        std::swap(tampered[1], tampered.back());
        BOOST_CHECK_EQUAL(RejectReasonFor(WithCoinbaseVout(block, tampered)), "bad-cb-migration-outputs");
    }
}

BOOST_AUTO_TEST_SUITE_END()
