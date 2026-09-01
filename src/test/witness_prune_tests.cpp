// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// witness_prune_tests.cpp — PAT witness pruning stage 1, against
// doc/PAT_WITNESS_PRUNING.md (test plan items 1-4, including the crash-window
// simulation). Section references are to that document.
//
// The fixture mines a real regtest chain (DilithiumChainSetup), rotates the
// append file so file 0 becomes a candidate, arms a small finality horizon
// with the regtest setter, and drives the actual compaction code. Reads after
// compaction go through ReadBlockFromDisk with the real index, so what is
// asserted is what a node would actually see.

#include "chain.h"
#include "undo.h"
#include "chainparams.h"
#include "consensus/pat_attestation.h"
#include "test/dilithium_chain_setup.h"
#include "init.h"
#include "txdb.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <atomic>

// The process-wide shutdown flag AbortNode sets (init.cpp). Declared here so
// the disconnect-guard test can clear it after deliberately tripping it.
extern std::atomic<bool> fRequestShutdown;

namespace {

//! Arm the regtest finality horizon for a scope; restore disabled (0).
struct ScopedRegtestHorizon {
    explicit ScopedRegtestHorizon(int nDepth)
    {
        UpdateRegtestMaxReorgDepth(nDepth);
        SelectParams(CBaseChainParams::REGTEST);
    }
    ~ScopedRegtestHorizon()
    {
        UpdateRegtestMaxReorgDepth(0);
        SelectParams(CBaseChainParams::REGTEST);
    }
};

} // namespace

struct WitnessPruneSetup : public DilithiumChainSetup {
    //! A signed v1 spend of coinbase `k`, so mined blocks carry witness data
    //! and a PAT commitment.
    CMutableTransaction Spend(int k)
    {
        const CTransaction& cb = coinbaseTxns[k];
        CMutableTransaction tx;
        tx.nVersion = 2;
        CTxIn in;
        in.prevout = COutPoint(cb.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);
        CTxOut out;
        out.nValue = cb.vout[0].nValue - 10000;
        out.scriptPubKey = Spk(OP_1);
        tx.vout.push_back(out);
        SignInput(tx, 0, coinbaseSpk, cb.vout[0].nValue);
        return tx;
    }

    //! Every block-index entry currently stored in `nFile`.
    static std::vector<CBlockIndex*> BlocksInFile(int nFile)
    {
        LOCK(cs_main);
        std::vector<CBlockIndex*> v;
        for (const auto& item : mapBlockIndex) {
            if (item.second->nFile == nFile && (item.second->nStatus & BLOCK_HAVE_DATA)) {
                v.push_back(item.second);
            }
        }
        return v;
    }

    static int TipHeight()
    {
        LOCK(cs_main);
        return chainActive.Height();
    }
};

BOOST_FIXTURE_TEST_SUITE(witness_prune_tests, WitnessPruneSetup)

// §7.1 — the stripping serialization round-trip, in memory. Transaction ids
// and the merkle root must be unchanged (they exclude witness data by
// construction); witness stacks must come back empty; the PAT commitment
// output must survive, because it is base data. Fails if the NO_WITNESS
// stream flag stops stripping, or if stripping ever reaches base data.
BOOST_AUTO_TEST_CASE(stripped_serialization_round_trip)
{
    const CBlock block = BuildSolvedBlock({Spend(0)}, Spk(OP_1));
    BOOST_REQUIRE(block.vtx.size() == 2);
    BOOST_REQUIRE_MESSAGE(!block.vtx[1]->vin[0].scriptWitness.IsNull(),
        "the spend must carry witness data or this test strips nothing");

    // The block must carry a PAT commitment (an output, which must survive).
    uint256 patHash;
    BOOST_REQUIRE_EQUAL(patattest::FindCommitments(*block.vtx[0], patHash), 1);

    CDataStream ss(SER_DISK, CLIENT_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    ss << block;
    CBlock stripped;
    ss >> stripped;

    BOOST_CHECK(stripped.GetHash() == block.GetHash());
    BOOST_CHECK(stripped.hashMerkleRoot == block.hashMerkleRoot);
    BOOST_REQUIRE_EQUAL(stripped.vtx.size(), block.vtx.size());
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        BOOST_CHECK(stripped.vtx[i]->GetHash() == block.vtx[i]->GetHash());
        for (const CTxIn& in : stripped.vtx[i]->vin) {
            BOOST_CHECK_MESSAGE(in.scriptWitness.IsNull(),
                "witness survived the NO_WITNESS serialization");
        }
    }
    uint256 patHashAfter;
    BOOST_CHECK_EQUAL(patattest::FindCommitments(*stripped.vtx[0], patHashAfter), 1);
    BOOST_CHECK(patHashAfter == patHash);
}

// §7.2 — the eligibility boundary. Depth exactly the horizon is not eligible;
// strictly deeper is; a disabled horizon makes nothing eligible; the append
// file is never eligible. Fails if any inequality is off by one, which is the
// classic way a finality boundary goes wrong.
BOOST_AUTO_TEST_CASE(eligibility_boundary)
{
    // File 0 holds the fixture chain; make it non-append so the append-file
    // rule stops masking the height rule.
    RotateBlockFileForTests();

    // With the horizon disabled (regtest default) nothing is eligible.
    {
        LOCK(cs_main);
        BOOST_CHECK(!WitnessFileEligibleForCompaction(0));
    }

    // The deepest block in file 0 is the tip at rotation time. Make the
    // horizon exactly the current depth of that block: still not eligible
    // (strictly-deeper is required), then one more block tips it over.
    const int nTipAtRotation = TipHeight();
    ScopedRegtestHorizon horizon(5);
    // Mine 5 blocks: the file-0 tip is now at depth exactly 5.
    for (int i = 0; i < 5; ++i) CreateAndProcessBlock({}, Spk(OP_1));
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(!WitnessFileEligibleForCompaction(0),
            "depth exactly the horizon must NOT be eligible (strictly deeper required)");
    }
    CreateAndProcessBlock({}, Spk(OP_1)); // depth horizon+1
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(WitnessFileEligibleForCompaction(0),
            "depth strictly beyond the horizon must be eligible");
        // The append file is never eligible regardless of depth. Its number is
        // wherever the most recent blocks live.
        const int nAppendFile = chainActive.Tip()->nFile;
        BOOST_CHECK(!WitnessFileEligibleForCompaction(nAppendFile));
    }
    (void)nTipAtRotation;
}

// §7.3 — compaction end to end on the real index: blocks move to a fresh
// file, read back stripped with ids and undo intact, the flag is set on
// exactly the moved range, the originals are gone, and the reindex-refusal
// marker is persisted (§7.4). Fails if any step of §3's ordering is wrong in
// a way visible after a clean pass.
BOOST_AUTO_TEST_CASE(compaction_moves_strips_and_marks)
{
    // Blocks with real witness data in file 0.
    CBlock spendBlock = BuildSolvedBlock({Spend(1)}, Spk(OP_1));
    {
        std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(spendBlock);
        bool fNewBlock = false;
        BOOST_REQUIRE(ProcessNewBlock(Params(), shared, true, &fNewBlock));
    }
    RotateBlockFileForTests();

    const std::vector<CBlockIndex*> vBefore = BlocksInFile(0);
    BOOST_REQUIRE(!vBefore.empty());
    // Snapshot identities and undo positions for the post-compaction compare.
    std::map<uint256, unsigned int> mapUndoPos;
    for (const CBlockIndex* p : vBefore) mapUndoPos[p->GetBlockHash()] = p->nUndoPos;

    ScopedRegtestHorizon horizon(3);
    for (int i = 0; i < 4; ++i) CreateAndProcessBlock({}, Spk(OP_1));

    std::string strError;
    BOOST_REQUIRE_MESSAGE(CompactWitnessFiles(strError), strError);

    // Every block formerly in file 0 moved, is flagged, and reads back
    // stripped with its identity intact.
    BOOST_CHECK(BlocksInFile(0).empty());
    int nNewFile = -1;
    for (CBlockIndex* p : vBefore) {
        BOOST_CHECK(p->nStatus & BLOCK_WITNESS_PRUNED);
        BOOST_CHECK(p->nFile != 0);
        if (nNewFile == -1) nNewFile = p->nFile;
        BOOST_CHECK_EQUAL(p->nFile, nNewFile); // one target file for the pass
        BOOST_CHECK_EQUAL(p->nUndoPos, mapUndoPos[p->GetBlockHash()]); // §3: offsets unchanged

        CBlock block;
        BOOST_REQUIRE_MESSAGE(ReadBlockFromDisk(block, p, Params().GetConsensus(p->nHeight)),
            "compacted block unreadable at its new position");
        BOOST_CHECK(block.GetHash() == p->GetBlockHash());
        for (const auto& tx : block.vtx) {
            for (const CTxIn& in : tx->vin) BOOST_CHECK(in.scriptWitness.IsNull());
        }
        // Undo data still readable through the carried rev file.
        if (p->nStatus & BLOCK_HAVE_UNDO) {
            CBlockUndo undo;
            BOOST_CHECK_MESSAGE(UndoReadFromDisk(undo, p->GetUndoPos(), p->pprev->GetBlockHash()),
                "undo data unreadable after the rev-file carry");
        }
    }

    // The spend block kept its PAT commitment (base data survives).
    {
        LOCK(cs_main);
        CBlockIndex* pSpend = mapBlockIndex.at(spendBlock.GetHash());
        CBlock reread;
        BOOST_REQUIRE(ReadBlockFromDisk(reread, pSpend, Params().GetConsensus(pSpend->nHeight)));
        uint256 h;
        BOOST_CHECK_EQUAL(patattest::FindCommitments(*reread.vtx[0], h), 1);
    }

    // Originals are gone; the target exists.
    BOOST_CHECK(!fs::exists(GetBlockPosFilename(CDiskBlockPos(0, 0), "blk")));
    BOOST_CHECK(!fs::exists(GetBlockPosFilename(CDiskBlockPos(0, 0), "rev")));
    BOOST_CHECK(fs::exists(GetBlockPosFilename(CDiskBlockPos(nNewFile, 0), "blk")));

    // §7.4 — the reindex-refusal marker persisted with the compaction.
    bool fFlag = false;
    BOOST_REQUIRE(pblocktree->ReadFlag("witnessprunedblocks", fFlag));
    BOOST_CHECK_MESSAGE(fFlag,
        "the witnessprunedblocks marker must be set by a successful compaction; "
        "init's reindex refusal reads exactly this flag");
}

// §7.3b — the crash windows, simulated at the two points §3's ordering
// defines. In BOTH interrupted states every indexed block must read back
// correctly, and the following clean pass must converge. Fails if the commit
// ordering regresses to any design with a window (the rename-in-place design
// this section replaced had one on each side).
BOOST_AUTO_TEST_CASE(crash_windows_leave_readable_state_and_converge)
{
    CBlock spendBlock = BuildSolvedBlock({Spend(2)}, Spk(OP_1));
    {
        std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(spendBlock);
        bool fNewBlock = false;
        BOOST_REQUIRE(ProcessNewBlock(Params(), shared, true, &fNewBlock));
    }
    RotateBlockFileForTests();
    ScopedRegtestHorizon horizon(3);
    for (int i = 0; i < 4; ++i) CreateAndProcessBlock({}, Spk(OP_1));

    const std::vector<CBlockIndex*> vFile0 = BlocksInFile(0);
    BOOST_REQUIRE(!vFile0.empty());

    auto allReadable = [&](const char* when) {
        LOCK(cs_main);
        for (const auto& item : mapBlockIndex) {
            const CBlockIndex* p = item.second;
            if (!(p->nStatus & BLOCK_HAVE_DATA)) continue;
            CBlock block;
            BOOST_REQUIRE_MESSAGE(ReadBlockFromDisk(block, p, Params().GetConsensus(p->nHeight)),
                std::string("block unreadable ") + when + ": the index points at data "
                "that does not exist, which is the exact window the ordering forbids");
            BOOST_REQUIRE(block.GetHash() == p->GetBlockHash());
        }
    };

    // Crash point 1: stripped data written, nothing committed. The index must
    // still point wholly at file 0; the partial target is inert.
    std::string strError;
    BOOST_REQUIRE_MESSAGE(CompactWitnessFiles(strError, /*nTestCrashPoint=*/1), strError);
    for (CBlockIndex* p : vFile0) {
        BOOST_CHECK_EQUAL(p->nFile, 0);
        BOOST_CHECK(!(p->nStatus & BLOCK_WITNESS_PRUNED));
    }
    BOOST_CHECK(fs::exists(GetBlockPosFilename(CDiskBlockPos(0, 0), "blk")));
    allReadable("after crash point 1");

    // Crash point 2: index durably moved, originals not yet deleted. Blocks
    // must read from the target; the originals are orphans.
    BOOST_REQUIRE_MESSAGE(CompactWitnessFiles(strError, /*nTestCrashPoint=*/2), strError);
    int nNewFile = -1;
    for (CBlockIndex* p : vFile0) {
        BOOST_CHECK(p->nStatus & BLOCK_WITNESS_PRUNED);
        BOOST_CHECK(p->nFile != 0);
        nNewFile = p->nFile;
    }
    BOOST_CHECK_MESSAGE(fs::exists(GetBlockPosFilename(CDiskBlockPos(0, 0), "blk")),
        "crash point 2 deletes nothing; the original must still be present as an orphan");
    allReadable("after crash point 2");

    // Convergence: the next clean pass sweeps the orphans and changes nothing
    // else. All blocks still readable, originals gone.
    BOOST_REQUIRE_MESSAGE(CompactWitnessFiles(strError), strError);
    BOOST_CHECK(!fs::exists(GetBlockPosFilename(CDiskBlockPos(0, 0), "blk")));
    BOOST_CHECK(!fs::exists(GetBlockPosFilename(CDiskBlockPos(0, 0), "rev")));
    for (CBlockIndex* p : vFile0) BOOST_CHECK_EQUAL(p->nFile, nNewFile);
    allReadable("after the converging pass");
}

// §6 — the finality assertion. A disconnect request for a witness-pruned
// block means the finality rule itself failed; DisconnectBlock must refuse via
// AbortNode rather than improvise. The guard fires before the view is touched,
// so driving it with the live view is safe. Fails if the guard is removed or
// reordered after the undo machinery.
BOOST_AUTO_TEST_CASE(disconnect_of_pruned_block_aborts)
{
    RotateBlockFileForTests();
    ScopedRegtestHorizon horizon(3);
    for (int i = 0; i < 4; ++i) CreateAndProcessBlock({}, Spk(OP_1));
    std::string strError;
    BOOST_REQUIRE_MESSAGE(CompactWitnessFiles(strError), strError);

    LOCK(cs_main);
    CBlockIndex* pPruned = nullptr;
    for (const auto& item : mapBlockIndex) {
        if ((item.second->nStatus & BLOCK_WITNESS_PRUNED) && item.second->nHeight > 0) {
            pPruned = item.second;
            break;
        }
    }
    BOOST_REQUIRE(pPruned != nullptr);

    CBlock block;
    BOOST_REQUIRE(ReadBlockFromDisk(block, pPruned, Params().GetConsensus(pPruned->nHeight)));

    BOOST_REQUIRE(!ShutdownRequested());
    CValidationState state;
    CCoinsViewCache view(pcoinsTip);
    BOOST_CHECK_MESSAGE(!DisconnectBlock(block, state, pPruned, view, nullptr),
        "DisconnectBlock accepted a witness-pruned block; the finality assertion "
        "of doc/PAT_WITNESS_PRUNING.md section 6 is gone");
    BOOST_CHECK_MESSAGE(ShutdownRequested(),
        "the refusal must go through AbortNode: a quiet error return leaves the "
        "node running on a chain state the pruning safety argument does not cover");

    // AbortNode sets the process-wide shutdown flag; clear it so later suites
    // in this binary are unaffected.
    fRequestShutdown = false;
}

BOOST_AUTO_TEST_SUITE_END()
