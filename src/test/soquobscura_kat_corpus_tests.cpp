// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// SoquObscura — the pinned KAT corpus, and what it proves about the shipped verifier.
//
// =============================================================================
// WHAT THIS CORPUS IS
//
// 64 known-answer vectors (range 23, balance 19, VE 22) generated and
// independently re-verified with LaZer at commit 2fa3dfb1de7c. Every proof, its
// statement, and its expected verdict are pinned, and the manifest carries a
// sha256 per file plus the parameter hashes and the public seed.
//
// It is the ACCEPTANCE GATE for the replacement verifier. When the native
// (portable, fleet-buildable) verifier lands, it must reproduce all 64 verdicts
// -- 15 accept / 8 reject on range, and so on -- or the build is red.
//
// ⚠️ ATTRIBUTION. The corpus was produced with LaZer (MIT, (c) IBM) and its
// LaBRADOR tree (Apache-2.0, (c) IBM Corp). See ATTRIBUTION.md. Those upstreams
// are OFFLINE ORACLES ONLY: LaZer hard-wires AVX-512 across 15 unguarded source
// files, and most of the fleet has no AVX-512, so it cannot be a consensus
// dependency even in principle.
//
// =============================================================================
// WHAT IT PROVES TODAY, AND WHY THAT MATTERS
//
// The verifier currently in this tree (latticebp::RangeProofParams /
// LatticeRangeProofV2) cannot consume ANY of these vectors. That has been stated
// in design documents as "0/23 corpus vectors deserialize", which reads like an
// encoding bug that someone could go and fix. It is not. The reason is
// structural and this file makes it executable:
//
//     corpus range proofs are ~21.7 kB
//     RangeProofParams::MAX_PROOF_SIZE is 16 kB
//
// A corpus proof exceeds the in-tree verifier's hard maximum, so it is refused on
// size before any cryptography runs. The two are UNRELATED PROOF SYSTEMS, not two
// implementations of one. That is why the in-tree verifier must be REPLACED rather
// than repaired, and it is independent evidence for the same conclusion the
// zero-witness forgery reached from the other direction.
//
// ⚠️ Stated precisely, because the loose version was wrong: 22 of the 23 vectors
// exceed the maximum, not all 23. The exception is `rng-adv-trunc` (10,876 bytes),
// an honest proof deliberately truncated to half length, expected verdict `reject`.
// So the defensible claim — and the one asserted below — is that NO vector the
// corpus expects to ACCEPT can be presented to the in-tree verifier at all. The
// first revision of this test asserted "all 23" and failed, which is the only
// reason the distinction is recorded here rather than repeated as folklore.
// =============================================================================

#include "crypto/latticebp/range_proof.h"
#include "hash.h"
#include "utilstrencodings.h"

#include "test/test_bitcoin.h"

#include <set>
#include <fstream>
#include <map>
#include <string>
#include <univalue.h>
#include <vector>

#include <boost/test/unit_test.hpp>

#ifndef SOQUOBSCURA_KAT_DIR
#error "SOQUOBSCURA_KAT_DIR must be defined (see Makefile.test.include)"
#endif

BOOST_FIXTURE_TEST_SUITE(soquobscura_kat_corpus_tests, BasicTestingSetup)

namespace {

std::string KatPath(const std::string& name)
{
    return std::string(SOQUOBSCURA_KAT_DIR) + "/" + name;
}

std::string ReadFileOrEmpty(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::string((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
}

//! Parse a .jsonl file into one UniValue per line.
std::vector<UniValue> ReadJsonl(const std::string& name)
{
    std::vector<UniValue> out;
    std::ifstream f(KatPath(name));
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        UniValue v;
        if (!v.read(line)) continue;
        out.push_back(v);
    }
    return out;
}

} // namespace

// -----------------------------------------------------------------------------
// The corpus must be intact. A tampered or truncated corpus that still "passed"
// would let the acceptance gate below certify a verifier against the wrong data.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(kat_corpus_manifest_integrity)
{
    const std::string manifest_raw = ReadFileOrEmpty(KatPath("manifest.json"));
    BOOST_REQUIRE_MESSAGE(!manifest_raw.empty(),
        "KAT manifest not found at " << KatPath("manifest.json")
        << " — the corpus is missing, so every check below would pass vacuously.");

    UniValue manifest;
    BOOST_REQUIRE_MESSAGE(manifest.read(manifest_raw), "KAT manifest is not valid JSON");

    // Pin the oracle identity. If the corpus is ever regenerated with a different
    // LaZer build, that is a deliberate act and this constant must change with it.
    BOOST_CHECK_EQUAL(manifest["lazer_commit"].get_str(), "2fa3dfb1de7c");

    const UniValue& files = manifest["files"];
    BOOST_REQUIRE_MESSAGE(files.isObject() && !files.getKeys().empty(),
        "manifest lists no files — an empty manifest must not be treated as valid.");

    size_t total_vectors = 0;
    for (const std::string& fname : files.getKeys()) {
        const std::string blob = ReadFileOrEmpty(KatPath(fname));
        BOOST_REQUIRE_MESSAGE(!blob.empty(), "corpus file missing or empty: " << fname);

        // sha256 must match the manifest, byte for byte.
        uint256 digest;
        CSHA256().Write((const unsigned char*)blob.data(), blob.size()).Finalize(digest.begin());
        BOOST_CHECK_MESSAGE(HexStr(digest) == files[fname]["sha256"].get_str(),
            fname << ": sha256 mismatch — corpus does not match its manifest. Expected "
                  << files[fname]["sha256"].get_str() << " got " << HexStr(digest));

        // Record count must match too: a truncated file can still hash-mismatch
        // loudly, but a count check localises the problem.
        const size_t lines = ReadJsonl(fname).size();
        BOOST_CHECK_MESSAGE(lines == (size_t)files[fname]["count"].get_int(),
            fname << ": expected " << files[fname]["count"].get_int()
                  << " vectors, parsed " << lines);
        total_vectors += lines;
    }

    // The whole corpus, as generated: range 23 + balance 19 + VE 22.
    BOOST_CHECK_MESSAGE(total_vectors == 64,
        "expected 64 pinned vectors across the corpus, found " << total_vectors);

    // ⛔ PIN THE ACCEPT/REJECT SPLIT. This exists because the figure "25 reject vectors" was
    // asserted in six committed places - including ORACLE.md, which predates this test - and
    // was WRONG. Counting the files gives 40 accept / 24 reject. An uncounted claim about the
    // corpus is exactly the kind of thing that gets quoted into an audit scope, so the split
    // is now derived from the data on every run rather than written down once.
    size_t core_accept = 0, core_reject = 0;
    for (const char* fname : {"range.jsonl", "balance.jsonl", "ve.jsonl"}) {
        for (const UniValue& v : ReadJsonl(fname)) {
            const std::string e = v["expect"].get_str();
            if (e == "accept") core_accept++;
            else if (e == "reject") core_reject++;
            else BOOST_ERROR(fname << " " << v["id"].get_str() << ": expect is neither "
                                      "accept nor reject but '" << e << "'");
        }
    }
    BOOST_CHECK_MESSAGE(core_accept == 40,
        "expected 40 accept vectors in the frozen core, found " << core_accept);
    BOOST_CHECK_MESSAGE(core_reject == 24,
        "expected 24 reject vectors in the frozen core, found " << core_reject
        << " (the long-standing '25 reject' figure was wrong)");
    BOOST_CHECK_MESSAGE(core_accept + core_reject == total_vectors,
        "accept+reject does not account for every vector");
}

// -----------------------------------------------------------------------------
// The DEGENERATE-WITNESS REJECT CLASS (extension_files in the manifest).
//
// Why this exists: the frozen 64 above contain 24 reject vectors and NOT ONE of
// them is a degenerate witness. The *-ok-zero vectors are zero-VALUE accepts,
// which is a legitimate thing to prove. So the core corpus is structurally blind
// to the one bug class this repository has shipped TWICE:
//
//   * LatticeFold+ EvalCheckFoldProof - Halborn 7.3, CRITICAL 10.0, six
//     remediations, signed off SOLVED, still exploitable
//   * LatticeRangeProofV2 - wire-reachable from public data
//
// In both, every accept-path check is homogeneous in the witness, so a zero
// witness satisfies all of them and the only non-homogeneous check is a
// Fiat-Shamir seed the attacker reads off public data and plants.
//
// Worse, the core corpus could never have revealed it: manifest.lazer_commit
// shows its expected verdicts were generated BY LaZer, so a defect LaZer shares
// would have been recorded as ground truth.
//
// Provenance of these vectors: generated by contrib/degen-corpus-gen.c THROUGH
// LaZer's own encoder, so each one decodes cleanly and therefore reaches the
// soundness path instead of dying in the decoder. That distinction is not
// theoretical - an earlier byte-level probe rejected 90/90 mutants and was
// entirely vacuous, because instrumenting the reject sites showed every single
// one died at DECPROOF and none ever reached poly_eq(c, c2).
//
// ⚠️ This test does NOT verify any proof today, for the same reason the core
// gate does not: there is deliberately no consensus verifier in-tree yet. It
// pins the class, its integrity and its shape so that the moment a verifier
// lands, the class is already frozen and cannot be quietly regenerated to make
// that verifier pass. See bead corpus-no-degenerate-witness-class-piz6.
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// PINNED -> EXECUTED.
//
// The tests above check integrity and shape but deliberately verify no proof,
// because there is no consensus verifier in-tree yet. That left a real gap: the
// vectors could be perfectly well-formed and pinned, and still never have been
// run against anything.
//
// EXECUTED-EVIDENCE.json closes it. It records the sha256 of every corpus file
// that was executed, the identity of the verifier that executed them, and the
// per-vector verdict observed. This test binds the record to the data:
//
//   * if a corpus file is regenerated, its hash changes and this goes RED until
//     the vectors are re-executed and the record refreshed;
//   * if a vector is added without being executed, it is missing from the record
//     and this goes RED;
//   * if any vector's observed verdict disagrees with its pinned expectation,
//     this goes RED.
//
// So the repo knows whether the CURRENT bytes have been run, rather than
// trusting that someone once ran something. It is not a substitute for
// verifying in-process, which arrives when a verifier lands in-tree.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(corpus_and_degenerate_class_have_been_executed)
{
    const std::string raw = ReadFileOrEmpty(KatPath("EXECUTED-EVIDENCE.json"));
    BOOST_REQUIRE_MESSAGE(!raw.empty(),
        "EXECUTED-EVIDENCE.json is missing — the corpus has no record of ever having been "
        "run against a verifier, so every check above passes on data nobody has executed.");
    UniValue ev;
    BOOST_REQUIRE_MESSAGE(ev.read(raw), "EXECUTED-EVIDENCE.json is not valid JSON");

    // 1. the record must describe the bytes that are here NOW
    const UniValue& hashes = ev["corpus_sha256"];
    BOOST_REQUIRE_MESSAGE(hashes.isObject() && !hashes.getKeys().empty(),
        "evidence lists no corpus hashes");
    for (const std::string& fname : hashes.getKeys()) {
        const std::string blob = ReadFileOrEmpty(KatPath(fname));
        BOOST_REQUIRE_MESSAGE(!blob.empty(), "evidence references a missing file: " << fname);
        uint256 digest;
        CSHA256().Write((const unsigned char*)blob.data(), blob.size()).Finalize(digest.begin());
        BOOST_CHECK_MESSAGE(HexStr(digest) == hashes[fname].get_str(),
            fname << ": EXECUTED-EVIDENCE.json records sha256 "
                  << hashes[fname].get_str() << " but the file on disk is " << HexStr(digest)
                  << " — the corpus changed since it was last executed. Re-run the vectors and "
                     "refresh the record; do NOT just edit the hash.");
    }

    // 2. the verifier must be identified, or the record proves nothing
    const UniValue& vf = ev["verifier"];
    BOOST_REQUIRE_MESSAGE(vf.isObject(), "evidence does not identify a verifier");
    for (const char* k : {"identity", "liblazer_a_sha256", "harness_binary_sha256",
                          "build_flags", "toolchain"}) {
        BOOST_CHECK_MESSAGE(vf.exists(k) && !vf[k].get_str().empty(),
            "evidence verifier block is missing '" << k << "' — an unidentified verifier makes "
            "the execution unreproducible");
    }

    // 3. every vector present on disk must appear in the record, with the right verdict
    std::map<std::string, std::pair<std::string, bool>> got;  // id -> (verdict, ok)
    for (const UniValue& v : ev["verdicts"].getValues()) {
        got[v["id"].get_str()] = {v["got"].get_str(), v["ok"].get_bool()};
    }
    size_t checked = 0, degen_rejects = 0;
    for (const char* fname : {"range.jsonl", "balance.jsonl", "ve.jsonl", "degenerate.jsonl"}) {
        for (const UniValue& v : ReadJsonl(fname)) {
            const std::string id = v["id"].get_str();
            const std::string expect = v["expect"].get_str();
            auto it = got.find(id);
            BOOST_REQUIRE_MESSAGE(it != got.end(),
                fname << " " << id << ": present on disk but ABSENT from "
                "EXECUTED-EVIDENCE.json — it has never been executed.");
            BOOST_CHECK_MESSAGE(it->second.first == expect,
                id << ": pinned expectation is " << expect << " but the verifier returned "
                   << it->second.first);
            BOOST_CHECK_MESSAGE(it->second.second,
                id << ": recorded as NOT ok — the verifier disagreed with the pinned verdict");
            checked++;
            if (std::string(fname) == "degenerate.jsonl" && it->second.first == "reject")
                degen_rejects++;
        }
    }
    BOOST_CHECK_MESSAGE(checked == 82,
        "expected 82 vectors (64 frozen core + 18 degenerate), executed-checked " << checked);

    // 4. ⭐ the load-bearing one: every degenerate vector was actually REJECTED by a real
    //    verifier. This is what "pinned -> executed" means for the soundness class.
    BOOST_CHECK_MESSAGE(degen_rejects == 18,
        "only " << degen_rejects << " of 18 degenerate-witness vectors are recorded as "
        "rejected by an executed verifier");

    const UniValue& sum = ev["summary"];
    BOOST_CHECK_MESSAGE(sum["wrong"].get_int() == 0,
        "evidence records " << sum["wrong"].get_int() << " wrong verdicts");
}

BOOST_AUTO_TEST_CASE(degenerate_witness_class_is_pinned_and_shaped)
{
    const std::string manifest_raw = ReadFileOrEmpty(KatPath("manifest.json"));
    BOOST_REQUIRE_MESSAGE(!manifest_raw.empty(), "KAT manifest missing");
    UniValue manifest;
    BOOST_REQUIRE_MESSAGE(manifest.read(manifest_raw), "KAT manifest is not valid JSON");

    const UniValue& ext = manifest["extension_files"];
    BOOST_REQUIRE_MESSAGE(ext.isObject() && !ext.getKeys().empty(),
        "manifest has no extension_files - the degenerate-witness class is missing, so "
        "this test would pass vacuously and the corpus would again be blind to the "
        "one bug class this repo has shipped twice.");

    for (const std::string& fname : ext.getKeys()) {
        const std::string blob = ReadFileOrEmpty(KatPath(fname));
        BOOST_REQUIRE_MESSAGE(!blob.empty(), "extension file missing or empty: " << fname);

        uint256 digest;
        CSHA256().Write((const unsigned char*)blob.data(), blob.size()).Finalize(digest.begin());
        BOOST_CHECK_MESSAGE(HexStr(digest) == ext[fname]["sha256"].get_str(),
            fname << ": sha256 mismatch. Expected " << ext[fname]["sha256"].get_str()
                  << " got " << HexStr(digest));

        const std::vector<UniValue> vectors = ReadJsonl(fname);
        BOOST_CHECK_MESSAGE(vectors.size() == (size_t)ext[fname]["count"].get_int(),
            fname << ": expected " << ext[fname]["count"].get_int()
                  << " vectors, parsed " << vectors.size());

        // Every vector in this class must be a REJECT. An accept here is not a test
        // case, it is a forgery.
        size_t rejects = 0, minnonzero = 0, wire_reachable = 0;
        std::set<std::string> relations;
        for (const UniValue& v : vectors) {
            const std::string id = v["id"].get_str();
            BOOST_CHECK_MESSAGE(v.exists("proof"), fname << " " << id << ": no proof");
            BOOST_CHECK_MESSAGE(v.exists("relation"), fname << " " << id << ": no relation");
            BOOST_CHECK_MESSAGE(v["expect"].get_str() == "reject",
                fname << " " << id << ": every vector in the degenerate class must be a "
                      "reject; an accept is a forgery, not a test case");
            if (v["expect"].get_str() == "reject") rejects++;
            relations.insert(v["relation"].get_str());

            // Per-relation wire caps from soq_lbpp_wire.h. A vector larger than its cap is
            // killed by soq_lbpp_unwrap_proof with ERR_OVERSIZE before the verifier runs,
            // so it tests the verifier but NOT the wire path.
            const size_t proof_bytes = v["proof"].get_str().size() / 2;
            const std::string rel = v["relation"].get_str();
            const size_t cap = rel == "range" ? 22496 : rel == "balance" ? 25140
                             : rel == "ve" ? 30930 : 0;
            BOOST_REQUIRE_MESSAGE(cap != 0, id << ": unknown relation " << rel);
            if (proof_bytes <= cap) wire_reachable++;
            if (id.find("-degen-minnonzero") != std::string::npos) {
                minnonzero++;
                // The grading contract's requirement: the non-zero member must be
                // reachable through the wire layer, or a size check fakes the gate.
                BOOST_CHECK_MESSAGE(proof_bytes <= cap,
                    id << ": the NON-ZERO degenerate member is " << proof_bytes
                       << " bytes, over the " << rel << " cap of " << cap
                       << ", so ERR_OVERSIZE would reject it before the verifier ran and "
                          "the class would not actually test soundness on the wire path");
            }
        }

        BOOST_CHECK_MESSAGE(rejects == vectors.size(),
            fname << ": " << (vectors.size() - rejects) << " vector(s) are not rejects");

        // The class is reject-only by construction: 18 vectors, 0 accepts.
        BOOST_CHECK_MESSAGE(rejects == 18,
            fname << ": expected 18 reject vectors in the degenerate class, found " << rejects);

        // All three relations must be covered; a class that only covers range would leave
        // balance and VE untested even though they share lnp_quad_verify.
        BOOST_CHECK_MESSAGE(relations.size() == 3,
            fname << ": expected all 3 relations (range, balance, ve), found "
                  << relations.size());

        // ⭐ The load-bearing assertion. Without a NON-ZERO member, a verifier that
        // simply rejects an all-zero witness would pass this whole class while still
        // being broken - which is exactly the shortcut that would have hidden both of
        // our real forgeries.
        BOOST_CHECK_MESSAGE(minnonzero >= 3,
            fname << ": found only " << minnonzero << " non-zero degenerate members; the "
                  "grading contract requires one per relation so that a "
                  "reject-if-all-zeros patch cannot fake this gate");

        BOOST_CHECK_MESSAGE(wire_reachable >= 3,
            fname << ": only " << wire_reachable << " vectors are under their relation's "
                  "wire cap; a class made entirely of oversize blobs tests ERR_OVERSIZE, "
                  "not soundness");
    }
}

// -----------------------------------------------------------------------------
// ⛔ The structural reason the in-tree verifier can never consume this corpus.
// This is the executable form of "0/23 vectors deserialize".
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(intree_verifier_cannot_accept_any_corpus_range_proof)
{
    const std::vector<UniValue> vectors = ReadJsonl("range.jsonl");
    BOOST_REQUIRE_MESSAGE(vectors.size() == 23,
        "expected 23 range vectors, got " << vectors.size()
        << " — a short read would make this test vacuous.");

    // ⚠️ The first version of this test asserted that ALL 23 exceed the in-tree
    // maximum. That was an overclaim and this assertion caught it: 22 do. The one
    // exception is `rng-adv-trunc` at 10,876 bytes — an honest proof deliberately
    // truncated to half length, whose expected verdict is `reject`. So the precise,
    // defensible statement is the one asserted below, and it is stronger than the
    // one I started with: NO VECTOR THE CORPUS EXPECTS TO ACCEPT can even be
    // presented to the in-tree verifier. Every well-formed proof is too large.
    size_t oversize = 0, accepts = 0, accepts_oversize = 0;
    size_t smallest = SIZE_MAX;
    std::string smallest_id;
    for (const UniValue& v : vectors) {
        // `proof` is hex, so bytes = chars / 2.
        const size_t proof_bytes = v["proof"].get_str().size() / 2;
        BOOST_REQUIRE_MESSAGE(proof_bytes > 0, "vector " << v["id"].get_str() << " has an empty proof");
        const bool is_accept = v["expect"].get_str() == "accept";
        const bool too_big = proof_bytes > latticebp::RangeProofParams::MAX_PROOF_SIZE;
        if (proof_bytes < smallest) { smallest = proof_bytes; smallest_id = v["id"].get_str(); }
        if (too_big) ++oversize;
        if (is_accept) { ++accepts; if (too_big) ++accepts_oversize; }
    }

    // THE LOAD-BEARING ASSERTION. If any accept-vector ever fits under the in-tree
    // maximum, the two formats overlap and the "unrelated proof systems" conclusion
    // must be re-examined.
    BOOST_CHECK_MESSAGE(accepts_oversize == accepts,
        "every ACCEPT vector must exceed the in-tree MAX_PROOF_SIZE ("
        << latticebp::RangeProofParams::MAX_PROOF_SIZE << " bytes); "
        << accepts_oversize << " of " << accepts << " did. If an accept-vector fits, the "
        << "in-tree verifier and the corpus may share a format after all — re-examine "
        << "the claim that the in-tree verifier must be replaced rather than repaired.");

    // And the only sub-maximum vector is the deliberately truncated one.
    BOOST_CHECK_MESSAGE(oversize == vectors.size() - 1,
        "expected exactly one sub-maximum vector, found " << (vectors.size() - oversize));
    BOOST_CHECK_MESSAGE(smallest_id == "rng-adv-trunc",
        "the smallest vector should be the truncated adversarial one, got '" << smallest_id
        << "' at " << smallest << " bytes. A new small vector needs its own analysis: it "
        << "would reach the in-tree deserializer rather than being refused on size.");
}

// -----------------------------------------------------------------------------
// The acceptance gate, in skeleton form. It asserts the corpus is shaped the way
// the future verifier will be graded against, so that when the native verifier
// lands, wiring it in is a one-line change rather than a redesign.
//
// ⚠️ This does NOT verify any proof today. There is deliberately no consensus
// verifier that can. Do not read a green run here as "the corpus passes".
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(kat_corpus_is_shaped_for_the_acceptance_gate)
{
    struct Family { const char* file; size_t count; };
    const Family families[] = {{"range.jsonl", 23}, {"balance.jsonl", 19}, {"ve.jsonl", 22}};

    for (const Family& fam : families) {
        const std::vector<UniValue> vectors = ReadJsonl(fam.file);
        BOOST_REQUIRE_MESSAGE(vectors.size() == fam.count,
            fam.file << ": expected " << fam.count << " vectors, got " << vectors.size());

        size_t accepts = 0, rejects = 0;
        for (const UniValue& v : vectors) {
            // Every vector must carry the fields the gate will need.
            BOOST_REQUIRE_MESSAGE(v.exists("id"), fam.file << ": a vector has no id");
            const std::string id = v["id"].get_str();
            BOOST_CHECK_MESSAGE(v.exists("proof"), fam.file << " " << id << ": no proof");
            BOOST_CHECK_MESSAGE(v.exists("statement"), fam.file << " " << id << ": no statement");
            BOOST_CHECK_MESSAGE(v.exists("params_sha256"), fam.file << " " << id << ": no params hash");

            const std::string expect = v["expect"].get_str();
            BOOST_CHECK_MESSAGE(expect == "accept" || expect == "reject",
                fam.file << " " << id << ": expect is '" << expect
                         << "', must be accept or reject — an unrecognised verdict would be "
                            "silently skipped by the gate.");
            if (expect == "accept") ++accepts; else ++rejects;
        }

        // ⛔ Both classes must be present. A corpus of only accept-vectors cannot
        // detect an always-accept verifier — which is exactly the bug that shipped.
        BOOST_CHECK_MESSAGE(accepts > 0, fam.file << ": no accept vectors");
        BOOST_CHECK_MESSAGE(rejects > 0,
            fam.file << ": NO REJECT VECTORS. A corpus without them cannot distinguish a "
                        "correct verifier from one that returns true unconditionally.");
    }

    // The range family's split is pinned, because it is the one the first native
    // verifier will be graded on.
    const std::vector<UniValue> range = ReadJsonl("range.jsonl");
    size_t range_accepts = 0;
    for (const UniValue& v : range) if (v["expect"].get_str() == "accept") ++range_accepts;
    BOOST_CHECK_EQUAL(range_accepts, 15u);
    BOOST_CHECK_EQUAL(range.size() - range_accepts, 8u);
}

// ---------------------------------------------------------------------------
// ⛔ THE GRADING CONTRACT FOR THE REPLACEMENT VERIFIER.
//
// The corpus is not 64 undifferentiated vectors; it is a set of named adversarial
// CLASSES. This test asserts each class is still present, so the ported verifier
// cannot be graded on a quietly-reduced corpus — which is the cheapest way for a
// hard case to disappear: not by deleting a test, but by deleting the input that
// makes the test hard.
//
// Rationale for each class is in ORACLE.md. The three starred ones are the
// soundness-critical ones:
//   - L2 norm-bound boundary: accept AT the bound, reject just past it. An
//     off-by-one here is a soundness hole, and bound-gate discipline is exactly
//     what the survey work found missing across other lattice codebases.
//   - wraparound: the wrap-boundary pitfall in ring-linear encodings. This is the
//     real result of the paper work and the case a naive implementation fails.
//   - dual-target VE: every honest value proved to BOTH the issuer and the
//     recipient key. Tier A's mandatory-issuer rule depends on it.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(kat_corpus_adversarial_classes_are_all_present)
{
    struct Required { const char* file; const char* id; const char* expect; const char* why; };
    const Required required[] = {
        // ⭐ L2 norm-bound boundary — accept exactly at the bound, reject past it.
        {"range.jsonl",   "rng-l2-atbound",      "accept", "accepts at l2^2(r) == 1536, the exact bound"},
        {"range.jsonl",   "rng-l2-1539",         "reject", "rejects just past the bound"},
        {"range.jsonl",   "rng-l2-2049",         "reject", "rejects well past the bound"},
        // bit-gadget soundness: the decomposition must be binary.
        {"range.jsonl",   "rng-adv-nonbin2",     "reject", "b[0] = 2 is not a bit"},
        {"range.jsonl",   "rng-adv-nonbin-neg1", "reject", "b[0] = -1 is not a bit"},
        // statement binding: an honest proof must not verify against another commitment.
        {"range.jsonl",   "rng-adv-tamper",      "reject", "honest proof pinned to the wrong commitment"},
        {"range.jsonl",   "rng-adv-bitflip",     "reject", "single flipped bit"},
        {"range.jsonl",   "rng-adv-trunc",       "reject", "truncated proof"},
        // ⭐ wraparound — the wrap-boundary pitfall in ring-linear encodings.
        {"balance.jsonl", "bal-adv-wrap-plus",   "reject", "wraparound, positive direction"},
        {"balance.jsonl", "bal-adv-wrap-minus",  "reject", "wraparound, negative direction"},
        // conservation must be exact, in both directions, including the fee.
        {"balance.jsonl", "bal-adv-plus1",       "reject", "outputs exceed inputs by 1"},
        {"balance.jsonl", "bal-adv-minus1",      "reject", "outputs below inputs by 1"},
        {"balance.jsonl", "bal-adv-fee-plus",    "reject", "fee inflated by 1"},
        {"balance.jsonl", "bal-adv-swapio",      "reject", "inputs and outputs swapped"},
        {"balance.jsonl", "bal-adv-foreignC",    "reject", "foreign commitment"},
        // ⭐ dual-target VE — the same value proved to issuer AND recipient.
        {"ve.jsonl",      "ve-ok-typical-iss",   "accept", "VE to the ISSUER key (Tier A)"},
        {"ve.jsonl",      "ve-ok-typical-rcp",   "accept", "VE to the RECIPIENT key (Tier B)"},
        // VE soundness: these are two of the WI-5 adversarial classes.
        {"ve.jsonl",      "ve-adv-wrongval",     "reject", "ciphertext decrypts to != the committed value"},
        {"ve.jsonl",      "ve-adv-crosskey",     "reject", "ciphertext verified against the wrong key"},
        {"ve.jsonl",      "ve-adv-c1tamper",     "reject", "tampered ciphertext component"},
    };

    // Index the corpus once per family.
    std::map<std::string, std::map<std::string, std::string>> byFile;  // file -> id -> expect
    for (const char* f : {"range.jsonl", "balance.jsonl", "ve.jsonl"}) {
        for (const UniValue& v : ReadJsonl(f)) {
            byFile[f][v["id"].get_str()] = v["expect"].get_str();
        }
        BOOST_REQUIRE_MESSAGE(!byFile[f].empty(),
            std::string(f) + " parsed to nothing — every assertion below would pass vacuously");
    }

    for (const Required& r : required) {
        auto& fam = byFile[r.file];
        auto it = fam.find(r.id);
        BOOST_CHECK_MESSAGE(it != fam.end(),
            std::string("MISSING ADVERSARIAL VECTOR '") + r.id + "' from " + r.file
            + " — it covers: " + r.why
            + ". Removing an input is how a hard case disappears without deleting a test. "
              "If this vector was retired deliberately, retire this assertion in the same "
              "commit and say why.");
        if (it == fam.end()) continue;
        BOOST_CHECK_MESSAGE(it->second == r.expect,
            std::string("vector '") + r.id + "' expects '" + it->second + "' but this gate "
            "requires '" + r.expect + "' (" + r.why + "). A flipped expectation silently "
            "changes what the verifier is being graded against.");
    }

    // ⛔ The reject vectors are the load-bearing ones: a verifier that returns
    // true unconditionally passes every accept vector. Assert there are enough of
    // them that such a stub cannot score well — this codebase has already shipped
    // one always-true verifier (crypto/sangria/fold.cpp).
    size_t total = 0, rejects = 0;
    for (const char* f : {"range.jsonl", "balance.jsonl", "ve.jsonl"}) {
        for (const auto& kv : byFile[f]) { ++total; if (kv.second == "reject") ++rejects; }
    }
    BOOST_CHECK_MESSAGE(total == 64, "expected 64 vectors across the corpus, found " << total);
    BOOST_CHECK_MESSAGE(rejects >= 20,
        "only " << rejects << " reject vectors of " << total << ". An always-accept stub would "
        "score " << (total - rejects) << "/" << total << "; the reject vectors are the only "
        "thing that distinguishes a verifier from a stub.");
}

BOOST_AUTO_TEST_SUITE_END()
