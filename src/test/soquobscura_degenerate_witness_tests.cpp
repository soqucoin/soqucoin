// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// SoquObscura — degenerate-witness battery for the consensus range verifier.
//
// =============================================================================
// WHY THIS FILE EXISTS
//
// This project has already shipped one lattice verifier that was fully audited,
// carried a test battery, had six findings remediated — and still accepted an
// all-zero proof whose only nonzero field was a public, recomputable
// Fiat-Shamir seed, authorising a spend with no valid signature. It was
// withdrawn from mainnet launch consensus.
//
// Two lessons drive every test below:
//
//   L1  An audit validates code against the properties someone thought to
//       check. Every check on that accept path was HOMOGENEOUS in the
//       prover-supplied values, so the zero witness satisfied all of them.
//
//   L2  The fix's own all-zeros test ZEROED THE SEED TOO, so the one field an
//       attacker must set was never set. The test was blind by construction.
//
// ⛔ THEREFORE: the load-bearing test here is not "all zeros is rejected". It is
// "all zeros WITH A CORRECT SEED is rejected". We obtain a correct seed without
// reimplementing the transcript by generating an HONEST proof and then zeroing
// only the witness fields, leaving version and challenge_seed untouched. The
// seed is then correct by construction for this exact
// (commitment, sighash, pubkey_hash) — which is precisely the attacker's
// position, since every input to that hash is public.
//
// If a test here fails, do not "fix the test".
// =============================================================================

#include "crypto/latticebp/commitment.h"
#include "crypto/latticebp/range_proof.h"
#include "test/test_bitcoin.h"

#include <array>
#include <cstring>
#include <vector>
#include <boost/test/unit_test.hpp>

using namespace latticebp;

BOOST_FIXTURE_TEST_SUITE(soquobscura_degenerate_witness_tests, BasicTestingSetup)

namespace {

struct Fixture {
    LatticeCommitment::PublicParams pub;
    RangeProofParams params;
    LatticeCommitment commitment;
    RingElement randomness;
    std::array<uint8_t, 32> sighash;
    std::array<uint8_t, 32> pubkey_hash;
    uint64_t value{123456789};

    Fixture()
    {
        std::array<uint8_t, 32> seed;
        seed.fill(0x42);
        pub = LatticeCommitment::PublicParams::generate(seed);
        params.commit_params = pub;

        // A non-degenerate blinding factor, so nothing is accidentally zero.
        for (size_t j = 0; j < LatticeParams::N; j++) {
            randomness.coeffs[j] = static_cast<int64_t>((j * 7919) % 5) - 2;
        }
        commitment = LatticeCommitment::commit(value, randomness, pub);

        sighash.fill(0xA5);
        pubkey_hash.fill(0x5A);
    }

    bool Prove(LatticeRangeProofV2& out) const
    {
        return LatticeRangeProofV2::prove(value, randomness, commitment, params,
                                          sighash, pubkey_hash, out);
    }

    bool Verify(const LatticeRangeProofV2& p) const
    {
        return p.verify(commitment, params, sighash, pubkey_hash);
    }
};

void ZeroRing(RingElement& r)
{
    for (size_t j = 0; j < LatticeParams::N; j++) r.coeffs[j] = 0;
}

} // namespace

// ---------------------------------------------------------------------------
// Baseline: an honest proof verifies. If this fails, every result below is
// meaningless, so it is asserted first and separately.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(honest_proof_verifies)
{
    Fixture f;
    LatticeRangeProofV2 p;
    BOOST_REQUIRE(f.Prove(p));
    BOOST_CHECK(f.Verify(p));
}

// ---------------------------------------------------------------------------
// ★★★ THE BREAK CLASS. Zero every prover-supplied witness value, keep the
// honest version and the honest (therefore CORRECT) Fiat-Shamir seed.
//
// This is the exact shape that broke the LatticeFold+ verifier. If the accept
// path is homogeneous in the witness, every algebraic check is satisfied at
// zero and this proof is accepted while proving nothing about the committed
// value.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(all_zero_witness_with_correct_seed_must_reject)
{
    Fixture f;
    LatticeRangeProofV2 p;
    BOOST_REQUIRE(f.Prove(p));
    BOOST_REQUIRE(f.Verify(p));

    ZeroRing(p.z_response);
    ZeroRing(p.z_randomness);
    for (size_t k = 0; k < LatticeParams::K; k++) ZeroRing(p.t_reconstruction[k]);
    // version and challenge_seed deliberately UNTOUCHED — see L2 at the top.

    BOOST_CHECK_MESSAGE(!f.Verify(p),
        "ZERO-WITNESS FORGERY: the verifier accepted an all-zero witness carrying a "
        "correct Fiat-Shamir seed. Every algebraic check on the accept path is "
        "homogeneous in the prover-supplied values, so the proof establishes nothing "
        "about the committed value. This is the LatticeFold+ break class.");
}

// ---------------------------------------------------------------------------
// ★★★ THE SAME FORGERY, BUILT FROM RAW WIRE BYTES.
//
// The test above mutates an in-memory object, which an attacker cannot do. This
// one constructs the blob an attacker would actually broadcast and pushes it
// through the real deserialize() entry point, so it settles whether the
// degenerate state is REACHABLE rather than merely representable:
//
//     byte 0        = 0x01                      (version)
//     bytes 1..32   = correct Fiat-Shamir seed  (all inputs are public)
//     everything else = 0x00                    (z_response, z_randomness,
//                                                t_reconstruction)
//
// The seed is lifted from an honest proof, which is legitimate: it is a hash of
// DOMAIN_SEP || sighash || pubkey_hash || commitment, every term of which the
// attacker knows. Nothing secret is used to build this blob.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(wire_reachable_zero_witness_must_reject)
{
    Fixture f;
    LatticeRangeProofV2 honest;
    BOOST_REQUIRE(f.Prove(honest));
    BOOST_REQUIRE(f.Verify(honest));

    const size_t elem_size = LatticeParams::N * 8;
    const size_t expected_size = 1 + 32 + elem_size * 2 + LatticeParams::K * elem_size;

    std::vector<uint8_t> blob(expected_size, 0x00);
    blob[0] = static_cast<uint8_t>(RangeProofParams::PROOF_VERSION);
    memcpy(blob.data() + 1, honest.challenge_seed.data(), 32);
    // Bytes 33..end stay zero: the entire witness is zero.

    BOOST_REQUIRE(blob.size() <= RangeProofParams::MAX_PROOF_SIZE);

    LatticeRangeProofV2 forged;
    BOOST_REQUIRE_MESSAGE(LatticeRangeProofV2::deserialize(blob, forged),
        "the all-zero blob did not even deserialize; if this fails the wire path "
        "is not reachable and the severity of the in-memory finding drops");

    BOOST_CHECK_MESSAGE(!f.Verify(forged),
        "WIRE-REACHABLE ZERO-WITNESS FORGERY: a blob an attacker can construct from "
        "public data alone deserialized and then VERIFIED. The range proof therefore "
        "establishes nothing about the committed value, and the forgery needs no "
        "secret, no grinding and no in-memory access.");
}

// ---------------------------------------------------------------------------
// The BLIND test, kept deliberately, to document what is NOT sufficient.
// Zeroing the seed as well makes the Fiat-Shamir check fail, so the proof is
// rejected for the wrong reason and the homogeneity question is never reached.
// A green result here proves nothing.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(all_zero_including_seed_rejects_but_proves_nothing)
{
    Fixture f;
    LatticeRangeProofV2 p;
    BOOST_REQUIRE(f.Prove(p));

    ZeroRing(p.z_response);
    ZeroRing(p.z_randomness);
    for (size_t k = 0; k < LatticeParams::K; k++) ZeroRing(p.t_reconstruction[k]);
    p.challenge_seed.fill(0);   // ← the blinding mistake, made on purpose

    BOOST_CHECK(!f.Verify(p));
}

// ---------------------------------------------------------------------------
// Field-wise degeneracy: zero ONE witness component, leave the rest honest and
// the seed correct. Each must reject on its own.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(zero_z_response_alone_must_reject)
{
    Fixture f;
    LatticeRangeProofV2 p;
    BOOST_REQUIRE(f.Prove(p));
    ZeroRing(p.z_response);
    BOOST_CHECK(!f.Verify(p));
}

BOOST_AUTO_TEST_CASE(zero_z_randomness_alone_must_reject)
{
    Fixture f;
    LatticeRangeProofV2 p;
    BOOST_REQUIRE(f.Prove(p));
    ZeroRing(p.z_randomness);
    BOOST_CHECK_MESSAGE(!f.Verify(p),
        "z_randomness was zeroed and the proof still verified. Note that Check 5 "
        "(the z_randomness norm bound) is an explicit no-op in the current code, so "
        "the only thing that can catch this is the t_reconstruction relation.");
}

BOOST_AUTO_TEST_CASE(zero_t_reconstruction_alone_must_reject)
{
    Fixture f;
    LatticeRangeProofV2 p;
    BOOST_REQUIRE(f.Prove(p));
    for (size_t k = 0; k < LatticeParams::K; k++) ZeroRing(p.t_reconstruction[k]);
    BOOST_CHECK(!f.Verify(p));
}

// ---------------------------------------------------------------------------
// External binding. The transcript commits to sighash and pubkey_hash, so a
// proof must not survive being moved to another transaction context. This is
// the SOQ-D002 replay class.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(proof_does_not_survive_wrong_sighash)
{
    Fixture f;
    LatticeRangeProofV2 p;
    BOOST_REQUIRE(f.Prove(p));
    BOOST_REQUIRE(f.Verify(p));

    std::array<uint8_t, 32> other_sighash;
    other_sighash.fill(0xC3);
    BOOST_CHECK(!p.verify(f.commitment, f.params, other_sighash, f.pubkey_hash));
}

BOOST_AUTO_TEST_CASE(proof_does_not_survive_wrong_pubkey_hash)
{
    Fixture f;
    LatticeRangeProofV2 p;
    BOOST_REQUIRE(f.Prove(p));

    std::array<uint8_t, 32> other_pkh;
    other_pkh.fill(0xC3);
    BOOST_CHECK(!p.verify(f.commitment, f.params, f.sighash, other_pkh));
}

// ---------------------------------------------------------------------------
// A proof must not verify against a DIFFERENT commitment. The commitment enters
// the transcript, so this should fail on the Fiat-Shamir check; the test exists
// so that a future refactor which drops the commitment from the transcript is
// caught immediately.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(proof_does_not_survive_wrong_commitment)
{
    Fixture f;
    LatticeRangeProofV2 p;
    BOOST_REQUIRE(f.Prove(p));

    RingElement other_r;
    for (size_t j = 0; j < LatticeParams::N; j++) other_r.coeffs[j] = 1;
    LatticeCommitment other = LatticeCommitment::commit(f.value + 1, other_r, f.pub);

    BOOST_CHECK(!p.verify(other, f.params, f.sighash, f.pubkey_hash));
}

// ---------------------------------------------------------------------------
// Version must be enforced. A zero-version proof is the naive degenerate blob.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(zero_version_must_reject)
{
    Fixture f;
    LatticeRangeProofV2 p;
    BOOST_REQUIRE(f.Prove(p));
    p.version = 0;
    BOOST_CHECK(!f.Verify(p));
}

// ---------------------------------------------------------------------------
// ★★★ A NON-ZERO MEMBER OF THE SAME BREAK CLASS.
//
// WHY THIS TEST EXISTS, and it is a defence against a plausible false fix.
//
// The two tests above zero z_response, z_randomness and t_reconstruction. A
// verifier patched with "reject if those are all zero" would turn both of them
// GREEN while leaving the actual defect — homogeneity of every algebraic check in
// the prover-supplied values — completely intact. That is not a hypothetical
// mistake: the previous remediation of the sibling LatticeFold+ verifier shipped
// with exactly that shape of blind spot.
//
// So the battery must contain at least one degenerate witness that is NOT all
// zeros. Here every witness value is scaled by a constant lambda (mod Q), with
// version and challenge_seed left honest so the Fiat-Shamir seed stays correct.
// If the accept path is homogeneous, a scaled witness satisfies it for the same
// reason zero does.
//
// ⚠️ This test asserts REJECTION. Its verdict is genuinely unknown in advance —
// unlike the two above, which are known-accepting. Whichever way it lands, it is
// recorded rather than guessed:
//   - if it FAILS (the scaled witness is accepted), the break class has a second,
//     non-zero member, and no zero-only patch can ever make this battery green;
//   - if it PASSES, the exploitable homogeneity is narrower than the comment above
//     assumes, and THAT is worth knowing before anyone designs a fix around it.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(scaled_witness_with_correct_seed_must_reject)
{
    Fixture f;
    LatticeRangeProofV2 p;
    BOOST_REQUIRE(f.Prove(p));
    BOOST_REQUIRE(f.Verify(p));

    const int64_t Q = LatticeParams::Q;
    const int64_t lambda = 2;
    auto scale = [&](RingElement& r) {
        for (size_t j = 0; j < LatticeParams::N; j++) {
            // centred representative of lambda * c (mod Q)
            int64_t v = (r.coeffs[j] % Q) * lambda % Q;
            if (v > Q / 2) v -= Q;
            if (v < -Q / 2) v += Q;
            r.coeffs[j] = v;
        }
    };
    scale(p.z_response);
    scale(p.z_randomness);
    for (size_t k = 0; k < LatticeParams::K; k++) scale(p.t_reconstruction[k]);
    // version and challenge_seed deliberately UNTOUCHED.

    BOOST_CHECK_MESSAGE(!f.Verify(p),
        "SCALED-WITNESS FORGERY: the verifier accepted a witness whose every value was "
        "multiplied by a constant, with the honest Fiat-Shamir seed. This is a NON-ZERO "
        "member of the same homogeneity break class, which means no 'reject if all "
        "zeros' patch can legitimately make this battery green — the accept path itself "
        "has to stop being homogeneous.");
}

BOOST_AUTO_TEST_SUITE_END()
