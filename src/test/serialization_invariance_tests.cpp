// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// serialization_invariance_tests.cpp — the same consensus object must mean the
// same bytes on every path it travels. Bead v7xm, fork-risk class F1.
//
// F1 is called the #1 recurring root cause on that bead, and its historical
// instance is genuinely closed: Phase 4 removed the nVisibility/nAssetType
// extension bytes, SERIALIZE_TXOUT_STANDARD is gone, and the byte-exact golden
// matrix in ctxout_format_matrix_tests.cpp pins the single wire format. The
// AuxPoW parent coinbase now goes through the same CTransaction serializer as a
// native transaction, so the dual-format seam that caused the original incident
// no longer exists.
//
// ⛔ BUT "ONE FORMAT EVERYWHERE" IS NOT TRUE, AND THE EXCEPTION IS UNTESTED.
// CTxOut still has a SECOND encoding. The UTXO set (coins.h) and the undo data
// (undo.h) both write it through CTxOutCompressor: a varint-compressed amount
// and a compressed script, with six special-case script forms that expand back
// into full scripts on read. So every output in the chain is stored twice, in
// two different encodings, and nothing checked that the second one round-trips
// Soqucoin's script shapes.
//
// That matters more here than in Bitcoin. CScriptCompressor's special cases were
// written for P2PKH, P2SH and P2PK; Soqucoin's outputs are 34-byte
// OP_N <32-byte program> witness programs that none of those detectors should
// match. If one ever did match, compression would replace the script with a
// 20-byte hash and decompression would hand back a DIFFERENT script: the UTXO
// set would silently disagree with the chain that produced it. Nothing would
// warn, and it would surface as a node that cannot spend its own coins.
//
// So this file asserts the property directly, across the whole witness matrix
// and the amount boundaries, plus the stream-type and AuxPoW invariances that
// close out the rest of F1.

#include "amount.h"
#include "auxpow.h"
#include "compressor.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include "undo.h"
#include "uint256.h"
#include "version.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(serialization_invariance_tests, BasicTestingSetup)

namespace {

typedef std::vector<unsigned char> Bytes;

template <typename T>
Bytes Ser(const T& obj, int nType, int nVersion)
{
    CDataStream ss(nType, nVersion);
    ss << obj;
    return Bytes(ss.begin(), ss.end());
}

//! Every witness-program shape a Soqucoin output can take, plus the non-witness
//! forms whose compressed encodings have special cases.
std::vector<CScript> AllScriptShapes()
{
    std::vector<CScript> out;
    for (int v = 0; v <= 16; ++v) {
        for (size_t len : {size_t(20), size_t(32)}) {
            CScript s;
            s << (v == 0 ? OP_0 : CScript::EncodeOP_N(v));
            s << std::vector<unsigned char>(len, 0x5a);
            out.push_back(s);
        }
    }
    out.push_back(CScript());                                   // empty
    out.push_back(CScript() << OP_TRUE);                        // 1 byte
    out.push_back(CScript() << OP_RETURN << std::vector<unsigned char>(80, 0x11));
    // The three shapes CScriptCompressor genuinely special-cases. Included so the
    // round-trip covers the compressed paths as well as the raw fallback.
    {
        CScript p2pkh;
        p2pkh << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x01)
              << OP_EQUALVERIFY << OP_CHECKSIG;
        out.push_back(p2pkh);
    }
    {
        CScript p2sh;
        p2sh << OP_HASH160 << std::vector<unsigned char>(20, 0x02) << OP_EQUAL;
        out.push_back(p2sh);
    }
    return out;
}

std::vector<CAmount> InterestingAmounts()
{
    return {
        0, 1, 2, 9, 10, 100, 1000,
        546,                    // dust-ish
        COIN, COIN - 1, COIN + 1,
        50 * COIN,
        123456789,
        100000000000000LL,      // 1M coins
        MAX_MONEY - 1, MAX_MONEY,
    };
}

} // namespace

// ---------------------------------------------------------------------------
// THE SECOND ENCODING. Every output the chain can contain must survive the
// UTXO-set/undo compressor byte-exactly. A failure here is the UTXO set
// disagreeing with the chain that produced it.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(compressed_txout_roundtrips_every_script_shape)
{
    for (const CScript& spk : AllScriptShapes()) {
        for (CAmount amount : InterestingAmounts()) {
            CTxOut original;
            original.nValue = amount;
            original.scriptPubKey = spk;

            CDataStream ss(SER_DISK, CLIENT_VERSION);
            CTxOut copy = original;                       // compressor takes a reference
            ss << CTxOutCompressor(REF(copy));

            CTxOut restored;
            ss >> REF(CTxOutCompressor(restored));

            BOOST_CHECK_MESSAGE(restored.nValue == original.nValue,
                "compressed amount did not round-trip: " + std::to_string(original.nValue) +
                " became " + std::to_string(restored.nValue));
            BOOST_CHECK_MESSAGE(restored.scriptPubKey == original.scriptPubKey,
                "compressed scriptPubKey did not round-trip for a " +
                std::to_string(spk.size()) + "-byte script. If a Soqucoin witness program "
                "has started matching one of CScriptCompressor's P2PKH/P2SH/P2PK special "
                "cases, the UTXO set now stores a DIFFERENT script than the chain contains");
        }
    }
}

// The premise, made explicit and measured: the two encodings really are
// different. If this ever stopped being true the compressor seam would be gone
// and the round-trip tests above would be trivially satisfied, so it is worth
// asserting that they still have something to prove.
BOOST_AUTO_TEST_CASE(the_utxo_encoding_genuinely_differs_from_the_wire_encoding)
{
    CTxOut o;
    o.nValue = 50 * COIN;
    o.scriptPubKey = CScript() << OP_7 << std::vector<unsigned char>(32, 0xaa);

    const Bytes wire = Ser(o, SER_NETWORK, PROTOCOL_VERSION);

    CTxOut copy = o;
    CDataStream cs(SER_DISK, CLIENT_VERSION);
    cs << CTxOutCompressor(REF(copy));
    const Bytes compressed(cs.begin(), cs.end());

    BOOST_TEST_MESSAGE("v7 output: wire " << wire.size() << " bytes, UTXO-compressed "
                       << compressed.size() << " bytes");
    BOOST_CHECK_MESSAGE(wire != compressed,
        "the UTXO encoding is now identical to the wire encoding. If CTxOutCompressor has "
        "been removed from coins.h and undo.h then the second encoding is gone and this "
        "whole file can shrink; if it has not, something is wrong");
}

// The amount compressor on its own, at the boundaries. Soqucoin's supply is far
// larger than Bitcoin's, so the interesting range is different even though the
// algorithm is inherited.
BOOST_AUTO_TEST_CASE(amount_compression_roundtrips_at_boundaries)
{
    for (CAmount a : InterestingAmounts()) {
        const uint64_t c = CTxOutCompressor::CompressAmount(a);
        const uint64_t back = CTxOutCompressor::DecompressAmount(c);
        BOOST_CHECK_MESSAGE(back == (uint64_t)a,
            "amount " + std::to_string(a) + " compressed to " + std::to_string(c) +
            " and decompressed to " + std::to_string(back));
    }
    // Powers of ten and their neighbours are where the exponent encoding switches.
    uint64_t p = 1;
    for (int i = 0; i < 19; ++i) {
        for (uint64_t v : {p ? p - 1 : 0, p, p + 1}) {
            BOOST_CHECK_MESSAGE(
                CTxOutCompressor::DecompressAmount(CTxOutCompressor::CompressAmount(v)) == v,
                "amount " + std::to_string(v) + " did not survive the exponent encoding");
        }
        if (p > UINT64_MAX / 10) break;
        p *= 10;
    }
}

// A spent output travels through the undo file in compressed form and must come
// back identical, or a reorg restores a different UTXO than it removed.
BOOST_AUTO_TEST_CASE(txundo_roundtrips_every_script_shape)
{
    CTxUndo undo;
    for (const CScript& spk : AllScriptShapes()) {
        CTxOut o;
        o.nValue = 12345678;
        o.scriptPubKey = spk;
        CTxInUndo in;
        in.txout = o;
        in.fCoinBase = false;
        in.nHeight = 1;
        in.nVersion = 2;
        undo.vprevout.push_back(in);
    }

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << undo;
    CTxUndo restored;
    ss >> restored;

    BOOST_REQUIRE_EQUAL(restored.vprevout.size(), undo.vprevout.size());
    for (size_t i = 0; i < undo.vprevout.size(); ++i) {
        BOOST_CHECK_MESSAGE(restored.vprevout[i].txout.scriptPubKey ==
                            undo.vprevout[i].txout.scriptPubKey,
            "undo entry " + std::to_string(i) + " changed script across the compressor; "
            "a reorg would restore a different output than it removed");
        BOOST_CHECK_EQUAL(restored.vprevout[i].txout.nValue, undo.vprevout[i].txout.nValue);
    }
}

// ---------------------------------------------------------------------------
// STREAM-TYPE INVARIANCE. A consensus object must not encode differently
// depending on whether it is going to disk, to the wire, or into a hash. The one
// legitimate exception is the witness flag on CTransaction, asserted separately
// below.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(consensus_objects_ignore_stream_type)
{
    CTxOut o;
    o.nValue = 12345678;
    o.scriptPubKey = CScript() << OP_7 << std::vector<unsigned char>(32, 0xaa);

    const Bytes net  = Ser(o, SER_NETWORK, PROTOCOL_VERSION);
    const Bytes disk = Ser(o, SER_DISK,    CLIENT_VERSION);
    const Bytes hash = Ser(o, SER_GETHASH, PROTOCOL_VERSION);
    BOOST_CHECK_MESSAGE(net == disk && disk == hash,
        "CTxOut serialises differently by stream type. That is the dual-format seam Phase 4 "
        "removed, and it is the single highest-frequency fork cause in this codebase");

    CTxIn in;
    in.prevout = COutPoint(uint256S("0x55"), 3);
    in.nSequence = 0xfffffffe;
    BOOST_CHECK(Ser(in, SER_NETWORK, PROTOCOL_VERSION) == Ser(in, SER_DISK, CLIENT_VERSION));

    CBlockHeader h;
    h.nVersion = 4; h.nTime = 1700000000; h.nBits = 0x1e0ffff0; h.nNonce = 7;
    h.hashPrevBlock = uint256S("0x11"); h.hashMerkleRoot = uint256S("0x22");
    BOOST_CHECK_MESSAGE(Ser(h, SER_NETWORK, PROTOCOL_VERSION) == Ser(h, SER_DISK, CLIENT_VERSION),
        "the block header must be one format everywhere; it is what the PoW commits to");
}

// Round-trip stability: decode then re-encode must be byte-identical, or two
// nodes that relay the same object to each other can compute different hashes.
BOOST_AUTO_TEST_CASE(transaction_roundtrip_is_byte_stable)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn in;
    in.prevout = COutPoint(uint256S("0x77"), 1);
    in.nSequence = CTxIn::SEQUENCE_FINAL;
    in.scriptWitness.stack.push_back(std::vector<unsigned char>(2421, 0x01));
    in.scriptWitness.stack.push_back(std::vector<unsigned char>(1313, 0x00));
    mtx.vin.push_back(in);
    for (const CScript& spk : AllScriptShapes()) {
        CTxOut o; o.nValue = 1000; o.scriptPubKey = spk;
        mtx.vout.push_back(o);
    }
    const CTransaction tx(mtx);

    for (int version : {PROTOCOL_VERSION, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS}) {
        const Bytes first = Ser(tx, SER_NETWORK, version);
        CDataStream ss(first, SER_NETWORK, version);
        CTransaction decoded(deserialize, ss);
        const Bytes second = Ser(decoded, SER_NETWORK, version);
        BOOST_CHECK_MESSAGE(first == second,
            std::string("transaction re-encoding differs after a decode round trip") +
            (version & SERIALIZE_TRANSACTION_NO_WITNESS ? " (no-witness)" : " (with witness)"));
    }
}

// The witness flag is the ONE legitimate encoding difference, and its semantics
// are consensus-critical: the txid must not cover the witness, the wtxid must.
BOOST_AUTO_TEST_CASE(witness_flag_is_the_only_legitimate_variance)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn in;
    in.prevout = COutPoint(uint256S("0x88"), 0);
    in.nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vin.push_back(in);
    CTxOut o; o.nValue = 500; o.scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0x03);
    mtx.vout.push_back(o);

    const CTransaction bare(mtx);
    const uint256 bareTxid = bare.GetHash();

    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(2421, 0x09));
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(1313, 0x00));
    const CTransaction witnessed(mtx);

    BOOST_CHECK_MESSAGE(witnessed.GetHash() == bareTxid,
        "adding a witness changed the TXID. Malleability protection depends on the txid "
        "covering no witness data");
    BOOST_CHECK_MESSAGE(witnessed.GetWitnessHash() != bareTxid,
        "the witness hash must cover the witness, or the coinbase commitment secures nothing");
    BOOST_CHECK_MESSAGE(bare.GetWitnessHash() == bareTxid,
        "with no witness present the two hashes must coincide");
}

// ---------------------------------------------------------------------------
// AUXPOW. The original F1 incident was the AuxPoW parent coinbase using a
// different CTxOut encoding than a native transaction. Phase 4 closed that by
// construction, since there is only one encoding now. This asserts it rather
// than trusting it: the parent coinbase inside a CAuxPow must be byte-identical
// to the same transaction serialised standalone.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(auxpow_parent_coinbase_matches_a_native_transaction)
{
    CMutableTransaction mtx;
    mtx.nVersion = 1;
    CTxIn cbin;
    cbin.prevout.SetNull();
    cbin.scriptSig = CScript() << 486604799 << CScriptNum(4);
    cbin.nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vin.push_back(cbin);
    CTxOut o; o.nValue = 50 * COIN;
    o.scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0xbb);
    mtx.vout.push_back(o);
    CTransactionRef parentCoinbase = MakeTransactionRef(mtx);

    const Bytes standalone = Ser(*parentCoinbase, SER_NETWORK, PROTOCOL_VERSION);

    CMerkleTx merkle(parentCoinbase);
    const Bytes inMerkleTx = Ser(merkle, SER_NETWORK, PROTOCOL_VERSION);

    BOOST_REQUIRE_MESSAGE(inMerkleTx.size() > standalone.size(),
        "a CMerkleTx must be the transaction plus its branch");
    BOOST_CHECK_MESSAGE(
        Bytes(inMerkleTx.begin(), inMerkleTx.begin() + standalone.size()) == standalone,
        "the AuxPoW parent coinbase does NOT serialise identically to the same transaction "
        "on its own. That is the exact dual-format divergence Phase 4 removed, and it is a "
        "merge-mining consensus split");
}

BOOST_AUTO_TEST_SUITE_END()
