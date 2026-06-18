// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Phase 4 Step E: Genesis nonce re-miner
// After the CTxOut byte-less serialization change, all genesis nonces are stale
// because the block hash (which includes the serialized coinbase) changed.
// This test mines new nonces for stagenet and mainnet.
//
// Usage:
//   test_soqucoin --run_test=genesis_remine_tests/mine_stagenet_genesis --log_level=message
//   test_soqucoin --run_test=genesis_remine_tests/mine_mainnet_genesis --log_level=message

#include "chainparams.h"
#include "consensus/consensus.h"
#include "soqucoin.h"
#include "primitives/block.h"
#include "uint256.h"
#include "arith_uint256.h"
#include "crypto/scrypt.h"
#include "consensus/merkle.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <cstdio>

BOOST_FIXTURE_TEST_SUITE(genesis_remine_tests, BasicTestingSetup)

// Helper: mine a genesis block starting from nonce 0
static void MineGenesis(CBlock& block, const std::string& networkName)
{
    arith_uint256 target;
    bool fNegative, fOverflow;
    target.SetCompact(block.nBits, &fNegative, &fOverflow);

    fprintf(stderr, "\n=== MINING %s GENESIS ===\n", networkName.c_str());
    fprintf(stderr, "  nTime   = %u\n", block.nTime);
    fprintf(stderr, "  nBits   = 0x%08x\n", block.nBits);
    fprintf(stderr, "  target  = %s\n", target.GetHex().c_str());
    fprintf(stderr, "  merkle  = %s\n", block.hashMerkleRoot.ToString().c_str());
    fprintf(stderr, "  Mining from nonce 0...\n");

    block.nNonce = 0;
    uint256 powHash;
    uint64_t attempts = 0;

    while (true) {
        scrypt_1024_1_1_256(BEGIN(block.nVersion), BEGIN(powHash));
        if (UintToArith256(powHash) <= target) {
            fprintf(stderr, "\n  ✓ FOUND valid nonce after %llu attempts!\n", (unsigned long long)attempts);
            fprintf(stderr, "  nNonce       = %u\n", block.nNonce);
            fprintf(stderr, "  GetHash()    = %s\n", block.GetHash().ToString().c_str());
            fprintf(stderr, "  GetPoWHash() = %s\n", powHash.ToString().c_str());
            fprintf(stderr, "  hashMerkleRoot = %s\n", block.hashMerkleRoot.ToString().c_str());
            fprintf(stderr, "\n  PASTE INTO chainparams.cpp:\n");
            fprintf(stderr, "    nNonce = %u\n", block.nNonce);
            fprintf(stderr, "    hashGenesisBlock = 0x%s\n", block.GetHash().ToString().c_str());
            fprintf(stderr, "    hashMerkleRoot   = 0x%s\n", block.hashMerkleRoot.ToString().c_str());
            fprintf(stderr, "=== END MINING %s ===\n\n", networkName.c_str());
            return;
        }
        block.nNonce++;
        attempts++;

        if (attempts % 1000000 == 0) {
            fprintf(stderr, "  ... %llu million nonces tried (current: %u)\n",
                    (unsigned long long)(attempts / 1000000), block.nNonce);
        }

        // Safety: if we wrap around 32-bit nonce space without finding, something is wrong
        if (block.nNonce == 0) {
            fprintf(stderr, "  ✗ EXHAUSTED 32-bit nonce space without finding valid hash!\n");
            fprintf(stderr, "  This should not happen with nBits=0x1e0ffff0.\n");
            BOOST_FAIL("Nonce space exhausted");
        }
    }
}

BOOST_AUTO_TEST_CASE(mine_stagenet_genesis)
{
    // Reproduce the stagenet genesis block construction
    // From chainparams.cpp line 949:
    // genesis = CreateGenesisBlockStagenet(1745769600, 942423, 0x1e0ffff0, 1, 500000 * COIN);

    // We can't call CreateGenesisBlockStagenet directly (it's static in chainparams.cpp),
    // so we replicate the construction here.
    const char* pszTimestamp = "Soqucoin Stagenet - Mainnet rehearsal network Jan 2026";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = 500000 * COIN;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = 1745769600;
    genesis.nBits = 0x1e0ffff0;
    genesis.nNonce = 0;  // Will be mined
    genesis.nVersion = 1;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

    // Verify merkle root matches what chainparams.cpp produces
    fprintf(stderr, "  Merkle root: %s\n", genesis.hashMerkleRoot.ToString().c_str());
    BOOST_CHECK_EQUAL(genesis.hashMerkleRoot.ToString(),
                      "994391b757742376b24ebdd37b0fa9ebc11da47366ca8f9ac0a21094da350736");

    MineGenesis(genesis, "STAGENET");

    // Verify PoW directly (don't call SelectParams — stagenet assert still has stale hash)
    {
        arith_uint256 target;
        bool fNeg, fOver;
        target.SetCompact(genesis.nBits, &fNeg, &fOver);
        BOOST_CHECK(!fNeg);
        BOOST_CHECK(!fOver);
        BOOST_CHECK(UintToArith256(genesis.GetPoWHash()) <= target);
    }
}

BOOST_AUTO_TEST_CASE(mine_mainnet_genesis)
{
    // Reproduce the mainnet genesis block construction
    // From chainparams.cpp line 320:
    // genesis = CreateGenesisBlock(1386325540, 99943, 0x1e0ffff0, 1, 88 * COIN);

    const char* pszTimestamp = "Nintondo";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = 88 * COIN;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = 1386325540;
    genesis.nBits = 0x1e0ffff0;
    genesis.nNonce = 0;  // Will be mined
    genesis.nVersion = 1;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

    fprintf(stderr, "  Merkle root: %s\n", genesis.hashMerkleRoot.ToString().c_str());

    MineGenesis(genesis, "MAINNET");

    // Verify PoW directly (don't call SelectParams — mainnet assert deferred)
    {
        arith_uint256 target;
        bool fNeg, fOver;
        target.SetCompact(genesis.nBits, &fNeg, &fOver);
        BOOST_CHECK(!fNeg);
        BOOST_CHECK(!fOver);
        BOOST_CHECK(UintToArith256(genesis.GetPoWHash()) <= target);
    }
}

BOOST_AUTO_TEST_SUITE_END()
