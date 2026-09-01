#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# PAT block-attestation commitment, end to end through a real node
# (doc/PAT_BLOCK_ATTESTATION.md; the reject-path matrix lives in
# src/test/pat_commitment_rule_tests.cpp, driven through ConnectBlock with
# named reject strings).
#
# This test covers what the unit suite cannot: the production miner emitting
# the commitment for a block whose spends came through the real mempool, the
# node accepting its own commitments across consecutive blocks, and the
# empty-block rule holding on a live chain.
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

# OP_RETURN OP_PUSHBYTES_34 'P' 'A' <32-byte hash> = 36 bytes = 72 hex chars.
PAT_PREFIX = "6a225041"
PAT_HEXLEN = 72

# Regtest coinbase maturity (60 * 4).
MATURITY = 240


class PatCommitmentTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.is_network_split = False
        self.nodes = [start_node(0, self.options.tmpdir, ["-debug"])]

    def pat_commitments_in_coinbase(self, height):
        node = self.nodes[0]
        block = node.getblock(node.getblockhash(height))
        vout = node.getrawtransaction(block['tx'][0], 1)['vout']
        return [out for out in vout
                if out['scriptPubKey']['hex'].startswith(PAT_PREFIX)
                and len(out['scriptPubKey']['hex']) == PAT_HEXLEN]

    def run_test(self):
        node = self.nodes[0]

        # Mature one coinbase. Every one of these blocks is coinbase-only, so
        # per the empty-batch rule none may carry a commitment.
        node.generate(MATURITY + 1)
        assert_equal(node.getblockcount(), MATURITY + 1)
        for height in (1, MATURITY // 2, MATURITY + 1):
            assert_equal(len(self.pat_commitments_in_coinbase(height)), 0)

        # A real spend through the mempool: the next block carries exactly one
        # attested tuple, so the miner must emit exactly one commitment, and
        # the node must accept its own block (generate would fail otherwise).
        node.sendtoaddress(node.getnewaddress(), 1)
        node.generate(1)
        spend_height = node.getblockcount()
        assert_equal(len(self.pat_commitments_in_coinbase(spend_height)), 1)

        # The rule is per-block, not sticky: the next empty block carries none.
        node.generate(1)
        assert_equal(len(self.pat_commitments_in_coinbase(spend_height + 1)), 0)

        # Several spends in one block still mean ONE commitment (one batch per
        # block), and the chain keeps extending normally past it.
        for _ in range(3):
            node.sendtoaddress(node.getnewaddress(), 1)
        node.generate(1)
        multi_height = node.getblockcount()
        assert_equal(len(self.pat_commitments_in_coinbase(multi_height)), 1)
        node.generate(2)
        assert_equal(node.getblockcount(), multi_height + 2)

        print("PAT commitment functional test passed")


if __name__ == '__main__':
    PatCommitmentTest().main()
