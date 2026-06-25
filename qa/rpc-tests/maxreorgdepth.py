#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test the finality horizon (Consensus::nMaxReorgDepth).
#
# A small merge-mined chain cannot out-hash a rental 51% attack (renting a
# majority of SOQ's scrypt hashrate is ~free because the same hashrate earns
# LTC+DOGE -- Analysis [A], 2026-06-22). The finality horizon makes deeply
# buried history irreversible: a node refuses to reorganize more than
# nMaxReorgDepth blocks deep, while still accepting shallower reorgs.
#
# The horizon is a consensus parameter on real networks; regtest exposes the
# -maxreorgdepth override so this test can use a small value (10) instead of
# the mainnet 288.
#

import time
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

REORG_LIMIT = 10  # -maxreorgdepth passed to every node

class MaxReorgDepthTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 4

    def setup_network(self):
        # Start every node UNCONNECTED so we can build divergent chains, each
        # with a small finality horizon. We connect specific pairs by hand.
        self.is_network_split = False
        self.nodes = []
        for i in range(self.num_nodes):
            self.nodes.append(start_node(i, self.options.tmpdir,
                                         ["-debug", "-maxreorgdepth=%d" % REORG_LIMIT]))

    def run_test(self):
        # ---- Scenario 1: a reorg DEEPER than the horizon is REJECTED ----
        # node0 builds a 20-block chain; node1 builds a competing, LONGER
        # 25-block chain (both fork at genesis). When connected, node0 would
        # have to disconnect all 20 of its blocks (depth 20 >= 10) to adopt
        # node1's longer chain, so it must refuse and hold its own chain.
        print("Scenario 1: deep reorg must be rejected")
        self.nodes[0].generate(20)
        self.nodes[1].generate(25)
        assert_equal(self.nodes[0].getblockcount(), 20)
        assert_equal(self.nodes[1].getblockcount(), 25)
        node0_tip = self.nodes[0].getbestblockhash()

        connect_nodes_bi(self.nodes, 0, 1)
        time.sleep(5)  # allow the (rejected) reorg attempt to be processed

        # node0 must NOT have adopted node1's longer-but-too-deep chain.
        assert_equal(self.nodes[0].getblockcount(), 20)
        assert_equal(self.nodes[0].getbestblockhash(), node0_tip)
        assert_equal(self.nodes[1].getblockcount(), 25)
        print("  OK: node0 held its 20-block chain; depth-20 reorg (>= %d) rejected" % REORG_LIMIT)

        # ---- Scenario 2: a reorg SHALLOWER than the horizon is ACCEPTED ----
        # node2 has only a 4-block chain; node3 has a competing 20-block chain.
        # node2 must disconnect only its 4 blocks (depth 4 < 10) to adopt the
        # longer chain, which is allowed -- proving the rule is active (not
        # globally disabled) yet does not break normal reorgs.
        print("Scenario 2: shallow reorg must be accepted")
        self.nodes[2].generate(4)
        self.nodes[3].generate(20)
        assert_equal(self.nodes[2].getblockcount(), 4)

        connect_nodes_bi(self.nodes, 2, 3)
        sync_blocks(self.nodes[2:4])

        assert_equal(self.nodes[2].getblockcount(), 20)
        assert_equal(self.nodes[2].getbestblockhash(), self.nodes[3].getbestblockhash())
        print("  OK: node2 adopted the longer chain; depth-4 reorg (< %d) accepted" % REORG_LIMIT)

if __name__ == '__main__':
    MaxReorgDepthTest().main()
