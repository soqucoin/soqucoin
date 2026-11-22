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
# buried history irreversible: a node refuses a new header on a branch that
# forks nMaxReorgDepth or more blocks below its tip, while still accepting
# shallower reorgs. A block with nMaxReorgDepth confirmations therefore stays,
# and one with nMaxReorgDepth - 1 can still be reorganised away; scenarios 3
# and 4 hold the rule to that boundary.
#
# The horizon is a consensus parameter on real networks; regtest exposes the
# -maxreorgdepth override so this test can use a small value (10) instead of
# the mainnet 288.
#

import os
import time
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

REORG_LIMIT = 10  # -maxreorgdepth passed to every node

class MaxReorgDepthTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 8

    def setup_network(self):
        # Start every node UNCONNECTED so we can build divergent chains, each
        # with a small finality horizon. We connect specific pairs by hand.
        self.is_network_split = False
        self.nodes = []
        for i in range(self.num_nodes):
            self.nodes.append(start_node(i, self.options.tmpdir,
                                         ["-debug", "-maxreorgdepth=%d" % REORG_LIMIT]))

    def debug_log(self, i):
        with open(os.path.join(self.options.tmpdir, "node%d" % i, "regtest", "debug.log"), encoding="utf-8") as f:
            return f.read()

    def wait_for_refusal(self, i, depth, timeout=60):
        """Polls node i's debug log until it records a header refused at this
        fork depth, so that a refusal is something the test saw and not the
        absence of a reorganisation within a sleep."""
        line = "block builds on a fork %d blocks deep, beyond the %d-block finality horizon" % (depth, REORG_LIMIT)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if line in self.debug_log(i):
                return
            time.sleep(0.5)
        raise AssertionError("node%d logged no header refused at fork depth %d within %d s" % (i, depth, timeout))

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

        # ---- Scenario 3: one block inside the horizon is ACCEPTED ----
        # node4 has REORG_LIMIT - 1 blocks, so its block 1 has REORG_LIMIT - 1
        # confirmations. node5's longer chain forks at genesis, REORG_LIMIT - 1
        # blocks below node4's tip, and node4 adopts it: a block with
        # REORG_LIMIT - 1 confirmations can still be reorganised away.
        print("Scenario 3: a reorg of depth limit - 1 must be accepted")
        self.nodes[4].generate(REORG_LIMIT - 1)
        self.nodes[5].generate(REORG_LIMIT + 3)
        first = self.nodes[4].getblockhash(1)
        assert_equal(self.nodes[4].getblock(first)['confirmations'], REORG_LIMIT - 1)

        connect_nodes_bi(self.nodes, 4, 5)
        sync_blocks(self.nodes[4:6])

        assert_equal(self.nodes[4].getblockcount(), REORG_LIMIT + 3)
        assert_equal(self.nodes[4].getbestblockhash(), self.nodes[5].getbestblockhash())
        assert_equal(self.nodes[4].getblock(first)['confirmations'], -1)
        assert "bad-fork-beyond-finality" not in self.debug_log(4)
        print("  OK: node4 adopted the longer chain; depth-%d reorg (limit - 1) accepted" % (REORG_LIMIT - 1))

        # ---- Scenario 4: exactly at the horizon is REJECTED ----
        # node6 has REORG_LIMIT blocks, so its block 1 has REORG_LIMIT
        # confirmations. node7's longer chain forks at genesis, REORG_LIMIT
        # blocks below node6's tip, and node6 refuses its first header: a
        # block with REORG_LIMIT confirmations stays.
        print("Scenario 4: a reorg of depth limit must be rejected")
        self.nodes[6].generate(REORG_LIMIT)
        self.nodes[7].generate(REORG_LIMIT + 3)
        first = self.nodes[6].getblockhash(1)
        node6_tip = self.nodes[6].getbestblockhash()
        assert_equal(self.nodes[6].getblock(first)['confirmations'], REORG_LIMIT)

        connect_nodes_bi(self.nodes, 6, 7)
        self.wait_for_refusal(6, REORG_LIMIT)

        assert_equal(self.nodes[6].getblockcount(), REORG_LIMIT)
        assert_equal(self.nodes[6].getbestblockhash(), node6_tip)
        assert_equal(self.nodes[6].getblock(first)['confirmations'], REORG_LIMIT)
        assert_equal(self.nodes[7].getblockcount(), REORG_LIMIT + 3)
        print("  OK: node6 held its %d-block chain; depth-%d reorg (the limit) rejected" % (REORG_LIMIT, REORG_LIMIT))

if __name__ == '__main__':
    MaxReorgDepthTest().main()
