#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
PAT witness pruning, stage 2: the serving rules (doc/PAT_WITNESS_PRUNING.md
test plan item 5).

A node running -witnessprune must:
- advertise NODE_NETWORK_LIMITED and NODE_WITNESS, and not NODE_NETWORK;
- serve getdata for blocks within the finality horizon normally, for both
  MSG_BLOCK and MSG_WITNESS_BLOCK;
- answer getdata for blocks beyond the horizon with notfound for both message
  types, even though the (possibly still uncompacted) base data exists locally.

The window rule is enforced from the node's own state, not the compaction
schedule, so this test needs no compaction to have happened: depth alone
decides.
"""

from collections import defaultdict

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import *

NODE_NETWORK = 1 << 0
NODE_WITNESS = 1 << 3
NODE_NETWORK_LIMITED = 1 << 10

HORIZON = 10
CHAIN_LENGTH = 30


class ServingTestNode(SingleNodeConnCB):
    def __init__(self):
        SingleNodeConnCB.__init__(self)
        self.blocks = defaultdict(int)      # sha256 -> times received
        self.notfound = set()               # (inv type, hash) answered notfound
        self.lastpong = 0
        self.nonce = 4919

    def add_connection(self, conn):
        self.connection = conn

    def on_block(self, conn, message):
        message.block.calc_sha256()
        self.blocks[message.block.sha256] += 1

    def on_notfound(self, conn, message):
        for inv in message.vec:
            self.notfound.add((inv.type, inv.hash))

    def on_pong(self, conn, message):
        self.lastpong = message.nonce

    # A ping round-trip after a getdata proves the getdata was fully
    # processed: any block or notfound it was going to produce has been sent.
    def ping(self):
        self.nonce += 1
        self.connection.send_message(msg_ping(self.nonce))
        def pong_received():
            return self.lastpong == self.nonce
        return wait_until(pong_received, timeout=10)

    def getdata(self, inv_type, block_hash):
        req = msg_getdata()
        req.inv.append(CInv(t=inv_type, h=block_hash))
        self.connection.send_message(req)
        assert(self.ping())


class WitnessPruneServingTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self, split=False):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir,
            ["-witnessprune=1", "-maxreorgdepth=%d" % HORIZON]))

    def run_test(self):
        node = self.nodes[0]
        node.generate(CHAIN_LENGTH)
        tip_height = node.getblockcount()
        assert_equal(tip_height, CHAIN_LENGTH)

        # Service bits: limited and witness advertised, full service not.
        localservices = int(node.getnetworkinfo()['localservices'], 16)
        assert(localservices & NODE_NETWORK_LIMITED)
        assert(localservices & NODE_WITNESS)
        assert(not (localservices & NODE_NETWORK))

        self.testnode = ServingTestNode()
        conn = NodeConn('127.0.0.1', p2p_port(0), node, self.testnode)
        self.testnode.add_connection(conn)
        NetworkThread().start()
        self.testnode.wait_for_verack()

        # The version handshake must carry the same honest bits.
        assert(conn.nServices & NODE_NETWORK_LIMITED)
        assert(not (conn.nServices & NODE_NETWORK))

        MSG_BLOCK_INV = 2
        MSG_WITNESS_BLOCK_INV = 2 | MSG_WITNESS_FLAG

        def block_hash_at(height):
            return int(node.getblockhash(height), 16)

        # Within the window: the tip and the boundary block (depth exactly
        # HORIZON) are served, for both message types.
        for height in (tip_height, tip_height - HORIZON):
            for inv_type in (MSG_BLOCK_INV, MSG_WITNESS_BLOCK_INV):
                h = block_hash_at(height)
                served_before = self.testnode.blocks[h]
                self.testnode.getdata(inv_type, h)
                assert_equal(self.testnode.blocks[h], served_before + 1)
                assert((inv_type, h) not in self.testnode.notfound)

        # Beyond the window (depth HORIZON + 1 and deeper): notfound for both
        # message types, and no block message.
        for height in (tip_height - HORIZON - 1, 1):
            for inv_type in (MSG_BLOCK_INV, MSG_WITNESS_BLOCK_INV):
                h = block_hash_at(height)
                self.testnode.getdata(inv_type, h)
                assert((inv_type, h) in self.testnode.notfound)
                assert_equal(self.testnode.blocks[h], 0)

        # The window follows the tip: mine one block and the old boundary
        # block falls out of the servable set.
        old_boundary = block_hash_at(tip_height - HORIZON)
        node.generate(1)
        self.testnode.getdata(MSG_BLOCK_INV, old_boundary)
        assert((MSG_BLOCK_INV, old_boundary) in self.testnode.notfound)


if __name__ == '__main__':
    WitnessPruneServingTest().main()
