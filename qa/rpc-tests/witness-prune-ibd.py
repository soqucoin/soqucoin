#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
PAT witness pruning, stage 2: sync-from-unpruned (doc/PAT_WITNESS_PRUNING.md
test plan item 6).

A fresh node performs IBD with both an unpruned peer and a witness-pruned
(NODE_NETWORK_LIMITED) peer connected, and completes. The limited peer is
connected first so that a wrong peer-selection or block-request path would
prefer it and stall the sync: most of the chain is deeper than the horizon,
which the limited peer answers with notfound.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes_bi,
    p2p_port,
    start_node,
    sync_blocks,
)

NODE_NETWORK = 1 << 0
NODE_WITNESS = 1 << 3
NODE_NETWORK_LIMITED = 1 << 10

HORIZON = 10
CHAIN_LENGTH = 40


class WitnessPruneIBDTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 3

    def setup_network(self, split=False):
        # node 0: unpruned. node 1: witness-pruned. node 2 starts in run_test
        # so that its whole life is an IBD against the two of them.
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir,
            ["-maxreorgdepth=%d" % HORIZON]))
        self.nodes.append(start_node(1, self.options.tmpdir,
            ["-maxreorgdepth=%d" % HORIZON, "-witnessprune=1"]))
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False

    def run_test(self):
        self.nodes[0].generate(CHAIN_LENGTH)
        sync_blocks(self.nodes)
        best_hash = self.nodes[0].getbestblockhash()
        assert_equal(self.nodes[1].getbestblockhash(), best_hash)

        # Fresh node, limited peer connected first.
        self.nodes.append(start_node(2, self.options.tmpdir,
            ["-maxreorgdepth=%d" % HORIZON]))
        connect_nodes_bi(self.nodes, 2, 1)
        connect_nodes_bi(self.nodes, 2, 0)

        # The pruned peer must be advertising limited, not full, service to
        # the syncing node — otherwise this test proves nothing.
        limited_peers = [p for p in self.nodes[2].getpeerinfo()
                         if "%d" % p2p_port(1) in p['addr']]
        assert(len(limited_peers) > 0)
        for p in limited_peers:
            services = int(p['services'], 16)
            assert(services & NODE_NETWORK_LIMITED)
            assert(services & NODE_WITNESS)
            assert(not (services & NODE_NETWORK))

        # The IBD must complete; a wrong request path stalls here on blocks
        # the limited peer answers with notfound.
        sync_blocks(self.nodes, timeout=120)
        assert_equal(self.nodes[2].getbestblockhash(), best_hash)

        # Steady state with a limited peer connected still works.
        self.nodes[0].generate(1)
        sync_blocks(self.nodes)
        assert_equal(self.nodes[2].getblockcount(), CHAIN_LENGTH + 1)
        assert_equal(self.nodes[1].getblockcount(), CHAIN_LENGTH + 1)


if __name__ == '__main__':
    WitnessPruneIBDTest().main()
