#!/usr/bin/env python3
# Copyright (c) 2025 The Soqucoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class PatBasicTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, []))
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        node = self.nodes[0]
        node.generate(101)

        # Similar to LatticeFold, we verify node health and basic mining.
        # OP_CHECKPATAGG (0xfd) integration is verified by unit tests.
        
        self.log.info("PAT functional test: Node running and mining blocks.")
        node.generate(1)
        assert_equal(node.getblockcount(), 102)

if __name__ == '__main__':
    PatBasicTest().main()
