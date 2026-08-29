#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# The -enablemining gate (launch mining posture, bead
# launch-mining-posture-gate-92yq, ratified 2026-08-29).
#
# Work-serving RPCs (getblocktemplate, generate, generatetoaddress and the
# createauxblock family) refuse unless -enablemining is set; the default is ON
# everywhere except mainnet. Regtest's default is ON — every other functional
# test proves that path by mining — so this test drives the gate explicitly
# with -enablemining=0, then proves the opt-in restores service.
#
# The mainnet DEFAULT (off) cannot be driven here (no mainnet in qa); it is
# one line in EnsureMiningRPCsEnabled and is verified in the artifact by
# audit lane A5 (PRE_LAUNCH_AUDIT_PLAN_FC4.md).
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

GATE_MSG = "Mining RPCs are disabled"

class MiningGateTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.is_network_split = False
        self.nodes = [start_node(0, self.options.tmpdir,
                                 ["-debug", "-enablemining=0"])]

    def assert_gated(self, fn, *args):
        try:
            fn(*args)
        except JSONRPCException as e:
            assert GATE_MSG in e.error["message"], (
                "expected the gate, got: %s" % e.error["message"])
            return
        raise AssertionError("%s was served despite -enablemining=0" % fn)

    def run_test(self):
        node = self.nodes[0]

        # Every work-serving RPC refuses, with the gate's own message.
        self.assert_gated(node.getblocktemplate)
        self.assert_gated(node.generate, 1)
        self.assert_gated(node.generatetoaddress, 1, node.getnewaddress())
        self.assert_gated(node.createauxblock, node.getnewaddress())
        self.assert_gated(node.getauxblock)

        # Read-only introspection and block acceptance are NOT gated.
        node.getmininginfo()
        try:
            node.submitblock("00")   # garbage: must fail on CONTENT, not the gate
        except JSONRPCException as e:
            assert GATE_MSG not in e.error["message"]

        # The opt-in restores service.
        stop_node(node, 0)
        self.nodes[0] = start_node(0, self.options.tmpdir,
                                   ["-debug", "-enablemining=1"])
        node = self.nodes[0]
        node.generate(2)
        assert_equal(node.getblockcount(), 2)

        print("Mining-gate functional test passed")

if __name__ == '__main__':
    MiningGateTest().main()
