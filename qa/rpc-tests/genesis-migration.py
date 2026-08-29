#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Genesis-migration one-shot allocation rule, end to end through a real node
# (DL-GENESIS-MIGRATION-IMPLEMENTATION section A; the full 10-case tamper
# matrix lives in src/test/migration_rule_tests.cpp, driven through
# ConnectBlock with named reject strings).
#
# This test covers what the unit suite cannot: the -migrationoutputs /
# -migrationheight / -migrationtotal regtest arming path through init, the
# production miner emitting the committed outputs at exactly the armed height,
# and the window being one block wide on a live chain.
#

import struct
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

MIGRATION_HEIGHT = 5

# Witness v1 (OP_1 <32 bytes>) — the shape real sq1 allocations have.
def v1_script(seed):
    return bytes([0x51, 0x20]) + bytes([seed] * 32)

# Values sit above the SOQ-ARCH-003 utxo-cost floor (6,500 sat/byte, active
# from height 0 on regtest), as every real allocation does (dust floor 1 SOQ).
ALLOCATIONS = [
    (10 * 100000000, v1_script(0xA1)),
    (20 * 100000000, v1_script(0xA2)),
    (50000000, v1_script(0xA3)),
]

# Standard CTxOut vector serialization, hand-rolled rather than imported from
# test_framework.mininode (which drags in asyncore, removed in Python 3.12).
def ser_compact_size(n):
    assert n < 253  # all this test ever needs
    return struct.pack("B", n)

def migration_outputs_hex():
    r = ser_compact_size(len(ALLOCATIONS))
    for (value, script) in ALLOCATIONS:
        r += struct.pack("<q", value) + ser_compact_size(len(script)) + script
    return bytes_to_hex_str(r)

class GenesisMigrationTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.is_network_split = False
        self.nodes = [start_node(0, self.options.tmpdir,
                                 ["-debug", "-txindex=1",
                                  "-migrationoutputs=%s" % migration_outputs_hex(),
                                  "-migrationheight=%d" % MIGRATION_HEIGHT])]

    def coinbase_vout(self, height):
        block_hash = self.nodes[0].getblockhash(height)
        block = self.nodes[0].getblock(block_hash)
        return self.nodes[0].getrawtransaction(block['tx'][0], 1)['vout']

    def run_test(self):
        node = self.nodes[0]

        # Below the armed height the rule is inert: plain coinbases.
        node.generate(MIGRATION_HEIGHT - 1)
        assert_equal(node.getblockcount(), MIGRATION_HEIGHT - 1)
        for height in range(1, MIGRATION_HEIGHT):
            vout = self.coinbase_vout(height)
            for out in vout[1:]:
                assert_equal(out['value'], Decimal(0))  # only the witness commitment trails

        # The migration block: the production miner must emit the committed
        # outputs as vout[1..N], in committed order, and the network accepts it.
        node.generate(1)
        assert_equal(node.getblockcount(), MIGRATION_HEIGHT)
        vout = self.coinbase_vout(MIGRATION_HEIGHT)
        assert len(vout) >= 1 + len(ALLOCATIONS), "migration block coinbase is missing committed outputs"
        for i, (value, script) in enumerate(ALLOCATIONS):
            got = vout[1 + i]
            assert_equal(got['value'], Decimal(value) / Decimal(100000000))
            assert_equal(got['scriptPubKey']['hex'], bytes_to_hex_str(script))

        # The window is one block wide: the very next coinbase is plain again.
        node.generate(1)
        assert_equal(node.getblockcount(), MIGRATION_HEIGHT + 1)
        vout = self.coinbase_vout(MIGRATION_HEIGHT + 1)
        for out in vout[1:]:
            assert_equal(out['value'], Decimal(0))

        # And the chain keeps extending normally past the window.
        node.generate(3)
        assert_equal(node.getblockcount(), MIGRATION_HEIGHT + 4)

        print("Genesis-migration functional test passed")

if __name__ == '__main__':
    GenesisMigrationTest().main()
