#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Block-1 launch time gate (Consensus::Params::nMinBlock1Time, bead w3y1):
# the block at height 1 must carry nTime at or after the gate; mainnet carries
# 2026-10-13T15:00:00Z. The unit test (consensus_validation_tests,
# block1_time_gate) drives the check and the miner in process; this covers what
# it cannot: the -minblock1time regtest path through init and its startup line,
# getblocktemplate refused before the launch hour and its mintime at the gate,
# a block 1 timed before the gate arriving from a peer that has no gate (refused
# with DoS 100, so the peer is dropped; a loopback peer is never banned, only
# disconnected), the gated node mining its own block 1 once its clock reaches
# the gate, height 2 carrying no gate, and the option's bound at the 32-bit
# nTime maximum.
#

import os
import subprocess
import time
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (assert_equal, assert_raises_jsonrpc,
                                 connect_nodes_bi, initialize_datadir,
                                 soqucoind_processes, start_node, start_nodes,
                                 stop_node)

# The mainnet constant; any value above the regtest genesis time would do.
GATE = 1791903600


class Block1TimeGateTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self, split=False):
        self.is_network_split = False
        # Node 0 carries the gate. Node 1 has none: a peer on a binary without
        # the rule.
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 [["-debug", "-minblock1time=%d" % GATE],
                                  ["-debug"]])
        connect_nodes_bi(self.nodes, 0, 1)

    def debug_log(self, i):
        with open(os.path.join(self.options.tmpdir, "node%d" % i, "regtest", "debug.log"), encoding="utf-8") as f:
            return f.read()

    def run_test(self):
        gated, plain = self.nodes
        for node in self.nodes:
            node.setmocktime(GATE - 60)
        assert_equal(gated.getblockcount(), 0)

        # 0. The startup line names the gate this binary enforces.
        assert "Block 1 time gate: nTime >= %d (2026-10-13T15:00:00Z)" % GATE in self.debug_log(0)
        assert "Block 1 time gate: none" in self.debug_log(1)

        # 1. Before the gate the gated node's own miner cannot build block 1, and
        #    a template request is refused with the gate's reject string (what a
        #    mining node answers before the launch hour; on mainnet the template
        #    RPC also needs mining enabled and a tip-age override at genesis). At
        #    the gate the template is built, and its mintime is exactly the gate:
        #    a BIP23 client may roll the time down to mintime, which at height 1
        #    would otherwise be the genesis median time past plus one.
        assert_raises_jsonrpc(-1, "block1-before-launch", gated.generate, 1)
        assert_equal(gated.getblockcount(), 0)
        assert_raises_jsonrpc(-1, "block1-before-launch", gated.getblocktemplate)
        gated.setmocktime(GATE)
        template = gated.getblocktemplate()
        assert_equal(template['mintime'], GATE)
        assert template['curtime'] >= GATE, template['curtime']
        gated.setmocktime(GATE - 60)

        # 2. A block 1 timed before the gate, mined by the node without it, is
        #    refused by the gated node, which drops the peer that announced it.
        #    The reject is read from the line AcceptBlockHeader writes for that
        #    block's hash: step 1 already wrote the bare reject string to this
        #    log through the miner's own validity check.
        plain.generate(1)
        assert_equal(plain.getblockcount(), 1)
        plain_hash = plain.getbestblockhash()
        assert plain.getblock(plain_hash)['time'] < GATE
        for _ in range(120):
            if gated.getpeerinfo() == []:
                break
            time.sleep(0.5)
        assert_equal(gated.getblockcount(), 0)
        assert_equal(gated.getpeerinfo(), [])
        log = self.debug_log(0)
        assert ("AcceptBlockHeader: Consensus::ContextualCheckBlockHeader: %s, block1-before-launch" % plain_hash) in log
        assert "BAN THRESHOLD EXCEEDED" in log

        # 3. At the gate the gated node mines block 1, timed at or after it.
        gated.setmocktime(GATE)
        block1 = gated.generate(1)[0]
        assert_equal(gated.getblockcount(), 1)
        assert gated.getblock(block1)['time'] >= GATE

        # 4. Height 2 carries no gate: the next block follows at once.
        gated.setmocktime(GATE + 1)
        gated.generate(1)
        assert_equal(gated.getblockcount(), 2)

        # 5. The regtest option is bounded to a block header's 32-bit nTime: the
        #    largest value starts a node and is formatted on its startup line;
        #    one more refuses to start. That refusal is printed on the daemon's
        #    stderr before its log opens, so the daemon's stderr is captured to a
        #    file for the check (the test runner fails any test whose own stderr
        #    is not empty). Whatever happens in this step, no process of the
        #    third node outlives it: the outer clause pops its entry from the
        #    process map (the framework's teardown stops nodes 0 and 1 only and
        #    then asserts the map is empty) and ends a process still alive.
        initialize_datadir(self.options.tmpdir, 2)
        stderr_path = os.path.join(self.options.tmpdir, "node2-stderr.txt")
        started_above_range = False
        try:
            node2 = start_node(2, self.options.tmpdir, ["-minblock1time=4294967295"])
            stop_node(node2, 2)
            assert "Block 1 time gate: nTime >= 4294967295 (2106-02-07T06:28:15Z)" in self.debug_log(2)
            saved_stderr = os.dup(2)
            try:
                with open(stderr_path, "w") as captured:
                    os.dup2(captured.fileno(), 2)
                    try:
                        start_node(2, self.options.tmpdir, ["-minblock1time=4294967296"])
                        started_above_range = True
                    except Exception as e:
                        assert "exited with status 1 during initialization" in str(e), str(e)
            finally:
                os.dup2(saved_stderr, 2)
                os.close(saved_stderr)
        finally:
            proc = soqucoind_processes.pop(2, None)
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        assert not started_above_range, "a node started with -minblock1time above the nTime range"
        with open(stderr_path, encoding="utf-8") as f:
            assert "Invalid -minblock1time" in f.read()


if __name__ == '__main__':
    Block1TimeGateTest().main()
