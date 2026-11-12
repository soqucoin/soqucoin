#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# The activation heights a node reports for its height-gated deployments
# (Consensus::BIP9Deployment::nActivationHeight): the "activation_heights"
# object of getblockchaininfo, one startup line per deployment, and the
# regtest argument -activationheight=<deployment>:<height>. A deployment is
# active for a block iff the block's height is at or above the stored number
# (Consensus::DeploymentActiveAtHeight); 2147483647 is the stored number of a
# deployment with no height (BIP9Deployment::NOT_SCHEDULED), which mainnet
# holds for the three reported here and which the JSON prints as it is.
#
# Covered: the number and the startup line for a height, for 2147483647, for
# regtest's default of 0, for a given 0 and for three different heights on one
# node; the first block the rule is enforced in, with a witness v6 output
# whose witness script is not the committed one, spent in a block at the
# height minus one and refused in a block at the height, by the block check
# and by the mempool, which judges for the next block; the same block accepted
# by a node that holds no height; and the argument's refusals: a name the node
# does not report, a malformed value, a height out of range, one deployment
# named twice, and any network other than regtest.
#

import hashlib
import os
import subprocess
import time
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (assert_equal, assert_raises_jsonrpc,
                                 bytes_to_hex_str, initialize_datadir,
                                 soqucoind_processes, start_node, start_nodes,
                                 stop_node)
from test_framework.mininode import COIN, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.script import CScript, OP_1, OP_6

# The rows, in the order the node lists them.
DEPLOYMENTS = ['p2wsh_dilithium', 'dilithium_keyhash', 'v6_controlflow']
NOT_SCHEDULED = 2147483647
# The funding coinbase is in block 1 and regtest's coinbase maturity is 60, so
# its outputs are spendable from block 61; the two blocks that spend them are
# at HEIGHT - 1 and HEIGHT.
HEIGHT = 70

# The witness script the outputs commit to, OP_1, and the one that is revealed
# in its place, OP_2.
COMMITTED_SCRIPT = b'\x51'
OTHER_SCRIPT = b'\x52'
V6_OUTPUT = CScript([OP_6, hashlib.sha256(COMMITTED_SCRIPT).digest()])
# A witness v1 output for the spends to pay.
PLAIN_OUTPUT = CScript([OP_1, b'\x11' * 32])
MISMATCH = "mandatory-script-verify-flag-failed (Witness program hash mismatch)"


def heights(a, b, c):
    return dict(zip(DEPLOYMENTS, (a, b, c)))


def arguments(a, b, c):
    return ["-activationheight=%s:%d" % (name, height) for name, height in zip(DEPLOYMENTS, (a, b, c))]


def startup_lines(a, b, c):
    return ["Deployment %s: %s\n" % (name, "not scheduled" if height == NOT_SCHEDULED else "active from height %d" % height)
            for name, height in zip(DEPLOYMENTS, (a, b, c))]


def spend(funding, n, witness_script):
    """Spends output n of the funding transaction to a witness v1 output,
    revealing witness_script. The last witness item begins with 0x00, the
    shape CheckTransaction requires of every input."""
    tx = CTransaction()
    tx.nVersion = 2
    tx.vin.append(CTxIn(COutPoint(funding.sha256, n), b'', 0xffffffff))
    tx.vout.append(CTxOut(funding.vout[n].nValue - COIN // 10, PLAIN_OUTPUT))
    witness = CTxInWitness()
    witness.scriptWitness.stack = [witness_script, b'\x00']
    tx.wit.vtxinwit = [witness]
    tx.rehash()
    return tx


class ActivationHeightsTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self, split=False):
        self.is_network_split = False
        # Node 0 holds the three at HEIGHT, as a release that schedules them
        # does. Node 1 holds none, as mainnet does today. They are never
        # connected: each is given the other's blocks by submitblock. -par=1
        # checks scripts on the validation thread, where a block's refusal
        # keeps the script error (CheckInputs without a check queue).
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 [["-par=1"] + arguments(HEIGHT, HEIGHT, HEIGHT),
                                  ["-par=1"] + arguments(NOT_SCHEDULED, NOT_SCHEDULED, NOT_SCHEDULED)])

    def debug_log(self, i):
        with open(os.path.join(self.options.tmpdir, "node%d" % i, "regtest", "debug.log"), encoding="utf-8") as f:
            return f.read()

    def build_block(self, node, t, coinbase_outputs, txs=()):
        """The next block on node's tip, with the given coinbase outputs and
        transactions. Nothing is submitted."""
        tip = node.getblockheader(node.getbestblockhash())
        coinbase = create_coinbase(tip['height'] + 1)
        coinbase.vout = coinbase_outputs
        coinbase.rehash()
        block = create_block(int(tip['hash'], 16), coinbase, max(t, tip['mediantime'] + 1))
        block.nVersion = 4
        block.nBits = int(tip['bits'], 16)
        block.vtx.extend(txs)
        if txs:
            add_witness_commitment(block)
        block.solve()
        return block

    def started_then_stopped(self, i, args):
        """Starts a further node with args, reads what it reports, stops it,
        and returns the report and its log."""
        initialize_datadir(self.options.tmpdir, i)
        node = start_node(i, self.options.tmpdir, args)
        try:
            reported = node.getblockchaininfo()['activation_heights']
        finally:
            stop_node(node, i)
        return reported, self.debug_log(i)

    def refused(self, i, args, conf=()):
        """Starts a further node with args, and with the lines of conf added
        to its configuration file, which soqucoind must refuse during
        initialization, and returns what it printed. The refusal is printed
        on the daemon's stderr before its log opens, so stderr is captured to
        a file for the call (the test runner fails any test whose own stderr
        is not empty). No process of the node outlives the call: its entry
        leaves the process map, which the framework's teardown expects to be
        empty, and a process still alive is ended."""
        datadir = initialize_datadir(self.options.tmpdir, i)
        with open(os.path.join(datadir, "soqucoin.conf"), "a", encoding="utf8") as f:
            f.writelines(line + "\n" for line in conf)
        stderr_path = os.path.join(self.options.tmpdir, "node%d-stderr.txt" % i)
        started = False
        saved_stderr = os.dup(2)
        try:
            with open(stderr_path, "w") as captured:
                os.dup2(captured.fileno(), 2)
                try:
                    start_node(i, self.options.tmpdir, args)
                    started = True
                except Exception as e:
                    assert "exited with status 1 during initialization" in str(e), str(e)
        finally:
            os.dup2(saved_stderr, 2)
            os.close(saved_stderr)
            proc = soqucoind_processes.pop(i, None)
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        assert not started, "a node started with %s" % args
        with open(stderr_path, encoding="utf-8") as f:
            return f.read()

    def run_test(self):
        scheduled, unscheduled = self.nodes
        t = int(time.time())
        for node in self.nodes:
            node.setmocktime(t)

        # 0. Each node reports the heights it holds: by RPC, one number per
        #    deployment in the node's order, and at startup, one line per
        #    deployment. A deployment with no height prints 2147483647 in the
        #    JSON and "not scheduled" in the log.
        reported = scheduled.getblockchaininfo()['activation_heights']
        assert_equal(reported, heights(HEIGHT, HEIGHT, HEIGHT))
        assert_equal(list(reported.keys()), DEPLOYMENTS)
        for line in startup_lines(HEIGHT, HEIGHT, HEIGHT):
            assert_equal(self.debug_log(0).count(line), 1)
        reported = unscheduled.getblockchaininfo()['activation_heights']
        assert_equal(reported, heights(NOT_SCHEDULED, NOT_SCHEDULED, NOT_SCHEDULED))
        assert all(type(height) is int for height in reported.values())
        for line in startup_lines(NOT_SCHEDULED, NOT_SCHEDULED, NOT_SCHEDULED):
            assert_equal(self.debug_log(1).count(line), 1)
        described = scheduled.help('getblockchaininfo')
        assert '"activation_heights"' in described
        assert "2147483647 = not scheduled" in described

        # 1. Block 1 pays two witness v6 outputs from its coinbase, both
        #    committing to COMMITTED_SCRIPT. Both nodes connect it and the
        #    blocks that follow, up to HEIGHT - 2.
        funding_block = self.build_block(scheduled, t, [CTxOut(4 * COIN // 10, V6_OUTPUT), CTxOut(4 * COIN // 10, V6_OUTPUT)])
        funding = funding_block.vtx[0]
        for node in self.nodes:
            assert_equal(node.submitblock(bytes_to_hex_str(funding_block.serialize())), None)
        for block_hash in scheduled.generate(HEIGHT - 3):
            assert_equal(unscheduled.submitblock(scheduled.getblock(block_hash, False)), None)
        for node in self.nodes:
            assert_equal(node.getblockcount(), HEIGHT - 2)
            assert_equal(node.getbestblockhash(), scheduled.getbestblockhash())

        # 2. Below the height a witness v6 output is spendable by anyone. A
        #    spend of the first output that reveals OTHER_SCRIPT enters the
        #    mempool at tip HEIGHT - 2, where the next block is HEIGHT - 1,
        #    and a block at HEIGHT - 1 that carries it connects.
        early = spend(funding, 0, OTHER_SCRIPT)
        assert_equal(scheduled.sendrawtransaction(bytes_to_hex_str(early.serialize_with_witness())), early.hash)
        assert_equal(scheduled.getrawmempool(), [early.hash])
        below = self.build_block(scheduled, t, [CTxOut(COIN // 2, PLAIN_OUTPUT)], [early])
        for node in self.nodes:
            assert_equal(node.submitblock(bytes_to_hex_str(below.serialize(True))), None)
            assert_equal(node.getblockcount(), HEIGHT - 1)
            assert_equal(node.getbestblockhash(), below.hash)
        assert early.hash in scheduled.getblock(below.hash)['tx']
        assert_equal(scheduled.getrawmempool(), [])

        # 3. At the height the same spend of the second output is refused:
        #    by the mempool at tip HEIGHT - 1, where the next block is HEIGHT,
        #    and in a block at HEIGHT, which the node does not connect.
        late = spend(funding, 1, OTHER_SCRIPT)
        assert_raises_jsonrpc(-26, MISMATCH, scheduled.sendrawtransaction, bytes_to_hex_str(late.serialize_with_witness()))
        at_height = self.build_block(scheduled, t, [CTxOut(COIN // 2, PLAIN_OUTPUT)], [late])
        assert_equal(scheduled.submitblock(bytes_to_hex_str(at_height.serialize(True))), MISMATCH)
        assert_equal(scheduled.getblockcount(), HEIGHT - 1)
        assert_equal(scheduled.getbestblockhash(), below.hash)

        # 4. The node that holds no height connects that block: nothing but
        #    the height separates the two nodes.
        assert_equal(unscheduled.submitblock(bytes_to_hex_str(at_height.serialize(True))), None)
        assert_equal(unscheduled.getblockcount(), HEIGHT)
        assert_equal(unscheduled.getbestblockhash(), at_height.hash)

        # 5. At the height the committed script still spends the output: the
        #    block at HEIGHT that reveals COMMITTED_SCRIPT connects.
        rightful = spend(funding, 1, COMMITTED_SCRIPT)
        enforced = self.build_block(scheduled, t, [CTxOut(COIN // 2, PLAIN_OUTPUT)], [rightful])
        assert_equal(scheduled.submitblock(bytes_to_hex_str(enforced.serialize(True))), None)
        assert_equal(scheduled.getblockcount(), HEIGHT)
        assert_equal(scheduled.getbestblockhash(), enforced.hash)
        assert rightful.hash in scheduled.getblock(enforced.hash)['tx']

        # 6. A node with no argument reports regtest's own heights, 0 for the
        #    three. A node given three different heights reports each
        #    deployment's own: every value sets one deployment and no other.
        reported, log = self.started_then_stopped(2, [])
        assert_equal(reported, heights(0, 0, 0))
        for line in startup_lines(0, 0, 0):
            assert_equal(log.count(line), 1)
        reported, log = self.started_then_stopped(3, arguments(11, NOT_SCHEDULED, 13))
        assert_equal(reported, heights(11, NOT_SCHEDULED, 13))
        for line in startup_lines(11, NOT_SCHEDULED, 13):
            assert_equal(log.count(line), 1)
        #    0 is the lowest height the argument takes: a node given 0 for
        #    the three starts and reports 0.
        reported, log = self.started_then_stopped(5, arguments(0, 0, 0))
        assert_equal(reported, heights(0, 0, 0))
        for line in startup_lines(0, 0, 0):
            assert_equal(log.count(line), 1)

        # 7. The argument's refusals on regtest. A name must be one the node
        #    reports: "usdsoq" and "segwit" are deployments, and are refused
        #    with the name that is none.
        for value in ("nosuchdeployment:5", "usdsoq:5", "segwit:5", ":5"):
            assert "Invalid -activationheight (%s): the deployment is not one listed under activation_heights" % value in self.refused(4, ["-activationheight=" + value])
        #    A value is <deployment>:<height> with a decimal height from 0 to
        #    2147483647. -1 is the stored number of a deployment that has no
        #    height gate at all, and is refused with every negative height.
        for value in ("p2wsh_dilithium", "p2wsh_dilithium:", "p2wsh_dilithium:5:6", "p2wsh_dilithium: 5",
                      "p2wsh_dilithium:5 ", "p2wsh_dilithium:0x5", "p2wsh_dilithium:five", "p2wsh_dilithium=5",
                      "p2wsh_dilithium:-1", "p2wsh_dilithium:-2147483648", "p2wsh_dilithium:2147483648", ""):
            assert "Invalid -activationheight (%s): expected <deployment>:<height>" % value in self.refused(4, ["-activationheight=" + value])
        assert "Invalid -activationheight (0): expected <deployment>:<height>" in self.refused(4, ["-noactivationheight"])
        #    One deployment is named once, on the command line and in the
        #    configuration file together. The file's values are read after
        #    the command line's, so the refusal names the file's.
        assert ("Invalid -activationheight (p2wsh_dilithium:6): the deployment is named more than once"
                in self.refused(4, ["-activationheight=p2wsh_dilithium:5", "-activationheight=p2wsh_dilithium:6"]))
        assert ("Invalid -activationheight (p2wsh_dilithium:5): the deployment is named more than once"
                in self.refused(4, ["-activationheight=p2wsh_dilithium:6"], conf=["activationheight=p2wsh_dilithium:5"]))

        # 8. The argument is refused on every other network, before any value
        #    is read. Each of these processes also carries
        #    -chainidrequiredheight, a regtest-only argument that is refused
        #    later in the same function, and -connect=0: a binary without this
        #    refusal stops at that one, so no process here gets as far as a
        #    data directory lock, a port or a connection.
        for network in ([], ["-testnet=1"], ["-stagenet=1"]):
            printed = self.refused(4, ["-regtest=0"] + network +
                                   ["-activationheight=p2wsh_dilithium:%d" % HEIGHT, "-chainidrequiredheight=1", "-connect=0"])
            assert "-activationheight may only be set on regtest." in printed, printed


if __name__ == '__main__':
    ActivationHeightsTest().main()
