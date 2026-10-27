#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Chain id rule (Consensus::Params::nChainIdRequiredHeight, bead 0o4b0): from
# the height every block that is not a legacy block must carry chain id 0x5351
# in the high bits of its version, merge-mined or not; 0 = no rule, which every
# network carries until a release schedules it. The unit test
# (consensus_validation_tests, chainid_required_height) drives the check and
# the miner in process; this covers what it cannot: the -chainidrequiredheight
# regtest path through init and its startup line; a direct block without the
# id, built with the scrypt helper as the parent of a merge-mined block,
# accepted below the height and refused at it; the same block arriving from a
# peer that has no rule (refused with DoS 0, so the peer is kept and the armed
# node stays on its tip); that peer reorganizing onto the armed node's chain
# once it is the heavier one; a peer that keeps building on the refused block,
# whose announcements no longer connect, disconnected by the unconnecting-
# headers rule (a loopback peer is never banned, only disconnected); the armed
# node's own blocks at the height; the peer restarted with the rule, keeping
# the chain it connected without it until a replay of its block files; and
# the option's bounds.
#

import os
import re
import struct
import subprocess
import time
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (assert_equal, assert_raises_jsonrpc,
                                 connect_nodes_bi, initialize_datadir,
                                 soqucoind_processes, start_node, start_nodes,
                                 stop_node, sync_blocks)
from test_framework.mininode import CBlockHeader, ser_string, ser_uint256
from test_framework.blocktools import create_block, create_coinbase, serialize_script_num

# Above the regtest AuxPoW start (20), so the merge-mined block of each pair
# below is in the AuxPoW era.
HEIGHT = 30
CHAIN_ID = 0x5351
# What the miner stamps on a direct block: base version 4, chain id 0x5351,
# the release mark at bit 15 (CPureBlockHeader::VERSION_RELEASE_MARK).
STAMPED_VERSION = (CHAIN_ID << 16) | (1 << 15) | 4
# The merge-mining tag that precedes the child's hash in the parent's coinbase.
MERGED_MINING_HEADER = b"\xfa\xbe" + b"mm"
# The unconnecting-headers rule (net_processing.cpp, MAX_UNCONNECTING_HEADERS):
# every tenth headers announcement that does not connect scores the peer 20,
# and 100 (DEFAULT_BANSCORE_THRESHOLD) is the ban threshold, reached at the
# fiftieth.
UNCONNECTING_HEADERS_PER_SCORE = 10
UNCONNECTING_HEADERS_SCORE = 20
BAN_THRESHOLD = 100
ANNOUNCEMENTS_TO_DISCONNECT = BAN_THRESHOLD // UNCONNECTING_HEADERS_SCORE * UNCONNECTING_HEADERS_PER_SCORE


class ChainIdRequiredHeightTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self, split=False):
        self.is_network_split = False
        # Node 0 carries the rule. Node 1 has none, and its miner stamps base
        # version 4 with no chain id: a peer on a binary without the rule
        # whose miner does not stamp the id.
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 [["-debug", "-chainidrequiredheight=%d" % HEIGHT],
                                  ["-debug", "-blockversion=4"]])
        connect_nodes_bi(self.nodes, 0, 1)

    def debug_log(self, i):
        with open(os.path.join(self.options.tmpdir, "node%d" % i, "regtest", "debug.log"), encoding="utf-8") as f:
            return f.read()

    def wait_for_log(self, i, predicate, timeout=60):
        """Polls node i's debug log until predicate(log) holds, for at most
        timeout seconds."""
        deadline = time.time() + timeout
        while True:
            log = self.debug_log(i)
            if predicate(log):
                return log
            assert time.time() < deadline, "node%d: the expected log lines did not appear within %d seconds" % (i, timeout)
            time.sleep(0.5)

    def reconnect(self):
        """Drops every connection between the two nodes and connects them
        again, so that each side's per-peer state starts fresh."""
        armed, plain = self.nodes
        for peer in armed.getpeerinfo():
            armed.disconnectnode(peer['addr'])
        for _ in range(120):
            if armed.getpeerinfo() == [] and plain.getpeerinfo() == []:
                break
            time.sleep(0.5)
        assert_equal(armed.getpeerinfo(), [])
        assert_equal(plain.getpeerinfo(), [])
        connect_nodes_bi(self.nodes, 0, 1)

    def build_pair(self, node, t):
        """A merge-mined block on node's tip and its parent block, built as
        the next block of this chain with base version 4 and chain id 0.
        Returns the child's hash, its auxpow and the parent block; nothing is
        submitted."""
        aux = node.getauxblock()
        child_hash = aux['hash']
        height = aux['height']
        # The child is timed at the node's clock or one past the median time,
        # whichever is later; the parent follows it by a second.
        median = node.getblockheader(node.getbestblockhash())['mediantime']
        child_time = max(t, median + 1)
        coinbase = create_coinbase(height + 1)
        coinbase.vin[0].scriptSig = (ser_string(serialize_script_num(height + 1)) +
                                     MERGED_MINING_HEADER + bytes.fromhex(child_hash) +
                                     struct.pack("<I", 1) + struct.pack("<I", 0))
        coinbase.rehash()
        parent = create_block(int(child_hash, 16), coinbase, child_time + 1)
        parent.nVersion = 4
        parent.nBits = int(aux['bits'], 16)
        parent.solve()
        auxpow = (coinbase.serialize_without_witness() + ser_uint256(parent.sha256) +
                  b"\x00" + struct.pack("<i", 0) + b"\x00" + struct.pack("<i", 0) +
                  CBlockHeader.serialize(parent))
        return child_hash, auxpow.hex(), parent

    def run_test(self):
        armed, plain = self.nodes
        t = int(time.time())
        for node in self.nodes:
            node.setmocktime(t)

        # 0. The startup line names the rule this binary enforces.
        assert "Chain id rule: 0x5351 required from height %d" % HEIGHT in self.debug_log(0)
        assert "Chain id rule: none" in self.debug_log(1)
        assert_equal(armed.getblockchaininfo()['chainid_required_height'], HEIGHT)
        assert_equal(plain.getblockchaininfo()['chainid_required_height'], 0)

        # 1. Below the height the armed node accepts the peer's blocks without
        #    the id: what every node does today.
        plain.generate(HEIGHT - 6)
        self.sync_all()
        assert_equal(armed.getblockcount(), HEIGHT - 6)
        assert_equal(armed.getblock(armed.getbestblockhash())['version'], 4)

        # 2. The pair below the height: the merge-mined child at HEIGHT - 5 and
        #    its parent at HEIGHT - 4 both connect, on the armed node and on
        #    the peer.
        child_hash, auxpow, parent = self.build_pair(armed, t)
        assert_equal(armed.getauxblock(child_hash, auxpow), True)
        assert_equal(armed.getblockcount(), HEIGHT - 5)
        assert_equal(armed.submitblock(parent.serialize().hex()), None)
        assert_equal(armed.getblockcount(), HEIGHT - 4)
        assert_equal(armed.getbestblockhash(), parent.hash)
        assert_equal(armed.getblock(parent.hash)['previousblockhash'], child_hash)
        assert_equal(armed.getblock(parent.hash)['version'], 4)
        self.sync_all()
        assert_equal(plain.getbestblockhash(), parent.hash)

        # 3. The pair at the height: the child at HEIGHT - 1 carries the id and
        #    connects; its parent at HEIGHT carries none and is refused by the
        #    armed node, which stays on the child.
        plain.generate(2)
        self.sync_all()
        assert_equal(armed.getblockcount(), HEIGHT - 2)
        child_hash, auxpow, parent = self.build_pair(armed, t)
        assert_equal(armed.getauxblock(child_hash, auxpow), True)
        assert_equal(armed.getblockcount(), HEIGHT - 1)
        assert_equal(armed.getbestblockhash(), child_hash)
        self.sync_all()
        assert_equal(armed.submitblock(parent.serialize().hex()), "bad-chain-id")
        assert_equal(armed.getblockcount(), HEIGHT - 1)
        assert_equal(armed.getbestblockhash(), child_hash)
        refusal = "AcceptBlockHeader: Consensus::ContextualCheckBlockHeader: %s, bad-chain-id" % parent.hash
        assert_equal(self.debug_log(0).count(refusal), 1)

        # 4. The peer, with no rule, accepts the same parent and extends its
        #    chain with it. It announces the parent on both connections, by
        #    headers or by compact block, and the armed node refuses the
        #    header each time with DoS 0: the refusal is logged once more per
        #    connection and no more, both connections stay at a ban score of
        #    0, and the armed node stays on the child.
        assert_equal(plain.submitblock(parent.serialize().hex()), None)
        assert_equal(plain.getblockcount(), HEIGHT)
        assert_equal(plain.getbestblockhash(), parent.hash)
        log = self.wait_for_log(0, lambda log: log.count(refusal) >= 3)
        assert_equal(log.count(refusal), 3)
        assert "invalid header received" in log or "sent us invalid header via cmpctblock" in log
        assert "BAN THRESHOLD EXCEEDED" not in log
        assert_equal([peer['banscore'] for peer in armed.getpeerinfo()], [0, 0])
        assert_equal(armed.getblockcount(), HEIGHT - 1)
        assert_equal(armed.getbestblockhash(), child_hash)

        # 5. The armed node's own blocks at and above the height carry the id
        #    and connect, and its chain is now the heavier one. The peer, still
        #    connected and without the rule, reorganizes onto it; the parent
        #    stays in the peer's index as a valid fork of one block and is in
        #    no index of the armed node's.
        armed.generate(2)
        assert_equal(armed.getblockcount(), HEIGHT + 1)
        for h in (HEIGHT, HEIGHT + 1):
            assert_equal(armed.getblock(armed.getblockhash(h))['version'], STAMPED_VERSION)
        armed_at_height = armed.getblockhash(HEIGHT)
        armed_tip = armed.getbestblockhash()
        sync_blocks(self.nodes)
        assert_equal(plain.getbestblockhash(), armed_tip)
        assert_equal(plain.getblockcount(), HEIGHT + 1)
        tips = {tip['hash']: tip for tip in plain.getchaintips()}
        assert_equal(tips[parent.hash]['status'], 'valid-fork')
        assert_equal(tips[parent.hash]['branchlen'], 1)
        assert parent.hash not in [tip['hash'] for tip in armed.getchaintips()]
        assert_equal([peer['banscore'] for peer in armed.getpeerinfo()], [0, 0])

        # 6. A peer that keeps building on the refused block. The connections
        #    are made afresh first: the armed node may have asked the old ones
        #    to announce by compact block (it asks that of a peer that has
        #    delivered it valid blocks), and a compact block that does not
        #    connect draws a headers request and no score, so only headers
        #    announcements count below. The peer puts the parent back at its
        #    tip and mines on it one block at a time. Each announcement names
        #    a previous block the armed node never indexed, so none connects:
        #    the armed node asks for headers, is given the parent first and
        #    refuses it again at DoS 0, and counts the announcement under the
        #    unconnecting-headers rule, which scores 20 every tenth and so
        #    reaches the ban threshold at the fiftieth. The armed node then
        #    disconnects the peer (local, so never banned) and has not moved.
        self.reconnect()
        # The armed node asks each new connection for headers at once. Wait
        # until both replies are in, so that no reply below is answered from
        # the peer's chain as it stands after the next step.
        ids = [peer['id'] for peer in armed.getpeerinfo()]
        assert_equal(len(ids), 2)
        self.wait_for_log(0, lambda log: all(re.search(r"received: headers \(\d+ bytes\) peer=%d(?!\d)" % i, log) for i in ids))
        refusals = self.debug_log(0).count(refusal)
        plain.invalidateblock(armed_at_height)
        assert_equal(plain.getbestblockhash(), parent.hash)
        # The peer announces its new tip, the parent, on both connections; it
        # connects and is refused once more on each. Wait for both, so that
        # the first block built on it below is announced on its own.
        self.wait_for_log(0, lambda log: log.count(refusal) >= refusals + 2)
        refusals += 2
        for k in range(1, ANNOUNCEMENTS_TO_DISCONNECT + 1):
            plain.generate(1)
            # Each connection logs the announcement as unconnecting, asks the
            # peer for headers, and refuses the parent at the head of the
            # reply. Wait for both replies before the next block: a block
            # mined before the peer has answered would be folded into that
            # reply and never announced on its own. At the fiftieth the peer
            # is dropped, and the reply may or may not be read before that.
            self.wait_for_log(0, lambda log: log.count("nUnconnectingHeaders=%d)" % k) >= 2)
            if k < ANNOUNCEMENTS_TO_DISCONNECT:
                self.wait_for_log(0, lambda log: log.count(refusal) >= refusals + 2)
                refusals += 2
            if k < ANNOUNCEMENTS_TO_DISCONNECT and k % UNCONNECTING_HEADERS_PER_SCORE == 0:
                score = k // UNCONNECTING_HEADERS_PER_SCORE * UNCONNECTING_HEADERS_SCORE
                assert_equal([peer['banscore'] for peer in armed.getpeerinfo()], [score, score])
        for _ in range(120):
            if armed.getpeerinfo() == []:
                break
            time.sleep(0.5)
        assert_equal(armed.getpeerinfo(), [])
        log = self.debug_log(0)
        assert "BAN THRESHOLD EXCEEDED" in log
        assert "not banning local peer" in log
        assert_equal(armed.listbanned(), [])
        assert_equal(armed.getbestblockhash(), armed_tip)
        assert_equal(plain.getblockcount(), HEIGHT + ANNOUNCEMENTS_TO_DISCONNECT)
        plain_tip = plain.getbestblockhash()

        # 7. The peer connected the parent, and the blocks on it, before it
        #    carried the rule. A node trusts its index as it stands on restart,
        #    for this rule as for every height-activated one, so restarted with
        #    the rule the peer stays on that chain; restarted with the rule and
        #    -reindex, the parent's header is refused as the block files
        #    replay, every block built on it is left without a parent, and the
        #    peer ends on the armed node's chain, whose blocks follow the
        #    parent in its files.
        stop_node(plain, 1)
        plain = self.nodes[1] = start_node(1, self.options.tmpdir,
                                           ["-debug", "-blockversion=4", "-chainidrequiredheight=%d" % HEIGHT])
        assert "Chain id rule: 0x5351 required from height %d" % HEIGHT in self.debug_log(1)
        assert_equal(plain.getblockchaininfo()['chainid_required_height'], HEIGHT)
        assert_equal(plain.getblockcount(), HEIGHT + ANNOUNCEMENTS_TO_DISCONNECT)
        assert_equal(plain.getbestblockhash(), plain_tip)
        assert_equal(plain.getblock(parent.hash)['height'], HEIGHT)
        stop_node(plain, 1)
        plain = self.nodes[1] = start_node(1, self.options.tmpdir,
                                           ["-debug", "-blockversion=4", "-chainidrequiredheight=%d" % HEIGHT, "-reindex"])
        # RPC answers once genesis is processed while the import thread still
        # replays the file and only then activates the chain, so wait, bounded,
        # on the tip itself: the parent is refused before the armed node's
        # blocks are read, since they follow it in the file, and nothing read
        # after them connects, so the armed node's tip, once it is the tip, is
        # the final tip. The parent's refusal is logged during the replay,
        # before that.
        for _ in range(240):
            if plain.getbestblockhash() == armed_tip:
                break
            time.sleep(0.5)
        assert_equal(plain.getbestblockhash(), armed_tip)
        assert_equal(plain.getblockcount(), HEIGHT + 1)
        assert refusal in self.debug_log(1)
        assert_raises_jsonrpc(-5, "Block not found", plain.getblock, parent.hash)
        assert_raises_jsonrpc(-5, "Block not found", plain.getblock, plain_tip)

        # 8. The regtest option is bounded to a block height: the largest value
        #    starts a node and is formatted on its startup line; a negative one
        #    refuses to start. That refusal is printed on the daemon's stderr
        #    before its log opens, so the daemon's stderr is captured to a file
        #    for the check (the test runner fails any test whose own stderr is
        #    not empty). Whatever happens in this step, no process of the third
        #    node outlives it: the outer clause pops its entry from the process
        #    map (the framework's teardown stops nodes 0 and 1 only and then
        #    asserts the map is empty) and ends a process still alive.
        initialize_datadir(self.options.tmpdir, 2)
        stderr_path = os.path.join(self.options.tmpdir, "node2-stderr.txt")
        started_out_of_range = False
        try:
            node2 = start_node(2, self.options.tmpdir, ["-chainidrequiredheight=2147483647"])
            stop_node(node2, 2)
            assert "Chain id rule: 0x5351 required from height 2147483647" in self.debug_log(2)
            saved_stderr = os.dup(2)
            try:
                with open(stderr_path, "w") as captured:
                    os.dup2(captured.fileno(), 2)
                    try:
                        start_node(2, self.options.tmpdir, ["-chainidrequiredheight=-1"])
                        started_out_of_range = True
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
        assert not started_out_of_range, "a node started with a negative -chainidrequiredheight"
        with open(stderr_path, encoding="utf-8") as f:
            assert "Invalid -chainidrequiredheight" in f.read()


if __name__ == '__main__':
    ChainIdRequiredHeightTest().main()
