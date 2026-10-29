#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Socket exception-set handling in CConnman::ThreadSocketHandler.

The socket loop selects each peer's socket for receive only when the peer's
receiving is not paused, and for send when there is buffered data to send. A
peer with a full send buffer and no reader on the other end is a socket the
node is draining its write buffer to and not reading from (the send-only state).

ThreadSocketHandler also watches sockets for exceptional conditions. select()
reports a socket as exceptional when TCP urgent (out-of-band) data arrives. The
node reads with a plain recv(), which does not consume the out-of-band byte, so
the exceptional condition stays set.

The node must not receive from a socket on an exceptional event when it is not
otherwise selecting that socket for receive. This test puts one peer into the
send-only state, sends it in-band bytes followed by urgent data, and checks the
node does not read those bytes. A second, responsive peer is pinged before and
after the probe, so the result is meaningful: the socket handler is running
across the probe, and it still did not read the send-only socket.

Before the change, every peer socket was placed in the exception fd_set
unconditionally, so the node read the in-band bytes through the exception path,
failed to parse them and disconnected the send-only peer. The test then fails.
With the change, a send-only socket is left out of the exception fd_set and the
bytes are not read.
"""

import socket
import time

from test_framework.mininode import (
    NodeConn,
    NetworkThread,
    SingleNodeConnCB,
    CInv,
    msg_getdata,
    mininode_lock,
    wait_until,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    mine_large_block,
    p2p_port,
    start_node,
)

# Receive type for a block in a getdata inventory entry.
MSG_BLOCK = 2

# A 24-byte message header whose message-size field is larger than the node
# accepts. If the node reads it, header parsing fails and the node disconnects
# the peer. These bytes are never a valid message.
UNREADABLE_BYTES = b'\x00' * 16 + b'\xff\xff\xff\xff' + b'\x00' * 4

# Large blocks to request at once, and the send backlog, in bytes, the node must
# hold to the send-only peer before the probe. The request is for several full
# blocks (megabytes) and the peer does not read, so the node's send buffer to it
# stays well above this and the socket stays send-only.
NUM_LARGE_BLOCKS = 8
PENDING_SEND_MIN = 200000


def pending_send(peer_info):
    """Bytes the node has queued to send to a peer but not yet written.

    bytessent_per_msg counts bytes as they are queued (PushMessage); bytessent
    counts bytes as they are written to the socket (SocketSendData). Their
    difference is the current send backlog, which is positive exactly when the
    node is selecting the socket for send.
    """
    queued = sum(peer_info["bytessent_per_msg"].values())
    return queued - peer_info["bytessent"]


class ControlledReadConn(NodeConn):
    """A NodeConn whose read side can be turned off.

    With reading off, the framework stops draining the socket, so the node's
    send buffer to this peer fills and stays full: the send-only state the test
    needs. Writing is unaffected, so the peer can still send the requests that
    build the node's send backlog.
    """

    def __init__(self, *args, **kwargs):
        self.allow_read = True
        super().__init__(*args, **kwargs)
        # Keep the receive buffer small so the node's send to this peer stalls
        # quickly once reading stops, and its send backlog stays stuck rather
        # than draining into a large kernel buffer.
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
        except OSError:
            # A platform that will not shrink the buffer is fine; the test runs
            # with the default size.
            pass

    def readable(self):
        with mininode_lock:
            return self.allow_read


class TestNode(SingleNodeConnCB):
    def __init__(self):
        super().__init__()
        self.disconnected = False

    def on_close(self, conn):
        self.disconnected = True

    def wait_for_verack(self, timeout=30):
        def done():
            return self.verack_received or self.disconnected
        wait_until(done, timeout=timeout)
        assert not self.disconnected, "peer disconnected before verack"
        assert self.verack_received, "timed out waiting for verack"


class SocketExceptionTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self, split=False):
        # -blockmintxfee=0 lets mine_large_block fill each block; -maxsendbuffer
        # raised so the node holds the whole multi-block response as a backlog
        # rather than capping it below the kernel send buffer.
        self.nodes = [start_node(0, self.options.tmpdir,
                                 ["-debug=net", "-blockmintxfee=0",
                                  "-maxsendbuffer=5000"])]

    def peer_by_port(self, node, port):
        """The getpeerinfo entry whose source port is `port`, or None."""
        tag = ":%d" % port
        for peer in node.getpeerinfo():
            if peer["addr"].endswith(tag):
                return peer
        return None

    def run_test(self):
        node = self.nodes[0]

        # Mature coinbases (regtest maturity is 60), then several large blocks
        # to serve at once.
        node.generate(110)
        block_hashes = []
        for _ in range(NUM_LARGE_BLOCKS):
            mine_large_block(node, [])
            block_hashes.append(int(node.getbestblockhash(), 16))

        # The send-only victim, and a second peer that stays responsive so that
        # a successful ping across the probe proves the socket handler ran.
        victim_cb = TestNode()
        victim = ControlledReadConn('127.0.0.1', p2p_port(0), node, victim_cb)
        victim_cb.add_connection(victim)
        live_cb = TestNode()
        live = NodeConn('127.0.0.1', p2p_port(0), node, live_cb)
        live_cb.add_connection(live)
        NetworkThread().start()

        try:
            victim_cb.wait_for_verack()
            live_cb.wait_for_verack()
            victim_port = victim.socket.getsockname()[1]
            assert_equal(len(node.getpeerinfo()), 2)

            # The second peer answers a ping: the socket handler is running.
            assert live_cb.sync_with_ping(), \
                "second peer did not answer before the probe"

            # Turn the victim's read side off, then ask for every large block in
            # one request. The node queues them, cannot send them to a peer that
            # is not reading, and keeps a large send backlog: the socket is
            # send-only and the node is not selecting it for receive.
            with mininode_lock:
                victim.allow_read = False
            getdata = msg_getdata()
            for block_hash in block_hashes:
                getdata.inv.append(CInv(MSG_BLOCK, block_hash))
            victim_cb.send_message(getdata)

            # Wait for the backlog to form, then to settle (bytes written stop
            # rising, so the node has stalled on the full send buffer).
            def backlog_formed():
                peer = self.peer_by_port(node, victim_port)
                return peer is not None and pending_send(peer) > PENDING_SEND_MIN
            assert wait_until(backlog_formed, timeout=30), \
                "node did not build a send backlog to the peer"
            prev_sent = -1
            for _ in range(50):
                peer = self.peer_by_port(node, victim_port)
                assert peer is not None, "victim dropped while the backlog settled"
                sent = peer["bytessent"]
                if sent == prev_sent:
                    break
                prev_sent = sent
                time.sleep(0.2)

            peer = self.peer_by_port(node, victim_port)
            assert peer is not None
            bytesrecv_before = peer["bytesrecv"]

            # Send in-band bytes, then TCP urgent data. The in-band bytes are
            # only reachable through the exception path, because the node is not
            # selecting this socket for receive.
            victim.socket.send(UNREADABLE_BYTES)
            victim.socket.send(b'!', socket.MSG_OOB)

            # The second peer answers again: the socket handler ran across the
            # probe, so the victim's survival is not a stalled-handler artefact.
            assert live_cb.sync_with_ping(), \
                "second peer did not answer after the probe"

            peer = self.peer_by_port(node, victim_port)
            assert peer is not None, "victim was disconnected after the probe"
            assert_equal(peer["bytesrecv"], bytesrecv_before)
            # Still send-only: the socket was not selected for receive.
            assert pending_send(peer) > 0, "send backlog drained unexpectedly"
            print("OK: node did not receive from the send-only socket on an "
                  "exceptional event; peer stayed connected")
        finally:
            victim.disconnect_node()
            live.disconnect_node()
            time.sleep(0.5)


if __name__ == '__main__':
    SocketExceptionTest().main()
