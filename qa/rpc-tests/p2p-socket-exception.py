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
otherwise selecting that socket for receive. This test puts a peer into the
send-only state, sends it in-band bytes followed by urgent data, and checks the
node does not read those bytes: the peer stays connected and its received-byte
count does not change.

Before the change, every peer socket was placed in the exception fd_set
unconditionally, so the node read the in-band bytes through the exception path,
failed to parse them and disconnected the peer. The test then fails. With the
change, a send-only socket is left out of the exception fd_set and the bytes are
not read.
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
            pass

    def readable(self):
        with mininode_lock:
            return self.allow_read


class SocketExceptionTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = [start_node(0, self.options.tmpdir, ["-debug=net"])]

    def run_test(self):
        node = self.nodes[0]

        # Mature coinbases (regtest maturity is 60), then a large block to serve.
        node.generate(110)
        mine_large_block(node, [])
        big_block = int(node.getbestblockhash(), 16)

        cb = SingleNodeConnCB()
        conn = ControlledReadConn('127.0.0.1', p2p_port(0), node, cb)
        cb.add_connection(conn)
        NetworkThread().start()
        cb.wait_for_verack()
        assert_equal(len(node.getpeerinfo()), 1)

        try:
            # Turn the read side off, then ask for the block, paced, until the
            # node's send buffer to this peer stops draining. A full, stuck send
            # buffer means the socket is send-only: the node is not selecting it
            # for receive.
            with mininode_lock:
                conn.allow_read = False
            getdata = msg_getdata()
            getdata.inv.append(CInv(MSG_BLOCK, big_block))

            prev_sent = -1
            stable = 0
            for _ in range(30):
                cb.send_message(getdata)
                time.sleep(0.4)
                info = node.getpeerinfo()
                assert_equal(len(info), 1)
                sent = info[0]["bytessent"]
                if sent > 0 and sent == prev_sent:
                    stable += 1
                    if stable >= 3:
                        break
                else:
                    stable = 0
                prev_sent = sent
            else:
                raise AssertionError("send buffer to the peer never filled")

            info = node.getpeerinfo()
            assert_equal(len(info), 1)
            bytesrecv_before = info[0]["bytesrecv"]

            # Send in-band bytes, then TCP urgent data. The in-band bytes are
            # only reachable through the exception path, because the node is not
            # selecting this socket for receive.
            conn.socket.send(UNREADABLE_BYTES)
            conn.socket.send(b'!', socket.MSG_OOB)

            # Give the socket loop time to act on the exceptional condition.
            time.sleep(3)

            info = node.getpeerinfo()
            assert_equal(len(info), 1)
            assert_equal(info[0]["bytesrecv"], bytesrecv_before)
            print("OK: node did not receive from the send-only socket on an "
                  "exceptional event; peer stayed connected")
        finally:
            conn.disconnect_node()
            time.sleep(0.5)


if __name__ == '__main__':
    SocketExceptionTest().main()
