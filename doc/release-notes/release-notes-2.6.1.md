Soqucoin Core 2.6.1
===================

Soqucoin Core 2.6.1 is a maintenance release for every network. It carries one
change to the node: the socket loop no longer receives from a peer socket it is
not selecting for receive when that socket signals out-of-band data.

It makes no consensus change. The chain id rule that 2.6.0 scheduled on mainnet
and testnet is unchanged: from block 67,000 every block must carry the chain id
0x5351 in its version. A node on 2.6.0 upgrading to 2.6.1 receives the socket
change alone. A node on 2.5.x upgrading to 2.6.1 receives the chain id rule as
well, and upgrades before block 67,000 as 2.6.0 required.

Every node operator should upgrade. The peer-to-peer protocol version, the RPC
interface, the wallet and every on-disk format are unchanged from 2.6.0, so the
upgrade is a binary replacement: no reindex, no migration.

Upgrading
---------

Stop the running daemon, replace `soqucoind` and `soqucoin-cli`, start it. The
data directory carries over on every network. The upgrade neither reads nor
writes a wallet file, whether the node loads one or runs with `disablewallet=1`;
the usual practice of keeping a current backup of any wallet file applies as
before. A node that last ran 2.5.0 or older on mainnet still needs a fresh
mainnet data directory, as `doc/node-operators.md` describes.

To confirm after the restart:

    soqucoin-cli getnetworkinfo | grep subversion
    soqucoin-cli getblockchaininfo | grep chainid_required_height

show `"subversion": "/Soqucoin Core:2.6.1/"` and
`"chainid_required_height": 67000` on the lines they print.

Notable changes
---------------

### Socket exception handling

The socket loop (`ThreadSocketHandler`) watches each peer's socket for
exceptional conditions as well as for reading and sending. A socket signals an
exceptional condition when a peer sends TCP urgent (out-of-band) data. The loop
now watches for that condition only on a socket it is also selecting for
receive. A socket the node is not reading from, because it is draining a send
buffer to a peer that is not receiving or because its own receive is paused, is
no longer read when such a condition is raised. Reading from a socket the node
had stopped receiving from let a peer drive the node past the receive pause,
which could grow the node's memory use. Sockets the node is reading from are
unaffected. A regtest functional test covers the case.

### The chain id rule from block 67,000

This release carries the rule 2.6.0 scheduled, unchanged.
`Consensus::Params::nChainIdRequiredHeight` is 67,000 on mainnet, and on
testnet, which mirrors mainnet. From that height a block whose version does not
carry chain id 0x5351 is refused with `bad-chain-id`. Legacy blocks (a version
field of 1 or 2, the form before merge mining) keep their exemption, which no
block after genesis can use on mainnet. Below the height nothing changes. The
refusal gives the relaying peer a misbehaviour score of 0, so a node that does
not yet carry the rule stays connected and follows the heavier chain. The
startup log names the height the binary enforces
(`Chain id rule: 0x5351 required from height 67000`), and `getblockchaininfo`
reports it as `chainid_required_height`. Every node operator upgrades before
block 67,000; a node that still runs 2.5.x at the height follows a block the
upgraded network refuses, if such a block appears, for as long as that branch
is the heavier one.

### Build and packaging

- The version is 2.6.1 in `configure.ac`, `src/clientversion.h` and
  `doc/Doxyfile`.
- The release archives are built as the 2.6.0 archives were: the Linux x64 and
  arm64 archives through depends with a static runtime and a container smoke
  test, the macOS archives on their own architecture without the wallet, the
  Windows archive through depends. The release page shows this file as its
  notes.

Known limitations
-----------------

- Verification-cost budgeting for post-quantum signatures is defined but not
  enforced. The block weight limit and the sigop budget bound the verification
  work a block can demand; peer limits and ban thresholds cover the rest. A fix
  is planned for a later release.
- `getblockchaininfo` reports `verificationprogress` as 1.0 whatever the sync
  state, because the chain's transaction statistics are not yet pinned; read
  `initialblockdownload`, and `headers` against `blocks`, instead.
- The manual pages under `doc/man/` still describe an earlier release.

Credits
-------

Thanks to everyone who contributed to this release.
