Soqucoin Core 2.6.0
===================

Soqucoin Core 2.6.0 is a scheduled consensus release for mainnet and a
maintenance release for every network. It schedules one consensus rule on
mainnet: from block 67,000 every block must carry the chain id 0x5351 in its
version, whether it is merge-mined or mined directly. Every block in mainnet
history from block 1 carries it, and every template a Soqucoin Core node
builds carries it, so the rule changes nothing for a miner on a current node.
It completes the chain id check in the form Dogecoin Core applies it.

Block 67,000 is expected about 23 November 2026 at the block rate of the week
this release was tagged; a higher block rate brings the date forward. Every
node operator upgrades before that height. A node that still runs 2.5.x at the
height follows a block the upgraded network refuses, if such a block appears,
for as long as that branch is the heavier one (see "The chain id rule" below),
so the upgrade is not optional for a node that holds or moves value.

The height can move once. If by 13 November too few of the blocks on the chain
come from 2.6.0 nodes, a point release moves the height later. It is published
no later than 16 November, and every operator installs it the day it appears,
because a 2.6.0 node that skips it enforces the rule from block 67,000 alone.

Below block 67,000 a 2.6.0 node accepts the same chain as a 2.5.3 node (the
pinned history below refuses only forks under block 2,029). The peer-to-peer
protocol version, the wallet and every on-disk format are unchanged, and the
RPC interface gains one field and loses none, so the upgrade is a binary
replacement: no reindex, no migration.

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

show `"subversion": "/Soqucoin Core:2.6.0/"` and
`"chainid_required_height": 67000` on the lines they print.

A node built from the `main` branch before this tag reports version 2.5.3 and
shows no `chainid_required_height` in `getblockchaininfo`: it does not carry
the height, even when its blocks carry the release mark described below.
Rebuild it from the `v2.6.0` tag or install the release build.

If `soqucoin.conf` or the command line carries `-blockmaxsize=750000`, the old
default, remove the line or set it to 3000000; an explicit value wins over the
new default (see "The default block template").

Notable changes
---------------

### The chain id rule from block 67,000

`Consensus::Params::nChainIdRequiredHeight` is 67,000 on mainnet, and on
testnet, which mirrors mainnet. From that height a block whose version does not
carry chain id 0x5351 is refused with `bad-chain-id`. Legacy blocks (a version
field of 1 or 2, the form before merge mining) keep their exemption, which no
block after genesis can use on mainnet. Below the height nothing changes. The refusal gives the relaying peer
a misbehaviour score of 0, so a node that does not yet carry the rule stays
connected and follows the heavier chain; a peer that keeps announcing headers
on top of a refused block is disconnected by the existing unconnecting-headers
rule after about fifty announcements. The startup log names the height the
binary enforces (`Chain id rule: 0x5351 required from height 67000`), and
`getblockchaininfo` reports it as `chainid_required_height`.

A node that connected a block without the chain id before it upgraded
reorganizes off it on its own once the network's chain is heavier, and the
block stays in its index as a valid fork. `-reindex` replays the block files
and leaves the block unindexed; `invalidateblock` on its hash keeps it in the
index marked invalid and moves the node off the branch; either answers a
refused branch that stays heavier, and rebuilding the chainstate alone does
neither.

### The release mark in the block version

Templates built by this release set bit 15 of the block version: a directly
mined block reads `0x53518004` and a merge-mined block `0x53518104`
(`versionHex` in `getblock`, without the prefix). No header check reads the bit; the share of
blocks carrying it is how the network's readiness for the height is read from
the chain. Pool software that pins the version literal must take it from the
template instead. Rolling the version field (BIP 320 style, bits 13 to 28)
overwrites the mark and the low bits of the chain id: a merge-mined block built
that way is refused at every height already, and a directly mined one is
refused from block 67,000, so version rolling is not supported on this chain,
and the readiness count is a lower bound.

### The default block template

`DEFAULT_BLOCK_MAX_SIZE` rises from 750,000 to 3,000,000 bytes, equal to the
default weight limit, so a default-configured node's template admits every
standard transaction, including the largest standard ML-DSA-44 consolidations,
which the old byte limit excluded. A node with an explicit `-blockmaxsize`
keeps its own value.

### Peer discovery and the connection cap

The mainnet DNS seeds are queried by their service-bit names and, when such a
name has no record, by their plain names; a fourth seed name is added. The
fixed-seed table gains two Soqucoin Labs nodes beside the three SOQUPOOL nodes,
and the fixed seeds are added 60 seconds after start whenever no outbound
connection has completed by then (before this release only when the address
manager was empty). Manually
added peers (`-addnode`, the `addnode` RPC) no longer count against
`-maxconnections`; they have their own limit, and a startup line reports the
inbound room.

### The chain's history pinned

Mainnet carries checkpoints at blocks 1, 1,502 and 2,029 beside genesis, the
minimum chain work of block 19,513, and block 19,513 as the assumed-valid
block. A node whose chain holds less work reports initial block download until
it catches up; `-assumevalid=0` verifies every script and `-checkpoints=0`
disables the fork refusal below the last checkpoint. A startup line reports
the checkpoint count, the last checkpoint and the minimum chain work the
binary carries.

### RPC

- `getblockchaininfo` carries `chainid_required_height`, the height from which
  this node requires the chain id in every block's version (0 when it enforces
  none), so an operator checks what a binary pins by RPC.

### Build and packaging

- The version is 2.6.0 in `configure.ac`, `src/clientversion.h` and
  `doc/Doxyfile`.
- The release archives are built as the 2.5.3 archives were: the Linux x64 and
  arm64 archives through depends with a static runtime and a container smoke
  test, the macOS archives on their own architecture without the wallet, the
  Windows archive through depends. The release page shows this file as its
  notes.

### Documentation

- `INSTALL.md`, `README.md` and `doc/node-operators.md` name 2.6.0 as the
  current release; `doc/node-operators.md` states the height, the check after
  the restart, and what a node built from the development branch lacks.

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
