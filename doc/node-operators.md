# Running a Soqucoin node around mainnet launch

This page is for operators who run their own node. It says what to expect on each network, in
order, and what a node cannot do during the first day of mainnet.

## Stagenet, available now

Stagenet is the live test network the project's own nodes run today. Use it to prove your build,
your configuration and your tooling before mainnet.

```ini
# soqucoin.conf
stagenet=1
server=1
rpcuser=<choose>
rpcpassword=<choose>
```

A fresh node finds peers through the stagenet seed (`stagenet.soqu.org`), downloads headers, then
blocks, and reports `initialblockdownload` false once it reaches the tip. On a fast connection the
first sync takes a few minutes. Stagenet addresses start with `ssq1p` and mainnet addresses with `sq1p`:
one address type, bech32m witness version 1. Both the 2.5.0 release and the mainnet release (2.5.1) run
stagenet.

```bash
soqucoin-cli getblockchaininfo   # chain "stagenet", blocks rising, initialblockdownload false at the tip
soqucoin-cli getconnectioncount  # above 0 within a minute
```

## Mainnet, from 13 October 2026, 15:00 UTC

There is no mainnet chain before that hour: the mainnet release refuses any block at height 1 timed
earlier. Until then a mainnet node shows height 0 and no peers, which is correct.

Run the mainnet release, 2.5.1, on a fresh data directory. The 2.5.0 release cannot follow mainnet
past the genesis block: block 1 carries the genesis migration that only 2.5.1 enforces, so a 2.5.0
node rejects it.

```ini
# soqucoin.conf
server=1
rpcuser=<choose>
rpcpassword=<choose>
```

**The first day.** Public peering opens at least a day after block 1 and not before the chain is
576 blocks deep, two finality horizons: a node past its initial sync refuses any reorganisation 288
blocks deep or deeper, so from then on the project's nodes hold the start as final. Until the opening the
project's nodes accept no outside connections: your mainnet node shows 0 connections and stays at
height 0. This is expected. Leave it running or start it after the opening. A node syncing from
scratch has no history of its own to hold, so at the opening we publish the hash of block 1 and
the hash at the opening height; check yours against both:

```bash
soqucoin-cli getblockhash 1
soqucoin-cli getblockhash <opening height>   # the height is published beside its hash
```

A node whose hashes differ from the published ones is on the wrong chain: stop it, remove the data
directory, and start again on the current release.

**Releases in the first weeks.** A release after launch may add checkpoints so that a node syncing
from scratch follows the launched chain. Stay on the current release; the release notes say when an
update is needed to stay in sync.

## What is not supported at launch

- Mining: SOQUPOOL is the only supported way to mine SOQ at mainnet launch. A node does not need
  mining enabled, and `getblocktemplate` on an ordinary node returns an error by design.
- Peering with the project's nodes during the first day (above).

## The wallet

The node's built-in wallet works on every network. If you only validate and relay, set
`disablewallet=1`: it removes the wallet from startup and from the RPC surface. SoquShield and the
SDK give you addresses and signing without the node wallet. If startup stays on `Loading wallet...`
for more than a minute, keep `debug.log` and tell us which release asset you run and whether the
data directory held a `wallet.dat` from an earlier release.
