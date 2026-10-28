# Pool Integration Guide: Soqucoin (SOQ)

> **Target audience**: Mining pool operators integrating Soqucoin  
> **Algorithm**: Scrypt (compatible with LTC/DOGE infrastructure)  
> **AuxPoW**: Yes, merge-mining with Litecoin or another Scrypt chain as the parent, valid from block 0  
> **Signatures**: ML-DSA-44 (FIPS 204, "Dilithium"), transparent to pool operators  
> **Last updated**: October 2026

> **Status**: SOQ is mined at SOQUPOOL and at other pools that merge-mine it.
> This guide is the integration reference for a pool that adds SOQ; questions
> go to dev@soqu.org.

---

## Overview

Soqucoin is a Scrypt-based AuxPoW blockchain based on Dogecoin Core. Mainnet has
run since 13 October 2026. Pool integration is straightforward if you already
support Litecoin or Dogecoin.

**Key differences from Dogecoin/Litecoin:**
- **Bech32m addresses** (`sq1p...` on mainnet, `ssq1p...` on stagenet)
- **60-second block target** (same as Dogecoin), retargeted every block
- **ML-DSA-44 signatures** in witness data (transparent to Stratum; coinbase and header formats unchanged)
- **AuxPoW chain ID 0x5351** (21329 decimal), checked strictly on mainnet; the format is Dogecoin's
- **Coinbase maturity 288 blocks**

### Networks

| Network | P2P port | RPC port | Address prefix | AuxPoW valid from | Strict chain ID | DNS seed |
|---------|----------|----------|----------------|-------------------|-----------------|----------|
| Mainnet | 33388 | 33389 | `sq1p` | block 0 | yes | `seed1.soqu.org`, `seed2.soqu.org`, `seed3.soqu.org` |
| Stagenet | 28333 | 28332 | `ssq1p` | block 100 | no | `stagenet.soqu.org` |
| Regtest | 18444 | 18332 | `sq1p` | block 20 | yes | none |

Source: `src/chainparams.cpp` and `src/chainparamsbase.cpp`.

---

## RPC Interface

Soqucoin's RPC interface is compatible with Bitcoin Core / Dogecoin Core.
All standard mining RPCs are available. On mainnet they are served only when
the node runs with `enablemining=1` (see the configuration below), and a node
that is still in initial block download refuses to serve work.

### Block Template (Stratum/GBT)

```bash
# Get block template for Stratum work generation
soqucoin-cli getblocktemplate '{"rules": ["segwit"]}'

# AuxPoW block creation (for merged mining)
soqucoin-cli createauxblock <payout_address>
soqucoin-cli submitauxblock <hash> <auxpow_hex>
```

`createauxblock` and `submitauxblock` need no wallet. `getauxblock` (the
Dogecoin form with no address argument) pays the node's own wallet and needs
one; the macOS builds are made without a wallet.

### Node Information

```bash
soqucoin-cli getblockchaininfo    # Chain state, deployment status
soqucoin-cli getmininginfo        # Current difficulty, hashrate
soqucoin-cli getnetworkhashps     # Network hash rate estimate
soqucoin-cli getblockcount        # Current block height
```

### Payouts

Payouts are signed outside the node. The Go SDK
([github.com/soqucoin-labs/soqucoin-sdk](https://github.com/soqucoin-labs/soqucoin-sdk))
derives keys and addresses, builds and signs transactions in your own
infrastructure, and uses the node only to read the chain and broadcast; its
`docs/EXCHANGE_INTEGRATION.md` describes that path, including the sizes of
ML-DSA-44 keys and signatures and the indexer the SDK reads unspent outputs
from. The node's built-in wallet (present in the Linux and Windows builds) is
not part of a pool integration: run the pool node with `disablewallet=1`, as
every node we operate does. A wallet rescan holds the node's chain lock for as
long as it runs, and every RPC, the mining RPCs included, waits on it.

The pool's own keys are a keypair made with the SDK's `keys` package and
saved in its encrypted keystore, backed up before its address is used; that
key's `sq1p` address is the one given to `createauxblock`. `examples/pool_payout`
is a batch payout tool: UTXO selection with a persistent spent set, a pre-check
against the node, then build, sign and broadcast, with the inputs recorded as
spent only after the node accepts the transaction, and a circuit breaker. It
stops at broadcast acceptance, so confirmations are tracked separately before a
miner's balance is settled, as the exchange guide's withdrawal engine
(`UpdateConfirmations`) does. `examples/generate_address` prints an address
without saving its key: a demonstration; mining to a printed address would leave
the reward unspendable, since the key is gone when the program exits.

```bash
soqucoin-cli validateaddress <addr>      # Validate miner address (isdilithium)
```

---

## RPC Configuration

```ini
# soqucoin.conf for a mainnet pool node
server=1

# RPC credentials
rpcuser=pool_rpc_user
rpcpassword=<strong_random_password>
rpcport=33389          # mainnet
# rpcport=28332        # stagenet, with stagenet=1

# Serve mining work over RPC (getblocktemplate, createauxblock, submitauxblock).
# Default is 1 on every network except mainnet, where the default is 0; a pool
# node opts in.
enablemining=1

# The node's wallet is not part of a pool integration; payouts are signed with
# the SDK in your own infrastructure (see Payouts above).
disablewallet=1

# Required for the SDK payout path: the SDK confirms a payout by transaction
# id (getrawtransaction), which needs the index once the payout's outputs are
# spent. Set it before the first start; adding it later needs -reindex-chainstate.
txindex=1

# Allow pool server to connect
rpcallowip=127.0.0.1
# rpcallowip=<pool_server_ip>  # if pool runs on separate host

# Performance
dbcache=1024
maxconnections=64
maxmempool=512

# Enable ZMQ for block notifications (optional, recommended)
zmqpubhashblock=tcp://127.0.0.1:28334
zmqpubrawtx=tcp://127.0.0.1:28334
```

A node that starts with a tip more than 24 hours old (`maxtipage`, default
86400) reports initial block download and refuses to serve work until it has
caught up; the chain is small and a sync takes minutes. After the first sync,
watch the tip's age and the block height yourself (`getblockchaininfo`, or
the ZMQ block notifications).

---

## Address Format

| Network | Format | Prefix | Example |
|---------|--------|--------|---------|
| Mainnet | Bech32m (witness v1) | `sq1p` | `sq1pxyz...` |
| Stagenet | Bech32m (witness v1) | `ssq1p` | `ssq1pxyz...` |
| Testnet / Regtest | Bech32m (witness v1) | `sq1p` | shares the mainnet HRP; select the network by RPC port, not by address prefix |

A miner gets an `sq1p` address from SoquShield (the self-custodial wallet, on
Google Play and on TestFlight for iOS) or from the browser generator at
[soqu.org/wallet](https://soqu.org/wallet/); the docs'
[first-transaction page](https://soqu.org/docs/get-started/first-tx/) walks through it.

**Important**: Do not pay Legacy Base58 addresses. They stand for pay-to-pubkey-hash and
pay-to-script-hash outputs, which the script layer cannot spend. Mainnet and stagenet nodes refuse
to relay a payment to one; testnet and regtest nodes accept non-standard transactions by default
(`-acceptnonstdtxn`), so there such a payment can still confirm as an output nobody can spend.
`validateaddress` reports a Base58 address as valid, so accept a miner address only when
`validateaddress` returns `isdilithium` true (witness version 1).

---

## Stratum Integration

### Standard Stratum v1

Soqucoin works with standard Stratum v1 protocol. The coinbase transaction
format matches Bitcoin/Dogecoin:

```
coinbase1: version + height + extranonce placeholder + pool tag
coinbase2: payout outputs + witness commitment (and the PAT commitment when the node built the coinbase; see Block attestation below)
```

### Pool Tag (Coinbase Signature)

Include your pool name in the coinbase scriptSig for identification:

```
/YourPoolName/
```

Example (hex): `2f596f7572506f6f6c4e616d652f`

With `getblocktemplate` you build the coinbase yourself and the tag goes into
it. With `createauxblock` the node builds the Soqucoin coinbase, so a
merge-mined block is identified by the tag in the parent chain's coinbase.

### AuxPoW (Merged Mining)

Soqucoin uses the same AuxPoW format as Dogecoin, with Litecoin as the usual
parent chain. The parent can be any Scrypt chain whose block version does not
carry chain ID 0x5351 (`fStrictChainId` on mainnet rejects a parent that does).
The slot of Soqucoin in the merged-mining merkle tree follows from the chain ID,
the merkle nonce and the tree size, as it does for Dogecoin. Use
`createauxblock` / `submitauxblock`:

```bash
# 1. Create an aux block (returns hash + fields to embed in the parent coinbase)
soqucoin-cli createauxblock <payout_address>

# Response:
# {
#   "hash": "...",
#   "chainid": 21329,
#   "previousblockhash": "...",
#   "coinbasevalue": 10000000000000,
#   "bits": "...",
#   "height": 15000,
#   "target": "..."
# }
# (With -rpcnamecoinapi the last field is named "_target".)

# 2. Embed the aux hash in parent chain coinbase (standard AuxPoW protocol)
# 3. When parent block found, submit the AuxPoW:
soqucoin-cli submitauxblock <hash> <serialized_auxpow>
```

`coinbasevalue` is the subsidy plus the fees of the transactions in the
template, in the smallest unit (100,000,000 per SOQ): 10,000,000,000,000 for
the 100,000 SOQ subsidy alone, more when the template carries fees, so use the
returned value. The block's version field already carries the chain ID; the
node sets it.

---

### Block attestation (PAT)

Every Soqucoin block that contains a transaction carries a PAT block attestation:
a 36-byte `OP_RETURN` output in the coinbase, `6a22 5041 <32-byte hash>`, that
commits to the ML-DSA-44 signatures the block spends
([`PAT_BLOCK_ATTESTATION.md`](PAT_BLOCK_ATTESTATION.md)). Every node verifies
the commitment on every block that carries one. A block without one is valid
today; a release will announce the height from which a block with transactions
must carry it, and from that height such a block without it is rejected. A
coinbase-only block carries none, by design.

The node adds the commitment only to a block it assembles itself, so the way
your pool obtains the Soqucoin block decides whether your blocks carry it:

| How you obtain the block | Attestation |
|---|---|
| `createauxblock` (recommended; SOQUPOOL runs this way) | the node builds the whole block, commitment included |
| `getblocktemplate`, keeping the node's own coinbase from `coinbasetxn.data` | included; keep the template's transactions as given, because the commitment binds that set and a changed set makes the block invalid (`bad-blk-pat-commitment`) |
| `getblocktemplate`, building your own coinbase from `coinbasevalue` and `default_witness_commitment` | **none**: no template field carries the commitment, so a coinbase you build cannot include it |

A pool engine that builds its own coinbase for every Bitcoin-family coin falls
into the last row. Switch it to `createauxblock` for SOQ: the node builds the
block and pays the address you give it, your engine embeds the returned hash in
the parent coinbase and submits through `submitauxblock`, and nothing changes in
your shares, your parent-chain mining or your payouts.

**Check your blocks.** Take any block of yours with at least one transaction
and read its coinbase, which is `tx[0]` of the block:

```bash
soqucoin-cli getblock <blockhash>
soqucoin-cli getrawtransaction <coinbase txid> 1
```

A `vout` whose `scriptPubKey.hex` starts with `6a225041` is the commitment. A
block with transactions and no such output means your coinbase path drops it.
The explorer shows the same output on the block's coinbase transaction.

---

## Block Reward Schedule

| Block Range | Subsidy (SOQ) | Phase |
|-------------|---------------|-------|
| 1 – 250,000 | 100,000 | Emission 1 |
| 250,001 – 500,000 | 50,000 | Halving 1 |
| 500,001 – 750,000 | 25,000 | Halving 2 |
| 750,001 – 1,000,000 | 12,500 | Halving 3 |
| 1,000,001+ | 2,500 | Perpetual tail emission |

**Notes:**
- Reward is 100% to miner (no dev tax, no foundation cut)
- Transaction fees are added to the block reward
- Source: `nInitialSubsidy` and `nSubsidyHalvingInterval` in `src/chainparams.cpp`, the tail in `src/soqucoin.cpp`

---

## Consensus Parameters

| Parameter | Value |
|-----------|-------|
| PoW Algorithm | Scrypt (N=1024, r=1, p=1) |
| Block Time Target | 60 seconds |
| Difficulty Adjustment | Every block from block 1 (DigiShield, 60-second timespan) |
| Max Block Size | 1 MB base, 4,000,000 weight units |
| Payment outputs | Witness v1 (bech32m `sq1p`), ML-DSA-44, the payment output a mainnet node relays; OP_RETURN data outputs are relayed too, within the standard size limit |
| Signature Algorithm | ML-DSA-44 (NIST FIPS 204) |
| AuxPoW | Enabled from block 0; chain ID 0x5351; strict chain ID on mainnet |
| Coinbase Maturity | 288 blocks |
| Reorganisation horizon | A synced node rejects a block that builds on a fork 288 blocks deep or more, with one exception: a competing chain whose headers it accepted while it was still syncing. A node downloading the chain for the first time does not have the protection yet, which is why the chain check below compares two published hashes |
| P2P Protocol Version | 70015 |

---

## Testing Your Integration

### Stagenet

Stagenet is the live test network. Put `stagenet=1` in `soqucoin.conf`; the
node finds peers through `stagenet.soqu.org` on port 28333 and serves RPC on
28332. Addresses start with `ssq1p`. AuxPoW is valid from block 100 there, and
the strict chain ID check is off on stagenet, so a wrong chain ID in a
submission is caught only on mainnet.

### Mainnet dry run

A synced mainnet node with `enablemining=1` answers `createauxblock` without
mining anything, so the fields and the merkle-tree slot can be checked before
the first real submission. A submission with a wrong chain ID is rejected by
the node itself. The block explorer at
[explorer.soqu.org](https://explorer.soqu.org) shows every block with its
AuxPoW parent, and its API answers `/api/blocks/tip/height`,
`/api/block/<height or hash>`, `/api/tx/<txid>` and `/api/mining/hashrate`.
To check that a node is on the live chain, compare `getblockhash 1` and
`getblockhash 1502` with the two hashes in [node-operators.md](node-operators.md)
(block 1, and block 1,502, where the network opened to outside nodes); if either
differs, the node is on another chain and that guide says what to do.

### Verification Checklist

1. ✅ Can connect to P2P network and sync blocks
2. ✅ Can derive bech32m payout addresses with the SDK
3. ✅ Can create block templates via `getblocktemplate`
4. ✅ Can validate miner addresses via `validateaddress`
5. ✅ Can build, sign and broadcast a payout with the SDK (`sendrawtransaction`)
6. ✅ Block notifications work (ZMQ or polling)
7. ✅ AuxPoW blocks submit successfully (if supporting merged mining)
8. ✅ A block of yours with transactions carries the PAT commitment (see Block attestation (PAT))

### Common Issues

**Q: Address validation fails for miner-submitted addresses**
A: Ensure you're accepting bech32m format (`sq1p...` or `ssq1p...`). If your
pool software only validates Base58, you'll need to add bech32m support.

**Q: Block template has large witness data**
A: ML-DSA-44 signatures are ~2.4 KB each (vs. 72 bytes for ECDSA). This is
normal. SegWit witness discount (4:1) applies, so effective weight impact is
~600 WU per signature.

**Q: `getblocktemplate` or `createauxblock` returns "Mining RPCs are disabled"**
A: The node runs with the mainnet default. Restart it with `enablemining=1`.

**Q: Can I merge-mine SOQ with my existing LTC pool?**
A: Yes. SOQ uses the same AuxPoW format as Dogecoin, through `createauxblock` /
`submitauxblock`; the parameters are in this guide, and a synced mainnet node
answers `createauxblock` so the setup can be checked before the first submission.

---

## Contact

Questions about a pool integration go to dev@soqu.org. Bugs in the node's
mining RPCs can be reported as
[GitHub issues](https://github.com/soqucoin/soqucoin/issues).
