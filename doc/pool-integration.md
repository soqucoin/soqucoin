# Pool Integration Guide — Soqucoin (SOQ)

> **Target audience**: Mining pool operators integrating Soqucoin  
> **Algorithm**: Scrypt (compatible with LTC/DOGE infrastructure)  
> **AuxPoW**: Yes — merge-mining with Litecoin, Dogecoin, and other Scrypt chains  
> **Signatures**: Dilithium ML-DSA-44 (quantum-safe) — transparent to pool operators  
> **Last updated**: April 2026

---

## Overview

Soqucoin is a Scrypt-based AuxPoW blockchain derived from Dogecoin Core. Pool
integration is straightforward if you already support Litecoin or Dogecoin.

**Key differences from Dogecoin/Litecoin:**
- **Bech32m addresses** (`soq1p...` on mainnet, `ssq1p...` on stagenet)
- **60-second block target** (same as Dogecoin)
- **Dilithium signatures** in witness data (transparent to Stratum — coinbase/header format unchanged)
- **AuxPoW chain ID**: matches Dogecoin's AuxPoW format

---

## RPC Interface

Soqucoin's RPC interface is compatible with Bitcoin Core / Dogecoin Core.
All standard mining RPCs are available:

### Block Template (Stratum/GBT)

```bash
# Get block template for Stratum work generation
soqucoin-cli getblocktemplate '{"rules": ["segwit"]}'

# AuxPoW block creation (for merged mining)
soqucoin-cli createauxblock <payout_address>
soqucoin-cli submitauxblock <hash> <auxpow_hex>
```

### Node Information

```bash
soqucoin-cli getblockchaininfo    # Chain state, BIP9 deployments
soqucoin-cli getmininginfo        # Current difficulty, hashrate
soqucoin-cli getnetworkhashps     # Network hash rate estimate
soqucoin-cli getblockcount        # Current block height
```

### Wallet Operations

```bash
soqucoin-cli getnewaddress "" bech32m    # Generate payout address
soqucoin-cli getbalance                  # Check balance
soqucoin-cli sendtoaddress <addr> <amt>  # Send payout
soqucoin-cli validateaddress <addr>      # Validate miner address
```

---

## RPC Configuration

```ini
# soqucoin.conf for pool backend
server=1
txindex=1

# RPC credentials
rpcuser=pool_rpc_user
rpcpassword=<strong_random_password>
rpcport=38332          # stagenet
# rpcport=22555        # mainnet (future)

# Allow pool server to connect
rpcallowip=127.0.0.1
# rpcallowip=<pool_server_ip>  # if pool runs on separate host

# Performance
dbcache=1024
maxconnections=64
maxmempool=512

# Enable ZMQ for block notifications (optional, recommended)
zmqpubhashblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28332
```

---

## Address Format

| Network | Format | Prefix | Example |
|---------|--------|--------|---------|
| Mainnet | Bech32m (Taproot) | `soq1p` | `soq1pxyz...` |
| Stagenet | Bech32m (Taproot) | `ssq1p` | `ssq1pxyz...` |
| Testnet3 | Bech32m (Taproot) | `tsq1p` | `tsq1pxyz...` |

**Important**: Legacy Base58 addresses (`S...`, `3...`) are supported but deprecated.
Bech32m is the canonical format. Use `validateaddress` RPC to verify miner addresses.

---

## Stratum Integration

### Standard Stratum v1

Soqucoin works with standard Stratum v1 protocol. The coinbase transaction
format matches Bitcoin/Dogecoin:

```
coinbase1: version + height + extranonce placeholder + pool tag
coinbase2: payout outputs + witness commitment
```

### Pool Tag (Coinbase Signature)

Include your pool name in the coinbase scriptSig for identification:

```
/YourPoolName/
```

Example (hex): `2f596f7572506f6f6c4e616d652f`

### AuxPoW (Merged Mining)

Soqucoin supports AuxPoW for merged mining with Litecoin as the parent chain.
Use `createauxblock` / `submitauxblock` RPCs:

```bash
# 1. Create an aux block (returns hash + hex to embed in parent coinbase)
soqucoin-cli createauxblock ssq1p23ssp9dsfcxzn33msmfzsk723rg24h9j8lrdn4qtaezcztjemd3smejtp7

# Response:
# {
#   "hash": "...",
#   "chainid": 98,
#   "previousblockhash": "...",
#   "coinbasevalue": 10000000000000,
#   "bits": "...",
#   "height": 126,
#   "_target": "..."
# }

# 2. Embed the aux hash in parent chain coinbase (standard AuxPoW protocol)
# 3. When parent block found, submit the AuxPoW:
soqucoin-cli submitauxblock <hash> <serialized_auxpow>
```

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
- Transaction fees (SOQ only) are added to the block reward
- USDSOQ fees are NOT miner-claimable (per-asset isolation)

---

## Consensus Parameters

| Parameter | Value |
|-----------|-------|
| PoW Algorithm | Scrypt (N=1024, r=1, p=1) |
| Block Time Target | 60 seconds |
| Difficulty Adjustment | Every block (DGW v3) |
| Max Block Size | 1 MB (weight: 4 MW) |
| SegWit | Active (witness v0, v1, v2, v3, v4, v5) |
| Signature Algorithm | Dilithium ML-DSA-44 (NIST FIPS 204) |
| AuxPoW | Enabled |
| P2P Protocol Version | 70015 |

---

## Testing Your Integration

### Stagenet Endpoints

| Service | Address |
|---------|---------|
| P2P | 64.23.197.144:28333 |
| P2P (backup) | 143.110.229.69:28333 |
| Stratum (test pool) | 64.23.197.144:3333 |

### Verification Checklist

1. ✅ Can connect to P2P network and sync blocks
2. ✅ Can generate bech32m addresses via RPC
3. ✅ Can create block templates via `getblocktemplate`
4. ✅ Can validate miner addresses via `validateaddress`
5. ✅ Can send payouts via `sendtoaddress`
6. ✅ Block notifications work (ZMQ or polling)
7. ✅ AuxPoW blocks submit successfully (if supporting merged mining)

### Common Issues

**Q: Address validation fails for miner-submitted addresses**
A: Ensure you're accepting bech32m format (`soq1p...` or `ssq1p...`). If your
pool software only validates Base58, you'll need to add bech32m support.

**Q: Block template has large witness data**
A: Dilithium signatures are ~2.4 KB each (vs. 72 bytes for ECDSA). This is
normal. SegWit witness discount (4:1) applies, so effective weight impact is
~600 WU per signature.

**Q: Can I merge-mine SOQ with my existing LTC pool?**
A: Yes. Use `createauxblock` / `submitauxblock` exactly as you would for any
AuxPoW chain. SOQ uses the same AuxPoW format as Dogecoin.

---

## Contact

For pool integration support:
- **GitHub**: [soqucoin/soqucoin](https://github.com/soqucoin/soqucoin)
- **Email**: pool-support@soqucoin.com
- **Discord**: [Soqucoin Community](https://discord.gg/soqucoin)
