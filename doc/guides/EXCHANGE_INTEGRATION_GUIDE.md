# Soqucoin Exchange Integration Guide

> **Version**: 1.1 | **Updated**: October 10, 2026
> **Audience**: Exchange operators, custodians, and trading platform developers
> **Support**: dev@soqu.org

---

## Overview

This guide covers building, configuring and operating a Soqucoin (SOQ) node for an exchange integration.

Soqucoin is **based on Dogecoin Core**. It uses Dogecoin's well-tested foundation while replacing the cryptographic engine with post-quantum primitives and adding high-performance feature engineering upgrades. Soqucoin begins with its own Genesis Block (Block 0) with **no shared transaction history** and **no airdrop to Dogecoin holders**. It is an entirely new and independent blockchain featuring Dilithium (ML-DSA-44) signatures and AuxPoW merged mining compatibility with Litecoin/Dogecoin.

### Integration Path

Exchanges integrate through the [Soqucoin SDK](https://github.com/soqucoin-labs/soqucoin-sdk). Deposit keys, address derivation and withdrawal signing run in your own infrastructure, and the node runs with its wallet disabled as a chain reader and broadcaster. The SDK's [Exchange Integration guide](https://github.com/soqucoin-labs/soqucoin-sdk/blob/main/docs/EXCHANGE_INTEGRATION.md) covers deposits, withdrawals and key custody; the sections below link to its steps.

### Key Properties

| Property | Value |
|----------|-------|
| **Consensus** | Proof-of-Work (Scrypt) |
| **Block Time** | 60 seconds |
| **Signature** | Dilithium ML-DSA-44 (NIST FIPS 204) |
| **Address Format** | Bech32m, witness version 1 (`sq1p...` on mainnet and testnet, `ssq1p...` on stagenet) |
| **Merged Mining** | Yes (Litecoin/Dogecoin compatible) |
| **Chain ID** | 0x5351 (21329) |
| **Ticker** | SOQ |
| **Decimals** | 8 |

---

## 1. Prerequisites

### 1.1 Hardware Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 8 GB | 16+ GB |
| **Storage** | 100 GB SSD | 500 GB NVMe |
| **Network** | 50 Mbps | 100+ Mbps |

### 1.2 Operating System

- Ubuntu 22.04 LTS (recommended)
- Ubuntu 24.04 LTS (verified)
- Debian 11/12
- RHEL 8/9

> **Note**: macOS and Windows are supported for development but not recommended for production exchange deployments.

### 1.3 Build Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y \
  build-essential libtool autotools-dev automake \
  pkg-config bsdmainutils python3 libssl-dev \
  libevent-dev libboost-all-dev libzmq3-dev \
  libdb5.3-dev libdb5.3++-dev
```

---

## 2. Node Setup

### 2.1 Building from Source

```bash
# Clone repository
git clone https://github.com/soqucoin/soqucoin.git
cd soqucoin
git checkout soqucoin-genesis  # Mainnet branch

# Build
./autogen.sh
./configure --without-gui --with-incompatible-bdb
make -j$(nproc)
sudo make install
```

### 2.2 Configuration File

Create `~/.soqucoin/soqucoin.conf`:

```ini
# Basic Configuration
server=1
daemon=1
txindex=1

# RPC Configuration (IMPORTANT)
rpcuser=your_secure_rpc_username
rpcpassword=your_very_long_secure_password_at_least_32_chars
# Mainnet RPC port: 33389 | Testnet RPC port: 44555 | Stagenet RPC port: 28332
rpcport=33389
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# Network Configuration
listen=1
maxconnections=50

# Performance Tuning
dbcache=1000
par=4
rpcworkqueue=128
rpcthreads=8

# Wallet and notifications (keys and signing run in your own infrastructure)
disablewallet=1
blocknotify=/path/to/your/block_script.sh %s
```

**Network Port Reference**:

| Network | P2P Port | RPC Port |
|---------|----------|----------|
| **Mainnet** | 33388 | 33389 |
| **Testnet3** | 44556 | 44555 |
| **Stagenet** | 28333 | 28332 |
| **Regtest** | 18444 | 18332 |

> **Security Warning**: Never expose RPC to the public internet. Use SSH tunnels or VPN for remote access.

### 2.3 Starting the Node

```bash
# Start daemon
soqucoind -daemon

# Check status
soqucoin-cli getblockchaininfo

# Monitor sync progress
soqucoin-cli getblockchaininfo | grep -E "(blocks|headers|verificationprogress)"
```

### 2.4 Sync Time Estimates

| Network | Blocks | Estimated Sync Time |
|---------|--------|---------------------|
| Mainnet | TBD (pre-launch) | TBD |
| Testnet3 | ~12,000 | < 1 hour |
| Stagenet | ~0 | Immediate |

---

## 3. Deposit Handling

### 3.1 Address Generation

Derive one deposit address per customer in your own key store with the SDK, as described in [Step 1: Generate Deposit Addresses](https://github.com/soqucoin-labs/soqucoin-sdk/blob/main/docs/EXCHANGE_INTEGRATION.md#step-1-generate-deposit-addresses). A Soqucoin address is bech32m with witness version 1, and its 32-byte witness program is the SHA-256 of an ML-DSA-44 public key.

### 3.2 Address Validation

Validate every address before you use it. The SDK's `address.Decode` accepts only a bech32m witness version 1 address with a 32-byte program for the network's prefix (`address/bech32m.go`). The node's `validateaddress` is wider: it first tries the legacy Base58 forms and reports a network-valid one as `"isvalid": true` without `isdilithium` or `witness_version` (`src/rpc/misc.cpp`), although nothing on this chain can spend an output to such an address and the relay refuses one (section 5). So when you use the node, accept an address only when all three fields are present and true; or use `pqvalidateaddress`, which accepts only the witness version 1 form (`src/wallet/pqwallet/rpc_pqwallet.cpp`).

```bash
soqucoin-cli validateaddress "sq1p..."
```

Accept the address only when the response carries `"isvalid": true`, `"isdilithium": true` and `"witness_version": 1` together. A legacy Base58 address with this network's version byte answers `"isvalid": true` and nothing else of the three; treat that as invalid. A malformed address answers `"isvalid": false`, which is then the only field.

### 3.3 Monitoring Deposits

With the node's wallet disabled, deposits are found through an address index. [Step 2: Monitor Deposits](https://github.com/soqucoin-labs/soqucoin-sdk/blob/main/docs/EXCHANGE_INTEGRATION.md#step-2-monitor-deposits) in the SDK guide describes the ElectrumX indexer that discovers deposits and the node check that confirms each one before it is credited.

### 3.4 Confirmation Requirements

| Transaction Size | Recommended Confirmations |
|------------------|---------------------------|
| < 1,000 SOQ | 6 confirmations (~6 min) |
| 1,000 - 10,000 SOQ | 12 confirmations (~12 min) |
| 10,000 - 100,000 SOQ | 24 confirmations (~24 min) |
| Large value / final settlement | **288 confirmations (~4.8h — absolute finality)** |

> **Note**: Below 288 blocks, confirmations are **probabilistic** — more confirmations lower the reversal risk, but a large hashpower rental can still reorganize recent blocks. At **288 blocks (~4.8h)** finality becomes **absolute**: the network rejects any reorg deeper than 288 blocks (`nMaxReorgDepth`), so a buried transaction cannot be reversed by hashpower. **Do not credit large deposits on a handful of confirmations** — wait for the 288-block finality horizon for high-value settlement. See [Chain Finality](https://soqu.org/docs/protocol/finality/) for the full properties and tradeoffs.

---

## 4. Withdrawal Handling

### 4.1 Fee Estimation

```bash
# Estimate fee for standard transaction
soqucoin-cli estimatesmartfee 6

# Estimate verification cost (PQ-specific)
soqucoin-cli pqestimatefeerate 1 2
```

**Response**:
```json
{
  "verify_cost": 9,
  "breakdown": {
    "signature_cost": 1,
    "script_cost": 6,
    "hash_cost": 2
  },
  "recommendation": "Standard transaction, no aggregation needed"
}
```

### 4.2 Sending Transactions

Build and sign each withdrawal with the SDK in your signing infrastructure, as described in [Step 3: Process Withdrawals](https://github.com/soqucoin-labs/soqucoin-sdk/blob/main/docs/EXCHANGE_INTEGRATION.md#step-3-process-withdrawals), then broadcast the signed transaction through the node:

```bash
soqucoin-cli sendrawtransaction "<signed transaction hex>"
```

On mainnet and stagenet, from 2.5.1, a transaction enters the node's mempool only if every output is `OP_RETURN` data, a witness version 1 program or a program of a witness version whose deployment is active; `sendrawtransaction` refuses any other output layout with the reason `scriptpubkey`, so a transaction built by a generic library for another address type is refused rather than confirmed as an output nothing can spend.

### 4.3 Transaction Confirmation

```bash
# Get transaction details (txindex=1 in the configuration above)
soqucoin-cli getrawtransaction "txid..." 1
```

### 4.4 Withdrawal Security

1. **Hot wallet limits**: Maintain only 5-10% of assets in hot wallet
2. **Cold wallet**: Store bulk assets in cold storage with multisig
3. **Rate limiting**: Implement withdrawal rate limits per user/IP
4. **2FA verification**: Require 2FA for all withdrawals
5. **Whitelisting**: Allow users to whitelist withdrawal addresses

---

## 5. AuxPoW/Merged Mining Considerations

### 5.1 Understanding AuxPoW Blocks

Soqucoin supports merged mining with Litecoin and Dogecoin. This means:
- Blocks may be submitted by Litecoin/Dogecoin miners
- AuxPoW headers contain parent chain proof
- Block structure differs from native PoW blocks

### 5.2 Block Validation

```bash
# Check if block is AuxPoW
soqucoin-cli getblock "blockhash" 2 | jq '.auxpow'
```

**AuxPoW block response includes**:
- `coinbasetx`: Parent chain coinbase
- `coinbranch`: Merkle branch for coinbase
- `blockchainbranch`: Merkle branch for aux chain
- `parentblock`: Parent chain block header

### 5.3 Chain ID Verification

Soqucoin's unique chain ID is `0x5351` (21329, representing "SQ"). This prevents cross-chain replay attacks with Dogecoin (`0x0062`).

```bash
# Verify chain ID in block
soqucoin-cli getblockchaininfo | jq '.chainid'
```

---

## 6. RPC Reference (Exchange-Relevant)

### 6.1 Transactions

| Command | Description |
|---------|-------------|
| `sendrawtransaction <hex>` | Broadcast a signed transaction |
| `getrawtransaction <txid> 1` | Transaction details (needs `txindex=1`) |
| `decoderawtransaction <hex>` | Decode a transaction before broadcast |
| `gettxout <txid> <n>` | An unspent output from the UTXO set |

### 6.2 Addresses

| Command | Description |
|---------|-------------|
| `validateaddress <addr>` | Check an address against the node's network and address rules |

### 6.3 Blockchain

| Command | Description |
|---------|-------------|
| `getblockchaininfo` | Sync status, chain info |
| `getblockcount` | Current block height |
| `getblock <hash> [verbosity]` | Block details |
| `getnetworkinfo` | Network/peer status |

### 6.4 PQ Wallet

| Command | Description |
|---------|-------------|
| `pqvalidateaddress <addr>` | Valid only for a bech32m witness version 1 address with a 32-byte program for this node's network; narrower than `validateaddress`, which also reports legacy Base58 as valid (section 3.2). `pubkey_hash` is the witness program |
| `pqwalletinfo` | Wallet configuration |
| `pqestimatefeerate [ins] [outs]` | Fee estimation |

`pqgetnewaddress` is removed in 2.5.1; it kept no key.

---

## 7. Security Recommendations

### 7.1 Network Security

- [ ] Run node behind firewall
- [ ] Use SSH tunnels for RPC access
- [ ] Implement VPN for remote management
- [ ] Enable fail2ban for SSH

### 7.2 RPC Security

- [ ] Use strong 32+ character RPC password
- [ ] Bind RPC to localhost only
- [ ] Use SSL/TLS for RPC (nginx proxy)
- [ ] Implement RPC rate limiting

### 7.3 Key Security

- [ ] Keep keys in your own key store; the SDK's keystore file is encrypted with AES-256-GCM
- [ ] Back up the master secret your deposit addresses derive from, offline
- [ ] Cold storage for bulk assets
- [ ] Hardware security modules (HSM) for production

### 7.4 Monitoring

- [ ] Alert on unusual withdrawal patterns
- [ ] Monitor node connectivity
- [ ] Track mempool size
- [ ] Watch for chain reorgs > 1 block

---

## 8. Troubleshooting

### 8.1 Common Issues

| Issue | Solution |
|-------|----------|
| Node not syncing | Check network connectivity, verify peers with `getpeerinfo` |
| RPC connection refused | Verify `rpcbind`, `rpcallowip`, and firewall rules |
| Transaction stuck | Check fee was adequate, verify UTXO not already spent |
| Address validation fails | Check the prefix for the node's network (`sq` on mainnet and testnet, `ssq` on stagenet) and witness version 1 (`sq1p...`) |

### 8.2 Log Analysis

```bash
# View recent logs
tail -f ~/.soqucoin/debug.log

# Search for errors
grep -i error ~/.soqucoin/debug.log | tail -20

# Check for network issues
grep -i "connection\|peer\|banned" ~/.soqucoin/debug.log
```

### 8.3 Node Recovery

```bash
# Reindex entire chain (if corruption suspected)
soqucoind -reindex

# Rebuild txindex
soqucoind -reindex-chainstate
```

---

## 9. Support & Resources

| Resource | Link |
|----------|------|
| **Protocol Spec** | https://soqu.org/protocol.html |
| **GitHub** | https://github.com/soqucoin/soqucoin |
| **Email Support** | dev@soqu.org |
| **Whitepaper** | https://soqu.org/whitepaper.html |

---

## Appendix A: Testnet Integration

For testing integration before mainnet:

```bash
# Testnet3 configuration
soqucoind -testnet -daemon

# Testnet RPC
soqucoin-cli -testnet getblockchaininfo

# Testnet addresses use the mainnet prefix
sq1p...
```

> **Note**: Contact dev@soqu.org for testnet node access during development.

---

## Appendix B: API Response Examples

### getblockchaininfo
```json
{
  "chain": "main",
  "blocks": 12108,
  "headers": 12108,
  "bestblockhash": "eb718060...",
  "difficulty": 170.06,
  "mediantime": 1736228400,
  "verificationprogress": 1.0,
  "chainwork": "...",
  "chainid": 21329
}
```

---

*Prepared for exchange partners*
*Soqucoin Development Team, October 2026*
