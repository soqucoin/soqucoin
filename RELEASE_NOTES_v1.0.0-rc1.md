# Soqucoin v1.0.0-rc1 — First Miner-Ready Release Candidate

> **Release Date:** April 16, 2026  
> **Branch:** `soqucoin-genesis`  
> **Status:** Release Candidate (Pre-Release)

---

## What Is This Release?

This is the **first official Soqucoin node binary** for miners and node operators. It represents the complete, audited Soqucoin Core with all post-quantum cryptography features active from genesis.

**Who should run this?**
- Miners who want to solo mine or operate pool infrastructure on Testnet3
- Node operators who want to contribute to network health
- Developers building on the Soqucoin L1

---

## Highlights

### 🔒 Security Audit — All 30 Findings Remediated
The Soqucoin codebase has undergone a comprehensive security audit by **Halborn** (March 2026). All 30 findings (FIND-003 through FIND-030) have been remediated and verified:

- **Wallet Crypto v2**: Argon2id KDF, HMAC-SHA256 MAC, constant-time tag comparison
- **Dilithium Key Material**: Stack zeroization after keygen/sign operations
- **PAT (Post-Quantum Aggregate Transactions)**: Merkle last-leaf replication, bounds checking, rogue-key attack mitigation via SHA3-256 aggregation
- **RPC Hardening**: Parameter validation, timer bounds, race condition serialization
- **Memory Cleanse**: Comprehensive sweep of sensitive data paths

### ⛏️ Mining Fixes
- **Deterministic Block Rewards**: Fixed 500K SOQ/block halving schedule from genesis (disables Dogecoin-style random rewards)
- **AuxPoW SegWit Fix**: Block templates now include SegWit transactions. Previously, all bech32 transactions were stuck in mempool.

### 🏗️ Build Infrastructure
- Multi-platform release builds: **Linux x64, Linux ARM64, macOS x64, macOS ARM64, Windows x64**
- SHA256 checksums for all binaries
- Automated GitHub Release via tag push

---

## Emission Schedule

| Epoch | Block Range | Reward/Block | Cumulative Supply |
|-------|------------|-------------|-------------------|
| 0 | 0 – 99,999 | 500,000 SOQ | 50B |
| 1 | 100,000 – 199,999 | 250,000 SOQ | 75B |
| 2 | 200,000 – 299,999 | 125,000 SOQ | 87.5B |
| 3 | 300,000 – 399,999 | 62,500 SOQ | 93.75B |
| 4 | 400,000 – 499,999 | 31,250 SOQ | 96.875B |
| 5 | 500,000 – 599,999 | 15,625 SOQ | 98.4375B |
| 6+ | 600,000+ | 10,000 SOQ | Perpetual (~5.26B/year) |

---

## Quick Start for Miners

### 1. Download & Extract
```bash
# Linux x64
wget https://github.com/soqucoin/soqucoin/releases/download/v1.0.0-rc1/soqucoin-v1.0.0-rc1-linux-x64.tar.gz
tar xzf soqucoin-v1.0.0-rc1-linux-x64.tar.gz

# Verify checksum
sha256sum -c SHA256SUMS
```

### 2. Start the Node (Testnet)
```bash
./soqucoind -testnet -daemon

# Check sync status
./soqucoin-cli -testnet getblockchaininfo
```

### 3. Connect to Pool (Stratum)
Point your ASIC miner's Stratum configuration to connect via AuxPoW merge-mining:
- **Pool endpoint:** Your pool's stratum address (port 3333)
- **Algorithm:** Scrypt

### 4. Solo Mining
```bash
# Generate a mining address
./soqucoin-cli -testnet getnewaddress "" "bech32"

# Configure soqucoin.conf
echo "gen=1" >> ~/.soqucoin/soqucoin.conf
```

---

## Network Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | Scrypt (PoW) + AuxPoW |
| Block Time | 60 seconds |
| Coinbase Maturity | 30 blocks |
| P2P Port (mainnet) | 44556 |
| RPC Port (mainnet) | 44555 |
| P2P Port (testnet) | 44556 |
| Signatures | ML-DSA-44 (Dilithium) from genesis |

---

## Platform Support

| Platform | Architecture | Format |
|----------|-------------|--------|
| Linux | x86_64 | `.tar.gz` |
| Linux | ARM64 (Raspberry Pi) | `.tar.gz` |
| macOS | Intel (x64) | `.tar.gz` |
| macOS | Apple Silicon (ARM64) | `.tar.gz` |
| Windows | x64 | `.zip` |

---

## Upgrading from Previous Versions

If you were running a node from the `v0.21.2-pq-genesis` tag, simply replace the binaries. No chain resync is required — the block database format is compatible.

---

## Known Issues

- macOS builds show harmless `-bind_at_load is deprecated` linker warnings
- Windows build uses cross-compilation (mingw-w64) and has not been tested with native MSVC

---

## Full Changelog

See the [commit history](https://github.com/soqucoin/soqucoin/compare/v0.21.2-pq-genesis...v1.0.0-rc1) for the complete list of changes since the last tag.
