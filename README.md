<p align="center">
  <img src="https://soqu.org/soq-logo-clean-quantum-v1.png" alt="Soqucoin" width="200"/>
</p>

<h1 align="center">Soqucoin™ Core</h1>

<p align="center">
  <strong>The first production cryptocurrency with native post-quantum signatures and confidential transactions</strong>
</p>

<p align="center">
  <a href="https://github.com/soqucoin/soqucoin/actions/workflows/ci.yml"><img src="https://github.com/soqucoin/soqucoin/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/soqucoin/soqucoin/releases/latest"><img src="https://img.shields.io/github/v/release/soqucoin/soqucoin?include_prereleases&label=release" alt="Release"></a>
  <a href="https://github.com/soqucoin/soqucoin/blob/main/COPYING"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License"></a>
  <a href="https://soqu.org"><img src="https://img.shields.io/badge/website-soqu.org-purple" alt="Website"></a>
</p>

<p align="center">
  <a href="#about">About</a> •
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

---

## About

Soqucoin is a Scrypt-based proof-of-work cryptocurrency that removes ECDSA from the transaction authorization path and uses **NIST-standardized ML-DSA-44 (Dilithium)** signatures. It combines two batch-verification techniques—**PAT** (Practical Aggregation Technique) and **LatticeFold+**—to achieve scalable post-quantum security without sacrificing performance.

> **Why does this matter?** Quantum computers will eventually break ECDSA. Soqucoin makes all user transaction signatures quantum-resistant without requiring a soft-fork migration from an ECDSA-based design.

### Current Status

| Milestone | Status | Date |
|-----------|--------|------|
| Consensus code merged | ✅ Complete | Nov 20, 2025 |
| ASIC validation (L7) | ✅ Complete | Nov 24, 2025 |
| Testnet3 launch | ✅ Complete | Dec 2025 |
| Stability testing (1200+ blocks) | ✅ Complete | Jan 2, 2026 |
| Halborn security audit (30 findings) | ✅ Complete | Feb–Mar 2026 |
| Lattice-BP++ consensus wired | ✅ Complete | Apr 2026 |
| Mainnet genesis | 🔄 In Progress | Q2 2026 |

---

## Features

### Post-Quantum Cryptography

| Component | Implementation | Security Level |
|-----------|---------------|----------------|
| **Signatures** | ML-DSA-44 (Dilithium) | NIST Level 2 (128-bit quantum) |
| **Address Hashing** | SHA-256 | 128-bit collision |
| **Batch Verification** | LatticeFold+ / PAT | Constant-size proofs |
| **Proof-of-Work** | Scrypt (N=1024, r=1, p=1) | Grover-resistant |

### Confidential Transactions (Lattice-BP++)

| Component | Implementation | Security Level |
|-----------|---------------|----------------|
| **Commitments** | Lattice (Module-LWE, n=256, q=8380417) | NIST Level 2 (quantum-safe) |
| **Range Proofs** | Lattice-BP++ | NIST Level 2 (quantum-safe) |
| **Ring Signatures** | Module-LWE ring sigs (up to size 11) | NIST Level 2 (quantum-safe) |
| **Proof Size** | 12,321 bytes | — |
| **Verify Time** | 0.022 ms | Apple M-series arm64 |

> **Note:** Lattice-BP++ uses the same Module-LWE/SIS hardness assumptions as NIST's ML-DSA (Dilithium) standard, providing full quantum resistance. Activated via `OP_LATTICEBP_RANGEPROOF` (witness v4) soft fork. Patent pending.

### Performance Benchmarks

```
┌─────────────────────────────────┬────────────────┬─────────────┐
│ Operation                       │ Time (M4)      │ Size        │
├─────────────────────────────────┼────────────────┼─────────────┤
│ Dilithium Sign                  │ 0.177 ms       │ 2,420 bytes │
│ Dilithium Verify                │ 0.041 ms       │ —           │
│ PAT Aggregate (1000 sigs)       │ 0.67 ms        │ 72 bytes    │
│ LatticeFold+ Verify (512 sigs)  │ 0.68 ms        │ 1.38 KB     │
│ Lattice-BP++ Prove              │ 0.556 ms       │ 12.3 KB     │
│ Lattice-BP++ Verify             │ 0.022 ms       │ —           │
└─────────────────────────────────┴────────────────┴─────────────┘
```

### ASIC Compatibility

Validated on **Antminer L7** (9.5 GH/s):
- Standard Stratum V1 protocol
- Zero firmware modifications
- Zero rejected shares (cleaner than Litecoinpool/Powerpool)
- 640+ blocks continuous operation, zero crashes

### PAT (Practical Aggregation Technique)

**Status**: ✅ Fully Implemented (v1.0) — November 2025

Soqucoin implements PAT for logarithmic batching of Dilithium signatures through Merkle tree commitments. This provides massive space savings for batch transaction validation.

#### Implementation Details

| Component | Status | File |
|-----------|--------|------|
| Proof Generation | ✅ Complete | `src/crypto/pat/logarithmic.cpp` |
| Proof Verification | ✅ Complete | `CreateLogarithmicProof()` |
| Simple Mode Verification | ✅ Production | `VerifyLogarithmicProof()` |
| Full Mode Verification | ✅ Infrastructure Ready | Full witness validation |
| Consensus Opcode | ✅ Active | `OP_CHECKPATAGG` (0xfd) |
| Unit Tests | ✅ 17/17 Passing | `test/pat_tests.cpp` |
| Integration Tests | ✅ Complete | `test/pat_script_tests.cpp` |

#### Verification Guarantees

- ✅ **Merkle Root Binding**: Prevents proof forgery and signature omission
- ✅ **Hash Aggregation (SHA3-256)**: Prevents rogue-key substitution attacks  
- ✅ **Message Commitment**: Prevents message tampering or reordering
- ✅ **Non-Malleability**: Canonical ordering ensures unique proofs

#### Performance Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| Proof Size | 100 bytes | Constant, regardless of batch size |
| Verification (Simple) | < 4 µs | O(1) constant time |
| Verification (Full) | ~800 µs @ n=1024 | O(log n) tree traversal |
| Space Savings | 25,600× @ n=1024 | vs individual Dilithium signatures |
| Activation | Block 0 | Active since genesis |

#### Consensus Mode

```
Stack: <sigs...> <pks...> <msgs...> <count> 
       <proof> <agg_pk> <msg_root> OP_CHECKPATAGG
Use Case: Transaction validation, block verification
Trust Model: Full cryptographic verification with witness data
```

#### Documentation

- **Wire Format**: [doc/pat-specification.md](doc/pat-specification.md)
- **API Reference**: [src/crypto/pat/logarithmic.h](src/crypto/pat/logarithmic.h)
- **Test Vectors**: [test/pat_tests.cpp](test/pat_tests.cpp)

---

## Quick Start

### Prerequisites

- C++14 compiler (GCC 7+ or Clang 8+)
- Boost 1.70+
- OpenSSL 1.1+
- libevent 2.1+

### Build from Source

```bash
git clone https://github.com/soqucoin/soqucoin.git
cd soqucoin
./autogen.sh
./configure
make -j$(nproc)
make install  # optional
```

### Run a Node

```bash
# Mainnet
./src/soqucoind -daemon

# Testnet
./src/soqucoind -testnet -daemon

# Regtest (local development)
./src/soqucoind -regtest -daemon
```

### Network Ports

| Network | P2P | RPC |
|---------|-----|-----|
| Mainnet | 33388 | 33389 |
| Testnet | 44556 | 44555 |
| Regtest | 18444 | 18332 |

---

## Documentation

| Document | Description |
|----------|-------------|
| [INSTALL.md](INSTALL.md) | Build instructions for all platforms |
| [doc/getting-started.md](doc/getting-started.md) | First steps guide |
| [doc/build-unix.md](doc/build-unix.md) | Linux/BSD build guide |
| [doc/build-macos.md](doc/build-macos.md) | macOS build guide |
| [doc/build-windows.md](doc/build-windows.md) | Windows build guide |
| [doc/FAQ.md](doc/FAQ.md) | Frequently asked questions |
| [Whitepaper](https://soqu.org/whitepaper/soqucoin_whitepaper.pdf) | Technical specification |

---

## Architecture

### Consensus Opcodes

| Opcode | Hex | Witness | Purpose |
|--------|-----|---------|----------|
| `OP_LATTICEBP_RANGEPROOF` | 0xfa | v4 | Lattice-BP++ range proof verification |
| `OP_CHECKFOLDPROOF` | 0xfc | v3 | LatticeFold+ batch proof verification |
| `OP_CHECKPATAGG` | 0xfd | v2 | PAT Merkle commitment verification |

### Prover Implementation Status

| Component | Location | Status |
|-----------|----------|--------|
| **PAT Prover** | `src/crypto/pat/logarithmic.cpp` | ✅ In-tree |
| **PAT Verifier** | `src/crypto/pat/logarithmic.cpp` | ✅ In-tree |
| **LatticeFold+ Prover** | Off-chain (trusted pools) | ✅ Operational |
| **LatticeFold+ Verifier** | `src/crypto/latticefold/verifier.cpp` | ✅ In-tree |
| **Lattice-BP++ Prover** | `src/crypto/latticebp/range_proof.cpp` | ✅ In-tree |
| **Lattice-BP++ Verifier** | `src/crypto/latticebp/range_proof.cpp` | ✅ In-tree |
| **PQ Wallet Library** | `src/wallet/pqwallet/` | ✅ In-tree |

Note: LatticeFold+ is `ALWAYS_ACTIVE` from genesis on all networks. Lattice-BP++ is `ALWAYS_ACTIVE` on regtest, `NEVER_ACTIVE` on mainnet pending audit.

### Branch Structure

| Branch | Purpose |
|--------|---------|
| `main` | Active development (default, protected) |
| `release/v1.0.x` | Stable release branch (hotfixes only) |
| `feature/*` | Feature branches (PR into main) |

---

## Contributing

### Pre-Launch Policy

Soqucoin Core is in **pre-genesis final validation**. The consensus stack has completed security audit (Halborn, 30 findings remediated) and is undergoing final pre-mainnet testing.

**How to contribute now:**

1. **Report bugs** — Open a [GitHub Issue](https://github.com/soqucoin/soqucoin/issues)
2. **Discuss features** — Join [GitHub Discussions](https://github.com/soqucoin/soqucoin/discussions)
3. **Share test data** — Regtest blocks, fuzz corpora, ASIC screenshots

> Pull requests will be enabled immediately after genesis. Contributors who help stress-test the chain will be credited in the launch paper.

### Code Style

This project follows [Bitcoin Core contribution guidelines](CONTRIBUTING.md):
- C++17 standard
- 4-space indentation
- No trailing whitespace
- Signed commits required

---

## Tokenomics

| Parameter | Value |
|-----------|-------|
| **Ticker** | SOQ |
| **Algorithm** | Scrypt |
| **Block Time** | 1 minute |
| **Initial Block Reward** | 500,000 SOQ |
| **Halving Interval** | 100,000 blocks (~69 days) |
| **Terminal Emission** | 10,000 SOQ perpetual (after block 600,000) |
| **Supply Model** | Inflationary with declining rate |
| **Premine** | 0 SOQ |

**Fair Launch** — No premine, no ICO, no founder allocation, no treasury. 100% proof-of-work distribution.

---

## Security

For security vulnerabilities, please see [SECURITY.md](.github/SECURITY.md).

**Do not** open public issues for security-related bugs.

---

## License

Soqucoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for details.

---

<p align="center">
  <sub>Built with 🔐 by the Soqucoin Core developers</sub>
</p>
