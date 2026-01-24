# Soqucoin Wallet Integration Guide

> **Version**: 1.0 | **Updated**: January 6, 2026
> **Audience**: External Developers, Exchanges, Auditors
> **Status**: Pre-Mainnet

---

## Overview

This guide covers building and testing the Soqucoin post-quantum wallet library for integration into external systems. The wallet implements Dilithium (ML-DSA-44) signatures and is designed for regulatory compliance with opt-in privacy features.

---

## 1. Build Prerequisites

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **OS** | Ubuntu 20.04 / macOS 12 | Ubuntu 22.04 / macOS 14 |
| **RAM** | 4 GB | 8 GB |
| **Disk** | 10 GB | 50 GB (with chain) |
| **CPU** | x86_64 or ARM64 | Apple Silicon or AVX2 |

### Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential libtool autotools-dev automake \
    pkg-config bsdmainutils python3 libssl-dev libevent-dev \
    libboost-all-dev libdb-dev libdb++-dev libminiupnpc-dev \
    libzmq3-dev libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev \
    qttools5-dev-tools libprotobuf-dev protobuf-compiler

# macOS (with Homebrew)
brew install automake libtool boost miniupnpc openssl pkg-config \
    protobuf qt@5 libevent berkeley-db@4 zeromq
```

---

## 2. Building with PQ Wallet

### Clone and Build

```bash
# Clone repository
git clone https://github.com/soqucoin/soqucoin.git
cd soqucoin

# Checkout mainnet candidate
git checkout soqucoin-genesis

# Build
./autogen.sh
./configure --with-gui=qt5
make -j$(nproc)
```

### Verify PQ Wallet Integration

```bash
# Check wallet library includes pqwallet
ar -t src/libsoqucoin_wallet.a | grep pqwallet

# Expected output:
# wallet_pqwallet_pqwallet.o
# wallet_pqwallet_pqcrypto.o
```

---

## 3. Network Configuration

### Testnet3 (Development)

```bash
# Start testnet3 node
./src/soqucoind -testnet -daemon

# Wait for sync
./src/soqucoin-cli -testnet getblockchaininfo
```

**Testnet3 Parameters:**
- Address prefix: `tsq1...`
- Genesis: December 2025
- All features active at genesis

### Stagenet (Mainnet Rehearsal)

```bash
# Start stagenet node
./src/soqucoind -stagenet -daemon

# Check status
./src/soqucoin-cli -stagenet getblockchaininfo
```

**Stagenet Parameters:**
- Address prefix: `ssq1...`
- Genesis: January 5, 2026
- Staged activation matching mainnet schedule

---

## 4. PQ Wallet RPC Commands

### Available Commands

| Command | Description |
|---------|-------------|
| `pqgetnewaddress` | Generate new Dilithium address |
| `pqvalidateaddress` | Validate PQ address format |
| `pqestimatefeerate` | Estimate verification cost |
| `pqwalletinfo` | Get wallet library info |

### Examples

```bash
# Generate new address
./src/soqucoin-cli -testnet pqgetnewaddress
# Returns:
# {
#   "address": "tsq1...",
#   "pubkey_hash": "abc123...",
#   "network": "testnet",
#   "type": "P2PQ"
# }

# Validate address
./src/soqucoin-cli -testnet pqvalidateaddress "tsq1..."
# Returns:
# {
#   "isvalid": true,
#   "network": "testnet",
#   "type": "P2PQ",
#   "pubkey_hash": "..."
# }

# Estimate fee for 5-input, 10-output transaction
./src/soqucoin-cli -testnet pqestimatefeerate 5 10
# Returns:
# {
#   "verify_cost": 35,
#   "breakdown": {
#     "signature_cost": 5,
#     "script_cost": 30,
#     "hash_cost": 10
#   },
#   "recommendation": "Standard transaction, no aggregation needed"
# }

# Get wallet info
./src/soqucoin-cli -testnet pqwalletinfo
# Returns:
# {
#   "version": "1.0",
#   "dilithium_mode": "ML-DSA-44",
#   "pubkey_size": 1312,
#   "signature_size": 2420,
#   "address_format": "Bech32m",
#   "encryption": "AES-256-CBC+HMAC",
#   ...
# }
```

---

## 5. Integration Testing

### Run Test Suite

```bash
# Make executable
chmod +x scripts/wallet_integration_test.sh

# Run on testnet3
./scripts/wallet_integration_test.sh testnet

# Run on stagenet
./scripts/wallet_integration_test.sh stagenet
```

### Expected Output

```
==============================================
Soqucoin PQ Wallet Integration Tests
Network: testnet
Date: Mon Jan 6 21:30:00 MST 2026
==============================================

--- Test 1: PQ Wallet Info ---
✓ PASS: pqwalletinfo returns dilithium_mode
✓ PASS: Dilithium mode is ML-DSA-44

--- Test 2: Generate New PQ Address ---
✓ PASS: Testnet address has correct prefix (tsq1)
✓ PASS: Address length is valid (58 characters)

[... more tests ...]

==============================================
TEST SUMMARY
==============================================
Passed: 15
Failed: 0
Total:  15

ALL TESTS PASSED
```

---

## 6. Address Format Specification

### Bech32m Encoding

| Network | HRP | Example |
|---------|-----|---------|
| Mainnet | `sq1` | `sq1q...` (52-62 chars) |
| Testnet | `tsq1` | `tsq1q...` (53-63 chars) |
| Stagenet | `ssq1` | `ssq1q...` (54-64 chars) |

### Address Types

| Type | Code | Description |
|------|------|-------------|
| P2PQ | `0x00` | Pay-to-Post-Quantum (single sig) |
| P2PQ_PAT | `0x01` | With PAT aggregation proof |
| P2SH_PQ | `0x02` | Script hash containing PQ keys |

---

## 7. Security Considerations

### Wallet File Encryption

- **Algorithm**: AES-256-CBC + HMAC-SHA256
- **Key Derivation**: PBKDF2-SHA256 (100,000 iterations)
- **Salt**: 16 bytes random per encryption
- **IV**: 12 bytes random per encryption

### Best Practices

1. **Always encrypt wallet files** with strong passphrase
2. **Backup seed phrase** offline (metal plate recommended)
3. **Test recovery** on testnet before mainnet
4. **Verify addresses** before large transactions

---

## 8. Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `pqgetnewaddress` not found | Rebuild with latest code; check RPC registration |
| Library not loaded | Run `make clean && make`; check library paths |
| Address validation fails | Ensure correct network flag (`-testnet`, `-stagenet`) |
| Build fails on pqwallet | Run `autoreconf -i && ./configure` |

### Support

- GitHub Issues: https://github.com/soqucoin/soqucoin/issues
- Stagenet Explorer: https://stagenet.soqucoin.org (coming soon)

---

## 9. Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-06 | Initial release |

---

*Soqucoin Wallet Integration Guide v1.0*
*Prepared for Halborn Security Audit and External Integration*
