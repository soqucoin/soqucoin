# Soqucoin Wallet Integration Guide

> **Version**: 1.1 | **Updated**: October 10, 2026
> **Audience**: External Developers, Exchanges, Auditors
> **Status**: Pre-Mainnet

---

## Overview

This guide covers building and testing the Soqucoin post-quantum wallet library for integration into external systems. The wallet implements Dilithium (ML-DSA-44) signatures and is designed for regulatory compliance with opt-in privacy features.

Exchanges and custodians integrate through the SDK's [Exchange Integration guide](https://github.com/soqucoin-labs/soqucoin-sdk/blob/main/docs/EXCHANGE_INTEGRATION.md), which derives keys and signs in your own infrastructure with the node's wallet disabled. From 2.5.1 the node wallet's `encryptwallet`, `dumpprivkey`, `importprivkey`, `dumpwallet` and `importwallet` handle ML-DSA-44 keys; earlier releases did not, and the [2.5.1 release notes](../release-notes/release-notes-2.5.1.md) describe each. Section 7 covers encrypting and backing up a node wallet.

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
- Address prefix: `sq1p...` (the mainnet prefix)
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
- Address prefix: `ssq1p...`
- Genesis: January 5, 2026
- Staged activation matching mainnet schedule

---

## 4. PQ Wallet RPC Commands

### Available Commands

| Command | Description |
|---------|-------------|
| `pqvalidateaddress` | Valid only for a bech32m witness version 1 address with a 32-byte program for this node's network (`rpc_pqwallet.cpp`); `pubkey_hash` is the witness program |
| `pqestimatefeerate` | Estimate verification cost |
| `pqwalletinfo` | Get wallet library info |

`pqgetnewaddress` is removed in 2.5.1; it kept no key. A node wallet address comes from `getnewaddress`. `validateaddress` is wider than `pqvalidateaddress`: it also reports a legacy Base58 address with this network's version byte as `"isvalid": true`, without `isdilithium` or `witness_version` (`src/rpc/misc.cpp`), although the chain cannot spend an output to one. Treat the two RPCs as different contracts: with `validateaddress`, require `isvalid`, `isdilithium` and `witness_version` 1 together.

### Examples

```bash
# New address in the node wallet
./src/soqucoin-cli -testnet getnewaddress
# Returns: "sq1p..."

# Validate an address
./src/soqucoin-cli -testnet validateaddress "sq1p..."
# Returns, for a valid address, among other fields:
# {
#   "isvalid": true,
#   "isdilithium": true,
#   "witness_version": 1,
#   ...
# }

# Estimate fee for 5-input, 10-output transaction
./src/soqucoin-cli -testnet pqestimatefeerate 5 10
# Returns:
# {
#   "verify_cost": 45,
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
#   "encryption": "AES-256-CBC",
#   "kdf": "SHA-512 EVP_BytesToKey",
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
| Mainnet | `sq` | `sq1p...` (62 chars) |
| Testnet | `sq` | `sq1p...` (62 chars) |
| Stagenet | `ssq` | `ssq1p...` (63 chars) |

Every address is witness version 1, and its 32-byte witness program is the SHA-256 of the ML-DSA-44 public key. The node accepts only witness version 1 addresses as payment destinations.

### Address Types

| Type | Code | Description |
|------|------|-------------|
| P2PQ | `0x00` | Pay-to-Post-Quantum (single sig) |
| P2PQ_PAT | `0x01` | With PAT aggregation proof |
| P2SH_PQ | `0x02` | Script hash containing PQ keys |

---

## 7. Security Considerations

### Wallet File Encryption

From 2.5.1 `encryptwallet` encrypts the wallet's ML-DSA-44 keys: AES-256-CBC, with the key and IV derived from the passphrase and a salt by the SHA-512 form of `EVP_BytesToKey`, the iteration count calibrated per wallet each time a passphrase is set (`pqwalletinfo` reports `encryption` and `kdf`). A wallet encrypted by 2.5.0 could not be unlocked by 2.5.0; its keys are intact and it unlocks with 2.5.1. Protect the wallet file with file permissions and full-disk encryption as well.

### Best Practices

1. **Encrypt the wallet** with `encryptwallet` and a strong passphrase; `walletpassphrase` unlocks it to spend
2. **Back up the wallet file** with `backupwallet`, which writes the copy to the `backups` folder in the data directory, then copy it off the machine; `dumpwallet` and `importwallet` round-trip every key as text
3. **Test recovery** from the backup on another node before relying on it
4. **Verify addresses** before large transactions

---

## 8. Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
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
| 1.1 | 2026-10-10 | Exchange path through the SDK; address format is witness version 1; `pqgetnewaddress` removed in 2.5.1 and `getnewaddress` in its place; `pqvalidateaddress` accepts only the witness version 1 form and `validateaddress` also reports legacy Base58 as valid; wallet encryption and the key export round trip from 2.5.1; backup with `backupwallet` |

---

*Soqucoin Wallet Integration Guide v1.1*
*Prepared for Halborn Security Audit and External Integration*
