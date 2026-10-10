# Soqucoin Wallet Development Roadmap

> **Version**: 1.1 | **Updated**: October 10, 2026
> **Audience**: Developers, Integrators, Auditors

---

## Overview

Soqucoin's post-quantum wallet is built on Dilithium (ML-DSA-44) signatures with native support for proof aggregation. This document outlines the wallet's architecture and planned feature evolution.

---

## Current Capabilities (Stage 1)

| Feature | Status | Notes |
|---------|--------|-------|
| Dilithium key generation | ✅ | NIST FIPS 204 compliant |
| Bech32m addresses | ✅ | witness version 1: `sq1p...` (mainnet and testnet), `ssq1p...` (stagenet) |
| Wallet encryption | ✅ | `encryptwallet`, AES-256-CBC, from 2.5.1 |
| PAT aggregation | ✅ | Batch signature verification |
| Basic RPC commands | ✅ | `getnewaddress`, `validateaddress`, `pqestimatefeerate`, etc. |

---

## Planned Features

### Near-Term (Q1-Q2 2026)

| Feature | Priority | Description |
|---------|----------|-------------|
| HD Wallet | 🔴 High | Full BIP-44 style derivation paths |
| Watch-Only Wallets | 🔴 High | For exchange cold storage |
| Coin Selection | 🟠 Medium | BnB + FIFO algorithms |
| PSBT Support | 🟠 Medium | Hardware wallet interoperability |

### Medium-Term (Q3-Q4 2026)

| Feature | Priority | Description |
|---------|----------|-------------|
| Multi-Asset Support | 🔴 High | Native stablecoin (USDSOQ) tracking |
| Hardware Wallets | 🟠 Medium | Ledger/Trezor research |
| Privacy Features | 🟠 Medium | Stealth addresses (Stage 3) |
| Multisig | 🟡 Future | FROST-based PQ multisig |

### Long-Term (2027+)

| Feature | Priority | Description |
|---------|----------|-------------|
| L2 Payment Channels | Research | SOQ Lightning (see Stage 5 spec) |
| Cross-Chain | Research | Bridge wallet integration |

---

## Documentation

| Document | Location | Purpose |
|----------|----------|---------|
| Wallet API Spec | `doc/WALLET_API_SPEC.md` | Library interface design |
| Integration Guide | `doc/WALLET_INTEGRATION_GUIDE.md` | External developer onboarding |
| Test Vectors | `doc/WALLET_TEST_VECTORS.md` | Interoperability testing |
| Address Format | `doc/ADDRESS_FORMAT_SPEC.md` | Bech32m encoding specification |

---

## Security

The wallet undergoes security review as part of the Halborn audit engagement. Key security features include:

- **SecureBytes class**: Memory-locked, zeroed-on-free key storage
- **Encrypted wallet files**: AES-256-CBC, the key and IV derived from the passphrase by the SHA-512 form of `EVP_BytesToKey` (from 2.5.1)
- **Dilithium signing**: Constant-time reference implementation

For security concerns, see `SECURITY.md` (dev@soqu.org).

---

## Contributing

Wallet development contributions are welcome. See `CONTRIBUTING.md` for guidelines.

---

*Soqucoin Wallet Roadmap v1.1 | October 2026*
