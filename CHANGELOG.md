# Changelog

All notable changes to Soqucoin Core will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc1] — 2026-04-17

First release candidate for Soqucoin mainnet.

### Added
- **Post-Quantum Addresses**: SHA3-256 + Bech32m encoding (`sq1` prefix for mainnet, `ts1` for testnet)
- **Dilithium-3 Signatures**: NIST FIPS 204 post-quantum digital signatures (CRYSTALS-Dilithium)
- **PAT Opcodes**: Post-quantum Address Transition script system
  - `OP_CHECKPATAGG` — aggregated Dilithium signature verification
  - `OP_CHECKPATVERIFY` — PQ address validation
- **LatticeFold+ Deployment**: Lattice-based proof folding (set to `ALWAYS_ACTIVE`)
- **Lattice-BP++ Core**: Ring element arithmetic with NTT (Stage 3 R&D)
  - NTT polynomial multiplication matching Dilithium reference
  - Pedersen-style lattice commitments using HKDF-SHA256
  - Gaussian sampling for blinding factors
- **HD Key Derivation**: HKDF-SHA256 deterministic key hierarchy
  - Domain separation (wallet, blinding, channel keys)
  - BIP-44 style path: `m/44'/21329'/account'/change/index`
- **Wallet Encryption**: AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC)
- **AuxPoW Merge Mining**: Compatible with Dogecoin/Litecoin/Scrypt chains
- **Multi-network Support**: Mainnet, Testnet3, Stagenet configurations

### Security
- All Halborn FIND-001 through FIND-019 findings remediated
- Constant-time tag comparison in wallet HMAC verification
- Memory cleanse on all sensitive buffers (keys, PRK, seeds)
- Opcode simple-mode execution path removed per SSC

### Infrastructure
- Automated release pipeline (GitHub Actions) for Linux x64, Linux ARM64, macOS ARM64, macOS x64, Windows x64
- CodeQL security scanning
- DNS seed nodes for Testnet3

### Known Issues
- PAT opcodes not yet wired into `VerifyScript()` consensus path (SOQ-P001)
- Lattice-BP++ range proofs are placeholder (Phase 2 pending)

## [0.21.0] — 2025-12-01

Initial public release (pre-genesis, Dogecoin Core derived).

### Added
- Soqucoin genesis block and network parameters
- Scrypt-based Proof of Work
- Dogecoin-compatible emission schedule (500K block reward, 6 halvings, 10K perpetual tail)
- Basic P2P networking with DNS seed support
