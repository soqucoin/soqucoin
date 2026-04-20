# Changelog

All notable changes to Soqucoin Core will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc2] — 2026-04-19

Second release candidate incorporating mining stability fixes, consensus wiring,
and enterprise-grade CI/CD infrastructure.

### Added
- **Consensus wiring**: PAT (`OP_CHECKPATAGG`) and LatticeFold+ (`OP_CHECKFOLDPROOF`) now routed from `VerifyScript()` via witness v2/v3 (SOQ-D001)
- **Lattice-BP++ range proofs**: Core polynomial arithmetic, NTT, Pedersen commitments, and `OP_LATTICEBP_RANGEPROOF` handler (witness v4)
- **Stagenet deployment**: `contrib/stagenet-deploy.sh` with mainnet-parity difficulty (`fPowAllowMinDifficultyBlocks=false`)

### Fixed
- **Mining race condition** (SOQ-INFRA-001/001b): `cs_blocktemplate` mutex serializing `getblocktemplate` / `submitblock` — eliminates SEGFAULT under ASIC load
- **IBD guard** (SOQ-INFRA-002): Re-enabled `IsInitialBlockDownload()` check in getblocktemplate
- **Long-poll tip cache** (SOQ-INFRA-003): Cached tip hash inside `cs_main` for safe long-poll path
- **RPC bech32m migration** (SOQ-INFRA-006/007/008): `createauxblock`, `createrawtransaction`, and 8+ wallet RPCs now use `DecodeDestination()` for bech32m-first address handling
- **PQ wallet hash alignment** (SOQ-INFRA-009/010): Both core and PQ wallet modules use SHA-256/32-byte witness programs (62-char bech32m)
- **Deterministic block rewards** (SOQ-INFRA-014): `fSimplifiedRewards=true` from genesis (fixed Dogecoin random reward inheritance)
- **GCC/MinGW build fixes**: `<cstddef>`, `<string>`, `<cstring>` portability includes; `M_PI` guard for Windows
- **Test expectations**: Updated subsidy sums and OP_RETURN assertions for Soqucoin's fixed reward model

### Infrastructure
- Enterprise GitHub architecture: `main` branch with protection (PR required, no force push)
- CI/CD: 4-target build matrix (Linux x64/ARM64, macOS ARM64, Windows x64) + CodeQL + Lint
- Enterprise metadata: SECURITY.md, CHANGELOG.md, CONTRIBUTING.md, CODEOWNERS, YAML issue templates
- `release/v1.0.x` maintenance branch

### Security
- All 30 Halborn FIND-001 through FIND-030 findings verified present in codebase
- All 6 extension audit findings (SOQ-A001 through SOQ-A006) verified present
- Dead Bulletproofs handler removed from VerifyScript (SOQ-INFRA-016)

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
