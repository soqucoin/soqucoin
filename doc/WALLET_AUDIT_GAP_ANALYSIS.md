# Soqucoin Wallet: Audit Gap Analysis & Development Roadmap

> **Date**: January 23, 2026
> **Author**: Casey (Founder)
> **Audience**: Core Team, Halborn Auditors, Future Developers
> **Classification**: Internal Planning Document

---

## Executive Summary

This document provides a comprehensive analysis of the Soqucoin wallet from a **top-tier L1 auditor's perspective**, identifying missing audit artifacts and documentation, then outlining the complete roadmap to evolve from a PQ L1 wallet to a full-featured platform supporting stablecoins and Lightning L2.

### Current State

| Component | Status | LOC | Audit Coverage |
|-----------|--------|-----|----------------|
| PQ Wallet Core (`pqwallet/`) | ✅ Implemented | ~2,400 | ⚠️ In Halborn Phase 1 |
| Wallet Encryption (`pqcrypto.cpp`) | ✅ Implemented | ~450 | ✅ In scope |
| RPC Commands (`rpc_pqwallet.cpp`) | ✅ Implemented | ~500 | ⚠️ Integration only |
| Test Suite (`pqwallet_test.cpp`) | ✅ Implemented | ~600 | ⚠️ Reference only |

---

## Part 1: Audit Documentation Gap Analysis

### 1.1 Documents That EXIST ✅

| Document | Location | Purpose | Audit Value |
|----------|----------|---------|-------------|
| `WALLET_API_SPEC.md` | `doc/` | API design reference | 🔴 High |
| `WALLET_INTEGRATION_GUIDE.md` | `doc/` | External developer guide | 🟠 Medium |
| `WALLET_TEST_VECTORS.md` | `doc/` | Deterministic test cases | 🔴 High |
| `WALLET_RESEARCH_COMPARISON.md` | `doc/` | Monero/Zcash/PQ chain comparison | 🟡 Background |
| `WALLET_DEVELOPMENT_ROADMAP.md` | `soqucoin-ops/` | Timeline and ownership | 🟡 Background |

### 1.2 Documents MISSING for Halborn Audit 🚨

| Missing Document | Priority | Why Auditors Need It | Recommended Action |
|------------------|----------|---------------------|-------------------|
| **WALLET_THREAT_MODEL.md** | 🔴 Critical | Defines attack vectors, adversary capabilities, security assumptions | Create immediately |
| **WALLET_CRYPTOGRAPHIC_SPEC.md** | 🔴 Critical | Formal spec of Dilithium parameters, key derivation, address hashing | Create before audit |
| **WALLET_KEY_DERIVATION_SPEC.md** | 🔴 Critical | BIP-44 path, HKDF parameters, seed→key flow | Create before audit |
| **WALLET_ENCRYPTION_SPEC.md** | 🟠 High | AES-256-CBC parameters, PBKDF2/Argon2 config, IV generation | Create before audit |
| **WALLET_RECOVERY_SPEC.md** | 🟠 High | Seed backup/restore, blinding factor recovery (GAP-010) | Create, addresses GAP-010 |
| **WALLET_SIDE_CHANNEL_ANALYSIS.md** | 🟠 High | Constant-time signing, memory protection verification | Create during audit |
| **WALLET_RPC_SECURITY_SPEC.md** | 🟡 Medium | RPC attack surface, authentication, rate limiting | Create post-Phase 1 |
| **WALLET_MULTISIG_SPEC.md** | 🟡 Medium | Not implemented yet; needed for future | Post-mainnet |

### 1.3 Missing Test Artifacts

| Missing Artifact | Priority | Purpose |
|-----------------|----------|---------|
| **Fuzz test harness** | 🔴 Critical | Automated discovery of edge cases |
| **Negative test vectors** | 🟠 High | Invalid signatures, malformed addresses |
| **Key derivation vectors** | 🟠 High | Reproducible BIP-44 → Dilithium derivation |
| **Encryption round-trip tests** | 🟠 High | Encrypt → Decrypt → Verify integrity |
| **Memory leak tests (Valgrind)** | 🟡 Medium | SecureBytes doesn't leak secrets |

### 1.4 Missing Code-Level Documentation

| Gap | Current State | Required for Audit |
|-----|---------------|-------------------|
| Function-level security comments | ⚠️ Partial | Every crypto function needs threat annotation |
| Invariant documentation | ❌ Missing | Pre/post conditions for key operations |
| Error handling rationale | ⚠️ Partial | Why each error path exists |
| Entropy source documentation | ❌ Missing | Where randomness comes from |
| Memory wiping verification | ⚠️ Partial | Proof that SecureBytes::Wipe() actually works |

---

## Part 2: Critical Audit Recommendations

### 2.1 Immediate (Before Jan 28 Halborn Kickoff)

```
Priority | Action | Owner | Est. Hours
---------|--------|-------|------------
🔴 P0    | Create WALLET_THREAT_MODEL.md | Casey | 4-6
🔴 P0    | Create WALLET_CRYPTOGRAPHIC_SPEC.md | Archith | 6-8
🔴 P0    | Add function security annotations to pqwallet/*.cpp | Casey | 3-4
🔴 P0    | Document entropy sources in SecureBytes | Casey | 1-2
```

### 2.2 During Audit (Jan 28 - Feb 19)

```
Priority | Action | Owner | Trigger
---------|--------|-------|--------
🟠 P1    | Respond to auditor questions with documentation | Casey | Daily
🟠 P1    | Create WALLET_SIDE_CHANNEL_ANALYSIS.md if auditor requests | Archith | On request
🟠 P1    | Add negative test vectors per auditor findings | Casey | Per finding
```

### 2.3 Pre-Mainnet (Post-Audit Remediation)

```
Priority | Action | Owner | Trigger
---------|--------|-------|--------
🟠 P1    | Implement GAP-010 blinding factor fix | Casey | After Stage 2 design
🟠 P1    | Create WALLET_RECOVERY_SPEC.md | Casey | With GAP-010
🟡 P2    | Fuzz testing integration | Tim | CI/CD setup
```

---

## Part 3: Wallet Evolution Roadmap

### 3.1 Current: Stage 1 PQ L1 Wallet (Jan 2026)

```
Features:
  ✅ Dilithium key generation (ML-DSA-44)
  ✅ Bech32m address encoding (sq1...)
  ✅ AES-256-CBC wallet encryption
  ✅ Basic send/receive via RPC
  ✅ PAT-ready transaction builder

Missing for "Top-Tier L1 Wallet":
  ⬜ Hardware wallet integration
  ⬜ Multisig support
  ⬜ Watch-only wallet mode
  ⬜ Coin selection algorithms
  ⬜ PSBT (Partially Signed Bitcoin Transactions)
  ⬜ Descriptor wallet support
```

### 3.2 Stage 2: Production L1 Wallet (Q2 2026)

| Feature | Priority | Rationale | Est. LOC |
|---------|----------|-----------|----------|
| **HD Wallet (BIP-44)** | 🔴 P0 | Proper key derivation from seed | ~800 |
| **Watch-Only Wallets** | 🔴 P0 | Exchange cold storage requirement | ~400 |
| **Coin Selection (BnB + FIFO)** | 🟠 P1 | Optimal UTXO selection | ~600 |
| **PSBT Support** | 🟠 P1 | Hardware wallet, multisig interop | ~1,200 |
| **Fee Estimation RPC** | 🟠 P1 | Smart fee recommendations | ~300 |
| **Wallet Backup/Restore** | 🟠 P1 | Full recovery from seed | ~500 |
| **Label Management** | 🟡 P2 | Address/TX labeling | ~200 |

**Total**: ~4,000 additional LOC

### 3.3 Stage 3: Stablecoin-Ready Wallet (Q3 2026)

| Feature | Priority | Rationale | Complexity |
|---------|----------|-----------|------------|
| **Asset Metadata Support** | 🔴 P0 | Track sSOQ-USD, sSOQ-EUR tokens | Medium |
| **Multi-Asset Balance** | 🔴 P0 | Display SOQ + stablecoin balances | Medium |
| **Asset-Aware Transactions** | 🔴 P0 | Send specific assets, not just SOQ | High |
| **Stablecoin Issuance API** | 🟠 P1 | Minting/burning (issuer wallets) | High |
| **Asset Verification** | 🟠 P1 | Verify asset authenticity on-chain | Medium |
| **Regulatory Metadata** | 🟡 P2 | KYC attestations for compliance | Medium |

### 3.4 Stage 4: Privacy Wallet (Q4 2026)

| Feature | Priority | Rationale | Complexity |
|---------|----------|-----------|------------|
| **Stealth Addresses** | 🔴 P0 | One-time receiving addresses | High |
| **View Key Export** | 🔴 P0 | Audit disclosure without spending | Medium |
| **Blinding Factor HKDF** | 🔴 P0 | GAP-010 fix - recoverable privacy | Medium |
| **Ring Signature Support** | 🟠 P1 | Sender privacy (Lattice-BP++) | High |
| **Confidential Amounts** | 🟠 P1 | BP++ range proofs | High |
| **Decoy Selection** | 🟡 P2 | Privacy-preserving output selection | Medium |

### 3.5 Stage 5: SOQ Lightning Wallet (Q2 2027+)

| Feature | Priority | Rationale | Complexity |
|---------|----------|-----------|------------|
| **L2 Key Derivation** | 🔴 P0 | HKDF domain separation for channels | Medium |
| **Channel Management** | 🔴 P0 | Open/close/force-close channels | Very High |
| **Off-Chain Payments** | 🔴 P0 | Instant sub-500ms payments | Very High |
| **Invoice Generation** | 🔴 P0 | BOLT11-compatible invoices | High |
| **Route Finding** | 🟠 P1 | Multi-hop payment paths | High |
| **Watchtower Client** | 🟠 P1 | Breach protection delegation | Medium |
| **HTLC Management** | 🟠 P1 | Hash-time-locked contracts | High |
| **Channel Backup** | 🟠 P1 | SCB (Static Channel Backups) | Medium |

---

## Part 4: Comparative Feature Matrix

### 4.1 Top-Tier L1 Wallets Comparison

| Feature | Bitcoin Core | Electrum | Soqucoin (Current) | Soqucoin (Target) |
|---------|--------------|----------|-------------------|-------------------|
| HD Wallet | ✅ | ✅ | ⚠️ Basic | ✅ Full BIP-44 |
| Hardware Wallet | ✅ | ✅ | ❌ | ✅ (Ledger + Trezor) |
| Multisig | ✅ | ✅ | ❌ | ✅ FROST-based |
| PSBT | ✅ | ✅ | ❌ | ✅ |
| Watch-Only | ✅ | ✅ | ❌ | ✅ |
| Coin Selection | ✅ (BnB) | ✅ | ❌ | ✅ (BnB + FIFO) |
| Quantum-Safe | ❌ | ❌ | ✅ | ✅ |
| Confidential TX | ❌ | ❌ | ⚠️ Stage 3 | ✅ |

### 4.2 Lightning Wallet Comparison (Target)

| Feature | Lightning Labs (LND) | c-lightning | SOQ Lightning (Target) |
|---------|---------------------|-------------|----------------------|
| Quantum-Safe | ❌ | ❌ | ✅ Dilithium |
| Payment Speed | <500ms | <500ms | <500ms |
| Multi-hop | ✅ | ✅ | ✅ |
| Watchtowers | ✅ | ✅ | ✅ |
| HTLCs | ✅ (Schnorr) | ✅ | ✅ (SHA-256) |
| Channel Capacity | Unlimited | Unlimited | Size-limited (PQ overhead) |

---

## Part 5: Implementation Priority Matrix

### 5.1 By Urgency (Pre-Mainnet)

| Priority | Feature | Deadline | Owner |
|----------|---------|----------|-------|
| 🔴 P0 | Audit documentation (Part 2.1) | Jan 28 | Casey/Archith |
| 🔴 P0 | GAP-010 blinding factor spec | Feb 15 | Archith |
| 🟠 P1 | HD Wallet full implementation | Pre-mainnet | Casey |
| 🟠 P1 | Watch-only wallets | Pre-mainnet | Casey |
| 🟠 P1 | Basic coin selection | Pre-mainnet | Casey |

### 5.2 By Strategic Value (Post-Mainnet)

| Priority | Feature | Value | Timeline |
|----------|---------|-------|----------|
| 🔴 High | Stablecoin support | Institutional adoption | Q3 2026 |
| 🔴 High | Hardware wallet | Security-conscious users | Q3 2026 |
| 🟠 Medium | Privacy features | Differentiator | Q4 2026 |
| 🟠 Medium | Multisig | Enterprise custody | Q4 2026 |
| 🟡 Future | Lightning L2 | Scalability | Q2 2027 |

---

## Part 6: Resource Requirements

### 6.1 Pre-Mainnet (Jan-Mar 2026)

| Item | Effort | Owner |
|------|--------|-------|
| Audit documentation creation | 20-30 hours | Casey/Archith |
| Audit Q&A support | 40-60 hours | Casey (22-day audit) |
| Core wallet hardening | 40 hours | Casey |
| Test suite expansion | 20 hours | Tim |

### 6.2 Post-Mainnet (Q2-Q4 2026)

| Phase | FTE-Months | Focus |
|-------|------------|-------|
| Stage 2 (Production L1) | 2.0 | HD, PSBT, Coin Selection |
| Stage 3 (Stablecoins) | 1.5 | Asset support |
| Stage 4 (Privacy) | 2.0 | Stealth addresses, CT |

### 6.3 L2 Lightning (2027)

| Role | FTE | Duration |
|------|-----|----------|
| Protocol Engineer | 2.0 | 12 months |
| Wallet Developer | 1.0 | 6 months |
| Security Audit | External | $100-200K |

---

## Part 7: Immediate Action Items

### For Casey (This Week)

- [ ] Create `WALLET_THREAT_MODEL.md` (4-6 hours)
- [ ] Add security annotations to `pqwallet.cpp` functions
- [ ] Document entropy sources in comments
- [ ] Review `pqcrypto.cpp` for encryption spec gaps

### For Archith (This Week)

- [ ] Create `WALLET_CRYPTOGRAPHIC_SPEC.md` (6-8 hours)
- [ ] Document Dilithium parameter choices
- [ ] Specify key derivation path formally

### For Halborn Audit (Ongoing)

- [ ] Ensure all 5 wallet docs are in audit repo
- [ ] Provide code walkthrough during kickoff
- [ ] Fast-track responses to cryptographic questions

---

## Appendix A: Existing Wallet Code Inventory

```
src/wallet/pqwallet/
├── pqaddress.h         (3.7 KB) - Address encoding/decoding
├── pqaggregation.h     (3.6 KB) - PAT proof aggregation
├── pqcost.h            (3.3 KB) - Fee/cost estimation
├── pqcrypto.cpp        (10.7 KB) - Wallet file encryption
├── pqcrypto.h          (3.7 KB) - Encryption headers
├── pqkeys.h            (4.5 KB) - Key management
├── pqtransaction.h     (3.9 KB) - Transaction building
├── pqwallet.cpp        (11 KB) - Core wallet implementation
├── pqwallet.h          (4 KB) - Wallet headers
├── pqwallet_test.cpp   (14 KB) - Test suite
├── rpc_pqwallet.cpp    (11.5 KB) - RPC commands
└── rpc_pqwallet.h      (0.8 KB) - RPC headers

Total: ~75 KB / ~3,000 LOC
```

---

## Appendix B: GAP-010 Blinding Factor Issue

**Current State**: Blinding factors use `GetStrongRandBytes()` (random).  
**Problem**: Cannot recover privacy outputs from seed backup.  
**Solution**: HKDF derivation from master seed.  
**Design Log**: `DL-2026-01-23-GAP010-BLINDING.md`  
**Timeline**: Fix before Stage 4 privacy activation (block 100,000).

---

*Wallet Audit Gap Analysis & Development Roadmap v1.0*
*January 23, 2026*
