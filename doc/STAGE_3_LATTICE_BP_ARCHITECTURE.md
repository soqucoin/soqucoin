# Soqucoin Stage 3: Lattice-BP Hybrid Privacy Architecture

> **Version**: 1.0-DRAFT | **Status**: Expert Review Required
> **Author**: Soqucoin Foundation R&D
> **Date**: January 15, 2026
> **Classification**: Strategic Research Document

---

## Executive Summary

This document presents a comprehensive architecture for **Stage 3: Lattice-BP Hybrid** — a post-quantum private transaction system that integrates with Soqucoin's existing cryptographic stack (Dilithium, PAT, LatticeFold+) while maintaining compliance-friendly opt-in semantics inspired by Litecoin's MWEB.

**Key Design Principles:**
1. **Opt-In Privacy** — Default transparency, user-optional confidentiality (MWEB model)
2. **Post-Quantum Security** — Replace secp256k1 with lattice-based commitments
3. **Full-Stack Integration** — Works with PQ Wallet, L2 (SOQ Lightning), Solana Bridge
4. **Compliance-Ready** — View keys for selective disclosure and auditability
5. **Performance Target** — ≤2ms verification, ≤1KB proofs

---

## Part I: Cryptographic Foundation

### 1.1 Problem Statement

Soqucoin's current privacy infrastructure (Stage 1 BP++) uses secp256k1 for Pedersen commitments:

| Component | Current (Stage 1) | Issue |
|-----------|-------------------|-------|
| Signatures | Dilithium (PQ-safe) | ✅ |
| Range Proofs | secp256k1 (classical) | ❌ Vulnerable to Shor's |
| Commitments | Pedersen (EC) | ❌ Vulnerable to Shor's |

**Goal**: Replace classical elliptic curve operations with lattice-based equivalents while maintaining performance.

### 1.2 Threat Model

| Adversary | Capability | Mitigation |
|-----------|------------|------------|
| Classical Attacker | Statistical/computational analysis | Ring signatures, stealth addresses |
| Quantum Attacker | Shor's algorithm (EC discrete log) | Lattice-based commitments |
| Regulatory Auditor | Legal subpoena authority | View keys, selective disclosure |
| Network Observer | IP/timing correlation | Dandelion++, Tor support |

### 1.3 Cryptographic Building Blocks

#### Lattice-Based Pedersen Commitments

Replace EC Pedersen with Ring-LWE commitment scheme:

```
Classical Pedersen: C = vG + rH  (EC points)
Lattice Pedersen:   C = vA + rS  (Lattice matrices, Ring-LWE)
```

**Parameters** (based on CRYSTALS-Dilithium security levels):
| Parameter | Value | Security Level |
|-----------|-------|----------------|
| Ring dimension n | 256 | NIST Level 1 |
| Modulus q | 8380417 | Same as Dilithium |
| Standard deviation σ | 2 | Gaussian sampling |
| Commitment size | ~1 KB | vs 32 bytes EC |

**Research Reference**: LaZer Library (CCS 2024), Greyhound (CRYPTO 2024)

#### Lattice-Based Range Proofs

Two approaches under consideration:

| Approach | Proof Size | Verify Time | Maturity |
|----------|-----------|-------------|----------|
| **Lattice Bulletproofs** | ~2-3 KB | ~5 ms | Research |
| **Lattice Folding + BP++** | ~0.5 KB | ~1-2 ms | Hybrid |

**Recommended**: Hybrid approach using LatticeFold+ for commitment binding + classical BP++ for range proof generation, with lattice-based blinding factors.

### 1.4 Hybrid Construction

```
┌─────────────────────────────────────────────────────────────┐
│                    TRANSACTION STRUCTURE                     │
├─────────────────────────────────────────────────────────────┤
│ INPUTS (consumed UTXOs)                                      │
│   - Stealth address derivation (Dilithium + HKDF)           │
│   - Ring signature (lattice-based, k=11 decoys)             │
│   - Key image (double-spend prevention)                      │
├─────────────────────────────────────────────────────────────┤
│ OUTPUTS (new UTXOs)                                          │
│   - Lattice Pedersen commitment: C = vA + rS                │
│   - Lattice range proof: v ∈ [0, 2^64)                      │
│   - One-time stealth address (Dilithium pubkey)             │
├─────────────────────────────────────────────────────────────┤
│ PROOFS                                                       │
│   - Balance proof: Σ inputs = Σ outputs (homomorphic)       │
│   - Ownership proof: Dilithium signature over TX            │
│   - LatticeFold+ batch proof (optional, for aggregation)    │
├─────────────────────────────────────────────────────────────┤
│ METADATA                                                     │
│   - View key encrypted memo (for recipient)                  │
│   - Audit disclosure proof (optional, for compliance)        │
└─────────────────────────────────────────────────────────────┘
```

---

## Part II: Privacy Model (MWEB-Inspired)

### 2.1 Opt-In Architecture

Following Litecoin's MWEB, privacy is **opt-in** via extension blocks:

```
┌─────────────────────────────────────────────────────────────┐
│                    MAIN CHAIN (Transparent)                  │
│  - Standard Dilithium P2PKH transactions                     │
│  - Amounts visible, fully auditable                          │
│  - AML/KYC compliant by default                              │
├─────────────────────────────────────────────────────────────┤
│                    EXTENSION BLOCK (Private)                 │
│  - Confidential transactions (Lattice-BP++)                  │
│  - Amounts hidden via commitments                            │
│  - Full post-quantum privacy                                 │
└─────────────────────────────────────────────────────────────┘
           │                              │
           │ PEG-IN                       │ PEG-OUT
           ▼                              ▼
    Main → Private               Private → Main
    (burn, mint)                 (reveal, claim)
```

### 2.2 Peg-In / Peg-Out Flow

**Peg-In (Transparent → Private):**
1. User creates TX burning SOQ on main chain
2. Equivalent hidden amount minted in extension block
3. Commitment to blinding factor published
4. User receives private UTXO

**Peg-Out (Private → Transparent):**
1. User proves ownership of private UTXO
2. Creates zero-knowledge proof of amount
3. Auditor-revealable commitment published
4. Equivalent SOQ released on main chain

### 2.3 View Keys for Compliance

Inspired by Monero, with enhancements for audit:

| Key Type | Can View | Can Spend | Use Case |
|----------|----------|-----------|----------|
| **Private Spend Key** | Own TXs | Yes | User wallet |
| **Private View Key** | Incoming TXs | No | Accountant/auditor |
| **Full Audit Key** | All TXs + Amounts | No | Regulatory compliance |
| **Transaction Proof** | Single TX | No | Payment verification |

**Implementation**:
```cpp
// Hierarchical key derivation
private_spend_key = HKDF("soqucoin.privacy.spend.v1", master_seed)
private_view_key  = HKDF("soqucoin.privacy.view.v1", master_seed)
audit_disclosure  = HKDF("soqucoin.privacy.audit.v1", tx_seed)
```

### 2.4 Comparison with Established Systems

| Feature | Monero | Zcash | LTC MWEB | **Soqucoin Stage 3** |
|---------|--------|-------|----------|----------------------|
| Privacy Default | Mandatory | Optional | Optional | **Optional** |
| Quantum Resistant | ❌ | ❌ | ❌ | **✅ Full** |
| View Keys | ✅ | ✅ | ❌ | **✅ Enhanced** |
| Extension Blocks | ❌ | ❌ | ✅ | **✅** |
| Ring Signatures | ✅ (EC) | ❌ | ❌ | **✅ (Lattice)** |
| Range Proofs | BP+ | Groth16 | BP | **Lattice-BP++** |
| Regulatory Status | 🔴 Delistings | 🟡 Mixed | 🟢 Accepted | **🟢 Designed** |

---

## Part III: Integration with Soqucoin Stack

### 3.1 PQ Wallet Integration

The existing PQ Wallet (`src/wallet/pqwallet/`) will be extended:

| Module | Current | Stage 3 Addition |
|--------|---------|------------------|
| `pqaddress.h` | Dilithium addresses | + Stealth address generation |
| `pqcrypto.cpp` | Key derivation | + View key derivation |
| `pqwallet.cpp` | Basic wallet | + Private UTXO tracking |
| **NEW** `privacy.cpp` | — | Ring signature creation |
| **NEW** `commitment.cpp` | — | Lattice commitments |

### 3.2 LatticeFold+ Integration

Stage 2's LatticeFold+ provides batch verification for private TXs:

```cpp
// Batch verify 512 private transactions
LatticeFoldProof batch_proof = CreateFoldProof(private_txs);
bool valid = VerifyFoldProof(batch_proof); // ~0.75ms
```

**Synergy**: Ring signatures over 11 decoys normally require 11 signature verifications. LatticeFold+ folds these into a single proof.

### 3.3 SOQ Lightning (L2) Compatibility

Stage 5 L2 must support private channels:

| L2 Feature | Privacy Requirement | Solution |
|------------|---------------------|----------|
| Channel open | Hidden capacity | Lattice commitment |
| HTLC | Hidden amount | Range proof |
| Channel close | Selective reveal | View key |
| Watchtower | Monitor without balance | Public key only |

### 3.4 Solana Bridge Compatibility

Private pSOQ tokens require special handling:

```
SOQ (Private) → Lock Script (reveals amount) → pSOQ (Solana)
pSOQ → Burn → ZK Proof → SOQ (Private, hidden again)
```

**Design Decision**: Bridge requires visibility at crossing. Users must peg-out to transparent before bridging.

---

## Part IV: Implementation Roadmap

### 4.1 Development Phases

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| **Research** | 3 months | Lattice commitment library, benchmarks |
| **Prototype** | 4 months | Ring sigs, stealth addresses, testnet |
| **Integration** | 3 months | Wallet, extension blocks, view keys |
| **Audit** | 2 months | Halborn/Trail of Bits review |
| **Activation** | — | v0.22 softfork |

### 4.2 Consensus Changes

| Parameter | Stage 1 (Current) | Stage 3 |
|-----------|-------------------|---------|
| `LATTICE_COMMIT_SIZE` | N/A | ~1 KB |
| `LATTICE_RANGE_PROOF_SIZE` | N/A | ~2 KB |
| `LATTICE_RING_SIZE` | N/A | 11 decoys |
| `MAX_PRIVATE_TX_PER_BLOCK` | N/A | 100 |
| `EXTENSION_BLOCK_WEIGHT` | N/A | 1 MB |

### 4.3 Code Locations (Proposed)

| Component | Directory |
|-----------|-----------|
| Lattice commitments | `src/crypto/lattice/commitment.cpp` |
| Ring signatures | `src/crypto/ring/lattice_ring.cpp` |
| Stealth addresses | `src/wallet/pqwallet/stealth.cpp` |
| View keys | `src/wallet/pqwallet/viewkey.cpp` |
| Extension blocks | `src/consensus/extblock.cpp` |
| Range proofs | `src/crypto/latticebp/range.cpp` |

---

## Part V: Security Analysis

### 5.1 Cryptographic Assumptions

| Assumption | Hardness Problem | Status |
|------------|------------------|--------|
| Ring-LWE | Lattice shortest vector | NIST PQ Standard |
| Module-SIS | Short integer solution | NIST PQ Standard |
| Dilithium | ML-DSA security | FIPS 204 |
| BP++ | EC discrete log | Classical (hybrid) |

### 5.2 Attack Surface

| Attack | Mitigation | Residual Risk |
|--------|------------|---------------|
| Quantum decryption | Lattice-based commitments | Low |
| Ring analysis | 11 decoys, uniform selection | Medium |
| Timing side-channel | Constant-time implementation | Low |
| Key image linkability | Unique per UTXO | Low |
| Amount correlation | Random fee padding | Low |

### 5.3 Audit Focus Areas

1. **Lattice commitment binding** — Prove discrete log hardness analog
2. **Ring signature unforgeability** — No impersonation without key
3. **Range proof soundness** — Cannot create negative amounts
4. **View key derivation** — Proper domain separation (HKDF)
5. **Extension block consensus** — Correct peg-in/peg-out balances

---

## Part VI: Expert Review Checklist

### Cryptography Review (Trail of Bits / Halborn)
- [ ] Lattice commitment scheme parameters (Ring-LWE)
- [ ] Ring signature construction (lattice adaptation)
- [ ] Range proof soundness (hybrid lattice-BP++)
- [ ] Key derivation paths (HKDF domain separation)
- [ ] Side-channel resistance (constant-time ops)

### Blockchain Architecture Review
- [ ] Extension block consensus rules
- [ ] Peg-in/peg-out atomic swap design
- [ ] Weight/cost accounting for private TXs
- [ ] Mempool handling of private TXs
- [ ] Reorg handling with extension blocks

### Compliance Review (Legal/Regulatory)
- [ ] View key disclosure mechanism
- [ ] Audit trail generation
- [ ] FATF Travel Rule compatibility
- [ ] Exchange listing requirements
- [ ] Jurisdictional analysis (US, EU, Asia)

### Performance Review
- [ ] Commitment generation: target <1ms
- [ ] Range proof generation: target <10ms
- [ ] Ring signature creation: target <5ms
- [ ] Batch verification: target 512 TX/s
- [ ] Memory requirements: target <64KB working

---

## Appendix A: Academic References

| Topic | Paper | Authors | Year |
|-------|-------|---------|------|
| Lattice Commitments | LaZer: A Lattice Library for ZKP | IBM Research | 2024 |
| Lattice Poly Commit | Greyhound: Fast Poly Commitments | IBM Research | 2024 |
| Zero-Knowledge Range | Survey of ZK Range Proofs | Dagstuhl | 2025 |
| Bulletproofs++ | Shorter Proofs for Privacy | Chung et al. | 2022 |
| MWEB | MimbleWimble Extension Block | LTC Foundation | 2022 |
| Ring Signatures | Lattice-Based Ring Signatures | Lyubashevsky | 2021 |

---

## Appendix B: Competitive Analysis

### Privacy Coin Market Position

| Project | Privacy Tech | Quantum | Compliance | Market Cap |
|---------|-------------|---------|------------|------------|
| Monero (XMR) | RingCT | ❌ | ❌ Delistings | ~$3B |
| Zcash (ZEC) | zk-SNARK | ❌ | 🟡 Optional | ~$500M |
| Litecoin (LTC) | MWEB | ❌ | ✅ Optional | ~$6B |
| Secret (SCRT) | TEE | ❌ | 🟡 | ~$100M |
| **Soqucoin** | Lattice-BP | ✅ | ✅ Optional | Pre-launch |

**Differentiator**: First privacy-enabled blockchain with:
- Post-quantum security (NIST L1)
- Compliance-first design (view keys, opt-in)
- Native L1 recursive SNARKs (LatticeFold+)

---

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| **Pedersen Commitment** | Cryptographic primitive hiding a value while binding to it |
| **Ring Signature** | Signature provably from group member, identity unknown |
| **Stealth Address** | One-time address generated for each transaction |
| **Key Image** | Unique identifier preventing double-spend |
| **View Key** | Read-only key for transaction inspection |
| **Extension Block** | Parallel block structure for optional features |
| **Peg-In/Out** | Moving between transparent and private chains |

---

*Prepared for expert review*
*Soqucoin Foundation R&D — January 2026*
