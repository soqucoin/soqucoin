# Privacy Wallet Research: Lessons from Monero, Zcash, and PQ Blockchains

> **Research Date**: January 6, 2026
> **Purpose**: Compare industry best practices to Soqucoin wallet implementation
> **Audience**: Core Team, Auditors

---

## Executive Summary

After researching Monero, Zcash, and emerging PQ blockchain wallets, several key lessons emerge for Soqucoin's wallet development:

| Finding | Our Status | Action Needed |
|---------|------------|---------------|
| Cryptographic audits (proofs) | ⚠️ Planned | Halborn scope |
| Secure key storage | ✅ SecureBytes | Enhance with hardware wallet research |
| Remote node security | ⚠️ Not addressed | Need trusted node strategy |
| Multisig implementation | ⬜ Not implemented | Future roadmap |
| Side-channel resistance | ⚠️ Unknown | Needs review |
| Metadata leakage | ⚠️ Partial | Stage 3 addresses |

---

## Part 1: Monero Wallet Lessons

### What They Did Right

| Feature | Implementation | Audit Status |
|---------|----------------|--------------|
| **CLSAG Signatures** | Replaced MLSAG (smaller, faster) | ✅ Audited 2020, no issues |
| **Bulletproofs+** | Range proofs for amounts | ✅ Quarkslab audit 2018 (issues fixed) |
| **Code Signing** | All releases cryptographically signed | ✅ Standard practice |
| **Multisig** | FROST-inspired implementation | 🔄 Ongoing audit (monero-serai) |

### Key Security Findings

1. **2018 Bulletproofs Audit** (Quarkslab):
   - Found arithmetic overflows
   - Possibility of false proofs with untrusted inputs
   - **Lesson**: ZK proofs need specialized cryptographic audits

2. **2021 Multisig Vulnerabilities**:
   - Implementation flaws allowed fund theft if not all parties trusted
   - **Lesson**: Multisig requires its own dedicated audit

3. **2023 Malicious Remote Node Attack**:
   - Remote nodes could feed incorrect data
   - Privacy loss, inflated fees possible
   - **Lesson**: Wallet must validate or trust node sources

### What We Should Adopt

| Practice | Priority | Notes |
|----------|----------|-------|
| Cryptographic proof audits | 🔴 High | BP++ already planned |
| Signed binary releases | 🟠 Medium | Pre-mainnet |
| Remote node validation | 🟡 Low | Future enhancement |
| Air-gapped seed generation docs | 🟠 Medium | User documentation |

---

## Part 2: Zcash Wallet Lessons

### What They Did Right

| Feature | Implementation | Audit Status |
|---------|----------------|--------------|
| **Shielded Transactions** | zk-SNARKs (Orchard protocol) | ✅ Multiple audits |
| **Unified Addresses** | Single address for all transaction types | ✅ User-friendly |
| **Full-disk encryption** | Recommended for wallet files | ✅ Best practice |
| **RPC localhost-only** | Prevents MITM attacks | ✅ Default config |

### Key Security Findings

1. **Hardware Wallet Audit Focus Areas**:
   - Secure UX for unified address display
   - Domain-separated key derivation (Sapling vs Orchard)
   - Side-channel leakage during signing
   - **Lesson**: Hardware wallet integration needs separate security review

2. **Debug Logging Risk**:
   - `-debug=zrpcunsafe` reveals private information
   - **Lesson**: Audit logging configurations

3. **Ciphertext "Burn" Vulnerabilities**:
   - Invalid ciphertexts could cause fund loss
   - **Lesson**: ZK implementations need edge case testing

### What We Should Adopt

| Practice | Priority | Notes |
|----------|----------|-------|
| Unified Address concept | 🟡 Low | Consider for Stage 3 |
| Side-channel analysis | 🟠 Medium | Include in audit scope |
| Wallet encryption at rest | 🔴 High | Already in SecureBytes design |
| Debug log security review | 🟡 Low | Pre-mainnet check |

---

## Part 3: PQ Blockchain Wallet Precedents (2025)

### Current State of PQ Wallets

| Project | Signature Scheme | Status | Audit |
|---------|------------------|--------|-------|
| **Algorand** | FALCON-1024 | First mainnet TX Nov 2025 | ⚠️ Unknown |
| **QRL** | XMSS → SPHINCS+ | 7 years, no security hotfixes | ✅ Track record |
| **QANplatform** | Dilithium | EU ministry pilot May 2025 | ⚠️ Funded Apr 2024 |
| **Naoris Protocol** | Dilithium 5 | Testnet Jan 2025 | ⚠️ Unknown |

### Key Insights

1. **No Comprehensive PQ Wallet Audits Yet**:
   - Most projects in 2025 just getting started
   - **Opportunity**: Soqucoin can be among first audited PQ wallets

2. **Algorand's Approach**:
   - Added FALCON as optional signature type
   - Backward compatible with existing infrastructure
   - **Lesson**: Hybrid approach for migration

3. **QRL's 7-Year Track Record**:
   - No security hotfixes on XMSS
   - Pioneers in post-quantum crypto
   - **Lesson**: Conservative algorithm choice pays off

4. **Signature Size Challenges**:
   - Dilithium: 2420 bytes (vs ECDSA 64 bytes)
   - Need gas/fee optimization
   - **Lesson**: This is why we have PAT aggregation

### What We Should Adopt

| Practice | Priority | Notes |
|----------|----------|-------|
| Hybrid signature support | 🟡 Low | Not needed for PQ-native chain |
| Conservative algorithm (Dilithium2) | ✅ Done | Already using ML-DSA-44 |
| Aggregation for size optimization | ✅ Done | PAT designed for this |
| Seek early comprehensive audit | 🔴 High | Halborn engagement |

---

## Part 4: Gap Analysis - Our Implementation vs Best Practices

### Current Implementation Strengths

| Feature | Status | Best Practice Alignment |
|---------|--------|------------------------|
| `SecureBytes` class | ✅ | Matches Monero's secure memory handling |
| Bech32m encoding | ✅ | Industry standard (Bitcoin SegWit v1) |
| Dilithium (NIST FIPS 204) | ✅ | Matches QANplatform, Naoris |
| PAT aggregation | ✅ | Unique to Soqucoin, addresses size issue |
| BP++ range proofs | ✅ | Same philosophy as Monero BP+ |

### Gaps to Address

| Gap | Risk | Mitigation | Priority |
|-----|------|------------|----------|
| **No hardware wallet research** | Medium | Begin Ledger/Trezor research | 🟠 Post-audit |
| **Side-channel analysis** | Medium | Include in audit scope | 🟠 Phase 1 |
| **Remote node security** | Low | Document trusted node strategy | 🟡 Future |
| **Multisig not implemented** | Low | Post-mainnet feature | 🟡 Future |
| **No wallet encryption** | Medium | Add file-level encryption | 🟠 Pre-mainnet |
| **Debug logging review** | Low | Code review before audit | 🟡 Phase 1 |

---

## Part 5: Recommendations

### Immediate (Before Halborn)

1. **Add to Audit Scope**:
   - Side-channel resistance of Dilithium signing
   - SecureBytes memory handling validation
   - BP++ proof verification correctness

2. **Documentation Updates**:
   - Add security considerations to WALLET_API_SPEC.md
   - Document threat model for wallet

### Pre-Mainnet

3. **File-Level Wallet Encryption**:
   - Encrypt wallet.dat with AES-256-GCM
   - Derive encryption key from passphrase with Argon2

4. **Node Trust Strategy**:
   - Document which nodes are trusted
   - Consider SPV-like proof verification for light wallets

### Post-Mainnet (Stage 3)

5. **Hardware Wallet Research**:
   - Contact Ledger/Trezor about Dilithium support
   - May require firmware updates for 2.5KB signatures

6. **Multisig Implementation**:
   - Study Monero's FROST implementation
   - Dedicated audit for multisig

---

## Part 6: Comparison Summary

| Aspect | Monero | Zcash | PQ Chains | Soqucoin |
|--------|--------|-------|-----------|----------|
| Signature | Ring (CLSAG) | ECDSA + zk | Dilithium/FALCON | Dilithium |
| Privacy | Ring sigs, stealth | zk-SNARKs | None yet | Stage 3 hybrid |
| Range Proofs | BP+ | Shielded | N/A | BP++ |
| Aggregation | None | N/A | N/A | PAT ✨ |
| Quantum Safe | ❌ | ❌ | ✅ | ✅ |
| Audit Status | Multiple | Multiple | Partial | Halborn planned |

### Our Unique Advantages

1. **Quantum-safe from genesis** - Not a migration
2. **PAT aggregation** - No other chain has this economic model
3. **Proof cost accounting** - Explicit per-proof pricing
4. **Merged mining** - Bitcoin-level security via Scrypt

---

*Research Document v1.0 | January 6, 2026*
