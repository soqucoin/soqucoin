# Stage 5: Quantum-Safe Payment Channel Network (SOQ Lightning)

> **Version**: 0.3 (Research Draft)
> **Status**: RESEARCH - Not a Near-Term Deliverable
> **Classification**: PUBLIC - Research Specification  
> **Target**: Prototype Q4 2026, Mainnet H2 2027+ (research-dependent)
> **Prepared For**: Public Review, VC Due Diligence, Future Audit Scope
> **Last Updated**: January 10, 2026

---

> [!CAUTION]
> **Research Preview Document**
> This specification describes a **research initiative**, not a committed deliverable. Post-quantum
> payment channels are an **unsolved problem** in the broader cryptographic research community.
> Timelines are aspirational targets contingent on solving open cryptographic challenges.
> No production timeline is guaranteed.

---

## Executive Summary

Stage 5 is a **research initiative** exploring quantum-safe Layer 2 payment channels built on 
Soqucoin's L1 settlement layer. Inspired by Bitcoin's Lightning Network, we're investigating:

- **Sub-second payments** (design target: <500ms)
- **High throughput** (theoretical target: 10,000+ TPS)
- **Quantum-resistant channels** (Dilithium commitment signatures)
- **Privacy by default** (channel state is off-chain)

### Research vs Engineering Distinction

| Category | Description |
|----------|-------------|
| **What we have** | Production L1 with native Dilithium signatures, L2-ready wallet key derivation |
| **What we're researching** | PQ payment channel constructions, adaptor signature alternatives |
| **What's unsolved** | PQ adaptor signatures, channel state aggregation, watchtower compatibility |
| **Our approach** | Adapt BOLT specs where possible, develop alternatives where needed |

---

## Motivation

### L1 Limitations

| Metric | L1 (All Stages) | Requirement for Payments |
|--------|-----------------|--------------------------|
| TPS | ~40-70 | 10,000+ |
| Confirmation | 60 seconds | <1 second |
| Fees | ~0.01 SOQ | <0.0001 SOQ |
| Privacy | Opt-in (on-chain visible) | Default private |

### Why L2 is Necessary

1. **Block size/time constraints**: L1 TPS is fundamentally limited by 4MB blocks and 60-second target
2. **Payment UX**: Users expect instant confirmations for retail transactions
3. **Micropayments**: On-chain fees prohibit sub-cent transactions
4. **Scalability ceiling**: Mainnet adoption will exceed L1 capacity

### Why Now (After Stage 4)

| Prerequisite | Stage | Rationale |
|--------------|-------|-----------|
| Dilithium signatures | Genesis | L2 channels must use PQ signatures |
| LatticeFold+ verification | Stage 2 | Efficient batch settlement of channel closes |
| Full PQ privacy | Stage 3 | End-to-end quantum-safe privacy |
| Liquidity bridge | Stage 4 | Cross-chain liquidity for channel funding |

---

## Open Research Challenges

> [!WARNING]
> **Unsolved Problems**
> The following challenges do not have known solutions in the post-quantum cryptography literature.
> Our research timeline is contingent on making progress on these problems.

### 1. Post-Quantum Adaptor Signatures

**Problem**: Bitcoin Lightning uses Schnorr adaptor signatures for atomic multi-hop payments (PTLCs).
Dilithium does not natively support adaptor signatures.

**Status**: Active research  
**Approaches under investigation**:
- Hash-based HTLC alternatives (proven but less efficient)
- Exploring lattice-based adaptor constructions from academic literature
- Hybrid approaches using hash-time-locked commitments

**References**:
- Erwig et al., "Two-Party Adaptor Signatures From Identification Schemes" (2021)
- Tairi et al., "Post-Quantum Adaptor Signature" (2023, preprint)

### 2. Channel State Size

**Problem**: Dilithium signatures are 2,420 bytes (vs 64 bytes for Schnorr). Each channel state
update requires signatures from both parties, accumulating storage and bandwidth costs.

**Status**: Exploring solutions  
**Potential mitigations**:
- Signature aggregation (research needed)
- State compression via LatticeFold+ proofs
- Periodic state consolidation

**Impact**: May limit practical channel update frequency compared to Bitcoin LN.

### 3. Watchtower Compatibility

**Problem**: Watchtowers monitor channels for breach attempts. Large signature sizes change
the economics (storage costs) and bandwidth requirements for monitoring services.

**Status**: Design phase  
**Considerations**:
- Watchtower storage costs ~38x higher per state
- May require different fee models
- Could benefit from LatticeFold+ batch verification

### 4. Route Finding

**Problem**: Large keys and signatures affect channel capacity variance and gossip protocol
bandwidth. Network topology may differ significantly from Bitcoin Lightning.

**Status**: Under analysis  
**Open questions**:
- Optimal channel capacity sizes with PQ overhead
- Gossip protocol modifications for larger announcements
- Pathfinding algorithm adaptations

---

## Technical Architecture

### Design Principles

1. **Quantum-safe from genesis**: All channel operations use Dilithium signatures
2. **Lightning-compatible design**: Adapt proven BOLT specifications where possible
3. **L1 settlement efficiency**: Leverage LatticeFold+ for batch channel settlements
4. **Privacy preservation**: Channel state never touches L1 during normal operation

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SOQ Lightning Network                        │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  Node A  │◄──►│  Node B  │◄──►│  Node C  │◄──►│  Node D  │  │
│  └────┬─────┘    └──────────┘    └──────────┘    └────┬─────┘  │
│       │              Payment Channels                  │        │
│       │                                                │        │
└───────┼────────────────────────────────────────────────┼────────┘
        │                                                │
        ▼                                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Soqucoin L1 (Settlement)                      │
│  ┌────────────────┐              ┌────────────────────────────┐ │
│  │ Channel Open   │              │ LatticeFold+ Batch Close   │ │
│  │ (Dilithium 2x) │              │ (512 channels per proof)   │ │
│  └────────────────┘              └────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Channel Lifecycle

#### 1. Channel Open (On-Chain)
```
Alice → L1 Transaction:
  - OP_CHECKFOLDPROOF: Funding proof
  - Output: 2-of-2 Dilithium multisig (Alice, Bob)
  - Value: X SOQ locked
```

#### 2. Off-Chain Payments (Instant)
```
Alice → Bob (off-chain):
  - Commitment Transaction: New balance state
  - Signed: Dilithium (Alice)
  - Revocation: Hash preimage exchange

Payment latency: <500ms
Fees: 0 SOQ (off-chain)
```

#### 3. Channel Close (On-Chain)
```
Cooperative Close:
  - Final commitment → L1
  - LatticeFold+ batch verification (if multiple channels)

Unilateral Close:
  - Broadcast commitment + penalty timeout
  - Watchtower support for security
```

### Quantum-Safe Adaptations

| Lightning (Bitcoin) | SOQ Lightning | Rationale |
|---------------------|---------------|-----------|
| ECDSA signatures | Dilithium ML-DSA-44 | Quantum resistance |
| SHA-256 HTLCs | SHA-256 HTLCs | SHA-256 is PQ-safe |
| secp256k1 revocation | Dilithium revocation keys | Quantum resistance |
| 71-byte signatures | 2,420-byte signatures | Larger but acceptable for L2 |

> [!NOTE]
> Dilithium's larger signature size (2,420 bytes vs 71 bytes) is acceptable for L2 because:
> - Channel state updates are off-chain (no bandwidth concern)
> - Only open/close transactions hit L1
> - LatticeFold+ amortizes close tx verification cost

---

## Performance Targets

### Comparison: Bitcoin Lightning vs SOQ Lightning

| Metric | Bitcoin Lightning (2025) | SOQ Lightning (Target) |
|--------|--------------------------|------------------------|
| Payment latency | <500ms | **<500ms** |
| Success rate | 99.7% | **>99%** |
| Theoretical TPS | 1M+ | **100K-1M** |
| Quantum safe | ❌ | **✅** |
| L1 settlement | ~10 min | **60 sec** |
| Privacy | Channel obscured | **Channel obscured** |

### Why SOQ Lightning is Competitive

| Advantage | Explanation |
|-----------|-------------|
| **1-minute L1 blocks** | Faster channel opens/closes than Bitcoin (10 min) |
| **Dogecoin-like tokenomics** | Lower fees, more suitable for micropayments |
| **LatticeFold+ settlements** | 512 channel closes in <1ms verification |
| **Quantum-safe channels** | Future-proof against cryptographic attacks |
| **Opt-in privacy foundation** | Stage 3 privacy primitives available |

---

## Research Roadmap

### Phase 1: Foundation (Q1 2026 - Ongoing) ✅

| Deliverable | Owner | Status |
|-------------|-------|--------|
| L2-compatible wallet architecture | Core Team | ✅ Complete |
| HKDF key derivation for channels | Core Team | ✅ Complete |
| Initial BOLT specification review | Research | 🔄 In Progress |
| Security model research | Security Lead | 🔄 In Progress |

### Phase 2: Specification (Q2 2026)

| Deliverable | Owner | Timeline |
|-------------|-------|----------|
| BOLT specification review complete | Research | 8 weeks |
| Dilithium channel prototype (regtest) | Crypto Lead | 10 weeks |
| SLP (SOQ Lightning Protocol) draft docs | Core Team | 6 weeks |
| Routing algorithm analysis | Research | 6 weeks |

### Phase 3: Development (Q3 2026)

| Deliverable | Owner | Timeline |
|-------------|-------|----------|
| Single-hop payment channels | Dev Team | 10 weeks |
| Basic routing implementation | Dev Team | 6 weeks |
| Integration with wallet infrastructure | Wallet Team | 8 weeks |
| Initial security review | External | 2 weeks |

### Phase 4: Prototype (Q4 2026)

| Deliverable | Owner | Timeline |
|-------------|-------|----------|
| Multi-hop routing on testnet | Dev Team | 8 weeks |
| Watchtower implementation | Dev Team | 6 weeks |
| Public testnet launch | Ops Team | 2 weeks |
| Initial performance benchmarks | Dev Team | 4 weeks |

### Phase 5: Audit (Q1 2027)

| Deliverable | Owner | Timeline |
|-------------|-------|----------|
| Full security audit | External | 8 weeks |
| Performance optimization | Dev Team | 6 weeks |
| Wallet integration finalization | Wallet Team | 4 weeks |
| Bug bounty program launch | Community | Ongoing |

### Phase 6: Mainnet (Q2 2027)

| Deliverable | Owner | Timeline |
|-------------|-------|----------|
| Security audit completion | External | 6 weeks |
| Mainnet deployment | Core Team | 2 weeks |
| Liquidity bootstrapping | Community | Ongoing |

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Quantum adversary | Dilithium signatures throughout |
| Channel breach | Watchtower monitoring + penalty txs |
| Routing attacks | Onion routing (Sphinx adaptation) |
| Liquidity attacks | Channel capacity limits |
| Eclipse attacks | L1 peer diversity requirements |

### Audit Scope (Preliminary)

1. Dilithium multisig implementation
2. HTLC hash-lock security
3. Revocation key derivation
4. Routing algorithm privacy
5. Watchtower protocol security

---

## Resource Requirements

### Team (Estimated)

| Role | FTE | Duration |
|------|-----|----------|
| Protocol Engineer | 2.0 | 12 months |
| Cryptography Researcher | 0.5 | 12 months |
| Security Engineer | 1.0 | 6 months |
| Wallet Developer | 1.0 | 6 months |
| DevOps/Infrastructure | 0.5 | 12 months |

**Total**: ~5 FTE-years

### External Costs (Estimated)

| Item | Cost (USD) |
|------|------------|
| Security Audit (L2 specific) | $100,000 - $200,000 |
| Infrastructure (Testnet) | $5,000/month |
| Bug Bounty Program | $50,000 initial |

---

## Dependencies

### Hard Prerequisites

- [x] Genesis: Dilithium signatures
- [ ] Stage 2 (Height 100,000): LatticeFold+ verification
- [ ] Stage 3 (v0.22): Full PQ privacy primitives
- [ ] Stage 4 (Q4 2026): Solana bridge operational

### Soft Prerequisites

- [ ] Mainnet stability (6+ months)
- [ ] Exchange integrations complete
- [ ] Wallet ecosystem mature
- [ ] Community liquidity available

---

## Success Metrics

| Metric | Target (Y1) | Target (Y2) |
|--------|-------------|-------------|
| Active channels | 1,000 | 10,000 |
| Network capacity | 1M SOQ | 10M SOQ |
| Payment success rate | >99% | >99.5% |
| Average payment latency | <1 sec | <500ms |
| Monthly transaction volume | 100K | 1M |

---

## Appendix A: Lightning Network Performance Data (2025)

*Source: Industry research, January 2025*

| Metric | Value | Source |
|--------|-------|--------|
| Monthly transactions | 8M+ | CoinLaw.io |
| Q1 2025 transactions | 100M | Medium/Industry |
| Payment success rate | 99.7% | RhinoBitcoin |
| Network capacity | 5,358 BTC (~$509M) | SimpleSwap |
| Active nodes | ~16,000 | CoinLaw.io |
| Active channels | ~52,700 | Industry data |
| Payment latency | <500ms typical | Lightning.network |

**Key insight**: Lightning Network processed 100M transactions in Q1 2025 alone, with 99.7% success rate.
This demonstrates that payment channel networks at scale are production-ready technology.

---

## Appendix B: Competitive Analysis

| Network | L1 | Quantum Safe | TPS | Status |
|---------|-----|--------------|-----|--------|
| Bitcoin Lightning | Bitcoin | ❌ | 1M+ | Production |
| Litecoin Lightning | Litecoin | ❌ | Similar | Limited adoption |
| Solana | N/A (L1) | ❌ | 65K | Production |
| **SOQ Lightning** | **Soqucoin** | **✅** | **100K-1M** | **Planned Q2 2027** |

**Unique value proposition**: SOQ Lightning would be the first quantum-safe payment channel network
with battle-tested Lightning design principles.

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | 2026-01-08 | Core Team | Initial draft |
| 0.3 | 2026-01-10 | Core Team | Added open research challenges, VC-ready framing, public release |

---

> [!NOTE]
> **Public Document**
> This specification is publicly available to encourage community feedback and research collaboration.
