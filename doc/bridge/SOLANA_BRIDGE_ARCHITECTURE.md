# Soqucoin-Solana Bridge Architecture

> **Version**: 0.1 (Draft) | **Status**: Engineering Design Phase
> **Last Updated**: January 2026
> **Network**: Soqucoin ↔ Solana

---

> [!WARNING]
> **Working Document**: This architecture is under active development. Design decisions are subject to change based on security review and implementation findings. This document is provided for transparency and feedback purposes.

---

## 1. Overview

The Soqucoin-Solana Bridge enables bidirectional transfer of value between the Soqucoin mainnet and the Solana blockchain through a wrapped token mechanism.

| Component | Description |
|-----------|-------------|
| **SOQ** | Native Soqucoin token (L1, Dilithium signatures) |
| **pSOQ** | Wrapped SOQ on Solana (SPL token) |
| **Bridge** | Smart contract system managing lock/mint/burn/release |

---

## 2. Token Mechanics

### SOQ → pSOQ (Lock & Mint)

```
1. User sends SOQ to bridge custody address on Soqucoin
2. Bridge validators observe and confirm deposit (N-of-M threshold)
3. pSOQ is minted on Solana to user's SPL wallet
```

### pSOQ → SOQ (Burn & Release)

```
1. User burns pSOQ on Solana via bridge program
2. Bridge validators observe and confirm burn
3. SOQ is released from custody to user's Dilithium address
```

---

## 3. Security Model

### Validator Set

| Parameter | Proposed Value | Notes |
|-----------|----------------|-------|
| **Validator count** | 7-11 | Decentralization vs coordination |
| **Threshold** | 5-of-7 or 7-of-11 | Byzantine fault tolerance |
| **Validator selection** | TBD | May include trusted partners + geographic distribution |

### Collateralization

| Model | Description | Status |
|-------|-------------|--------|
| **1:1 Custody** | SOQ locked = pSOQ minted | Baseline |
| **Over-collateralization** | Extra reserves for failure modes | Under consideration |
| **Proof of Reserves** | On-chain attestation of custody balance | Planned |

---

## 4. Smart Contract Architecture

### Solana Program (pSOQ)

| Component | Technology | Notes |
|-----------|------------|-------|
| **Token Standard** | SPL Token | Native Solana token standard |
| **Mint Authority** | Multisig PDA | Controlled by bridge validators |
| **Upgrade Authority** | Timelocked multisig | 48-hour delay for upgrades |

### Soqucoin Bridge Address

| Component | Technology | Notes |
|-----------|------------|-------|
| **Custody Address** | Dilithium multisig | M-of-N signature threshold |
| **Monitoring** | Validator nodes | Watch for deposits/releases |

---

## 5. Risk Considerations

### Known Risks

| Risk | Mitigation |
|------|------------|
| **Validator collusion** | Threshold signature, geographic distribution |
| **Smart contract bugs** | Audit before launch, timelocked upgrades |
| **Solana outages** | Queue deposits, process on recovery |
| **Soqucoin reorgs** | Wait for 240+ confirmations (coinbase maturity) |
| **Key compromise** | Hardware security modules, rotation procedures |

### Out of Scope (v1)

- Atomic swaps (requires protocol-level support)
- Trustless bridge (requires light client verification)
- Cross-chain smart contracts

---

## 6. Deployment Timeline

| Phase | Target | Description |
|-------|--------|-------------|
| **Design** | Q1 2026 | Architecture finalization |
| **Development** | Q2 2026 | Smart contract implementation |
| **Audit** | Q2-Q3 2026 | Security review |
| **Testnet** | Q3 2026 | Integration testing |
| **Mainnet** | Q4 2026 | Production deployment |

---

## 7. pSOQ Token Information

| Parameter | Value |
|-----------|-------|
| **Name** | Pegged Soqucoin |
| **Symbol** | pSOQ |
| **Decimals** | 8 (matches SOQ) |
| **Network** | Solana Mainnet |
| **Mint Address** | TBD (will be published at launch) |

---

## 8. pSOQ Launch Models (Community Analysis)

> [!NOTE]
> **Community Feedback Integration**: This section incorporates feedback from community members
> analyzed by blockchain security and tokenomics experts. The final model will be selected based
> on security, compliance, and decentralization priorities.

### The Core Challenge

At **mainnet genesis, there is 0 SOQ in circulation** until miners produce blocks. This creates
a chicken-and-egg problem for pSOQ:

| Challenge | Impact |
|-----------|--------|
| No SOQ to lock | Cannot mint backed pSOQ |
| No pSOQ liquidity | No Solana DeFi integration |
| Miners need incentive | Early adoption requires rewards |

### Model A: Pre-Mine Pool (Treasury-Backed)

```
Foundation pre-mines pSOQ supply → available at Solana launch
SOQ backing comes from early mining treasury
```

| Aspect | Assessment |
|--------|------------|
| **Liquidity** | ✅ Immediate — pSOQ available day 1 |
| **Complexity** | ✅ Simple — no oracle dependency |
| **Trust** | ❌ Centralized — users trust foundation backing |
| **Alignment** | ❌ Conflicts with "0% premine" philosophy |

> [!WARNING]
> **Expert Assessment**: This model contradicts Soqucoin's fair-launch principles.
> While operationally simple, it introduces counter-party risk and undermines
> the project's core value proposition. **Not recommended.**

### Model B: Mining-Backed (Pure Lock/Mint)

```
pSOQ exists ONLY when SOQ is locked in bridge contract
No pSOQ until mainnet miners produce SOQ
```

| Aspect | Assessment |
|--------|------------|
| **Liquidity** | ❌ Delayed — wait for mining circulation |
| **Trust** | ✅ Fully trustless — 1:1 provable backing |
| **Alignment** | ✅ Perfect — no premine, no treasury |
| **DeFi Timeline** | ❌ Weeks/months delay for Solana integration |

> [!TIP]
> **Expert Assessment**: This is the most philosophically pure model and aligns
> with Soqucoin's values. The liquidity delay is acceptable if properly communicated.
> **Recommended for long-term.**

### Model C: Hybrid (Forward-Commit Mining)

```
Phase 1: Foundation provides temporary liquidity guarantee
Phase 2: Mining-backed pSOQ replaces temporary supply
Phase 3: Foundation guarantee expires, fully decentralized
```

| Aspect | Assessment |
|--------|------------|
| **Liquidity** | ✅ Early access with transition plan |
| **Trust** | 🟡 Temporary centralization, planned sunset |
| **Alignment** | 🟡 Compromise — transparent about tradeoffs |
| **Complexity** | ❌ Higher — requires migration mechanics |

> [!IMPORTANT]
> **Expert Assessment**: This model balances pragmatism with principles IF:
> - Foundation liquidity is time-bounded (e.g., 90 days)
> - Transition to mining-backed is automatic and verifiable
> - Community is fully informed of the hybrid phase
>
> **Acceptable if properly executed.**

### Recommended Approach

Based on expert analysis, the recommended path is:

| Phase | Timeline | Model | Notes |
|-------|----------|-------|-------|
| **Genesis** | Q1 2026 | No pSOQ | Focus on SOQ mining, network stability |
| **Early Bridge** | Q2 2026 | Model B | Mining-backed only, limited liquidity |
| **Mature Bridge** | Q3+ 2026 | Model B | Full liquidity from mining circulation |

**Key Principle**: Wait for natural mining circulation rather than compromising
on the "0% premine" commitment. Early Solana integration is not worth
sacrificing long-term credibility.

### Forward-Commit Mining (Rejected Alternative)

Community suggested: *"Miners claim pSOQ immediately; SOQ unlocks as mined"*

| Concern | Expert Response |
|---------|-----------------|
| Creates unbacked pSOQ | Violates 1:1 backing principle |
| Complexity | Adds oracle dependencies |
| Regulatory risk | Unbacked claims may be securities |

> [!CAUTION]
> **Rejected**: Forward-commit mining creates unbacked tokens which contradicts
> the bridge's security model and may attract regulatory scrutiny.

---

## 9. Open Design Questions

1. **Validator economics**: How are validators compensated for bridge operations?
2. **Fee structure**: Should bridge transfers incur fees beyond network gas?
3. **Rate limiting**: Should there be per-transaction or per-day limits initially?
4. **Emergency procedures**: How to handle bridge pause/freeze in case of exploit?
5. **Governance**: Who controls bridge upgrades long-term?
6. **pSOQ Launch Timing**: When does sufficient SOQ liquidity exist for bridge launch?
7. **Proof of Reserves**: On-chain attestation frequency and audit requirements?

---

## 9. Related Documents

- [Consensus Cost Specification](CONSENSUS_COST_SPEC.md) — Mainnet protocol parameters
- [Mining Guide](mining-guide.md) — SOQ acquisition
- [Node Operator Guide](node-operator-guide.md) — Running Soqucoin infrastructure

---

*Working document — Soqucoin Core Development Team*
*Feedback welcome via GitHub issues*
