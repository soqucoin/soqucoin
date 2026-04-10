# pSOQ ↔ SOQ Bridge Architecture

> **Status:** Tentative Decisions — Pending Board Approval  
> **Target Activation:** Q3 2026 (after block 100,000 / 5B SOQ mined)  
> **Last Updated:** February 2, 2026  
> **Audit Requirement:** Third-party audit mandatory before activation

---

## Overview

This document specifies the planned bridge architecture for converting between pSOQ (Solana SPL token) and native SOQ. We're publishing this early to address legitimate questions from miners and developers about the bridge's technical design and trust model.

**Bottom line up front:** The bridge uses a standard lock-and-mint / burn-and-release pattern. It's not novel cryptography—it's proven infrastructure adapted for our PQ context. The hard part isn't the mechanism; it's the oracle trust assumption and the audit process.

---

## Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SOQ → pSOQ (Minting)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   User sends SOQ ──► Vault (Dilithium multi-sig) ──► Oracle attestation     │
│                                                            │                │
│                                                            ▼                │
│                                              pSOQ minted on Solana          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           pSOQ → SOQ (Redemption)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   User burns pSOQ on Solana ──► Oracle observes burn ──► Vault releases SOQ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Components

#### 1. Vault Contract (Soqucoin L1)

- **Location:** Native Soqucoin script
- **Security:** Dilithium ML-DSA-44 multi-signature (3-of-5 threshold recommended)
- **Function:** Holds locked SOQ backing all circulating pSOQ
- **Audit scope:** Script correctness, signature verification, replay protection

The vault is the critical component. It's secured by the same post-quantum signatures that protect all Soqucoin transactions. Unlike the pSOQ side, this component benefits from Soqucoin's quantum resistance.

#### 2. pSOQ Token Contract (Solana)

- **Standard:** SPL Token
- **Mint Authority:** Bridge program (controlled by oracle consensus)
- **Security:** Ed25519 (classical—NOT quantum-safe)

This is inherited Solana infrastructure. We're not reinventing the wheel here. The trade-off is explicit: pSOQ holders accept Solana's security model in exchange for pre-mainnet liquidity access.

#### 3. Oracle Network

- **Function:** Observes lock/burn events, attests to state changes
- **Options under evaluation:**
  - Wormhole Guardians (established, but external dependency)
  - Custom validator set (more control, more development overhead)
  - Threshold signature scheme (distributed trust)

**Honest assessment:** This is where the trust assumptions live. The oracle network is the bridge's weakest link. A compromised oracle set could:
- Mint unbacked pSOQ (inflation attack)
- Fail to release locked SOQ (liveness failure)
- Censor specific redemption requests

We're evaluating options with explicit trust/complexity trade-offs. The final design will be published with a threat model before deployment.

---

## Security Model

### What IS Protected

| Component | Protection Level |
|-----------|-----------------|
| Locked SOQ in vault | Dilithium ML-DSA-44 (NIST Level 2 PQ) |
| Vault script logic | Consensus-enforced on Soqucoin L1 |

### What is NOT Protected

| Component | Vulnerability |
|-----------|--------------|
| pSOQ holdings on Solana | Ed25519 (vulnerable to Shor's algorithm) |
| Oracle attestations | Trust in oracle operator set |
| Bridge liveness | Dependent on oracle uptime |

**For miners considering pSOQ:** If your threat model includes quantum adversaries, pSOQ is not the right vehicle. It's a liquidity bridge, not a long-term store of value. Mine native SOQ post-mainnet for actual PQ protection.

---

## Economic Considerations

### Peg Maintenance

The 1:1 peg is maintained through arbitrage:
- If pSOQ trades below SOQ: Arbitrageurs buy pSOQ, redeem for SOQ, sell SOQ
- If pSOQ trades above SOQ: Arbitrageurs buy SOQ, lock for pSOQ, sell pSOQ

This assumes:
1. Bridge is operational
2. Liquidity exists on both sides
3. Transaction costs don't exceed the spread

### Liquidity Risk Post-Mainnet

Solana DEX liquidity for pSOQ will likely decline after native SOQ trading begins. We're exploring:
- Liquidity incentive programs for pSOQ LPs
- Gradual migration path with clear timelines
- Potential sunset date for the bridge

We'll communicate this clearly. No one should be caught off-guard by liquidity changes.

---

## Implementation Timeline (Updated)

| Phase | Target | Deliverable |
|-------|--------|-------------|
| Design | Q2 2026 ✅ | This document, threat model |
| Development | Q2 2026 | Wormhole integration, vault contract |
| Audit | Q2-Q3 2026 | Third-party bridge audit (Halborn Phase 2) |
| Testnet | Q2-Q3 2026 | Integration testing (after block 100,000) |
| Mainnet | **Q3 2026** | Production activation (when 5B SOQ mined) |

> [!NOTE]
> **Timeline Updated (Feb 2026)**: Previously Q4 2026. Using Wormhole (vs custom oracle) accelerates timeline by ~3 months. Activation gated by 5B SOQ circulation threshold.

**No activation without audit.** This is non-negotiable. We've seen too many bridges exploited due to rushed deployments.

---

## Risk Disclosure

### The Bridge May Never Activate

We're being explicit: **the 1:1 bridge is aspirational, not guaranteed**. Reasons it might not ship:

1. **Audit findings:** Critical vulnerabilities that can't be remediated
2. **Regulatory uncertainty:** Legal advice indicating bridge creates unacceptable risk
3. **Technical blockers:** Oracle infrastructure proves infeasible
4. **Community governance:** Token holders vote against activation

If the bridge doesn't activate, pSOQ becomes an independent Solana token with no guaranteed backing. This is a real risk that participants should price in.

### Oracle Compromise Scenarios

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| Oracle set colludes | Unbacked pSOQ minted | Threshold signatures, time-locked withdrawals |
| Oracle keys compromised | Same as above | Key rotation, hardware security modules |
| Oracle set goes offline | Bridge halts, no new mints/redeems | Fallback oracle set, emergency governance |

We're designing for these threats, but no system is invulnerable. The bridge adds trust assumptions that native SOQ doesn't have.

---

## For Miners: Practical Guidance

If you're evaluating participation in Soqucoin, here's our honest recommendation:

1. **pSOQ is for pre-mainnet exposure only.** It's a speculation vehicle, not the product.
2. **Mining native SOQ post-mainnet gives you actual PQ protection.** That's the thesis.
3. **Don't over-allocate to pSOQ based on bridge assumptions.** Price in the possibility that it doesn't happen.
4. **Watch for audit announcements.** We'll publish results transparently.

We're building this in public. If you see design flaws, open an issue. If you want to contribute to the bridge implementation, reach out on Discord (#dev channel).

---

## Questions?

- **GitHub Issues:** [soqucoin/soqucoin/issues](https://github.com/soqucoin/soqucoin/issues)
- **Discord:** [discord.gg/kc6GMmbZvX](https://discord.gg/kc6GMmbZvX)
- **Technical Contact:** pm@soqu.org

---

*Last updated: January 13, 2026*  
*Document maintainer: Soqucoin Core Team*
