# pSOQ ↔ SOQ Gateway Architecture

> **Status:** Shipped to Devnet/Stagenet  
> **Target Activation:** Q3 2026 (after block 100,000 / 5B SOQ mined)  
> **Last Updated:** June 15, 2026  
> **Audit Requirement:** Halborn Phase 2 Audit in progress  

---

## Overview

This document specifies the gateway architecture for converting between pSOQ (Solana SPL token) and native SOQ. We are publishing this to document the technical design and trust model of the SOQ-TEC cross-chain gateway.

**Bottom line up front:** The gateway uses a standard lock-and-mint / burn-and-release pattern. It is built for cryptographic longevity in a post-quantum environment, utilizing Dilithium attestations and XMSS-Lite revolving vault custody.

---

## Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SOQ → pSOQ (Deposit)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   User sends SOQ ──► Dilithium L1 Vault ──► Relayer committee attestation   │
│                                                            │                │
│                                                            ▼                │
│                                              pSOQ minted to XMSS Vault      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           pSOQ → SOQ (Redemption)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   User burns pSOQ on Solana ──► Relayers detect burn ──► Quantum Express    │
│                                                            │                │
│                                                            ▼                │
│                                                   SOQ released from L1 Vault│
└─────────────────────────────────────────────────────────────────────────────┘
```

### Components

#### 1. Dilithium L1 Vault (Soqucoin L1)

- **Location:** Native Soqucoin script
- **Security:** Dilithium ML-DSA-44 multi-signature (3-of-5 threshold)
- **Function:** Holds locked SOQ backing all circulating pSOQ
- **Audit scope:** Script correctness, signature verification, replay protection

The vault is the critical L1 component. It is secured by the same post-quantum signatures that protect all Soqucoin transactions.

#### 2. pSOQ Token Contract & XMSS Vault (Solana)

- **Standard:** SPL Token & Anchor program
- **Mint Authority:** Gateway program (controlled by relayer consensus)
- **Solana Fees:** Ed25519 (required by Solana for gas fees, but keys never touch the network for bridge signatures)
- **Custody:** XMSS Revolving Door (WOTS+ key hashes)

This component resides on Solana. The trade-off is explicit: pSOQ holders use Solana's runtime for liquidity while securing their assets inside an offline-signer XMSS vault.

#### 3. Dilithium Relayer Network (3-of-5 Committee)

- **Function:** Observes lock/burn events, attests to state changes
- **Mechanism:**
  - 3-of-5 Dilithium attestation relayer committee
  - Independent validator nodes running on-chain verification
  - Quantum Express optimistic release for rapid redemptions (under 30 seconds)

**Honest assessment:** The relayer committee is the trust anchor of the gateway. A compromised relayer set could:
- Mint unbacked pSOQ (inflation attack)
- Fail to release locked SOQ (liveness failure)
- Censor specific redemption requests

We mitigate this through multi-signature threshold requirements and active monitoring.

---

## Security Model

### What IS Protected

| Component | Protection Level |
|-----------|-----------------|
| Locked SOQ in vault | Dilithium ML-DSA-44 (NIST Level 2 PQ) |
| L1 Vault script logic | Consensus-enforced on Soqucoin L1 |
| Solana Asset Custody | XMSS Revolving Door (WOTS+ key hashes) |

### What is NOT Protected

| Component | Vulnerability |
|-----------|--------------|
| Solana gas fee signatures | Ed25519 (vulnerable to Shor's algorithm) |
| Relayer uptime | Dependent on relayer committee stability |

**For miners considering pSOQ:** If your threat model includes quantum adversaries on the Solana network, pSOQ is not the right vehicle. It is a liquidity gateway, not a long-term store of value. Mine native SOQ post-mainnet for actual PQ protection.

---

## Economic Considerations

### Peg Maintenance

The 1:1 peg is maintained through arbitrage:
- If pSOQ trades below SOQ: Arbitrageurs buy pSOQ, redeem for SOQ, and sell SOQ.
- If pSOQ trades above SOQ: Arbitrageurs buy SOQ, lock for pSOQ, and sell pSOQ.

This assumes:
1. Gateway is operational
2. Liquidity exists on both sides
3. Transaction costs do not exceed the spread

### Backing Model

The gateway is designed for full 1:1 backing. Foundation mining rewards fund reserve pools post-Phase-2 audit to ensure senior priority redemption for the public float.

---

## Implementation Timeline

| Phase | Target | Deliverable |
|-------|--------|-------------|
| Design | Q2 2026 ✅ | This document, threat model |
| Development | Q2 2026 ✅ | Custom Dilithium relayer, XMSS Vault |
| Audit | Q2-Q3 2026 | Halborn Phase 2 audit (in progress) |
| Testnet | Q2-Q3 2026 | Integration testing on devnet and stagenet |
| Mainnet | Q3 2026 | Production gateway activation |

> [!NOTE]
> **Gateway Design Choice**: The team pivoted from third-party oracle providers to a custom post-quantum relayer committee to ensure native signature compatibility and eliminate third-party oracle risks.

---

## Risk Disclosure

### The Gateway May Never Activate

We are being explicit: **the 1:1 gateway activation is contingent on audit completion**. Reasons it might not activate:

1. **Audit findings:** Critical vulnerabilities that cannot be remediated
2. **Regulatory uncertainty:** Legal advice indicating the gateway creates unacceptable risk
3. **Technical blockers:** L1 script limitations or Solana runtime issues

If the gateway does not activate, pSOQ remains an independent Solana token. This is a real risk that participants should price in.

### Relayer Compromise Scenarios

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| Relayer set colludes | Unbacked pSOQ minted | Threshold signatures, time-locked withdrawals |
| Relayer keys compromised | Same as above | Key rotation, hardware security modules |
| Relayer set goes offline | Gateway halts, no new mints or redeems | Fallback relayer set, emergency governance |

We are designing for these threats, but no system is invulnerable. The gateway adds trust assumptions that native SOQ does not have.

---

## For Miners: Practical Guidance

If you are evaluating participation in Soqucoin, here is our honest recommendation:

1. **pSOQ is for pre-mainnet exposure only.** It is a speculation vehicle, not the ultimate store of value.
2. **Mining native SOQ post-mainnet gives you actual PQ protection.** That is the core thesis.
3. **Do not over-allocate to pSOQ based on gateway assumptions.** Price in the possibility that it does not happen.
4. **Watch for audit announcements.** We will publish results transparently.

---

## Questions?

- **GitHub Issues:** [soqucoin/soqucoin/issues](https://github.com/soqucoin/soqucoin/issues)
- **Discord:** [discord.gg/kc6GMmbZvX](https://discord.gg/kc6GMmbZvX)
- **Technical Contact:** pm@soqu.org

---

*Last updated: June 15, 2026*  
*Document maintainer: Soqucoin Core Team*
