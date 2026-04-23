# Soqucoin Governance Documentation
**Version:** 1.0  
**Status:** P8-01 Compliance Document  
**Model:** Based on Dogecoin Foundation governance  
**Last Updated:** 2026-01-26

---

## Executive Summary

Soqucoin follows a **community-driven governance model** similar to Dogecoin, with the addition of the **Soqucoin Foundation** for protocol stewardship and **Soqucoin Labs** for commercial development.

---

## Governance Structure

### 1. Protocol Governance (Decentralized)

| Component | Description |
|-----------|-------------|
| **Consensus Changes** | BIP9 soft fork activation (95% miner signaling) |
| **Hard Forks** | Require community consensus + miner majority |
| **Emergency Changes** | Core maintainer discretion for critical security |

### 2. Soqucoin Foundation (Non-Profit)

**Entity Type:** Wyoming Non-Profit Corporation  
**Purpose:** Protocol stewardship, not commercial value capture

| Role | Responsibility |
|------|----------------|
| Protocol Maintenance | Core codebase security & updates |
| Documentation | Public documentation & standards |
| Community Outreach | Developer relations & education |
| Trademark Stewardship | Protect Soqucoin™, SOQ™, sSOQ™, USDSOQ™ marks |

**Foundation Does NOT:**
- Control consensus rules unilaterally
- Hold or manage user funds
- Operate for profit

### 3. Soqucoin Labs (Commercial)

**Entity Type:** For-profit commercial development  
**Purpose:** Commercial products, enterprise services

| Role | Responsibility |
|------|----------------|
| Wallet Development | pqwallet, mobile apps |
| Enterprise Solutions | Custom integrations |
| Mining Infrastructure | Pool development, hosting |
| Business Development | Partnerships, listings |

---

## Decision-Making Process

### Protocol Changes

```mermaid
flowchart LR
    A[Proposal] --> B[Community Discussion]
    B --> C[BIP/SIP Draft]
    C --> D[Code Review]
    D --> E[Testnet Deployment]
    E --> F[Miner Signaling]
    F --> G{95% Threshold?}
    G -->|Yes| H[Activation]
    G -->|No| I[Revise/Reject]
```

### Soft Fork Activation (BIP9)

| Parameter | Value |
|-----------|-------|
| Activation Threshold | 95% of 10,080 blocks (1 week) |
| Signaling Window | 10,080 blocks |
| Timeout | 1 year from start |
| Lock-in Period | 10,080 blocks |

---

## Key Holders & Roles

### Foundation Board

| Role | Responsibility | Key Access |
|------|----------------|------------|
| **Executive Director** | Strategic direction | None (governance only) |
| **Technical Lead** | Protocol decisions | GitHub maintainer |
| **Secretary** | Legal compliance | Document signing |

### Development Roles

| Role | Access Level |
|------|--------------|
| Core Maintainers | Merge to `main` branch |
| Contributors | Pull request submission |
| Reviewers | Code review & approval |

### Multi-Sig Requirements

| Asset | Signers Required | Total Signers |
|-------|------------------|---------------|
| Foundation Treasury | 2-of-3 | 3 |
| Protocol Emergency Fund | 3-of-5 | 5 |
| Bug Bounty Fund | 2-of-3 | 3 |

---

## Emission Schedule

Soqucoin follows Dogecoin's emission model with minor adjustments:

### Block Rewards

| Height | Reward | Notes |
|--------|--------|-------|
| 0 - 99,999 | 500,000 SOQ | Genesis phase |
| 100,000 - 199,999 | 250,000 SOQ | First halving |
| 200,000 - 299,999 | 125,000 SOQ | Second halving |
| 300,000+ | 10,000 SOQ | Perpetual tail emission |

### Tail Emission Rationale

Like Dogecoin, Soqucoin uses **perpetual tail emission** (no supply cap) to:
- Incentivize mining security long-term
- Replace lost coins over time
- Maintain transaction fee competitiveness

**Annual Inflation:** ~5.26B SOQ (~3% decreasing annually)

---

## Upgrade Process

### Staged Activation (Mainnet)

| Phase | Description | Timeline |
|-------|-------------|----------|
| **Testnet** | Feature testing | 2+ weeks |
| **Stagenet** | Mainnet rehearsal | 1+ week |
| **Signaling** | Miner BIP9 votes | 1 week window |
| **Lock-in** | Activation guaranteed | 1 week |
| **Activation** | Feature goes live | Height-based |

### Current Deployments

| Feature | Status | Activation |
|---------|--------|------------|
| Dilithium Signatures | ✅ ACTIVE | Genesis |
| SegWit | ✅ ACTIVE | Always-active |
| CSV (BIP68/112/113) | ✅ ACTIVE | Always-active |
| LatticeFold+ | 🟡 SIGNALING | Height 100,000 |

---

## Security Governance

### Vulnerability Disclosure

See [INCIDENT_RESPONSE_PLAN.md](INCIDENT_RESPONSE_PLAN.md) for:
- Severity classification
- Response timelines
- Escalation procedures

### Bug Bounty Program

| Severity | Reward Range |
|----------|--------------|
| Critical | $5,000 - $25,000 |
| High | $1,000 - $5,000 |
| Medium | $250 - $1,000 |
| Low | Recognition |

**Scope:** Core protocol, consensus, cryptography, RPC

---

## Community Participation

### How to Contribute

1. **Code:** Submit PRs to [github.com/soqucoin/soqucoin](https://github.com/soqucoin/soqucoin)
2. **Documentation:** Improve docs via PRs
3. **Discussion:** GitHub Discussions or Discord
4. **Testing:** Run testnet/stagenet nodes

### Governance Participation

- **Miners:** Signal for/against protocol upgrades
- **Node Operators:** Choose software version to run
- **Community:** Participate in discussions, provide feedback

---

## Comparison to Dogecoin

| Aspect | Dogecoin | Soqucoin |
|--------|----------|----------|
| Foundation | Dogecoin Foundation | Soqucoin Foundation |
| Consensus | SHA-256 (merged-mined) | Scrypt (AuxPoW capable) |
| Signatures | ECDSA | **Dilithium (PQ-safe)** |
| Block Time | 1 minute | 1 minute |
| Tail Emission | 10,000 DOGE/block | 10,000 SOQ/block |
| Governance | BIP9 soft forks | BIP9 soft forks |

**Key Differentiator:** Soqucoin is the **first quantum-resistant Scrypt chain**.

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-26 | Initial P8-01 compliance document |

---

*This document addresses finding P8-01: Governance Documentation*
