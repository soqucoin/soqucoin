# Soqucoin-Solana Bridge Architecture

> **Version**: 0.2 | **Status**: Tentative Decisions Pending Board Approval
> **Last Updated**: February 2, 2026
> **Network**: Soqucoin ↔ Solana

---

> [!NOTE]
> **Tentative Decisions**: This document now includes tentative architecture decisions based on expert analysis. These decisions are pending final board approval post-mainnet. Design may evolve based on security audit findings.

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

### Validator Set (Tentative Decision)

| Parameter | **Tentative Decision** | Justification |
|-----------|------------------------|---------------|
| **Validator count** | **7** | Balance between decentralization and coordination |
| **Threshold** | **5-of-7 (71%)** | Byzantine fault tolerant (survives 2 malicious) |
| **Geographic distribution** | **Minimum 4 continents** | Jurisdiction diversity, latency distribution |
| **Technical requirements** | HSM, 99.5% uptime, 24/7 on-call | Professional operations standard |

### Validator Selection Criteria

| Slot | Type | Region | Selection Criteria |
|------|------|--------|-------------------|
| 1 | Foundation-operated | North America | Fiduciary responsibility |
| 2 | Mining pool partner | Europe | Hashrate stake alignment |
| 3 | Exchange partner | Asia | Liquidity stake alignment |
| 4 | Security firm | Variable | Audit relationship (e.g., Halborn) |
| 5 | Infrastructure provider | Variable | Professional operations |
| 6 | Community-elected | Variable | Decentralization signal |
| 7 | Rotating seat | Variable | 6-month rotation |

### Collateralization

| Model | Description | Status |
|-------|-------------|--------|
| **1:1 Custody** | SOQ locked = pSOQ minted | ✅ Confirmed |
| **Proof of Reserves** | 6-hour automated + quarterly audit | ✅ Planned |

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

## 6. Deployment Timeline (Updated)

| Phase | Target | Description |
|-------|--------|-------------|
| **Design** | Q2 2026 | Architecture finalization ✅ |
| **Development** | Q2 2026 | Wormhole integration, vault contract |
| **Audit** | Q2 2026 | Third-party security review |
| **Testnet** | Q2-Q3 2026 | Integration testing (after block 100,000) |
| **Mainnet** | **Q3 2026** | Production deployment (when 5B SOQ mined) |

> [!NOTE]
> **Timeline Updated**: Previously Q4 2026. Using Wormhole (vs custom oracle) accelerates timeline by ~3 months.

---

## 7. pSOQ Token Information

| Parameter | Value |
|-----------|-------|
| **Name** | Pegged Soqucoin |
| **Symbol** | pSOQ |
| **Decimals** | 8 (matches SOQ) |
| **Network** | Solana Mainnet |
| **Total Supply** | 1,000,000,000 (1 billion) |
| **Mint Address** | `6NX2MWBuJM2Fn63K4hUgMPivLXHV8pwsU1yTdmjKpump` |

---

## 8. pSOQ Backing Economics (Tentative)

> [!IMPORTANT]
> This section documents the economic model for pSOQ backing under the Mining-Backed (Model B) approach.
> These are tentative recommendations pending board approval.

### The Core Economics

pSOQ was launched on Pump.fun **before** Soqucoin mainnet exists. This creates a timing mismatch:

| Asset | Supply | Current Backing |
|-------|--------|-----------------|
| **pSOQ (Solana)** | 1 billion | ❌ Not backed (pre-bridge) |
| **SOQ (at block 100k)** | ~5 billion | N/A (native L1 token) |

**"1:1" refers to the exchange rate, not supply parity:**
- 1 SOQ locked in vault = 1 pSOQ mintable/redeemable
- Bridge operates at 1:1 unit rate
- Total pSOQ backing depends on SOQ locked in vault

### pSOQ Distribution

| Holder | Amount | Percentage | Status |
|--------|--------|------------|--------|
| **LP (Foundation)** | ~120M pSOQ | 12% | Locked until June 2026 |
| **Team Wallets** | ~60M pSOQ | 6% | Liquid |
| **Foundation Total** | **~180M pSOQ** | **18%** | See subordination below |
| **Public Float** | ~820M pSOQ | 82% | Trading on Solana DEXs |

### Backing Model: Foundation Commitment + Market Arbitrage

#### Phase 1: Bridge Launch (Q3 2026)

```
Foundation commits: Lock 180M mined SOQ
Vault balance: 180M SOQ
pSOQ circulation: 1B
Foundation pSOQ (subordinated): 180M
Public pSOQ (senior): 820M

Effective public backing: 180M / 820M = 22%
```

#### Phase 2: Market Arbitrage (Ongoing)

```
Arbitrageurs lock additional SOQ to mint pSOQ
Sell pSOQ on Solana DEXs for profit
Vault fills progressively

Month 1: ~380M SOQ in vault (46% public backing)
Month 3: ~580M SOQ in vault (70% public backing)
Month 6+: Approaching full backing
```

### Foundation Subordination Structure (Tentative)

> [!NOTE]
> The foundation's 180M pSOQ is **subordinated** to public holdings.
> This means the team's pSOQ is worth nothing until public pSOQ is fully backed.

| Priority | Holder | Redemption Rights |
|----------|--------|-------------------|
| **Senior (1st)** | Public (820M pSOQ) | Can redeem immediately from vault |
| **Junior (2nd)** | Foundation (180M pSOQ) | Can only redeem after vault ≥ 1B SOQ |

**Subordination Terms:**
1. Foundation locks 180M mined SOQ at bridge launch
2. Foundation pSOQ redeems LAST — after all public pSOQ is 100% backed
3. Foundation cannot front-run public redemptions
4. Subordination is enforced by smart contract or governance commitment

### Expected Price Convergence

| Timeframe Post-Bridge | Est. Vault Balance | Public Backing | Expected pSOQ/SOQ |
|-----------------------|-------------------|----------------|-------------------|
| Bridge launch | 180M SOQ | 22% | 0.20 - 0.40 |
| Month 1 | ~380M SOQ | 46% | 0.40 - 0.60 |
| Month 3 | ~580M SOQ | 70% | 0.65 - 0.85 |
| Month 6+ | ~800M+ SOQ | 97%+ | 0.90 - 1.00 |

*Actual convergence depends on SOQ liquidity and arbitrageur participation.*

### Why This Model Works

| Stakeholder | Benefit |
|-------------|---------|
| **Public pSOQ holders** | 22% day-1 backing (vs 0% pure market model) |
| **Foundation** | Demonstrates alignment — "we eat last" |
| **Community** | Founders can't dump before bridge is stable |
| **Regulators** | Clear subordination = transparent risk hierarchy |

### Required Disclosures

**Pre-Bridge (Now):**
> pSOQ is a speculation vehicle representing aspirational access to Soqucoin. 
> It is NOT currently backed. Bridge activation is planned for Q3 2026.

**At Bridge Launch:**
> pSOQ Bridge Economics:
> - Total pSOQ: 1 billion
> - Foundation holdings: 180M (18%) — **subordinated**
> - Public float: 820M (82%) — **senior**
> - Current vault balance: [LIVE DASHBOARD]
>
> Foundation pSOQ cannot be redeemed until public pSOQ is 100% backed.

### LP Lock Consideration

| Event | Date | Notes |
|-------|------|-------|
| Current LP unlock | June 2026 | Before bridge launch |
| Bridge activation | Q3 2026 | After LP unlock |

**Board Decision Required:** Consider extending LP lock to Q4 2026 or converting to subordinated bridge position for optics and alignment demonstration.


## 9. pSOQ Launch Models (Community Analysis)

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
| **Genesis** | Q2 2026 | No pSOQ | Focus on SOQ mining, network stability |
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

## 10. Tentative Board Decisions (Pending Approval)

> [!IMPORTANT]
> The following decisions are **tentative recommendations** based on expert blockchain development analysis.
> Final approval pending board review post-mainnet launch.

### Decision 1: Oracle Provider — Wormhole for v1

| Option | Recommendation |
|--------|----------------|
| **Wormhole Guardians** | ✅ **Selected** |
| Custom validator set | v2 consideration |
| LayerZero | Alternative if terms unfavorable |

**Justification:**
- 19 validators, $35B+ processed volume, battle-tested
- 2-3 month integration vs 6-12 months custom development
- Already audited, reduces our audit burden
- Industry standard (Jupiter, Pyth, 20+ major protocols)

**Risks:**
- External dependency on Wormhole operations
- Not quantum-safe (Ed25519 attestations)
- Mitigation: Emergency fallback to multisig-only mode

---

### Decision 2: Activation Threshold — 5B SOQ Mined

| Threshold | Blocks | Timeline | Status |
|-----------|--------|----------|--------|
| 1B SOQ | ~20,000 | ~14 days | ❌ Too early |
| **5B SOQ** | ~100,000 | **~69 days** | ✅ **Selected** |
| 10B SOQ | ~200,000 | ~139 days | ❌ Unnecessary delay |

**Justification:**
- Sufficient on-chain liquidity for arbitrage peg maintenance
- Aligns with Stage 2 (LatticeFold+) activation, signaling maturity
- Exchange listings likely by this point
- Conservative threshold — better stable than broken

**Risks:**
- pSOQ holders wait ~70 days post-mainnet
- Mitigation: Clear communication, published countdown

---

### Decision 3: Fee Structure — 0.1% Bridge Fee

| Component | Tentative Decision |
|-----------|-------------------|
| **Bridge fee** | 0.1% of transfer value |
| **Minimum fee** | 100 SOQ (prevents dust attacks) |
| **Maximum fee** | 10,000 SOQ cap |
| **Distribution** | 80% validators, 20% treasury |
| **Payment** | Monthly settlement in SOQ |

**Justification:**
- Industry standard (Wormhole, Multichain, Axelar: ~0.1%)
- Sustainable for professional validator operations
- Lower discourages validators; higher discourages users

**Economic Model (at maturity):**
```
Monthly volume $10M → Validators earn ~$1,140/month each
Monthly volume $100M → Validators earn ~$11,400/month each
```

---

### Decision 4: Emergency Procedures — Tiered Response

| Level | Trigger | Action | Authority |
|-------|---------|--------|-----------|
| **1: Anomaly** | Unusual volume | Monitoring alert | Ops team |
| **2: Concern** | Failed attestation | Rate limiting | 2 validators |
| **3: Incident** | Exploit suspected | Bridge pause | 3 validators |
| **4: Critical** | Active exploit | Full freeze | 4 validators |

**Automatic Circuit Breakers:**
- Hourly volume >200% of 7-day average → Rate limit to 50%
- Single transaction >5% of vault → Manual review required
- 3+ consecutive attestation failures → Pause new mints
- Proof of Reserves mismatch → Full freeze

**Justification:**
- Based on Compound/Aave incident response frameworks
- Graduated response prevents false positives and slow reactions
- Automatic triggers eliminate human error/delay

---

### Decision 5: Governance — Progressive Decentralization

| Phase | Timeline | Model |
|-------|----------|-------|
| **Phase 1** | Months 0-6 | Foundation multisig (3-of-5) |
| **Phase 2** | Months 6-12 | Validator committee (5-of-7) |
| **Phase 3** | Months 12-18 | Committee + token holder veto |
| **Phase 4** | Months 18-24 | Full token governance |

**Upgrade Timelocks:**
| Type | Timelock |
|------|----------|
| Parameter adjustment | 24 hours |
| Bug fix | 48 hours |
| Feature addition | 7 days |
| Critical change | 14+ days |

**Justification:**
- Day-1 DAO is dangerous (see: Beanstalk hack)
- Compound/Uniswap progressive decentralization model
- Credible exit path to full decentralization

---

### Decision 6: Sunset Planning — 24-Month Support Window

| Phase | Timeline | Status |
|-------|----------|--------|
| **Full support** | Months 0-18 | Normal operations, LPincentives |
| **Notice period** | Month 18 | Announce 6-month sunset |
| **Reduced support** | Months 18-24 | No new incentives, full function |
| **Sunset** | Month 24+ | Bridge open, no guaranteed support |

**Post-Sunset:**
- pSOQ remains redeemable indefinitely (vault stays)
- Minimum 3 validators maintain operations
- Monthly community updates in final 6 months

**Justification:**
- pSOQ purpose: Pre-mainnet liquidity access
- Post-mainnet: Native SOQ on CEX/DEX is superior (PQ-safe)
- Publishing sunset plan signals maturity, prevents rug accusations

---

## 11. Remaining Open Questions

1. **Wormhole commercial terms**: Negotiate integration agreement
2. **Initial validator candidates**: Identify 7 entities meeting criteria
3. **Bridge audit timeline**: Coordinate with Halborn for Phase 2
4. **Regulatory review**: Confirm bridge structure with legal counsel

---

## 12. Related Documents

- [Consensus Cost Specification](CONSENSUS_COST_SPEC.md) — Mainnet protocol parameters
- [Mining Guide](mining-guide.md) — SOQ acquisition
- [Node Operator Guide](node-operator-guide.md) — Running Soqucoin infrastructure
- [BRIDGE_ARCHITECTURE.md](BRIDGE_ARCHITECTURE.md) — Detailed technical architecture

---

*Last Updated: February 2, 2026*
*Tentative decisions pending board approval post-mainnet*
*Soqucoin Core Development Team*
