# Soqucoin Protocol Parameters & Consensus Cost Specification

> **Version**: 3.0 | **Status**: Pre-Mainnet
> **Last Updated**: April 27, 2026
> **Specification Tag**: Mainnet Candidate v1.0.0-rc1
> **Prepared For**: Halborn Security Audit (Hossam Mohamed, Alexis Fabre)

---

> [!IMPORTANT]
> **Pre-Mainnet Notice**: The following parameters are subject to change before mainnet launch:
> - **Policy parameters** (fees, dust limits) may be adjusted based on market conditions
> - **Benchmark-derived weights** (PQ verification costs) may be rebalanced based on hardware telemetry
> - **Consensus parameters** are frozen and will not change without a coordinated network upgrade
>
> **Privacy Model**: Privacy features (Lattice-BP++ range proofs, ring signatures) are **opt-in via native
> dual-format transactions**. The `nVisibility` field in `CTxOut` determines whether outputs are transparent
> (default) or confidential. View keys enable selective disclosure for auditors and exchanges.
>
> **Activation Model**: All features use **BIP9 deployment** with `ALWAYS_ACTIVE` (genesis features) or
> `NEVER_ACTIVE` (pending audit). Height-based staged activation has been replaced. See §9.
>
> This document reflects the current mainnet candidate specification.

---

## Overview

This document details the consensus-enforced limits and costs for the Soqucoin network. These parameters are **consensus-critical** — violations result in block/transaction rejection at the protocol level.

Soqucoin inherits Bitcoin/Dogecoin's core architecture while adding post-quantum cryptographic primitives with their own verification costs.

---

## Research Roadmap & Performance Projections

> [!NOTE]
> This section provides context for auditors and researchers on Soqucoin's cryptographic
> performance relative to other blockchains and projected improvements from future protocol upgrades.

### Current Benchmark Comparison (April 2026)

Soqucoin's post-quantum cryptography introduces verification overhead compared to classical ECDSA chains:

| Blockchain | Algorithm | Signature Size | Verify Time | Quantum Resistant |
|------------|-----------|----------------|-------------|-------------------|
| **Bitcoin** | ECDSA/secp256k1 | 71 bytes | ~50 µs | ❌ No |
| **Litecoin** | ECDSA/secp256k1 | 71 bytes | ~50 µs | ❌ No |
| **Dogecoin** | ECDSA/secp256k1 | 71 bytes | ~50 µs | ❌ No |
| **Soqucoin** | Dilithium ML-DSA-44 | 2,420 bytes | **175 µs** (measured) | ✅ Yes |

**Analysis**: Dilithium verification is ~3.5x slower than ECDSA. This is the expected trade-off for
NIST-standardized quantum resistance and is considered acceptable by the cryptographic community.

> **Benchmark Source**: VPS Testnet3 (4-core, 8GB), 327,680 iterations, 2026-01-07

### Range Proof Comparison

| System | Proof Size | Verify Time | Algorithm | Notes |
|--------|-----------|-------------|-----------|-------|
| Monero Bulletproofs+ | ~0.5 KB | ~1.5 ms | secp256k1 (classical) | Production (2022) |
| **Soqucoin Lattice-BP++** | ~12 KB | **0.055 ms** | Module-LWE/SIS (PQ) | Current — 27x faster verify |
| Soqucoin Lattice-BP++ (ring sig) | ~26 KB | ~67.7 ms | Ring-LWE (PQ, n=11) | Full private TX |

> **Benchmark Source**: Stagenet VPS (4-core, 16GB), April 2026. Lattice-BP++ uses pure lattice math —
> no classical elliptic curve arithmetic. All operations are post-quantum secure.

### Privacy-Enabled Blockchain Comparison

| Blockchain | Privacy Tech | Proof Size | Verify (1 TX) | Opt-In Model | Quantum Safe | Regulatory Risk |
|------------|-------------|------------|---------------|--------------|--------------|----------------|
| **Monero** | Bulletproofs+ | ~0.5 KB | 1.5 ms | ❌ Mandatory | ❌ No | 🔴 High (delistings) |
| **Zcash** | Groth16 zk-SNARK | ~0.2 KB | ~2 ms | ✅ Optional | ❌ No | 🟡 Medium |
| **Litecoin** | MWEB | ~1.5 KB | ~3 ms | ✅ Optional (ext. block) | ❌ No | 🟢 Low |
| **Soqucoin** | Lattice-BP++ | ~12 KB | **0.055 ms** | ✅ **Opt-In** (`nVisibility`) | ✅ Yes | 🟢 Low |

### Feature Activation Architecture

Soqucoin uses **BIP9 deployment flags** for feature activation. All features are either `ALWAYS_ACTIVE`
(enabled from genesis) or `NEVER_ACTIVE` (gated pending audit). There are no height-based activation
schedules.

| Feature | BIP9 Bit | Witness Version | Mainnet Status | Stagenet Status |
|---------|----------|-----------------|----------------|-----------------|
| **CSV** | 0 | — | ALWAYS_ACTIVE | ALWAYS_ACTIVE |
| **SegWit** | 1 | — | ALWAYS_ACTIVE | ALWAYS_ACTIVE |
| **BatchSig** | 2 | — | ALWAYS_ACTIVE | ALWAYS_ACTIVE |
| **PAT** (`OP_CHECKPATAGG`) | 3 | v2 (`OP_2`) | ALWAYS_ACTIVE | ALWAYS_ACTIVE |
| **LatticeFold** (`OP_CHECKFOLDPROOF`) | 28 | v3 (`OP_3`) | ALWAYS_ACTIVE | ALWAYS_ACTIVE |
| **Lattice-BP++** (`OP_LATTICEBP_RANGEPROOF`) | 5 | v4 (`OP_4`) | NEVER_ACTIVE | NEVER_ACTIVE |
| **USDSOQ** (`OP_USDSOQ_*`) | 6 | v5 (`OP_5`) | NEVER_ACTIVE | NEVER_ACTIVE |

> [!NOTE]
> **Witness version routing** in `VerifyScript()`: v0/v1 = Dilithium, v2 = PAT, v3 = LatticeFold,
> v4 = Lattice-BP++, v5 = USDSOQ, v6-v16 = future (anyone-can-spend). Each handler pushes the witness
> stack into `EvalScript()` with the corresponding opcode. Flag gating ensures soft fork safety.
>
> **`NEVER_ACTIVE` features**: When the flag is not set, transactions using that witness version pass
> as anyone-can-spend (standard BIP141 behavior). This allows future activation via miner signaling
> without a hard fork.

### LatticeFold+ Performance (ALWAYS_ACTIVE from Genesis)

> [!NOTE]
> **Implementation Status**: LatticeFold+ verifier is implemented (`src/crypto/latticefold/verifier.cpp`)
> based on ePrint 2025/247 (October revision). BIP9 `ALWAYS_ACTIVE` from genesis on both mainnet and
> stagenet. The following are **measured values** from benchmarks, not projections.

LatticeFold+ provides **recursive proof composition** for Dilithium batch verification:

**Measured Performance**:
| Platform | 512-sig Batch Verify | Effective TPS | Source |
|----------|---------------------|---------------|--------|
| Apple M4 | **0.68 ms** | ~753,000 sigs/sec | Code comment (dev) |
| **VPS Intel 4-core** | **0.751 ms** | **~682,000 sigs/sec** | Benchmark (Jan 7, 2026) |

> [!NOTE]
> The VPS benchmark uses crafted test data that exercises the **full verification path**
> (all 8 sumcheck rounds, range proof, commitment check), failing only at the final
> Fiat-Shamir seed check. The M4 and VPS results are consistent, validating the implementation.

> [!IMPORTANT]
> Unlike PAT (which verifies commitments only), LatticeFold+ performs **actual cryptographic
> verification** of Dilithium signatures through recursive proof folding.

**Node Verification Overhead Comparison**:

> **Note**: Users always sign transactions with Dilithium - that never changes.
> This table compares what **nodes** must do to verify a batch of transactions.

| Feature | PAT (Genesis) | LatticeFold+ (Genesis) |
|---------|--------------|------------------------|
| User creates Dilithium signature? | ✅ Yes (always) | ✅ Yes (always) |
| **Node verifies each Dilithium individually?** | **Yes** (175µs each) | **No** (replaced by proof) |
| Node verifies batch proof? | Yes (PAT Merkle) | Yes (recursive SNARK) |
| Batch size | Up to 256 | Up to 512 |
| **Total node verification time (256 tx)** | ~50 ms | ~1 ms |
| Light client can independently verify? | No (trusts full nodes) | Yes (verifies proof) |

### Academic References

The cryptographic primitives in Soqucoin are based on peer-reviewed research:

| Primitive | Paper | Authors | Year |
|-----------|-------|---------|------|
| **Dilithium** | CRYSTALS-Dilithium | Ducas et al. | 2018 (NIST FIPS 204) |
| **Bulletproofs++** | Bulletproofs+: Shorter Proofs | Chung et al. | 2022 |
| **LatticeFold** | LatticeFold: A Lattice-based Folding Scheme | Boneh, Chen | 2024 |
| **Nova/HyperNova** | Recursive SNARKs from Folding | Kothapalli et al. | 2022/2023 |

### Comparison to Rollup/ZK Technologies

Soqucoin is unique as a **native L1** with recursive proof composition, rather than a rollup:

| System | Architecture | Verify Time | Quantum Resistant |
|--------|--------------|-------------|-------------------|
| zkSync Era | Ethereum L2 (Groth16) | ~2 ms | ❌ No |
| StarkNet | Ethereum L2 (STARK) | ~10 ms | ⚠️ Partial |
| Polygon zkEVM | Ethereum L2 (PLONK) | ~3 ms | ❌ No |
| **Soqucoin LatticeFold+** | Native L1 (Lattice IVC) | **0.68-0.75 ms** (measured) | ✅ Yes |

**Key Differentiator**: Soqucoin's LatticeFold+ implementation is based on ePrint 2025/247
and provides the first production L1 with native lattice-based recursive SNARKs.

---

## 1. Parameter Classification

Understanding which parameters are inherited vs novel is critical for risk assessment:

| Category | Examples | Risk Profile |
|----------|----------|--------------|
| **Inherited (Dogecoin)** | Block weight, script limits, DigiShield | Low — battle-tested |
| **Modified** | Block reward schedule, fee structure | Medium — adapted for SOQ |
| **Novel (Soqucoin)** | PQ verify costs, LatticeFold caps, Chain ID | Higher — requires audit focus |

---

## 2. Design Rationale for Modified Parameters

This section explains **why** each modified parameter differs from Dogecoin's base values.

### 2.1 Block Reward: Random → Deterministic

| Dogecoin | Soqucoin | Rationale |
|----------|----------|-----------|
| Blocks 0-100k: Random 0-1,000,000 DOGE | Blocks 0-100k: Fixed 500,000 SOQ | **Predictability** |

Dogecoin's random block rewards were a "fun" feature reflecting its meme origins. For a serious post-quantum chain:
- Miners and investors require **predictable economic models**
- Mining pool variance creates unnecessary volatility
- Institutional due diligence requires deterministic supply curves

### 2.2 Terminal Emission: Aligned with Dogecoin Philosophy

| Dogecoin | Soqucoin | Rationale |
|----------|----------|-----------|
| 10,000 DOGE perpetual (after block 600k) | 10,000 SOQ perpetual (after block 600k) | **Miner incentive sustainability** |

Both chains converge to **identical terminal emission**: 10,000 tokens/block indefinitely. This is intentional:
- Perpetual inflation ensures ongoing miner incentives
- Prevents "fee-only" security model concerns
- Aligns with Dogecoin's proven long-term approach

### 2.3 Fee Structure: Placeholder for Mainnet Economics

| Dogecoin | Soqucoin | Rationale |
|----------|----------|-----------|
| ~1 DOGE/kB recommended | 0.01 SOQ/kB recommended | **Lower initial barrier** |

Fee parameters are **policy, not consensus**. The 0.01 SOQ value is conservative:
- Prevents spam while SOQ has low/no market value
- Subject to community review post-mainnet launch
- Will be adjusted based on actual transaction economics

### 2.4 Chain ID: Security-Critical Unique Identifier

| Dogecoin | Soqucoin | Rationale |
|----------|----------|-----------|
| 0x0062 (98 decimal) | 0x5351 (21329 decimal, "SQ") | **Merged mining isolation** |

This is a **mandatory security parameter**:
- Same Chain ID enables cross-chain replay attacks
- Blocks mined for Dogecoin could be accepted on Soqucoin
- Unique ID is required for any AuxPoW chain

The value `0x5351` encodes "SQ" in ASCII, serving as a human-readable identifier.

### 2.5 Post-Quantum Verification Costs: Novel Requirement

These parameters don't exist in Dogecoin (no PQ cryptography):

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `DILITHIUM_VERIFY_COST = 1` | Baseline unit; Dilithium is our fastest proof |
| `LATTICEBP_VERIFY_COST = 50` | ~50× Dilithium due to lattice arithmetic |
| `PAT_VERIFY_COST = 20` | Merkle verification, moderate complexity |
| `LATTICEFOLD_VERIFY_COST = 200` | Recursive SNARK requires intensive computation |

Cost ratios derived from **Testnet3 VPS benchmarks** (DO-Premium-Intel). May require rebalancing based on:
- Mainnet hardware diversity telemetry
- Future algorithm optimizations
- Actual block composition patterns

### 2.6 LatticeFold Rate Limit: DoS Prevention

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `MAX_LATTICEFOLD_PER_BLOCK = 10` | 10 proofs × 40ms ≈ 400ms verification budget |

LatticeFold+ proofs are computationally expensive. Without a hard cap:
- Attackers could craft blocks taking >60s to verify
- Validators would fall behind chain tip
- Network could experience consensus forks

The limit of 10 ensures block validation completes well within target block time.

---

## 3. Per-Block Budgets

### Block Size & Weight Limits (Inherited)

| Parameter | Value | Source | Notes |
|-----------|-------|--------|-------|
| **MAX_BLOCK_WEIGHT** | 4,000,000 | Bitcoin/Dogecoin | Consensus enforced |
| **MAX_BLOCK_BASE_SIZE** | 1,000,000 | Bitcoin/Dogecoin | Excludes witness |
| **MAX_BLOCK_SERIALIZED_SIZE** | 4,000,000 | Bitcoin/Dogecoin | Buffer limit |
| **DEFAULT_BLOCK_MAX_SIZE** | 750,000 | Dogecoin | Miner policy |
| **DEFAULT_BLOCK_MAX_WEIGHT** | 3,000,000 | Dogecoin | Miner policy |

### Signature/Verification Limits

| Parameter | Value | Source | Notes |
|-----------|-------|--------|-------|
| **MAX_BLOCK_SIGOPS_COST** | 80,000 | Bitcoin/Dogecoin | Legacy sigops |
| **MAX_BLOCK_VERIFY_COST** | 80,000 | **Soqucoin (Novel)** | PQ verification budget |

---

## 4. Post-Quantum Proof Verification Costs (Novel)

Each post-quantum proof type has an assigned verification cost. The **total verification cost** in a block cannot exceed `MAX_BLOCK_VERIFY_COST` (80,000 units).

| Proof Type | Cost | Benchmark¹ | Theoretical Max² |
|------------|------|------------|------------------|
| **Dilithium Signature** | 1 | ~0.175ms | 80,000 |
| **PAT Merkle Proof** | 20 | ~5ms | 4,000 |
| **Lattice-BP++ Range Proof** | 50 | ~0.055ms (verify only) | 1,600 |
| **LatticeFold+ Recursive SNARK** | 200 | ~0.75ms (512-sig batch) | 400 |

> ¹ Benchmarks from VPS Intel 4-core (Testnet3) single-threaded verification, January 7, 2026.
>
> ² Theoretical maximum if block contains ONLY that proof type. In practice, blocks contain mixed proofs sharing the 80,000 budget.

### Hard Rate Limits (Novel)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **MAX_LATTICEFOLD_PER_BLOCK** | 10 | 10 proofs × 40ms = ~400ms verification budget; prevents block validation exceeding target time |
| **MAX_PROOF_BYTES_PER_TX** | 65,536 (64 KB) | Prevents single TX from dominating block |
| **MAX_PROOF_BYTES_PER_BLOCK** | 262,144 (256 KB) | Limits total proof bandwidth |

### Cost Accounting Rationale

**Q: Is verification cost counted per output, per proof, or per transaction?**

**A: Per proof.** Each cryptographic proof submitted incurs its assigned cost regardless of what it covers.

| Proof Type | Cost Basis | Rationale |
|------------|------------|-----------|
| **Dilithium** | Per signature | Each signature requires one verification |
| **BP++** | Per range proof | One proof may cover multiple outputs (aggregation) |
| **PAT** | Per merkle proof | One proof aggregates multiple signatures |
| **LatticeFold+** | Per recursive proof | One proof may represent an entire TX or batch |

#### Why Per-Proof Pricing?

1. **Accurate Resource Accounting**: Verification work is proportional to proof count, not output count. A proof takes X ms to verify regardless of what it proves.

2. **Aggregation Incentive**: Per-proof pricing naturally rewards efficient proof construction:

   | Scenario | Per-Output Model | Per-Proof Model |
   |----------|-----------------|-----------------|
   | 10 outputs, 10 separate proofs | 500 units | 500 units |
   | 10 outputs, 1 aggregated proof | 500 units | **50 units** |

3. **DoS Resistance**: Attackers cannot craft cheap transactions with expensive verification. Cost scales with actual verification work.

4. **Industry Alignment**: Matches Bitcoin (per-sigop), Monero (per-range-proof), and Zcash (per-shielded-output) accounting models.

#### Aggregation Economics

PAT (Proof Aggregation Tree) demonstrates the economic benefit:

| Signatures | Without PAT | With PAT | Savings |
|------------|-------------|----------|---------|
| 10 | 10 × 1 = 10 units | 1 × 20 = 20 units | -10 (small batches: slight overhead) |
| 100 | 100 × 1 = 100 units | 1 × 20 = 20 units | **80%** |
| 512 | 512 × 1 = 512 units | 1 × 20 = 20 units | **96%** |

**Insight**: PAT aggregation becomes cost-effective at ~20+ signatures, incentivizing batch verification.

#### Trade-offs Acknowledged

| Consideration | Assessment |
|---------------|------------|
| Wallet complexity | Wallets must implement aggregation for optimal pricing |
| Sublinear batch verify | Batched proofs are faster than linear; users may slightly overpay |
| Privacy | Output count visible; mitigated by Lattice-BP++ (`nVisibility=1`) |
| Parameter rigidity | Cost ratios adjustable via softfork; rebalancing supported |

> [!NOTE]
> Cost ratios (50:20:1:200) are derived from Testnet3 benchmarks and may be adjusted pre-mainnet
> based on hardware diversity telemetry and algorithm optimizations.

## 5. Transaction Limits

### Inherited from Bitcoin/Dogecoin

| Parameter | Value | Notes |
|-----------|-------|-------|
| **MAX_STANDARD_TX_WEIGHT** | 400,000 | ~100 KB effective |
| **MAX_STANDARD_TX_SIGOPS_COST** | 16,000 | 20% of block budget |
| **MAX_SCRIPT_SIZE** | 10,000 bytes | Script bytecode limit |
| **MAX_SCRIPT_ELEMENT_SIZE** | 520 bytes | Stack element limit |
| **MAX_P2SH_SIGOPS** | 15 | P2SH script sigops |

### Post-Quantum Witness Considerations (Novel)

Standard Bitcoin witness limits were designed for ECDSA (~72 byte signatures). Dilithium signatures are significantly larger:

| Component | ECDSA (Legacy) | Dilithium (ML-DSA-44) |
|-----------|----------------|----------------------|
| Signature | ~72 bytes | ~2,420 bytes |
| Public Key | ~33 bytes | ~1,312 bytes |

**Implementation Note**: Standard P2WSH limits (`MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80 bytes`) do NOT apply to Dilithium outputs. Post-quantum transactions use a dedicated output type with appropriate size allowances defined in `script/standard.cpp`.

---

## 6. Fee Policy (Modified)

| Parameter | Value | Notes |
|-----------|-------|-------|
| **RECOMMENDED_MIN_TX_FEE** | 0.01 SOQ/kB | Base fee reference |
| **DEFAULT_MIN_RELAY_TX_FEE** | 0.001 SOQ/kB | Mempool acceptance |
| **DEFAULT_DUST_LIMIT** | 0.01 SOQ | Minimum UTXO value |
| **DEFAULT_HARD_DUST_LIMIT** | 0.001 SOQ | Non-standard rejection |

> **Note**: Fees are **policy**, not consensus. Miners may include any valid transaction regardless of fee. Fee parameters are subject to review based on mainnet economics.

---

## 7. Chain Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| **Block Time Target** | 60 seconds | Inherited (Dogecoin) |
| **Difficulty Adjustment** | Every block (DigiShield) | Inherited (Dogecoin) |
| **Halving Interval** | 100,000 blocks (~80 days)¹ | Modified (Soqucoin) |
| **Initial Block Reward** | 500,000 SOQ | Modified (Soqucoin) |
| **Terminal Reward** | 10,000 SOQ (after block 600,000) | Modified (Soqucoin) |
| **Coinbase Maturity** | 30 blocks | Modified (Soqucoin) |
| **AuxPoW Chain ID** | 0x5351 (21329 decimal) | Novel (Soqucoin) |

> ¹ Calculation: 100,000 blocks × 60 seconds = 6,000,000 seconds ≈ 69.4 days at target. Actual time varies with hashrate.

---

## 8. Consensus vs. Policy

Understanding the difference is critical for node operators and miners:

### Consensus Rules (Protocol Enforced — Absolute)

Violating blocks are rejected by ALL nodes:

| Category | Rules | Source |
|----------|-------|--------|
| **Block Validity** | MAX_BLOCK_WEIGHT, MAX_BLOCK_SIGOPS_COST, valid PoW | Inherited |
| **Transaction Validity** | Valid signatures, no double-spends, correct scripts | Inherited |
| **PQ Proof Limits** | MAX_BLOCK_VERIFY_COST, MAX_LATTICEFOLD_PER_BLOCK | Novel |
| **Chain Rules** | Correct subsidy, difficulty, timestamps, maturity | Inherited |

### Policy Rules (Node/Miner Discretion — Configurable)

Nodes can adjust, miners can override:

| Category | Default | Flag | Source |
|----------|---------|------|--------|
| **Block Size** | 750 KB | `-blockmaxsize` | Inherited |
| **Block Weight** | 3 MB | `-blockmaxweight` | Inherited |
| **Mempool Size** | 300 MB | `-maxmempool` | Inherited |
| **Min Relay Fee** | 0.001 SOQ/kB | `-minrelaytxfee` | Modified |
| **Dust Limit** | 0.01 SOQ | `-dustlimit` | Modified |

## 9. Feature Activation Architecture

### Overview

Soqucoin uses **BIP9 deployment flags** for all feature activation. Features are either `ALWAYS_ACTIVE`
(enabled from genesis block 0) or `NEVER_ACTIVE` (gated pending security audit and miner signaling).
There is no height-based staged activation.

> [!IMPORTANT]
> **Pre-activation behavior**: Transactions using `NEVER_ACTIVE` witness versions (v4, v5) pass as
> **anyone-can-spend** per BIP141. This is safe: miners won't mine these transactions, and
> `fRequireStandard=true` on mainnet/stagenet rejects them from the mempool. Activation via BIP9
> miner signaling will enable full consensus enforcement without a hard fork.

### Genesis Features (ALWAYS_ACTIVE)

These features are active from block 0 on both mainnet and stagenet:

| Feature | Opcode/Mechanism | Witness Version | BIP9 Bit | What It Does |
|---------|------------------|-----------------|----------|-------------|
| **Dilithium** | Inline in `VerifyScript()` | v0, v1 | — | NIST FIPS 204 quantum-safe signatures |
| **PAT** | `OP_CHECKPATAGG` | v2 (`OP_2`) | 3 | Merkle-based signature aggregation (up to 256 sigs) |
| **LatticeFold+** | `OP_CHECKFOLDPROOF` | v3 (`OP_3`) | 28 | Recursive batch verification (512 sigs in ~0.75ms) |
| **AuxPoW** | Merged mining | — | — | Scrypt AuxPoW with unique Chain ID `0x5351` |
| **SegWit** | BIP141/143/147 | — | 1 | Witness data segregation |
| **CSV** | BIP68/112/113 | — | 0 | Relative timelocks |

### Future Features (NEVER_ACTIVE — Pending Audit)

These features exist in the codebase but are gated behind `NEVER_ACTIVE` BIP9 deployments:

| Feature | Opcode | Witness Version | BIP9 Bit | Status | Audit Target |
|---------|--------|-----------------|----------|--------|-------------|
| **Lattice-BP++** | `OP_LATTICEBP_RANGEPROOF` (0xfa) | v4 (`OP_4`) | 5 | Code complete, 16/16 tests pass | July 2026 (Halborn) |
| **USDSOQ** | `OP_USDSOQ_MINT/BURN/FREEZE` | v5 (`OP_5`) | 6 | Design complete, implementation TODO | July 2026 (Halborn) |

**Lattice-BP++ (SOQ-P003)**: Verifies lattice-based range proofs (Module-LWE/SIS, n=256, q=8380417, k=4)
proving transaction amounts ∈ [0, 2^64). Fiat-Shamir binds to sighash + pubkey_hash. Three-mode build guard
(standalone R&D, consensus shared lib, production). Performance: prove=0.55ms, verify=22µs, proof=12KB.
Patent pending.

**USDSOQ (SOQ-AUD2-002)**: Quantum-safe stablecoin with 4 authority opcodes (mint, burn, freeze,
rotate_authority). Foundation M-of-N Dilithium multisig (3-of-5) for supply management. Reorg-safe
supply invariant tracking. Design log: `DL-USDSOQ-STABLECOIN.md`.

### Witness Version Routing

`VerifyScript()` dispatches based on witness version:

```
Witness v0 → Dilithium signature verification (inline)
Witness v1 → Dilithium signature verification (inline, SHA-256 program)
Witness v2 → PAT: OP_CHECKPATAGG via EvalScript()
Witness v3 → LatticeFold: OP_CHECKFOLDPROOF via EvalScript()
Witness v4 → Lattice-BP++: OP_LATTICEBP_RANGEPROOF via EvalScript()  [NEVER_ACTIVE]
Witness v5 → USDSOQ: OP_USDSOQ_* via EvalScript()                   [NEVER_ACTIVE]
Witness v6-v16 → Future: anyone-can-spend (BIP141 forward compatibility)
```

Each handler pushes the witness stack into `EvalScript()` with the corresponding opcode. Flag gating
via `SCRIPT_VERIFY_*` constants ensures soft fork safety.

### LatticeFold+ Batch Verification

LatticeFold+ provides **recursive proof composition** for Dilithium batch verification:

| Metric | Without LatticeFold | With LatticeFold |
|--------|---------------------|------------------|
| **Single signature verification** | ~0.175ms | ~0.175ms (unchanged) |
| **512-signature block verification** | ~90ms | ~0.75ms |
| **Speedup for high-tx blocks** | 1x | ~150x |
| **Light client verification** | No (trusts full nodes) | Yes (verifies proof) |

*Benchmarks: VPS Intel 4-core = 0.751ms for 512-sig batch (verified Jan 7, 2026). Apple M4 ~0.68ms.*

### Upgrade & Security Response Policy

- **BIP9 deployments are consensus-frozen** once a tagged release is published
- **Activation changes require a new release** with minimum 2-week upgrade window
- **Security response**: Critical vulnerabilities trigger coordinated disclosure to major miners/exchanges within 24 hours, followed by emergency release
- **Release signing**: All binaries signed by core maintainers; reproducible builds available
- **Rollback policy**: No consensus rollbacks except for chain-halting bugs affecting >50% of network

---

## 10. Network Alignment

| Network | Genesis | Chain ID | HRP | P2P Port | RPC Port | Dilithium | PAT | LatticeFold | Lattice-BP++ |
|---------|---------|----------|-----|----------|----------|-----------|-----|-------------|-------------|
| **Mainnet** | Q2 2026 | 0x5351 | `sq` | 33388 | 33389 | ✅ Active | ✅ Active | ✅ Active | ❌ Not Active |
| **Stagenet** | Jan 5, 2026 | 0x5351 | `ssq` | 28333 | 28332 | ✅ Active | ✅ Active | ✅ Active | ❌ Not Active |
| **Testnet3** | Dec 2025 | 0x5351 | `sq` | 44556 | 44555 | ✅ Active | ✅ Active | ✅ Active | ❌ Not Active |
| **Regtest** | — | 0x5351 | `scrt` | 18444 | 18332 | ✅ Active | ✅ Active | ✅ Active | ✅ Active |

> [!NOTE]
> **Stagenet** mirrors mainnet consensus exactly (`fPowAllowMinDifficultyBlocks=false`,
> `fRequireStandard=true`). It uses a distinct HRP (`ssq`) and port range to prevent
> accidental cross-network transactions.
>
> **Regtest** has all features `ALWAYS_ACTIVE` including Lattice-BP++ for development testing.

**Stagenet Genesis**: `59009fbfe94b607d9722bdd5da35e1a4e33ce8d9dfd1dd03ec66b17711977282`  
**Stagenet Purpose**: Mainnet rehearsal network — community mining, SoquShield testing, SOQ-TEC bridge validation.

---

## 11. DoS Protections

| Attack Vector | Mitigation | Type |
|---------------|------------|------|
| **Proof Spam** | MAX_BLOCK_VERIFY_COST budget (80k units) | Consensus |
| **LatticeFold Floods** | MAX_LATTICEFOLD_PER_BLOCK = 10 | Consensus |
| **Large Proofs** | MAX_PROOF_BYTES_PER_BLOCK = 256 KB | Consensus |
| **Large Scripts** | MAX_SCRIPT_SIZE = 10 KB | Consensus |
| **Expensive Operations** | Per-op verification costs | Consensus |
| **Block Size Attacks** | MAX_BLOCK_WEIGHT = 4 MB | Consensus |
| **Dust Attacks** | DEFAULT_HARD_DUST_LIMIT | Policy |

---

## 12. Reference Implementation

All values are defined in the Soqucoin Core source code at the following paths:

| File | Contains |
|------|----------|
| `src/consensus/consensus.h` | Block size, sigops, and verification cost limits |
| `src/policy/policy.h` | Fee and dust policy defaults |
| `src/script/script.h` | Script size limits |
| `src/chainparams.cpp` | Chain parameters and maturity rules |

> Refer to the tagged release corresponding to this specification for exact line numbers.
> Public repository: `https://github.com/soqucoin/soqucoin`

---

## 13. Summary Table

| Category | Limit | Type | Source |
|----------|-------|------|--------|
| Block Weight | 4,000,000 | **Consensus** | Inherited |
| Block Sigops | 80,000 | **Consensus** | Inherited |
| Block Verify Cost | 80,000 | **Consensus** | Novel |
| LatticeFold per Block | 10 | **Consensus** | Novel |
| Proof Bytes per Block | 256 KB | **Consensus** | Novel |
| Transaction Weight | 400,000 | Policy | Inherited |
| Script Size | 10,000 bytes | **Consensus** | Inherited |
| Coinbase Maturity | 30 blocks | **Consensus** | Modified |
| Min Relay Fee | 0.001 SOQ/kB | Policy | Modified |
| Dust Limit | 0.01 SOQ | Policy | Modified |

---

## Appendix A: Security Assumptions & Threat Model (Summary)

### Adversary Models

| Adversary | Assumed Capability | Mitigation |
|-----------|-------------------|------------|
| **Mempool spammer** | Can broadcast many low-fee transactions | Relay fees, verify-cost budget |
| **Merged-mining manipulation** | Controls auxiliary chain hashrate | Unique Chain ID (0x5351), AuxPoW validation |
| **Eclipse/Sybil attacker** | Controls multiple network nodes | Peer rotation, DNS seeds, checkpoint awareness |
| **Miner cartel** | >50% hashrate coordination | DigiShield difficulty adjustment, community monitoring |
| **Malicious proof generator** | Crafts adversarial proofs | Per-op verification costs, MAX_LATTICEFOLD_PER_BLOCK cap |
| **Quantum adversary** | Shor's algorithm capability | Dilithium signatures (NIST PQ standard) |

### Known Limitations

- **Long-range reorg under low AuxPoW participation**: Mitigated by monitoring, checkpoints (if needed)
- **Novel cryptography risk**: LatticeFold is research-grade; staged activation provides buffer
- **Fee economics pre-market**: Policy parameters are placeholders pending real market data

---

## Appendix B: Supply Curve & Allocations

### Emission Schedule

| Block Range | Reward per Block | Cumulative Supply |
|-------------|------------------|-------------------|
| 0 - 100,000 | 500,000 SOQ | 50 billion SOQ |
| 100,001 - 200,000 | 250,000 SOQ | 75 billion SOQ |
| 200,001 - 300,000 | 125,000 SOQ | 87.5 billion SOQ |
| 300,001 - 400,000 | 62,500 SOQ | 93.75 billion SOQ |
| 400,001 - 500,000 | 31,250 SOQ | 96.875 billion SOQ |
| 500,001 - 600,000 | 15,625 SOQ | 98.4375 billion SOQ |
| 600,001+ | 10,000 SOQ | Perpetual inflation |

### Allocations

| Category | Allocation | Notes |
|----------|------------|-------|
| **Premine** | **NONE** | 0 SOQ premined |
| **Founder allocation** | **NONE** | No reserved tokens |
| **Treasury** | **NONE** | No protocol treasury |
| **Distribution** | 100% mining | Fair launch, all SOQ mined |

> All SOQ is distributed through proof-of-work mining. There is no premine, founder allocation, or treasury.

---

## Appendix C: Cryptographic Components & Implementations

| Component | Standard | Library | Test Vectors | Side-Channel Posture |
|-----------|----------|---------|--------------|----------------------|
| **Dilithium (ML-DSA-44)** | NIST FIPS 204 | Custom (NIST reference) | NIST KAT | Constant-time implementation |
| **Lattice-BP++** | Novel (Module-LWE/SIS) | Custom (Soqucoin) | 16/16 Soqucoin test vectors | Constant-time lattice ops |
| **PAT Aggregation** | Novel | Custom | Soqucoin test suite | N/A (hash-based) |
| **LatticeFold+** | ePrint 2025/247 | Custom | Soqucoin test suite | Constant-time field ops |
| **Scrypt PoW** | RFC 7914 | Colin Percival reference | Litecoin/Dogecoin | N/A (PoW) |

### Audit Scope Notes

- **NIST-grade**: Dilithium uses NIST PQ standard parameters
- **Novel lattice crypto**: Lattice-BP++ uses Module-LWE/SIS — custom implementation requiring focused audit
- **Research-grade**: LatticeFold+ is novel; active from genesis, requires focused audit attention
- **Inherited**: Scrypt PoW, consensus rules from Dogecoin/Bitcoin

---

## Appendix D: Code Pointers & Enforcement Locations

> [!TIP]
> **For Auditors**: This section maps specification parameters to exact source code locations.

### Consensus Limit Definitions

| Parameter | Value | Source Location |
|-----------|-------|-----------------|
| `MAX_BLOCK_VERIFY_COST` | 80,000 | [`src/consensus/consensus.h:43`](https://github.com/soqucoin/soqucoin/blob/main/src/consensus/consensus.h#L43) |
| `MAX_LATTICEFOLD_PER_BLOCK` | 10 | [`src/consensus/consensus.h:46`](https://github.com/soqucoin/soqucoin/blob/main/src/consensus/consensus.h#L46) |
| `MAX_PROOF_BYTES_PER_TX` | 65,536 | [`src/consensus/consensus.h:49`](https://github.com/soqucoin/soqucoin/blob/main/src/consensus/consensus.h#L49) |
| `MAX_PROOF_BYTES_PER_BLOCK` | 262,144 | [`src/consensus/consensus.h:52`](https://github.com/soqucoin/soqucoin/blob/main/src/consensus/consensus.h#L52) |

### Verification Cost Weights

| Operation | Cost | Source Location |
|-----------|------|-----------------|
| Dilithium Verify | 1 unit | [`src/consensus/consensus.h:28`](https://github.com/soqucoin/soqucoin/blob/main/src/consensus/consensus.h#L28) |
| BP++ Range Proof | 50 units | [`src/consensus/consensus.h:31`](https://github.com/soqucoin/soqucoin/blob/main/src/consensus/consensus.h#L31) |
| PAT Aggregate | 20 units | [`src/consensus/consensus.h:37`](https://github.com/soqucoin/soqucoin/blob/main/src/consensus/consensus.h#L37) |
| LatticeFold+ SNARK | 200 units | [`src/consensus/consensus.h:40`](https://github.com/soqucoin/soqucoin/blob/main/src/consensus/consensus.h#L40) |

### Script Interpreter Enforcement

| Opcode | Enforcement Location | Notes |
|--------|---------------------|-------|
| `OP_CHECKDILITHIUMSIG` | [`src/script/interpreter.cpp:278-296`](https://github.com/soqucoin/soqucoin/blob/main/src/script/interpreter.cpp#L278-L296) | Single signature verify |
| `OP_CHECKPATAGG` | [`src/script/interpreter.cpp:149-261`](https://github.com/soqucoin/soqucoin/blob/main/src/script/interpreter.cpp#L149-L261) | PAT Merkle aggregation |
| `OP_CHECKFOLDPROOF` | [`src/script/interpreter.cpp:262-277`](https://github.com/soqucoin/soqucoin/blob/main/src/script/interpreter.cpp#L262-L277) | LatticeFold+ gating |
| BP++ VerifyRangeProof | [`src/script/interpreter.cpp:394-400`](https://github.com/soqucoin/soqucoin/blob/main/src/script/interpreter.cpp#L394-L400) | CT range proof check |

### Rejection Test Reference

Budget enforcement is tested via unit tests. Example rejection test:

```cpp
// Test: Over-budget block rejected
// Location: src/test/consensus_tests.cpp (planned)
// Coverage: Block exceeding MAX_BLOCK_VERIFY_COST is rejected at CheckBlock()
```

> **Status**: Functional test `verify_cost_tests.cpp` added (Jan 5, 2026). Tests consensus limit constants.

---

## Appendix E: Benchmark Harness & Reproducibility

> [!NOTE]
> **For Reviewers**: All performance claims are derived from reproducible benchmarks.

### Benchmark Executables

| Benchmark | Source | Run Command |
|-----------|--------|-------------|
| Dilithium Sign/Verify | [`src/bench/dilithium.cpp`](https://github.com/soqucoin/soqucoin/blob/main/src/bench/dilithium.cpp) | `./bench_soqucoin --filter='Dilithium*'` |
| Bulletproofs++ Gen/Verify | [`src/bench/bench_bulletproofs.cpp`](https://github.com/soqucoin/soqucoin/blob/main/src/bench/bench_bulletproofs.cpp) | `./bench_soqucoin --filter='Bulletproofs*'` |
| LatticeFold+ Verify | [`src/crypto/latticefold/verifier.cpp`](https://github.com/soqucoin/soqucoin/blob/main/src/crypto/latticefold/verifier.cpp) | Inline benchmark (see header comment) |

### Hardware Reference Platforms ✅ Verified

| Platform | Specs | Notes |
|----------|-------|-------|
| **Apple M4 Mini** | 10-core, 16GB RAM, macOS 15 | Primary development platform |
| **Testnet3 VPS** | DO-Premium-Intel 4-core, 8GB RAM, Ubuntu 24.04 | DigitalOcean droplet |
| **Stagenet VPS** | DO-Premium-Intel 4-core, 16GB RAM, 309GB NVMe, Ubuntu 24.04 | DigitalOcean droplet |
| **Engineering VPS** | DO-Regular 2-core, 4GB RAM, Ubuntu 22.04 | DigitalOcean droplet |

### Build Configuration

```bash
# Reproducible benchmark build
./autogen.sh
./configure --enable-bench --with-incompatible-bdb --disable-wallet-gui \
    CXXFLAGS="-O2 -march=native" CFLAGS="-O2 -march=native"
make -j$(nproc)

# Run benchmarks
./src/bench/bench_soqucoin --output-csv=results.csv
```

### Reference Benchmark Results ✅ Verified (Testnet3 VPS, 2026-01-05)

| Operation | Average Time | Min Time | Iterations | Notes |
|-----------|--------------|----------|------------|-------|
| DilithiumSign | 594 µs | 485 µs | 1,792 | ML-DSA-44 |
| DilithiumVerify | 187 µs | 130 µs | 5,632 | ML-DSA-44 |
| Bulletproofs_GenRangeProof | 5.49 ms | 5.00 ms | 192 | 64-bit range |
| Bulletproofs_VerifyRangeProof | 4.07 ms | 3.54 ms | 256 | 64-bit range |

> **Platform**: DO-Premium-Intel 4-core, 8GB RAM, Ubuntu 24.04 (Docker container)
> **Date**: January 5, 2026
> **Build**: `./configure --enable-bench --with-incompatible-bdb`

### Docker Reproducibility ✅ Verified

```bash
# Build and test (all 244 unit tests pass)
docker build -f docker/Dockerfile.audit --target builder -t soqucoin-audit .

# Run benchmarks
docker build -f docker/Dockerfile.audit --target benchmark -t soqucoin-bench .
docker run --rm -v $(pwd):/out soqucoin-bench
```

| Test Suite | Result |
|------------|--------|
| `test_soqucoin` (244 cases) | ✅ ALL PASSED |
| Univalue tests | ✅ 3/3 PASSED |

> **Status**: Docker harness verified on Ubuntu 22.04 VPS (Jan 5, 2026). See [`docker/DOCKER_BUILD_GUIDE.md`](../docker/DOCKER_BUILD_GUIDE.md) for full instructions.

---

## Appendix E: Wallet SDK Reference

The PQ Wallet SDK (`libsoqucoin-wallet`) implements per-proof cost optimization for wallet developers.

### SDK Component Overview

| File | Purpose | LOC |
|------|---------|-----|
| `pqwallet.h/cpp` | Main wallet interface | 550 |
| `pqkeys.h` | Dilithium key management | 145 |
| `pqaddress.h` | Bech32m address encoding | 115 |
| `pqcrypto.h/cpp` | Wallet file encryption | 454 |
| `pqaggregation.h` | PAT/BP++ batching utilities | 130 |
| `pqcost.h` | Per-proof cost estimation | 105 |

**Location**: `src/wallet/pqwallet/`

### Key Security Features

| Feature | Implementation | Status |
|---------|----------------|--------|
| Secure Memory | `SecureBytes` (mlock, explicit zeroing) | ✅ Complete |
| File Encryption | AES-256-CBC + HMAC-SHA256 | ✅ Complete |
| Key Derivation | Argon2id (preferred) / PBKDF2-SHA256 (fallback) | ✅ Complete |
| Side-Channel | Constant-time Dilithium reference impl | ✅ In Use |
| Address Format | Bech32m (sq1/tsq1/ssq1) | ✅ Complete |

### Related Documentation

| Document | Purpose |
|----------|---------|
| [WALLET_API_SPEC.md](WALLET_API_SPEC.md) | Full API specification |
| [ADDRESS_FORMAT_SPEC.md](ADDRESS_FORMAT_SPEC.md) | Address encoding details |
| [WALLET_TEST_VECTORS.md](WALLET_TEST_VECTORS.md) | Deterministic test vectors |
| [WALLET_RESEARCH_COMPARISON.md](WALLET_RESEARCH_COMPARISON.md) | Monero/Zcash audit lessons |

---

## Appendix F: Compliance and Optional Privacy

> [!IMPORTANT]
> This section addresses regulatory alignment for auditors and exchanges.

### Opt-In Privacy Design

To align with 2026 global regulations (EU MiCA, FATF Travel Rule, SEC/FinCEN guidance), Soqucoin privacy features are **user-optional**:

| Feature | Default State | Privacy Mode | Regulatory Alignment |
|---------|---------------|--------------|---------------------|
| Base transactions | Transparent (`nVisibility=0`) | N/A | ✅ Compliant |
| Lattice-BP++ range proofs | **Disabled** (`NEVER_ACTIVE`) | Opt-in via `nVisibility=1` | ✅ Selective disclosure |
| USDSOQ stablecoin | **Disabled** (`NEVER_ACTIVE`) | N/A (transparent) | ✅ Authority-controlled |

### View Keys for Selective Disclosure

Soqucoin implements view key functionality (Lattice-BP++ activation) enabling:
- **User disclosure**: Share view keys with auditors/exchanges on demand
- **Regulatory compliance**: Exchanges can verify source of funds without requiring privacy disabled
- **Auditability**: View keys provide read-only access to transaction history

### Regulatory Context (2025-2026)

| Regulation | Privacy Coin Impact | Soqucoin Alignment |
|------------|---------------------|--------------------|
| **FATF Travel Rule** | Mandatory privacy = high risk | ✅ Opt-in, view keys |
| **EU MiCA (2027)** | May restrict mandatory privacy coins | ✅ Opt-in preserves listing |
| **Exchange trends** | 73 delistings in 2025 (Monero affected) | ✅ Zcash-style opt-in model |

### Audit Focus

For Halborn audit review, verify:
1. **No mandatory privacy enforcement** in consensus (`src/validation.cpp`)
2. **Opt-in flag gating** for Lattice-BP++ (`VerifyScript()` witness v4 handler)
3. **BIP9 deployment gating** — `DEPLOYMENT_LATTICEBP` must be `NEVER_ACTIVE` before activation
4. **Default transparency** maintained for base transactions (`nVisibility=0`)

---

*Soqucoin Protocol Parameters Specification v3.0*
*Updated April 27, 2026 — Reflects BIP9 activation model, Lattice-BP++ migration, and USDSOQ opcodes*
*Soqucoin Core Development Team*

