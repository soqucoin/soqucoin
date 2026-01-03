# Soqucoin Consensus Cost Specification

> **Version**: 1.2 | **Status**: Public Reference
> **Last Updated**: January 2026
> **Network**: Mainnet (Q1 2026)

---

## Overview

This document details the consensus-enforced limits and costs for the Soqucoin network. These parameters are **consensus-critical** — violations result in block/transaction rejection at the protocol level.

Soqucoin inherits Bitcoin/Dogecoin's core architecture while adding post-quantum cryptographic primitives with their own verification costs.

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
| `BPPP_VERIFY_COST = 50` | ~50× Dilithium due to elliptic curve operations |
| `PAT_VERIFY_COST = 20` | Merkle verification, moderate complexity |
| `LATTICEFOLD_VERIFY_COST = 200` | Recursive SNARK requires intensive computation |

Cost ratios derived from **Apple M4 Max benchmarks**. May require rebalancing based on:
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
| **Dilithium Signature** | 1 | ~0.2ms | 80,000 |
| **PAT Merkle Proof** | 20 | ~4ms | 4,000 |
| **Bulletproofs++ Range Proof** | 50 | ~10ms | 1,600 |
| **LatticeFold+ Recursive SNARK** | 200 | ~40ms | 400 |

> ¹ Benchmarks from M4 Max (Apple Silicon) single-threaded verification. Reference hardware for timing estimates. Actual verification times vary by CPU.
>
> ² Theoretical maximum if block contains ONLY that proof type. In practice, blocks contain mixed proofs sharing the 80,000 budget.

### Hard Rate Limits (Novel)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **MAX_LATTICEFOLD_PER_BLOCK** | 10 | 10 proofs × 40ms = ~400ms verification budget; prevents block validation exceeding target time |
| **MAX_PROOF_BYTES_PER_TX** | 65,536 (64 KB) | Prevents single TX from dominating block |
| **MAX_PROOF_BYTES_PER_BLOCK** | 262,144 (256 KB) | Limits total proof bandwidth |

---

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
| **Coinbase Maturity** | 240 blocks (post-DigiShield)² | Inherited (Dogecoin) |
| **AuxPoW Chain ID** | 0x5351 (21329 decimal) | Novel (Soqucoin) |

> ¹ Calculation: 100,000 blocks × 60 seconds = 6,000,000 seconds ≈ 69.4 days at target. Actual time varies with hashrate.
>
> ² Pre-DigiShield maturity was 30 blocks. Post-DigiShield (current) requires 240 block confirmations before coinbase outputs are spendable. This is inherited from Dogecoin's consensus parameters.

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

---

## 9. Activation Status

### Currently Active (Genesis)

All features active from block 0 on Testnet3 and Mainnet:

| Feature | Status | Height |
|---------|--------|--------|
| Dilithium signatures (OP_CHECKDILITHIUMSIG) | ✅ Active | Genesis |
| Bulletproofs++ range proofs | ✅ Active | Genesis |
| PAT Merkle aggregation | ✅ Active | Genesis |
| LatticeFold+ recursive SNARKs | ✅ Active | Genesis |
| AuxPoW merged mining (Chain ID 0x5351) | ✅ Active | Genesis |
| DigiShield difficulty adjustment | ✅ Active | Genesis |

### Network Alignment

| Network | Genesis | Chain ID | Status |
|---------|---------|----------|--------|
| Mainnet | Q1 2026 | 0x5351 | Pending |
| Testnet3 | Dec 2025 | 0x5351 | Active |

---

## 10. DoS Protections

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

## 11. Reference Implementation

All values are defined in the Soqucoin Core source code:

| File | Contains |
|------|----------|
| `src/consensus/consensus.h` | Block/verify cost limits (lines 13-52) |
| `src/policy/policy.h` | Fee and dust defaults (lines 23-81) |
| `src/script/script.h` | Script size limits (lines 22-31) |
| `src/chainparams.cpp` | Chain parameters, maturity (lines 94-163) |

---

## 12. Summary Table

| Category | Limit | Type | Source |
|----------|-------|------|--------|
| Block Weight | 4,000,000 | **Consensus** | Inherited |
| Block Sigops | 80,000 | **Consensus** | Inherited |
| Block Verify Cost | 80,000 | **Consensus** | Novel |
| LatticeFold per Block | 10 | **Consensus** | Novel |
| Proof Bytes per Block | 256 KB | **Consensus** | Novel |
| Transaction Weight | 400,000 | Policy | Inherited |
| Script Size | 10,000 bytes | **Consensus** | Inherited |
| Coinbase Maturity | 240 blocks | **Consensus** | Inherited |
| Min Relay Fee | 0.001 SOQ/kB | Policy | Modified |
| Dust Limit | 0.01 SOQ | Policy | Modified |

---

*Document prepared for community reference*
*Soqucoin Core Development Team — January 2026*
*Commit: 178212cae*
