# Soqucoin Consensus Cost Specification

> **Version**: 1.0 | **Status**: Public Reference
> **Last Updated**: January 2026
> **Network**: Mainnet (Q1 2026)

---

## Overview

This document details the consensus-enforced limits and costs for the Soqucoin network. These parameters are **consensus-critical** — violations result in block/transaction rejection at the protocol level.

Soqucoin inherits Bitcoin/Dogecoin's core architecture while adding post-quantum cryptographic primitives with their own verification costs.

---

## 1. Per-Block Budgets

### Block Size & Weight Limits

| Parameter | Value | Notes |
|-----------|-------|-------|
| **MAX_BLOCK_WEIGHT** | 4,000,000 | Weight units per block (consensus) |
| **MAX_BLOCK_BASE_SIZE** | 1,000,000 | Max bytes excluding witness data |
| **MAX_BLOCK_SERIALIZED_SIZE** | 4,000,000 | Buffer size limit |
| **DEFAULT_BLOCK_MAX_SIZE** | 750,000 | Miner policy default |
| **DEFAULT_BLOCK_MAX_WEIGHT** | 3,000,000 | Miner policy default |

### Signature/Verification Limits

| Parameter | Value | Notes |
|-----------|-------|-------|
| **MAX_BLOCK_SIGOPS_COST** | 80,000 | Legacy sigop budget |
| **MAX_BLOCK_VERIFY_COST** | 80,000 | Post-quantum verification budget |

---

## 2. Proof Verification Costs

Each post-quantum proof type has an assigned verification cost. The sum of all verification costs in a block cannot exceed `MAX_BLOCK_VERIFY_COST` (80,000 units).

| Proof Type | Cost (Units) | Approx. Time | Max Per Block |
|------------|--------------|--------------|---------------|
| **Dilithium Signature** | 1 | ~0.2ms | 80,000 |
| **PAT Merkle Proof** | 20 | ~4ms | 4,000 |
| **Bulletproofs++ Range Proof** | 50 | ~10ms | 1,600 |
| **LatticeFold+ Recursive SNARK** | 200 | ~40ms | *10 (hard cap)* |

### Additional Proof Limits

| Parameter | Value | Notes |
|-----------|-------|-------|
| **MAX_LATTICEFOLD_PER_BLOCK** | 10 | Hard cap per block (v1 rate limit) |
| **MAX_PROOF_BYTES_PER_TX** | 65,536 (64 KB) | Per-transaction proof data |
| **MAX_PROOF_BYTES_PER_BLOCK** | 262,144 (256 KB) | Total block proof data |

---

## 3. Transaction Limits

| Parameter | Value | Notes |
|-----------|-------|-------|
| **MAX_STANDARD_TX_WEIGHT** | 400,000 | ~100 KB effective |
| **MAX_STANDARD_TX_SIGOPS_COST** | 16,000 | 20% of block budget |
| **MAX_SCRIPT_SIZE** | 10,000 bytes | Script bytecode limit |
| **MAX_SCRIPT_ELEMENT_SIZE** | 520 bytes | Stack element limit |
| **MAX_P2SH_SIGOPS** | 15 | P2SH script sigops |

---

## 4. Fee Policy

| Parameter | Value | Notes |
|-----------|-------|-------|
| **RECOMMENDED_MIN_TX_FEE** | 0.01 SOQ/kB | Base fee reference |
| **DEFAULT_MIN_RELAY_TX_FEE** | 0.001 SOQ/kB | Mempool acceptance |
| **DEFAULT_DUST_LIMIT** | 0.01 SOQ | Minimum UTXO value |
| **DEFAULT_HARD_DUST_LIMIT** | 0.001 SOQ | Non-standard rejection |

> **Note**: Fees are **policy**, not consensus. Miners may include any valid transaction regardless of fee.

---

## 5. Chain Parameters

| Parameter | Value |
|-----------|-------|
| **Block Time Target** | 60 seconds |
| **Difficulty Adjustment** | Every block (DigiShield) |
| **Halving Interval** | 100,000 blocks (~69 days) |
| **Initial Block Reward** | 500,000 SOQ |
| **Terminal Reward** | 10,000 SOQ (after block 600,000) |
| **Coinbase Maturity** | 100 blocks |
| **AuxPoW Chain ID** | 0x5351 (21329 decimal) |

---

## 6. Consensus vs. Policy

Understanding the difference is critical for node operators and miners:

### Consensus Rules (Enforced at Protocol Level)

These are **absolute** — violating blocks are rejected by all nodes:

| Category | Rules |
|----------|-------|
| **Block Validity** | MAX_BLOCK_WEIGHT, MAX_BLOCK_SIGOPS_COST, valid PoW |
| **Transaction Validity** | Valid signatures, no double-spends, correct script execution |
| **Proof Limits** | MAX_BLOCK_VERIFY_COST, MAX_LATTICEFOLD_PER_BLOCK |
| **Chain Rules** | Correct subsidy, proper difficulty, valid timestamps |

### Policy Rules (Node/Miner Discretion)

These are **defaults** — nodes can adjust, miners can override:

| Category | Default | Configurable |
|----------|---------|--------------|
| **Block Size** | 750 KB | `-blockmaxsize` |
| **Block Weight** | 3 MB | `-blockmaxweight` |
| **Mempool Size** | 300 MB | `-maxmempool` |
| **Min Relay Fee** | 0.001 SOQ/kB | `-minrelaytxfee` |
| **Dust Limit** | 0.01 SOQ | `-dustlimit` |

### What This Means in Practice

1. **For Miners**: You can create blocks up to 4 MB weight (consensus), but the default is 3 MB (policy). Adjust with `-blockmaxweight`.

2. **For Node Operators**: Your node won't relay transactions below the dust limit by default, but miners could still include them in blocks.

3. **For Applications**: Build against **consensus limits** for guarantee, but respect **policy defaults** for relay reliability.

---

## 7. Activation & Upgrade Path

### Currently Active (Genesis)

- Dilithium signature verification (OP_CHECKDILITHIUMSIG)
- Bulletproofs++ range proofs
- PAT Merkle aggregation
- LatticeFold+ recursive SNARKs
- AuxPoW merged mining (Chain ID 0x5351)
- DigiShield difficulty adjustment

### Future Considerations

- Dynamic fee adjustment for proof types
- Verification cost rebalancing based on hardware benchmarks
- Potential soft forks for additional proof types

---

## 8. DoS Protections

| Attack Vector | Mitigation |
|---------------|------------|
| **Proof Spam** | MAX_BLOCK_VERIFY_COST budget |
| **Large Scripts** | MAX_SCRIPT_SIZE (10 KB) |
| **Expensive Operations** | Per-op sigops/verify costs |
| **Block Size Attacks** | MAX_BLOCK_WEIGHT (4 MB) |
| **LatticeFold Floods** | MAX_LATTICEFOLD_PER_BLOCK=10 |
| **Dust Attacks** | DEFAULT_HARD_DUST_LIMIT (policy) |

---

## 9. Reference Implementation

All values are defined in the Soqucoin Core source code:

| File | Contains |
|------|----------|
| `src/consensus/consensus.h` | Block/verify cost limits |
| `src/policy/policy.h` | Fee and dust defaults |
| `src/script/script.h` | Script size limits |
| `src/chainparams.cpp` | Chain parameters |

---

## 10. Summary Table

| Category | Limit | Type |
|----------|-------|------|
| Block Weight | 4,000,000 | **Consensus** |
| Block Sigops | 80,000 | **Consensus** |
| Block Verify Cost | 80,000 | **Consensus** |
| LatticeFold per Block | 10 | **Consensus** |
| Transaction Weight | 400,000 | Policy |
| Script Size | 10,000 bytes | **Consensus** |
| Min Relay Fee | 0.001 SOQ/kB | Policy |
| Dust Limit | 0.01 SOQ | Policy |

---

*Document prepared for community reference*
*Soqucoin Core Development Team — January 2026*
