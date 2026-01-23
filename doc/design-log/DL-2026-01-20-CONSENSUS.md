# Design Log: Consensus Architecture Verification

> **Log ID**: DL-2026-01-20-CONSENSUS
> **Author**: Casey (Founder)
> **Date**: January 20, 2026
> **Status**: APPROVED (Founder-confirmed design decisions)

---

## Background

During state machine diagram analysis, three consensus parameters were flagged for verification:
1. COINBASE_MATURITY value (found 240, expected 100)
2. Timestamp validation constants
3. PAT root validation architecture

This log documents the **intentional design decisions** behind these implementations.

---

## Problem Statement

External reviewers unfamiliar with Soqucoin's design may question:
- Why maturity differs from Bitcoin's 100 blocks
- How PAT relates to traditional Merkle validation
- The role of LatticeFold in signature verification

These are features, not bugs - but need documentation.

---

## Design Decisions (Founder Confirmed)

### 1. COINBASE_MATURITY = 240 Blocks

**Rationale**: Normalize to wall-clock time, not block count.

| Chain | Block Time | Maturity Blocks | Wall-Clock Time |
|-------|-----------|-----------------|-----------------|
| Bitcoin | 10 min | 100 | ~16.7 hours |
| Litecoin | 2.5 min | 100 | ~4.2 hours |
| **Soqucoin** | 60 sec | **240** | **4 hours** |

**Decision**: Match Litecoin's ~4 hour maturity window for consistent economic security. Miners cannot spend rewards until network has high confidence in block finality.

**Action**: Document in `src/consensus/consensus.h`:
```cpp
// COINBASE_MATURITY: 240 blocks = 4 hours at 60-second block time
// Matches Litecoin's ~4 hour maturity window
static const int COINBASE_MATURITY = 240;
```

---

### 2. Timestamp Validation

**Implementation**: Standard Bitcoin rules adapted for 60-second blocks.

**Rules Enforced**:
1. Block timestamp > median of last 11 blocks (`GetMedianTimePast()`)
2. Block timestamp ≤ current time + 2 hours

**Location**: `src/validation.cpp` → `ContextualCheckBlockHeader()`

**Action**: Add explicit constant for audit clarity:
```cpp
static const int64_t MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60;  // 2 hours in seconds
```

---

### 3. PAT (Practical Aggregation Technique) Architecture

**Purpose**: Mitigate Dilithium signature size (2,420 bytes vs ECDSA 72 bytes).

**Design**:
```
Block Validation Flow:
├── Merkle Root: Validates TX structure (standard)
├── Dilithium Sigs: Validates TX authorization (per-input)
└── PAT Commitment: Aggregated signature commitment (100 bytes)
    ├── 32B: XOR of all public keys
    ├── 32B: Merkle root of signed messages
    └── 32B+4B: Root commitment + count
```

**Key Files**:
- `src/pat/` - Core PAT logic
- `src/rpc/pat.cpp` - RPC interface
- `src/test/pat_tests.cpp` - Unit tests
- `src/bench/bench_pat.cpp` - Performance benchmarks

**Benefits**:
1. Block header stays compact (100 bytes for PAT vs full signatures)
2. Archival nodes can prune signatures after verification
3. Light clients verify PAT commitment without all signatures

---

### 4. LatticeFold+ Batch Verification

**Purpose**: Optimize Dilithium signature verification throughput.

**Implementation**: `src/crypto/latticefold/verifier.h` and `verifier.cpp`

**Verified Implementation Details** (from actual code):
```cpp
// LatticeFold+ verifier (October 2025 revision, ePrint 2025/247)
// Exact 8-round non-interactive verifier
// Uses Goldilocks-style field p = 2^64 - 2^32 + 1
// Verification time on Apple M4 ≈ 0.68 ms for 512-Dilithium batch
```

**Key Functions**:
- `LatticeFoldVerifier::VerifyDilithiumBatch()` - Main entry point
- `BatchInstance` struct: Contains batch_hash, t_coeffs (8 folded coefficients), c (folded challenge)
- `Proof` struct: ~1.38 KB total (sumcheck proof, range openings, folded commitment)

**Performance (Measured)**:
| Platform | 512-sig Batch Verify | Effective TPS |
|----------|---------------------|---------------|
| Apple M4 | **0.68 ms** | ~753,000 sigs/sec |
| VPS Intel 4-core | **0.751 ms** | ~682,000 sigs/sec |

**Integration Point**: Used by `OP_CHECKFOLDPROOF` in script interpreter (post Stage 2 activation at height 100,000).

> **Existing Documentation**: Full specification in `doc/CONSENSUS_COST_SPEC.md` (lines 107-131)

---

## Reference to Existing Documentation

> [!IMPORTANT]
> The comprehensive consensus specification already exists at:
> **`doc/CONSENSUS_COST_SPEC.md`** (875 lines, Version 2.3, Audit-Ready)
>
> This design log confirms the existing documentation is accurate and founder-approved.

### Key Sections in CONSENSUS_COST_SPEC.md

| Topic | Lines | Status |
|-------|-------|--------|
| LatticeFold+ Performance | 107-131 | ✅ Verified |
| Coinbase Maturity = 240 | 410, 606 | ✅ Verified |
| Staged Activation Schedule | 87-105, 446-535 | ✅ Verified |
| Verification Cost Weights | 287-300 | ✅ Verified |
| Code Pointers (Appendix D) | 679-722 | ✅ Verified |

---

## Trade-offs

| Decision | Trade-off | Rationale |
|----------|-----------|-----------|
| 240-block maturity | Miners wait longer than BTC | Security > convenience |
| PAT commitment | Additional header field | Size reduction worth it |
| LatticeFold batching | Added complexity | Performance critical for PQC |

---

## Implementation Plan

### Phase 1: Documentation (This Week)
- [x] Create this design log
- [x] Add inline comments to `consensus.h` for PAT acronym (Practical Aggregation Technique)
- [x] Verify timestamp validation in `validation.cpp` (lines 3028-3032) 
- [x] Create `doc/PAT-Architecture.md` for auditors

> **Note**: COINBASE_MATURITY is properly documented in `chainparams.cpp` (lines 118, 174, 338).
> Timestamp constants are inline (2 * 60 * 60) at `validation.cpp:3032`.

### Phase 2: Test Coverage (Before Audit) ✅ COMPLETE
- [x] Add test: coinbase spend at block N+100 → REJECT (`consensus_validation_tests.cpp`)
- [x] Add test: coinbase spend at block N+240 → ACCEPT (`consensus_validation_tests.cpp`)
- [x] Add test: block with timestamp 3hrs future → REJECT (`consensus_validation_tests.cpp`)
- [x] Add test: PAT commitment mismatch → block REJECT (existing: `pat_tests.cpp`)

> **Test File**: `src/test/consensus_validation_tests.cpp` (13 test cases)
> **PAT Tests**: `src/test/pat_tests.cpp` (17 test cases) - already comprehensive

#### Test Execution Results (Jan 20, 2026)

| Metric | Value |
|--------|-------|
| **VPS** | testnet3 (64.23.197.144) |
| **Test Suites** | 40+ |
| **Total Time** | 27.5 seconds |
| **Failures** | **0** |
| **Fix Applied** | BLAKE2b-160 test vector (commit `a5bb2cd`) |

### Phase 3: Audit Readiness
- [x] Review with John Fastiggi (System-Gap-Verification-Checklist.md updated)
- [ ] Include in Halborn audit scope documentation
- [ ] Prepare FAQ for auditor questions

---

## Examples

### ✅ Correct: Spending mature coinbase
```
Block 1000: Coinbase TX creates 50 SOQ to miner
Block 1240: Miner creates TX spending that 50 SOQ → VALID (≥240 confirmations)
```

### ❌ Incorrect: Spending immature coinbase
```
Block 1000: Coinbase TX creates 50 SOQ to miner
Block 1100: Miner creates TX spending that 50 SOQ → REJECTED (only 100 confirmations)
```

---

## Summary

All three questioned parameters are **intentional design decisions**:

| Parameter | Value | Status |
|-----------|-------|--------|
| COINBASE_MATURITY | 240 blocks | ✅ Intentional (4-hour wall-clock) |
| MAX_FUTURE_BLOCK_TIME | 2 hours | ✅ Standard (needs constant naming) |
| PAT Architecture | Dual commitment | ✅ Intentional (signature size mitigation) |
| LatticeFold Batching | 3.5x speedup | ✅ Implemented |

**No code changes required** - only documentation improvements.

---

*Approved by: Casey (Founder) - January 20, 2026*
