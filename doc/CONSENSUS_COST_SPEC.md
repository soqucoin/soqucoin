# Soqucoin Protocol Parameters & Consensus Cost Specification

> **Version**: 1.8 | **Status**: Public Reference
> **Last Updated**: January 2026
> **Specification Tag**: Mainnet Candidate v1.0

---

> [!IMPORTANT]
> **Pre-Mainnet Notice**: The following parameters are subject to change before mainnet launch:
> - **Policy parameters** (fees, dust limits) may be adjusted based on market conditions
> - **Benchmark-derived weights** (PQ verification costs) may be rebalanced based on hardware telemetry
> - **Consensus parameters** are frozen and will not change without a coordinated network upgrade
>
> This document reflects the current mainnet candidate specification.

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

## 9. Staged Activation Schedule

### Overview

Soqucoin uses **staged consensus activation** to minimize launch risk. Novel cryptographic features activate at predetermined block heights rather than at genesis.

> [!IMPORTANT]
> **Pre-activation behavior**: Transactions using BP++ or LatticeFold proofs are **consensus-invalid** before their activation height. This is a security feature, not a limitation.

### Mainnet Activation Schedule

| Stage | Height | ~Calendar | Features | Rationale |
|-------|--------|-----------|----------|-----------|
| **Genesis** | 0 | Q1 2026 | Dilithium signatures, PAT aggregation, AuxPoW | Core PQ identity |
| **Stage 1** | 50,000 | +~35 days | Bulletproofs++ range proofs | Privacy primitive (secp256k1-zkp) |
| **Stage 2** | 100,000 | +~69 days | LatticeFold+ batch verification | Scaling optimization |

### Testnet Activation Schedule

| Stage | Height | Features | Notes |
|-------|--------|----------|-------|
| Testnet3 | 0 | All features | Development/testing (all active) |
| **Mainnet-candidate testnet** | Mirrors mainnet | Staged activation | Upgrade rehearsal environment |

### What Each Feature Provides

**BP++ Range Proofs (Stage 1)**:
- Pedersen commitments with cryptographic range proofs [0, 2^64)
- Based on secp256k1-zkp (Elements/Blockstream) — battle-tested library
- **Note**: This is range proof infrastructure, not full confidential transactions
- Full privacy features (CT, confidential assets) planned for future softfork (see Roadmap)

> [!WARNING]
> **Privacy Status Clarification (v1.0)**
> 
> In Soqucoin v1.0, BP++ range proofs are **consensus-verified** but **amounts remain plaintext**:
> 
> | Aspect | v1.0 (Stage 1) | Future (Stage 3) |
> |--------|----------------|------------------|
> | `vout.nValue` | **Visible** (plaintext on-chain) | Hidden (zero on-chain) |
> | Pedersen commitment | Present in `OP_RETURN` | Primary amount carrier |
> | Range proof verification | Consensus-enforced | Consensus-enforced |
> | Privacy | ❌ None | ✅ Full CT |
> 
> **Rationale**: Stage 1 activates the *plumbing* for confidential transactions — the verification code path, consensus cost accounting, and proof byte budgets. This allows wallets and infrastructure to test CT workflows with real proofs before privacy semantics activate. Full confidential transactions (hidden amounts) require a Stage 3 softfork.

**LatticeFold+ Batch Verification (Stage 2)**:
- Verifies up to 512 Dilithium signatures in ~0.68ms (vs ~102ms individually)
- ~150x verification speedup for blocks with many transactions
- Based on ePrint 2025/247 (October revision) — custom research implementation
- **Not required** for basic operation; optimization for high-throughput scenarios

### Quantitative Impact

| Metric | Before Stage 2 | After Stage 2 |
|--------|----------------|---------------|
| **Single signature verification** | ~0.2ms | ~0.2ms (unchanged) |
| **512-signature block verification** | ~102ms | ~0.68ms |
| **Speedup for high-tx blocks** | 1x | ~150x |
| **Throughput ceiling** | Adequate for early adoption | Scales to high volume |

*Benchmarks: Apple M4 Max (single-threaded). x86 server ~1.2ms for batch; low-end VPS ~3-5ms.*

### Activation Ordering Rationale

**Why BP++ activates before LatticeFold:**

1. **Cryptographic maturity**: BP++ uses battle-tested secp256k1-zkp. LatticeFold is custom research code (ePrint 2025/247).

2. **Blast radius**: LatticeFold has highest complexity. Activating it last maximizes operational signal.

3. **Independence**: Neither is required for basic operation. Dilithium transactions work at genesis.

4. **We accept lower throughput early to minimize consensus risk.** Expected early throughput is adequate for initial adoption patterns.

### Pre-Activation Behavior

| Feature | Before Activation | After Activation |
|---------|-------------------|------------------|
| **BP++ range proofs** | Consensus-invalid | Standard, relay enabled |
| **LatticeFold proofs** | Consensus-invalid | Standard, relay enabled |

### Roadmap Features (Future Softforks)

| Feature | Target | Description |
|---------|--------|-------------|
| **Stage 3: Lattice-BP Hybrid** | v0.22 | Full confidential transactions with PQ privacy |
| **Stage 4: Solana Bridge** | TBD | Cross-chain SOQ ↔ pSOQ integration |

*These features require separate softforks and are not consensus-frozen in this specification.*

### Upgrade & Security Response Policy

- **Activation heights are consensus-frozen** once a tagged release is published
- **Height changes require a new release** with minimum 2-week upgrade window
- **Security response**: Critical vulnerabilities trigger coordinated disclosure to major miners/exchanges within 24 hours, followed by emergency release
- **Release signing**: All binaries signed by core maintainers; reproducible builds available
- **Rollback policy**: No consensus rollbacks except for chain-halting bugs affecting >50% of network

---

## 10. Network Alignment

| Network | Genesis | Chain ID | BP++ Activation | LatticeFold Activation |
|---------|---------|----------|-----------------|------------------------|
| Mainnet | Q1 2026 | 0x5351 | Height 50,000 | Height 100,000 |
| Testnet3 | Dec 2025 | 0x5351 | Genesis (all features) | Genesis (all features) |
| Mainnet-candidate | Pre-launch | 0x5351 | Height 50,000 | Height 100,000 |

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
| Coinbase Maturity | 240 blocks | **Consensus** | Inherited |
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
| **Bulletproofs++** | Academic (Bünz et al.) | secp256k1-zkp (Blockstream) | Elements test suite | Constant-time multiexp |
| **PAT Aggregation** | Novel | Custom | Soqucoin test suite | N/A (hash-based) |
| **LatticeFold+** | ePrint 2025/247 | Custom | Soqucoin test suite | Constant-time field ops |
| **Scrypt PoW** | RFC 7914 | Colin Percival reference | Litecoin/Dogecoin | N/A (PoW) |

### Audit Scope Notes

- **NIST-grade**: Dilithium uses NIST PQ standard parameters
- **Battle-tested**: Bulletproofs++ uses Elements/Liquid production library
- **Research-grade**: LatticeFold+ is novel; requires focused audit attention
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
| BP++ Range Proof | 4 units | [`src/consensus/consensus.h:31`](https://github.com/soqucoin/soqucoin/blob/main/src/consensus/consensus.h#L31) |
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
| **Testnet3 VPS** | DO-Premium-Intel 4-core, 8GB RAM, Ubuntu 24.04 | DigitalOcean 64.23.197.144 |
| **Engineering VPS** | DO-Regular 2-core, 4GB RAM, Ubuntu 22.04 | DigitalOcean 64.23.245.81 |

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

*Soqucoin Protocol Parameters Specification*
*Prepared for community and investor reference*
*Soqucoin Core Development Team — January 2026*

