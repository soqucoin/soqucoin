# Soqucoin Verification Benchmarks

Performance characteristics for post-quantum cryptographic operations on Soqucoin.

## Test Environment

| Spec | Value |
|------|-------|
| CPU | Apple M4 (reference) / AMD Ryzen 7950X (comparison) |
| RAM | 16 GB minimum |
| Build | Release (-O2, LTO enabled) |

## Signature Verification

| Operation | M4 Time | Ryzen Time | Notes |
|-----------|---------|------------|-------|
| Dilithium ML-DSA-44 verify | 0.18 ms | 0.25 ms | Single signature |
| Dilithium batch verify (x64) | 8.5 ms | 12 ms | ~2.3x faster than individual |
| ECDSA verify (deprecated) | N/A | N/A | Disabled in v1.0 |

## Range Proofs

| Operation | M4 Time | Ryzen Time | Proof Size |
|-----------|---------|------------|------------|
| Bulletproofs++ verify (64-bit) | 10 ms | 15 ms | ~700-900 bytes |
| Bulletproofs++ verify (aggregated, 16 outputs) | 35 ms | 50 ms | ~1.2 KB |

## Signature Aggregation (PAT)

| Operation | M4 Time | Ryzen Time | Notes |
|-----------|---------|------------|-------|
| PAT Merkle verify (≤256 sigs) | 4 ms | 6 ms | Logarithmic in batch size |

## LatticeFold+ (Recursive SNARK)

| Operation | M4 Time | Ryzen Time | Proof Size |
|-----------|---------|------------|------------|
| LatticeFold+ verify (512-sig batch) | 0.68 ms | 1.2 ms | ~1.38 KB |
| LatticeFold+ verify (worst case) | 40 ms | 60 ms | Heavy proof |

## Block Validation Targets

| Scenario | Target | Max Proof Load |
|----------|--------|----------------|
| Typical block | < 50 ms | Few proofs |
| Heavy block (max BP++) | < 100 ms | 1,600 BP++ proofs |
| Heavy block (max LatticeFold+) | < 500 ms | 10 LatticeFold+ proofs |

## Minimum Hardware Requirements

| Role | CPU | RAM | Storage |
|------|-----|-----|---------|
| Full node (sync) | ARM64 4-core (Pi 4+) | 4 GB | 50 GB SSD |
| Full node (validate) | x86/ARM64 4-core | 8 GB | 100 GB SSD |
| Mining node | x86/ARM64 4-core | 16 GB | 100 GB SSD |

## Consensus Cost Model

See `src/consensus/consensus.h` for authoritative values:

```cpp
DILITHIUM_VERIFY_COST = 1      // baseline
BPPP_VERIFY_COST = 50          // ~10ms
PAT_VERIFY_COST = 20           // ~4ms
LATTICEFOLD_VERIFY_COST = 200  // ~40ms

MAX_BLOCK_VERIFY_COST = 80000
MAX_LATTICEFOLD_PER_BLOCK = 10
MAX_PROOF_BYTES_PER_TX = 65536     // 64 KB
MAX_PROOF_BYTES_PER_BLOCK = 262144 // 256 KB
```

## Methodology

Benchmarks measured using:
- `src/bench/bench_dilithium.cpp`
- `src/bench/bench_bulletproofs.cpp`
- `make bench` target

All times are median of 1000 iterations, single-threaded.

---

*Last updated: 2025-12-22*
