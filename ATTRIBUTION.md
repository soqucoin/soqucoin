# Attribution & Third-Party Licenses

Soqucoin Core is released under the MIT License (see [`COPYING`](COPYING)). It is
derived from Bitcoin Core (via the Dogecoin lineage) and bundles several
third-party and original cryptographic modules. This file records the license
and provenance of each so the boundaries are unambiguous.

## Derivation
Soqucoin Core is based on Bitcoin Core (≈ 0.16/0.17) via the Dogecoin 1.14
lineage. Copyright is held by The Bitcoin Core developers and The Soqucoin Core
developers (see `COPYING`).

## Vendored third-party libraries

| Path | Component | License | Provenance |
|------|-----------|---------|------------|
| `src/leveldb/` | LevelDB | BSD-3-Clause | Google (carries upstream license) |
| `src/univalue/` | UniValue | MIT | Jonas Schnelli et al. (carries upstream license) |
| `src/crypto/ctaes/` | ctaes | MIT | Pieter Wuille (per-file MIT headers) |
| `src/crypto/dilithium/` | CRYSTALS-Dilithium ref (FIPS-204 ML-DSA) | CC0-1.0 OR Apache-2.0 OR GPL-2.0 | PQ-Crystals — see [`src/crypto/dilithium/LICENSE`](src/crypto/dilithium/LICENSE) |
| `src/pat/dilithium-ref/` | CRYSTALS-Dilithium ref (copy) | CC0-1.0 OR Apache-2.0 OR GPL-2.0 | PQ-Crystals — see [`src/pat/dilithium-ref/LICENSE`](src/pat/dilithium-ref/LICENSE) |

Within the Dilithium trees, `fips202.c/.h` (Keccak/SHAKE) and the randombytes
implementation are public-domain code by their respective authors (see the
comments at the top of those files).

## Soqucoin-original cryptographic modules

All MIT (root `COPYING`), authored by The Soqucoin Core developers as clean-room
implementations of published cryptographic constructions — not derived from
third-party source code.

| Path | Module | License | Notes |
|------|--------|---------|-------|
| `src/crypto/latticebp/` | Lattice-BP++ (confidential tx primitives) | MIT + **patent-pending** | U.S. Provisional No. 63/999,796 + No. 64/023,515; see [`LICENSE`](src/crypto/latticebp/LICENSE) |
| `src/crypto/latticefold/` | LatticeFold+ verifier (Dilithium batch verify) | MIT | Halborn-remediated |
| `src/crypto/binius/` | Binius binary-field commitments | MIT | Foundation for Sangria |
| `src/crypto/binius64/` | GF(2^128) field arithmetic | MIT | Halborn-remediated (SOQ-A001..A004) |
| `src/crypto/sangria/` | Recursive folding engine | MIT | Constant-size batch verification |
| `src/crypto/pat/` | PAT — logarithmic Dilithium signature aggregation | MIT | Basis of `CHECKPATAGG` |
| `src/pat/` | PAT Dilithium keystore (`CDilithiumKey`) | MIT | `dilithium-ref/` subdir keeps its own upstream license |

## Notes
- Per-directory `LICENSE` files state the authoritative terms for each module.
- The CI `license-check` job (`.github/workflows/license-check.yml`) asserts that
  every cryptographic module directory carries a `LICENSE`.
- The latticebp patent notice references U.S. Provisional Patent Application
  No. 63/999,796 (2025) and No. 64/023,515 (2026), both filed by Soqucoin Labs Inc.
