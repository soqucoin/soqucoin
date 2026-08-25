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

⛔ **This claim is load-bearing, so keep the table honest.** A row here asserts
original authorship. On 2026-08-17 `src/crypto/sangria/` was listed as a
*"Recursive folding engine — constant-size batch verification"* while the module
was 25 lines that returned `true` after a hash check, with a body of leftover
generated text; its per-directory `LICENSE` asserted a clean-room folding engine
that did not exist. The module has been removed and the row with it. Do not add a
row here for anything that is a port, a wrapper, or a placeholder — see the
upstream-dependencies section above.

| Path | Module | License | Notes |
|------|--------|---------|-------|
| `src/crypto/latticebp/` | Lattice-BP++ (confidential tx primitives) | MIT + **patent-pending** | Patent pending (provisional serials withheld); see [`LICENSE`](src/crypto/latticebp/LICENSE) |
| `src/crypto/latticefold/` | LatticeFold+ verifier (Dilithium batch verify) | MIT | Halborn-remediated |
| `src/crypto/binius/` | Binius commitment scheme | MIT | Hash-based commitment over a 32-byte field element vector; exercised by the `binius_commit` fuzz target |
| `src/crypto/binius64/` | GF(2^128) field arithmetic | MIT | Halborn-remediated (SOQ-A001..A004) |
| `src/crypto/pat/` | PAT — logarithmic Dilithium signature aggregation | MIT | Basis of `CHECKPATAGG` |
| `src/pat/` | PAT Dilithium keystore (`CDilithiumKey`) | MIT | `dilithium-ref/` subdir keeps its own upstream license |

## Upstream cryptographic dependencies (not vendored — yet)

Recorded here because the README states publicly that SoquObscura is *"built on the
LNP22/LaZer proof system with LaBRADOR block-level proof aggregation"*, and that
relationship must be attributed whether or not the code ships in this tree.

| Component | License | Copyright | How it is used today |
|---|---|---|---|
| [LaZer](https://github.com/lazer-crypto/lazer) — lattice ZKP library (LNP22) | MIT | © 2022-2026 **IBM** | **Offline oracle only.** Generates and independently re-verifies the KAT corpus that gates our verifier. Not linked into `soqucoind`, and it cannot be: it hard-wires AVX-512 in 15 unguarded source files, and most of our fleet has no AVX-512. |
| LaBRADOR proof system (LaZer's `src/labrados/`, a re-implementation for the Orthus / Toolkit papers, built on the arithmetic of [lattice-dogs/labrador](https://github.com/lattice-dogs/labrador)) | Apache-2.0 | © 2026 **IBM Corp.** | Same: offline. `lin_verifier_verify` is the proof check our corpus verdicts come from. |

⚠️ **Both upstreams state they are research code.** LaZer's LaBRADOR tree carries:
*"This code is intended for research purposes and has not undergone the security
review, testing, or validation required for production deployment."* That is one of
the reasons it is an oracle and not a consensus dependency.

⛔ **PLANNED, AND IT CHANGES THIS FILE.** The consensus range/VE verifier is to be
made fleet-buildable by **porting LaBRADOR's AVX-512 core (~3,130 LOC) to portable
C**. A port is a **derivative work of Apache-2.0 IBM code**, which is permitted and
carries an express patent grant from IBM, but obligates us to: include the Apache-2.0
license text, retain IBM's copyright and notices, ship a `NOTICE`, and state our
modifications. When that lands it belongs in the *vendored third-party* table above,
**not** in the Soqucoin-original table below.

★ To be unambiguous about what is ours: SOQ-P010/P011 claim the **relation** —
corrector-chain pins, ring-degree headroom, dual-target verifiable encryption,
H_lat. They do not claim IBM's proof system, and a ported verifier must never be
described as a Soqucoin clean-room implementation.

## Notes
- Per-directory `LICENSE` files state the authoritative terms for each module.
- The CI `license-check` job (`.github/workflows/license-check.yml`) asserts that
  every cryptographic module directory carries a `LICENSE`.
- The latticebp patent notice references two pending U.S. provisional patent
  applications (filed 2025 and 2026) by Soqucoin Labs Inc.; serial numbers are withheld.
