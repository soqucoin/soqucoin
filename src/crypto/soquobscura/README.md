# SoquObscura verifier — vendored source

**Read `NOTICE` before touching anything here.** This is third-party code, modified, and the
modification statements in `NOTICE` are a licence obligation, not documentation.

⛔ **This code is not wired into consensus.** `DEPLOYMENT_SOQUOBSCURA` is `NOT_SCHEDULED` on all
four networks. Vendoring it makes the KAT corpus executable in-process; it does not activate
anything.

## What is here

| | files | LOC |
|---|---|---|
| `lazer/` — the reachable subset of LaZer, one unity translation unit | 23 `.c` · 16 `.h` · 1 `.cpp` | 14,716 |
| `hexl/` — the 8 HEXL kernels the verifier reaches, plus headers | 8 `.cpp` · 21 `.hpp` | 4,646 |
| `hexl/shim/` — Soqucoin-original replacements for two upstream deps | 2 `.h` | 35 |
| **total** | **85 files** | **19,362** |

Excluded, with evidence rather than assertion: Falcon 23,526 LOC (dropped entirely, no
reference survives), `labrados` 28,705 (never linked), `lattice-hash` 2,401, `python/demos/tests`
32,108, plus 11 dead files and 174 unreachable functions from the remaining sources.

## The three invariants a change here must not break

Soundness against the degenerate-witness class rests on these, and on nothing else. Every norm
check in `lnp_quad_verify` is homogeneous in the witness, so a zero witness passes all of them.

1. **`v` is absorbed into the challenge derivation, not compared against zero.**
   `lazer/src/lnp-quad.c`: `v = z*R2*z + c*r1*z + c^2*r0 - f` is hashed into `cseed`. That makes
   the equation check *be* the Fiat-Shamir check. With a zero witness `v = c^2*r0`, so a forger
   would need `c = F(H(... c^2*r0 ...))` — a hash fixed point.
2. **`poly_eq (c, c2)`** against the recomputed challenge.
3. **`poly_urandom_autostable`'s fixed-weight ω constraint**, which keeps the zero polynomial
   out of the challenge image.

⛔ "Simplifying" (1) into a separate `v == expected` comparison **reintroduces the forgery** that
this repository has already shipped twice. Treat it as the highest-risk edit in the subsystem.

## Build constraints and dependencies

- ✅ **`--gc-sections` is NOT required.** An earlier draft of this file said it was; that was
  true of the *pre-pruned* tree, where retained prover entry points still referenced removed
  files. Function-level pruning removed those, and the tree now links with a plain link line.
  Verified by linking without it and re-running all 82 vectors.
- **GMP is required. mpfr is not.** The pruned archives need exactly **10** `__gmpn_*` symbols —
  `sec_div_qr`, `sec_div_r`, `sec_mul`, `sec_sqr`, their `_itch` companions, `lshift`, `rshift` —
  which are GMP's constant-time mpn routines. There are **zero** undefined `mpfr_*` symbols, so
  `-lmpfr` should not appear in any link line for this subsystem. Vendoring therefore adds one
  external dependency to the project, not two.
- **Do not enable AVX-512.** `defines.hpp` deliberately leaves every `HEXL_HAS_AVX512*` macro
  undefined, and the shim reports no CPU features. Build for a fixed baseline
  (`-march=x86-64-v3 -maes -mtune=generic`); a host-derived `-march` makes the binary depend on
  whichever machine compiled it.
- **Do not regenerate `lazer.h`.** It is committed in generated form on purpose.

## ⛔ This subsystem is x86-64 ONLY, and that is a consensus problem, not a build inconvenience

`lazer/src/lazer.c` includes `aes256ctr-amd64.c` **unconditionally**, and that file pulls
`immintrin.h` for AES-NI. On arm64 the translation unit does not compile at all:

```
immintrin.h:14:2: error: "This header is only meant to be used on x86 and x64 architecture"
```

Setting `TARGET TARGET_GENERIC` in `config.h` is **not sufficient** — the generic implementation
in `aes256ctr.c` becomes active, but the amd64 file is still included and still pulls the x86
header. Making that include conditional is a source change, and it is the first thing to do
before this can build anywhere else.

**Why it matters beyond convenience:** a verifier that only builds on x86-64 means only x86-64
nodes can validate confidential transactions. And once a generic AES path is enabled, whether it
derives a **bit-identical** statement matrix must be proven, not assumed — that is the same
question `nh6m` answered the hard way for optimisation levels, and the same class of chain-split
risk. `contrib/nh6m-opt-invariance-falsifier.sh` is the right shape of test; it needs an
architecture axis added.

⚠️ Practical consequence today: this cannot be built or tested on an Apple Silicon workstation,
so any build-system wiring must make the subsystem and its tests conditional on the host
architecture rather than unconditional.

## How it is verified

| check | what it proves |
|---|---|
| 64-vector KAT corpus, verdict-identical | agrees with the pinned oracle |
| 18-vector degenerate-witness class, all reject | rejects the break class, including a non-zero, wire-reachable member |
| optimisation-invariance falsifier | one seed-derived statement matrix across gcc-13/14 `-O1/-O2/-O3/-Os` and clang-18 `-O2/-O3` |

`contrib/nh6m-opt-invariance-falsifier.sh` is the regression gate for the third and belongs in
CI for any build that ships this code.
