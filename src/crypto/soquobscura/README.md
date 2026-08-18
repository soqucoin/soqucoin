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

## Architecture support — CORRECT everywhere, FAST only on x86-64

⛔ **An earlier version of this file said the subsystem was x86-64 only and that
`TARGET_GENERIC` was "not sufficient". Both statements are now obsolete, and the second was
never actually tested** — it was based on editing `config.h`, which has no effect, because the
generated `lazer.h` embeds the configuration at line 31. Edit `lazer.h`.

**Portability is fixed.** Upstream gated three things on `_OS_IOS`, an *operating system* macro
defined only for `__APPLE__ && TARGET_OS_IPHONE`, so iOS and x86-64 worked and every other
target fell through to x86-only code: the second `immintrin.h` include site, and both
`_addcarry_u64_` / `_subborrow_u64_`. All three now select on the **architecture**, with a
plain-C carry fallback so no compiler is excluded. One HEXL kernel's AVX-512 header include is
guarded to match its already-guarded uses, and the vestigial `mpfr.h` include is gone.

**Verdicts and derived public data are bit-identical across every configuration tested:**

| build | AES path | statement-matrix digest | vectors |
|---|---|---|---|
| x86-64 gcc, `TARGET_AMD64` | AES-NI | `d5b417375955cb07` | 82/82 |
| x86-64 gcc, `TARGET_GENERIC` | portable C | `d5b417375955cb07` | 82/82 |
| arm64 clang `-O0`…`-Os`, `TARGET_GENERIC` | portable C | `d5b417375955cb07` | 82/82 |

That is the property a consensus verifier needs, and it is now measured rather than assumed —
the same discipline `nh6m` had to teach for optimisation levels.

### ✅ Performance: resolved with an ARMv8 AES path

The portable C AES is correct but **50–300x slower** on the verify path, and AES-CTR is the RNG
behind every seed-derived value, so that gap was a denial-of-service surface rather than a
benchmark curiosity. `lazer/src/aes256ctr-aarch64.c` (Soqucoin-original) closes it using the
ARMv8 cryptographic extensions.

| build | AES path | 23 range vectors | all 82 |
|---|---|---|---|
| x86-64 gcc | AES-NI | 0.86 s | 82/82 |
| **arm64 clang** | **ARMv8 crypto** | **0.59 s** | **2.35 s** |
| arm64 clang | portable C | 44.2 s | 219 s |
| x86-64 gcc | portable C | 258 s | — |

★ **arm64 with the crypto extensions is now faster than x86-64 with AES-NI** (0.59 s vs 0.86 s),
and ~75x faster than the portable path on the same vectors. 114 `aese`/`aesmc` instructions are
present in the archive, so the hardware unit is genuinely in use.

**Scope of the new file is deliberately narrow:** only the key schedule and the block cipher are
new. The counter-mode logic — big-endian increment, cache, partial-block bookkeeping — is a
byte-for-byte copy of the generic implementation that was already proven correct. Reimplementing
CTR mode would risk the counter semantics for no benefit. `SubWord` uses the crypto unit rather
than a lookup table, so there is no data-dependent table access.

`TARGET` is now **auto-detected** from the architecture rather than hardcoded, with
`SOQ_LAZER_TARGET` as an override. Editing `config.h` still has no effect — the generated
`lazer.h` embeds the configuration.

### Bit-identity, the property that actually matters

| build | AES path | statement-matrix digest | vectors |
|---|---|---|---|
| x86-64 gcc, auto → AMD64 | AES-NI | `d5b417375955cb07` | 82/82 |
| x86-64 gcc, `TARGET_GENERIC` | portable C | `d5b417375955cb07` | 82/82 |
| arm64 clang `-O0`…`-Os`, auto → AARCH64 | ARMv8 crypto | `d5b417375955cb07` | 82/82 |
| arm64 clang `-O0`…`-Os`, `TARGET_GENERIC` | portable C | `d5b417375955cb07` | 82/82 |

Four AES implementations across two architectures, two compilers and five optimisation levels.
The derived public data is the same in every case. ★ That is what makes adding a hardware AES a
**performance** change rather than a consensus-semantics one, and the digest is the instrument
that proves it — not an argument that "AES is AES".

## How it is verified

| check | what it proves |
|---|---|
| 64-vector KAT corpus, verdict-identical | agrees with the pinned oracle |
| 18-vector degenerate-witness class, all reject | rejects the break class, including a non-zero, wire-reachable member |
| optimisation-invariance falsifier | one seed-derived statement matrix across gcc-13/14 `-O1/-O2/-O3/-Os` and clang-18 `-O2/-O3` |

`contrib/nh6m-opt-invariance-falsifier.sh` is the regression gate for the third and belongs in
CI for any build that ships this code.
