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

### ⛔ But the portable AES path is 50–300x slower, and that is a DoS surface

| build | AES path | 23 range vectors |
|---|---|---|
| x86-64 | AES-NI | **0.84 s** |
| arm64 Apple Silicon | portable C | **44.2 s** (~53x) |
| x86-64 | portable C | **258 s** (~307x) |

AES-CTR is the RNG behind every seed-derived value, so this lands squarely on the verify path.
At ~2 s per range proof a non-x86 node cannot keep up with block validation, and an attacker
choosing to fill blocks with confidential transactions would be exploiting the gap deliberately.

⇒ **A non-x86 node needs an architecture-specific AES to be viable**, e.g. ARMv8 crypto
extensions (`vaeseq_u8`). ★ That is a *performance* change and not a consensus-semantics one —
AES is AES — and the digest table above is exactly the test that proves it stays bit-exact.
Until then, treat non-x86 as **correct but not production-capable**, and do not read "it builds
on arm64" as "it runs on arm64".

## How it is verified

| check | what it proves |
|---|---|
| 64-vector KAT corpus, verdict-identical | agrees with the pinned oracle |
| 18-vector degenerate-witness class, all reject | rejects the break class, including a non-zero, wire-reachable member |
| optimisation-invariance falsifier | one seed-derived statement matrix across gcc-13/14 `-O1/-O2/-O3/-Os` and clang-18 `-O2/-O3` |

`contrib/nh6m-opt-invariance-falsifier.sh` is the regression gate for the third and belongs in
CI for any build that ships this code.
