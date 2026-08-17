# How these verdicts were produced, and how to reproduce them

This directory is the **acceptance gate** for the replacement SoquObscura verifier.
The `expect` field on every vector is not an aspiration — it is the verdict an
independent implementation actually returns. This file records how that was
established so a third party (an auditor, a reviewer, a future maintainer) can
re-establish it without taking our word for it.

⚠️ **Attribution.** Produced with **LaZer** (MIT, © 2022-2026 IBM) and its
**LaBRADOR** tree (Apache-2.0, © 2026 IBM Corp), pinned at commit
`2fa3dfb1de7c`. See [`ATTRIBUTION.md`](../../../../ATTRIBUTION.md). Both upstreams
state they are research code, not production-reviewed — which is why they are an
**offline oracle** and not a consensus dependency.

⛔ **LaZer cannot run in CI, and this is not a gap to be closed.** It hard-wires
AVX-512 intrinsics across 15 unguarded source files, and it needs gcc ≥ 13.2 and
SageMath ≥ 10.2. `ubuntu-22.04` runners ship gcc 11, and 6 of our 8 fleet nodes
have no AVX-512 at all. So the division of labour is deliberate:

| where | what runs | what it proves |
|---|---|---|
| offline, on an AVX-512 host | LaZer + the C KAT harness | the `expect` verdicts are real |
| CI, on any host | `soquobscura_kat_corpus_tests.cpp` | the corpus is intact and unmodified |

CI verifies the *artifact*; it does not re-derive it. That is the same reason
NIST KAT files are shipped rather than regenerated.

---

## Environment fingerprint (captured 2026-08-17)

```
host_cpu      Intel(R) Xeon(R) Platinum 8358 CPU @ 2.60GHz
isa           avx512 avx512bw avx512cd avx512dq avx512f avx512vbmi avx512vl
os            Ubuntu 24.04.4 LTS
kernel        6.8.0-137-generic
gcc           gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
sage          10.9
python3       3.12.3
lazer commit  2fa3dfb1de7c        (also recorded in manifest.json)
```

Artifact digests (first 32 hex chars of sha256), so the exact binaries that
produced these verdicts are identifiable:

```
liblazer.a    249ea7d2659b2ecf33536b9adf8cc1c4...
liblazer.so   f8564c37d6afc569d0a86373a906626c...
kat_verify    b9575a8eb07912af97ab37365b72ce87...
kat_verify.c  5bd6d272b7007e60646ab0a8c3da655a...
```

## Reproducing

The harness lives in the Lattice-BP++ worktree, **not this repo**:
`contrib/latticebp/phase2/verifier/` — `kat_verify.c`, `soq_lbpp_wire.c`,
`soq_lbpp_verify.c`, built by `build-box.sh`. On a host meeting the requirements
above:

```sh
./build-box.sh /path/to/lazer /path/to/corpus
```

Expected output, reproduced 2026-08-17:

```
C verifier KAT gate (corpus: .../out)
  range: 23 vectors, ALL VERDICTS REPRODUCED
  balance: 19 vectors, ALL VERDICTS REPRODUCED
  ve: 22 vectors, ALL VERDICTS REPRODUCED
TOTAL: 64 vectors, 64/64 expected
KAT-GATE-PASSED
```

Runtime ~4.8 s single-threaded, deterministic across repeated runs.

## ★ The gate is not vacuous, and that was verified by falsification

A gate that reports success without comparing anything is worse than no gate.
So the harness was tested against a **deliberately corrupted** copy of the
corpus: one range vector's `expect` was flipped from `accept` to `reject`, with
nothing else changed.

```
  MISMATCH rng-ok-zero: got accept, expect reject
  range: 23 vectors, FAILURES
TOTAL: 64 vectors — GATE FAILED
```

It performs a genuine per-vector comparison, names the offending vector, and
reports the oracle's own verdict (`got accept`) rather than only a pass/fail. The
corrupted copy was discarded; the corpus in this directory is unmodified and its
digests match `manifest.json`.

## What the corpus covers, and why the port must be graded on all of it

Not 64 undifferentiated vectors — structured adversarial classes. These are the
ones a replacement verifier has to get right, and
`soquobscura_kat_corpus_tests.cpp` asserts that each class is still **present**,
so the port cannot be quietly graded on a reduced set.

**range (23: 15 accept / 8 reject)**
- honest values across the domain: `0`, `1`, dust, typical, `2^63`, `2^64-1`, randoms
- ⭐ **L2 norm-bound boundary**: `rng-l2-atbound` accepts at exactly `‖r‖² = 1536`;
  `rng-l2-1539`, `-2046`, `-2049` reject just past it. This is the bound-gate
  discipline — an off-by-one here is a soundness hole
- non-binary bit gadget: `rng-adv-nonbin2` (b₀=2), `rng-adv-nonbin-neg1` (b₀=-1)
- statement binding: `rng-adv-tamper` (honest proof pinned to the wrong commitment)
- `rng-adv-bitflip`, `rng-adv-trunc` (truncated to half length)

**balance (19: 9 accept / 10 reject)**
- ⭐ **wraparound**: `bal-adv-wrap-plus`, `bal-adv-wrap-minus`. This is the
  wrap-boundary pitfall in ring-linear encodings — the actual result of the paper
  work, and the one a naive implementation gets wrong
- non-conservation by ±1, fee ±1, swapped inputs/outputs, foreign commitment

**ve (22: 16 accept / 6 reject)**
- ⭐ **dual-target**: every honest value appears twice, `-iss` (issuer) and `-rcp`
  (recipient). Tier A's mandatory-issuer-key rule depends on this working
- ⭐ `ve-adv-crosskey` (ciphertext verified against the wrong key) and
  `ve-adv-wrongval` (decrypts to a value ≠ the commitment) — these are two of the
  WI-5 adversarial classes, already built at the proof level

★ **Consequence worth noting:** the plan's `ADV-SUITE` (WI-5) node is partly
pre-built. Wrong-value, wrong-key, truncation, bitflip and non-conservation all
have pinned vectors here. WI-5 still needs the *consensus-rule* adversarial cases
(missing disclosure, malformed wire, cross-epoch key), but not the proof-level ones.

## The grading contract for the ported verifier

When the portable verifier exists, it passes this gate iff it returns **exactly**
these 64 verdicts. Not "most". A single disagreement is a red build, because a
disagreement means one of the two implementations is wrong and we do not get to
assume which.

⚠️ Two rules that are easy to lose:
1. **Verdict-identical, not just count-identical.** 62 right and 2 compensating
   errors is not a pass.
2. **The reject vectors matter more than the accept ones.** A verifier that
   returns `true` unconditionally passes all 39 accept vectors. The 25 reject
   vectors are what distinguish a verifier from a stub — which is not a
   hypothetical failure mode in this codebase.
