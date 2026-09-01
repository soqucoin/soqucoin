# PAT block attestation — consensus specification

**Status:** SPEC, pre-implementation. Phase 3 of the PAT completion epic
(`pat-completion-epic-xlab`). Nothing in this document is implemented yet;
§10 lists the decisions it needs before it can be.

**What this is.** The rules a node follows to compute, commit, and verify the
per-block PAT attestation. It exists because the attestation is recomputed
independently by every node and compared byte-for-byte against a miner's
commitment: **any ambiguity here is a chain split, not a bug**. A reimplementer
must be able to produce identical bytes from this document alone.

---

## 1. What the attestation is

One PAT proof per block, over the Dilithium signatures that block's spends
carry. The proof is committed in the coinbase and validated in `ConnectBlock`.
It is **block metadata, not an output type** — witness v2 is permanently
unfundable (`validation.cpp` `versionActive` case 2), so no value can be paid
into the attestation machinery.

What it buys: nodes may discard attested raw witness data past the finality
horizon while retaining the attestation. That is the storage benefit PAT was
researched for, and it is delivered in phase 5, not here.

What it does **not** buy: any statement that the signatures are valid. That is
per-input script verification's job. The attestation attests; it does not
authorize. A commitment cannot verify a signature.

---

## 2. Which spends are attested ⚠️ DECISION 1

This is the single most split-prone definition in the document, because several
witness versions reach the *same* Dilithium verification code by different
routes, and the set changes as deployments activate.

The Dilithium single-key path in `VerifyScript` (`interpreter.cpp:1906-1949`) is
reached by:

| Version | Reaches the Dilithium path | Witness shape | Status at genesis |
|---|---|---|---|
| v0, v1 | directly (`is_dilithium`) | exactly `[sig, pubkey]` | **active** |
| v7 (USDSOQ holding) | falls through, gated on `SCRIPT_VERIFY_USDSOQ` | exactly `[sig, pubkey]` | dormant |
| v8 (BTCSOQ holding) | falls through, gated on `SCRIPT_VERIFY_BTCSOQ` | exactly `[sig, pubkey]` | dormant |
| v6 (P2WSH-Dilithium) | executes a witnessScript | arbitrary; 0..n sig checks | dormant |
| v5, v9 (authority markers) | **never** — skips per-input verification entirely; M-of-N verified whole-tx in `ConnectBlock` | marker | dormant |

**Specified rule:** a spend is attested if and only if it is a witness spend
whose witness stack is **exactly two items** and which reaches the single-key
Dilithium verification — that is v0, v1, and (once their deployments are active)
v7 and v8.

**v6 and the v5/v9 authority markers are explicitly OUT of scope**, and the
reason is not convenience:

- **v6** executes an arbitrary witnessScript that may perform zero, one, or many
  signature checks, at positions the block does not expose. There is no 1:1
  spend-to-tuple mapping to canonicalise, so including it would require the
  attestation to re-execute scripts. That is a far larger consensus surface, and
  it is where an ordering ambiguity would be hardest to see.
- **v5/v9 authority spends** never reach `VerifyScript` at all. Their M-of-N
  signatures are verified whole-transaction in `ConnectBlock`, so they are not
  per-input tuples in the first place.

⛔ **The set must be defined by rule, not by "whatever the code happens to
collect."** v7 and v8 are dormant at genesis, so a naive implementation that
iterates and collects "two-item witnesses" produces the same answer today and a
*different* answer the day USDSOQ or BTCSOQ activates. Activating a deployment
must not silently change the attestation of blocks. Hence Decision 1 in §10.

---

## 3. The tuple ⚠️ DECISION 2

PAT batches triples of **32-byte commitments**; `VerifyLogarithmicProof`
structurally requires 32-byte fields. A Dilithium signature is 2,420 bytes and a
public key 1,312, so each field is committed by hash.

For each attested spend, in the order fixed by §4:

| Field | Value |
|---|---|
| `sig` | `SHA3-256(witness.stack[0])` — the signature exactly as it appears in the witness |
| `pk`  | `SHA3-256(canonical public key)` — see below |
| `msg` | the **sighash** already computed for that input's verification |

`SHA3-256` is PAT's own hash (`PatHash` in `logarithmic.cpp`), used here for
consistency with the proof's internal hashing.

### ⚠️ The public-key encoding duality

Soqucoin accepts **two encodings of the same key**: the bare 1,312-byte form and
a `0x00`-prefixed 1,313-byte form (FIPS 204 Table 3). `VerifyScript` strips the
prefix before hashing to compare against the witness program
(`interpreter.cpp:1921-1924`). This is tracked as bead
`dilithium-pubkey-encoding-duality-flpa`.

**Specified:** `pk` commits to the **stripped canonical form** — the same bytes
that are SHA-256'd to produce the witness program — never the raw witness item.

Rationale: the two encodings are the same key, and the attestation should say so.
Committing the raw witness bytes would make the attestation depend on an encoding
choice that consensus already treats as equivalent, so the same block content
under a re-encoded witness would produce a different attestation. That is a
malleability surface pointed straight at a consensus commitment.

⛔ This is a real coupling: if `flpa` is ever resolved by rejecting one encoding,
this rule stays correct but its justification changes. Do not silently invert it.

### The sighash

`msg` is the sighash for that input, as computed by `SignatureHash` with
`scriptCode` = the prevout `scriptPubKey` and `SIGVERSION_WITNESS_V0` — the same
value `CheckSig` used. It must be **taken from the verification that already
happened**, not recomputed independently: two derivations of the same value is
exactly the drift hazard that `Create`/`Verify` carried until PR #65.

⚠️ APO sighash types (`DEPLOYMENT_APO`, dormant) change what the sighash covers.
Since `msg` is whatever the input actually verified against, the attestation
follows automatically — but see §8.

---

## 4. Canonical order

**Implemented and merged** (PR #65). Entries are sorted by the total key
`(PatHash(msg), PatHash(pk), PatHash(sig))` with the entry's original position as
a final tie-break, via `CanonicalOrder` in `crypto/pat/logarithmic.cpp`. Both
`CreateLogarithmicProof` and `VerifyLogarithmicProof` derive it from that one
function.

"Original position" for the attestation is defined as **transaction index within
the block, then input index within the transaction**, ascending, coinbase first.
This must be stated because it is the input to a tie-break: an implementation
that collected tuples in a different order would agree on every batch without
fully identical tuples and disagree on one that has them.

⛔ Pinned by `pat_canonical_ordering_tests.cpp`, including known-answer vectors.
A mismatch there is the chain split, caught in a test.

---

## 5. Empty and oversized batches

- `CreateLogarithmicProof` **returns false for n = 0** (`logarithmic.cpp:184`).
  A block with no attested spends therefore has no attestation. **Specified:**
  such a block MUST NOT carry a PAT commitment, and a commitment present on such
  a block is invalid. A coinbase-only block is the common case here, so this is
  not an edge case — it is every empty block on the chain.
- `n > 2^20` is rejected by the same guard. A block cannot approach this under
  current limits, but the rule is stated so the failure is a defined rejection
  rather than an accumulator that silently produces nothing.

---

## 6. Commitment placement and encoding

An `OP_RETURN` output in the coinbase, following the established in-tree shape
(SegWit's witness commitment, and LatticeFold's accumulator at
`block_accumulator.h:90`):

```
OP_RETURN OP_PUSHBYTES_34 0x50 0x41 <32-byte attestation hash>
```

36 bytes total; magic `PA` (`0x50 0x41`). Does not collide with LatticeFold's
`LF`, and the 36-byte length is distinct from SegWit's 38-byte `aa21a9ed` form.

⛔ **Exactly one.** A block carrying more than one output that parses as a PAT
commitment is **invalid**. The LatticeFold validator instead breaks on the first
match (`validation.cpp:5401-5413`), which makes its behaviour depend on coinbase
output order and lets a miner plant a decoy ahead of the real one. Do not copy
that. (Worth a separate look for LatticeFold itself; it is dormant, so it is not
urgent, but it is the same defect.)

⚠️ A 2-byte magic is a weak tag: any 36-byte `OP_RETURN` beginning with the same
four bytes parses as a commitment. In the coinbase this is miner-controlled, so
a planted decoy is self-harm rather than an attack — the block simply fails to
validate. It is called out because "the tag is weak but the surface is
miner-only" is a reasoning step, not an accident, and the next person should not
have to rediscover it.

---

## 7. Validation and activation

Ratified fail-safe shape: **optional-but-verified at genesis, mandatory at a
scheduled height.**

At genesis:
1. A miner **MAY** emit the commitment.
2. A node that sees one **MUST** verify it: recompute the attestation over the
   block per §2-§5 and compare. Mismatch ⇒ reject the block.
3. A block **without** one is valid.

After the scheduled height, a block with attested spends and no commitment is
invalid.

Rationale: a mandatory-from-genesis rule means a bug in commitment computation
halts the chain. Optional-but-verified gives full PAT function from block 1 with
no chain-halt risk, and uses `DeploymentActiveAtHeight` exactly as
`DEPLOYMENT_PRECONDITIONS.md` rule 1 prescribes.

⛔ Note this differs from LatticeFold's shape, which is *mandatory whenever the
block has confidential outputs* (`bad-blk-missing-latticefold-commitment`,
`validation.cpp:5416`). Do not copy that shape here; it is the chain-halt posture
the ratified plan deliberately rejected.

Reject reasons, named so tests can pin them by string:

| Condition | Reject reason |
|---|---|
| Commitment present, recomputation differs | `bad-blk-pat-commitment` |
| More than one PAT commitment in the coinbase | `bad-blk-pat-commitment-duplicate` |
| Commitment present on a block with no attested spends | `bad-blk-pat-commitment-empty` |
| Attested spends present, no commitment, past the mandatory height | `bad-blk-missing-pat-commitment` |

---

## 8. Determinism hazards

The whole risk surface, collected so it can be reviewed as a list:

1. **Tie-breaking in the ordering.** Closed by PR #65 and pinned by vectors. This
   was a live defect, not a hypothetical.
2. **The attested set changing under deployment activation** (§2). Open —
   Decision 1.
3. **Public-key encoding duality** (§3). Addressed by committing the canonical
   stripped form; coupled to bead `flpa`.
4. **Sighash provenance.** `msg` must come from the verification that happened,
   not a second derivation.
5. **APO sighash types.** Dormant. When `DEPLOYMENT_APO` activates, the set of
   bytes a sighash covers changes; the attestation inherits that automatically,
   but the activation review must confirm it.
6. **Iteration order** feeding the positional tie-break (§4).
7. **Digest blindness.** The consensus digest currently absorbs PAT proof bytes
   only for distinct-message batches, so it cannot detect an ordering regression
   — see §9.

---

## 9. Digest and cross-build evidence

The attestation is consensus crypto, so it must be inside the consensus digest
and swept across optimisation levels and platforms by
`contrib/f4-digest-sweep.sh`.

⛔ **Two things go into the same deliberate re-pin, and they are not the same
thing:**

1. The block attestation itself.
2. **A duplicate-message PAT batch added to `AbsorbOpcodeVerdicts`.** The digest
   already absorbs PAT proof bytes, but only for batches built by
   `BuildValidPatScript`, whose messages are all distinct (`0x70+i`). Its
   material therefore never reaches the tie path — the digest did **not** move
   when the canonical ordering was corrected in PR #65. Without this, the F4
   sweep does not cover canonical ordering, which is the highest-risk element of
   the plan. Bead `pat-canonical-ordering-not-total-97dz` stays open until it
   lands.

One re-pin, one sweep. The general lesson, recorded because it has now recurred
three times in this epic: **ask what input would make the check fail, not just
what it absorbs.**

---

## 10. Decisions needed before implementation

1. **The attested set (§2).** Confirm v0/v1/v7/v8 by rule, with v6 and the v5/v9
   authority markers explicitly excluded — and confirm the intent that activating
   USDSOQ or BTCSOQ *does* extend the attested set from that height forward,
   rather than the set being frozen at its genesis membership. Both are
   defensible; they must not be left to the implementation.
2. **The public-key commitment (§3).** Canonical stripped form (recommended) vs
   raw witness bytes.

The magic bytes (§6) are specified as `PA` rather than left open — there is no
tradeoff to rule on, only a collision to avoid.

---

Related: `DL-PAT-COMPLETION-PLAN-2026-08-31.md`, `DEPLOYMENT_PRECONDITIONS.md`,
`crypto/pat/logarithmic.h`, beads `pat-completion-epic-xlab`,
`pat-canonical-ordering-not-total-97dz`, `dilithium-pubkey-encoding-duality-flpa`.
