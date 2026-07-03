# DL-USDSOQ-MEMPOOL-CRASH-FIX

**Bug class:** remotely-triggerable node crash (DoS) + missing mempool policy
**Found:** 2026-07-03, live stagenet drill (first-ever USDSOQ *spend* through the mempool)
**Severity:** high — any peer can abort() a node with one crafted USDSOQ tx; also blocks all USDSOQ sends
**Scope:** stagenet today (USDSOQ ALWAYS_ACTIVE); mainnet once USDSOQ activates — must ship before that

## Symptom

A SoquShield USDSOQ send failed with `RpcException(-502)`. Root cause on the node:

```
txmempool.cpp:35: CTxMemPoolEntry::CTxMemPoolEntry(...):
  Assertion `inChainInputValue <= nValueIn' failed.
```

The daemon `abort()`ed; systemd restarted it 30s later. The -502 was the node
dying mid-request. No funds moved (the tx never entered the mempool).

## Why it happens

In the `CTxMemPoolEntry` constructor:

```cpp
CAmount nValueIn = tx->GetValueOut() + nFee;   // GetValueOut() sums ALL assets; nFee is SOQ-only
assert(inChainInputValue <= nValueIn);
```

- `inChainInputValue` (coins.cpp `GetPriority`) sums the **raw** value of confirmed
  inputs — **including** the full USDSOQ nValue.
- `nFee` (validation.cpp ATMP) is the **SOQ-only** fee (`nSOQIn − nSOQOut`), by
  design (USDSOQ value must not count as fee).

For a fully-confirmed-input tx the delta is exactly:

```
inChainInputValue − nValueIn = USDSOQ_in − USDSOQ_out
```

So the assert fires **iff USDSOQ is not conserved** (a deficit spend). A valid
conserving send gives 0 (holds); an authority mint gives USDSOQ_out ≥ USDSOQ_in,
i.e. a negative delta (holds) — which is why the mint never crashed and only a
*spend* exposed this.

The consensus rule that rejects non-conserving USDSOQ (`bad-txns-usdsoq-not-conserved`
in `Consensus::CheckTxInputs`) DOES run in the mempool path — but via `CheckInputs`
at validation.cpp ~1057, **~200 lines after** the `CTxMemPoolEntry` is constructed
(~834). The crashing assert fires first. Unit tests never caught it because they
drive `ConnectBlock`, not `AcceptToMemoryPool`, and no USDSOQ UTXO had ever been
spent on-chain before this drill.

## Fix (two layers)

**1. Correctness — reject early (validation.cpp, AcceptToMemoryPool).**
Run the USDSOQ per-asset conservation check *before* constructing the
`CTxMemPoolEntry`, mirroring the ConnectBlock rule (authority/OP_5 txs exempt).
A non-conserving USDSOQ tx is now rejected cleanly with
`bad-txns-usdsoq-not-conserved` — mempool policy matches block-validation
consensus, and the bad tx never reaches the entry constructor.

**2. Never-crash hardening (txmempool.cpp).**
A node must never `abort()` on a peer's transaction. `inChainInputValue` only
feeds the priority heuristic, so the fatal `assert` is replaced with a clamp:
if `inChainInputValue > nValueIn`, log and clamp to `nValueIn`. This removes the
crash primitive entirely, independent of any single validation ordering.

Together: layer 1 makes the node *behave correctly* (clean reject); layer 2
guarantees it *cannot crash* here even if some future path builds an imbalanced
entry.

## Tests

- `mempool_tests.cpp::MempoolEntryNoCrashOnUsdsoqImbalance` — constructs an entry
  with `inChainInputValue ≫ GetValueOut()+fee`; asserts no abort + value clamped.
  (Before the fix this test kills the test binary.)
- Regression: `usdsoq_tests`, `usdsoq_authority_tests`,
  `usdsoq_v7_conservation_harness_tests`, `freeze_registry_tests` all still green.

## Deploy note

This is a node consensus-path change. It must be built and rolled to the whole
node fleet in lockstep (Services + Broadcast + Mining/pool + any ElectrumX-backing
node) — a Casey-gated operation. The fix is backward-compatible: it only adds a
rejection for txs that are already consensus-invalid, and removes an abort; it
does not change what blocks are valid.

## Related app-side bug (separate arc — Bug 1)

The proximate trigger was SoquShield's tx_builder computing USDSOQ `change =
totalInput − amount − SOQ_fee`, i.e. deducting the SOQ fee out of the USDSOQ
value and emitting no SOQ input/output — producing the non-conserving tx. Fixed
separately by porting the signer's two-asset-set construction (USDSOQ inputs
fund USDSOQ recipient+change exactly; separate SOQ inputs pay the fee). This node
fix stands on its own: the node must reject such txs cleanly regardless of who
sends them.
