# Soqucoin v1.5.0 — USDSOQ Stablecoin: Freeze Authority and Enforcement

> **Release Date:** July 4, 2026
> **Branch:** `release/v1.5.0`
> **Status:** Release

---

## What Is This Release?

v1.5.0 completes the USDSOQ stablecoin subsystem and proves it end to end on a live chain. The full lifecycle now works under real authority enforcement: mint, transfer, burn, freeze, and unfreeze, each validated on-chain against an M-of-N ML-DSA-44 (post-quantum) authority.

The headline capability is compliance-grade freeze authority. A frozen USDSOQ output cannot be moved by anyone, including the issuer's own burn authority, until it is explicitly unfrozen. This is enforced by consensus and recorded on-chain, so every freeze and release is publicly verifiable.

This release also carries a chain of consensus and policy fixes uncovered while proving the system live, plus the height-gated soft-fork activation groundwork for mainnet.

**Who should run this?**
- Node operators and miners on the current network.
- Anyone integrating USDSOQ issuance, redemption, or compliance workflows.

Deploy to all chain-backing nodes together. USDSOQ policy is active on the network, so a mixed fleet is not supported.

---

## Highlights

### 🪙 USDSOQ lifecycle, proven live
Mint, transfer, burn, freeze, and unfreeze were each exercised on-chain under real authority-signature enforcement. Supply accounting is exact across every operation: mint adds, burn subtracts, and a plain transfer is supply-neutral.

### 🔒 Freeze authority you can verify
Freeze and unfreeze operations write to a consensus-enforced registry. A spend of a frozen output is rejected at both block validation and mempool acceptance, so a frozen coin never even enters a block template. Freeze authority follows GENIUS Act §4(a)(2) semantics and every action is on-chain.

### 🧮 Supply-accounting and mempool-crash fixes
Five defects found while bringing USDSOQ live, all fixed and regression-tested:
- A non-conserving USDSOQ spend could crash the node. It is now rejected cleanly.
- A dry-run validation path leaked into the global supply counter and stalled block production. Supply now commits only on a real connect.
- Plain transfers were counted as new issuance. Supply now moves only for authority transactions.
- Authority burns did not decrement supply. Burned inputs are now read from the block undo.
- The mempool accepted transactions that block validation rejects, poisoning templates. Mempool acceptance now mirrors the block-level script flags.

### 🧊 Frozen-outpoint mempool mirror
Mempool acceptance now also rejects spends of frozen USDSOQ outputs, closing the same accept-then-reject gap for the freeze registry that would otherwise stall templates.

### 🔗 Authority-chain visibility for signers
`getusdsoqstatus` now reports the tracked `authority_outpoint`, which an in-process signer needs to build a correctly chained authority transaction after bootstrap.

### ⚙️ Flag-day soft-fork activation and strict chain id
Height-gated (flag-day) activation for the post-quantum and asset deployments, and `fStrictChainId` enabled so a miner stamps the chain id that AuxPoW validation checks.

---

## Consensus and Policy Notes

- All block-validity changes are backward compatible: any block that was valid before remains valid.
- On mainnet the USDSOQ and PAT deployments are not yet scheduled, so the new mempool script flags are inert until activation.
- The stagenet authority-enforcement height was recalibrated for the current chain so authority-signature verification and freeze-registry application engage as intended.
- Unit test suites (575 cases) pass, including the USDSOQ conservation harness, the freeze registry, and the mempool policy regressions.

---

## Upgrading

Build from source and restart your node. A one-time reindex is only needed on a node whose supply counter was corrupted by a pre-fix binary; a clean node self-heals its supply from disk on restart.

```
./autogen.sh && ./configure --without-gui --disable-bench && make -j$(nproc)
```

Verify after restart:

```
soqucoin-cli getusdsoqstatus
# reports deployment status, supply counters, and the authority_outpoint
```
