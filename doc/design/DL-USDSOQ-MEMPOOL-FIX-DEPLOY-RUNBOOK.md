# USDSOQ Mempool Crash Fix — Fleet Deploy Runbook (Buddy handoff)

**Fix branch:** `consensus/usdsoq-mempool-crash-fix` (repo `soqucoin/soqucoin`), tip `a982ee25b`
**Spec:** `doc/design/DL-USDSOQ-MEMPOOL-CRASH-FIX.md`
**Staged binary (REBUILT — now contains Bug 2 + BUG-18 + BUG-19 + BUG-20):** Services VPS `143.110.229.69:/usr/local/bin/soqucoind.usdsoqfix`
- version `v1.4.0.0-a982ee25b`, sha256 `095b67c25e558c2c41d067ecbb2838a03c577a455f664257ed8d04cff35597c9`
- Linux x86-64 ELF, built on the Services VPS from the fix branch.
- ⚠️ Supersedes the earlier `e61e727c…` (Bug2+BUG-18) and `625ecd23…` (Bug2-only) binaries. Deploy THIS one.

## What this fixes (FOUR bugs, all in this binary)

**Bug 2 — node crash on USDSOQ spend.** A non-conserving USDSOQ spend crashed
the node (`CTxMemPoolEntry` assert → abort) — remotely-triggerable DoS.
Mempool acceptance now rejects non-conserving USDSOQ txs cleanly and the entry
constructor clamps instead of asserting.

**BUG-18 — USDSOQ supply-accumulator leak in dry-run validation (found live).**
`ConnectBlock` mutated the global supply counter even during `fJustCheck` dry-runs
(`TestBlockValidity`, run on every `getblocktemplate` poll) with no rollback, so
the counter inflated ~1000→137000 after ~140 polls; `TestBlockValidity` then
failed and the pool mined ~570 empty (coinbase-only) blocks, blocking ALL USDSOQ
confirmation. Now the delta is validated on a copy and committed only on a real
connect (`!fJustCheck`).

**BUG-19 — plain USDSOQ transfers inflated the supply (found live; this was the
remaining empty-block cause after BUG-18).** `ConnectBlock` counted EVERY
transparent v7 output as "minted", so an ordinary v7→v7 send added its amount to
the supply every time (the burn side couldn't offset it — see BUG-20). The
inflated supply then failed the block template carrying the send. Fix: supply is
moved only by AUTHORITY txs (OP_5 marker); a transfer is now supply-neutral.
Mirrored in `DisconnectBlock` so reorgs only reverse authority-tx deltas.

**BUG-20 — authority burns didn't decrement the supply (latent; would have
surfaced at the burn step).** The burned-input counter read the coins view after
`UpdateCoins` had already spent the inputs, so it was silently always 0 — a burn
tx confirmed but the supply never dropped. Fix: read the spent prevouts from the
block undo (same source `DisconnectBlock` uses), gated on `isAuthorityTx`. Supply
accounting is now correct for mint (+outputs), pure burn (−inputs), and
burn-with-change (outputs−inputs = net burned).

All four are **backward-compatible** (block validity rules unchanged for any
already-valid block) and verified by unit tests — `mempool_tests`, the v7
conservation harness (7 cases: the SOQ→v7 rejection, v7→v7 conservation, the
BUG-18 dry-run-no-leak regression, the BUG-19 `v7_send_connects_with_prior_minted_supply`
regression, and the BUG-20 `v7_authority_burn_decrements_supply` regression),
plus the usdsoq/authority/v7-holding/freeze/covenant/ctxout suites — all green.
BUG-19/20 are NOT yet live-proven; this deploy + the send/burn drill steps are
the proof. NOTE: a restart reloads the correct supply from LevelDB (persist was
always `!fJustCheck`-gated), so the redeploy self-heals any inflated in-memory value.

## ⚠️ Binary-parity caveat

The staged binary links against the Services VPS system libs (boost 1.83.0,
db_cxx-5.3, libevent 2.1, libzmq5). **Only copy it to another node if that node
has the same lib versions** — check with `ldd` on the first target. If versions
differ, build per-VPS from the branch instead (the safe, canonical path):

```
cd /opt && git clone -b consensus/usdsoq-mempool-crash-fix \
  https://github.com/soqucoin/soqucoin.git soqucoin-usdsoqfix && \
cd soqucoin-usdsoqfix && ./autogen.sh && ./configure --without-gui --disable-bench && \
make -j$(nproc)   # real binary at src/.libs/soqucoind
```

## Fleet — must deploy in LOCKSTEP (all chain-backing nodes)

USDSOQ is ALWAYS_ACTIVE on stagenet; a mixed fleet (some patched, some not)
means unpatched nodes still crash on the same tx. Deploy to ALL:
- Services `143.110.229.69` (stagenet node behind ElectrumX + the balance API)
- Broadcast `64.23.129.28` (soqucoind-broadcast — the node the signer + app hit via staging-rpc)
- Any pool / Mining node still backing the chain
- Monitoring node if it runs one
Confirm the full node set from the fleet topology before starting.

## Per-node steps (systemctl stop/restart is DCG-gated — Casey/coordinated)

1. Verify sha of the binary you're installing.
2. Back up the current binary (`cp /usr/local/bin/soqucoind{,.bak-YYYYMMDD}`).
3. Install the new binary in place.
4. `systemctl restart soqucoind-<role>` (per node role).
5. Verify: `soqucoind ... --version` == `v1.4.0.0-a982ee25b`; node reaches the
   current tip and stays up (`getblockcount`, no assertion in the journal).

## Post-deploy verification (the live proof)

1. **Clean-reject, no crash:** submit a deliberately non-conserving USDSOQ tx
   (or just retry the app send below) and confirm the node returns
   `bad-txns-usdsoq-not-conserved` and STAYS UP (no `Assertion ... failed` in the
   journal, no systemd restart).
2. **Send now CONFIRMS (BUG-19 proof):** the earlier send `daf9fd85` was
   mempool-flushed, so re-broadcast a fresh v7→v7 send (SoquShield → Send →
   USDSOQ → 100 to self → approve, with the app fix below; or via the signer).
   Then confirm it gets MINED into a real block (not just accepted) and that
   `getusdsoqsupply`/the balance API shows `outstanding` UNCHANGED across the
   send (a transfer is supply-neutral). Empty blocks around the send = BUG-19 not
   deployed. ⚠️ Do NOT re-broadcast until ALL chain-backing nodes run
   `a982ee25b` — a mixed fleet with an old node re-inflates the supply.
3. **Burn drops supply (BUG-20 proof):** run the drill's burn step and confirm
   `outstanding` DECREASES by the burned amount (before this binary a burn
   confirmed but supply stayed flat).

## App side (same handoff)

Rebuild SoquShield from `soqucoin-ops` branch `feat/usdsoq-balance-v7-index`
(carries the USDSOQ send asset-isolation + v7-input-scriptPubKey fixes, the
balance/UTXO API v7 queries, and the privacy de-claw). The node fix + the app
fix are BOTH required for the send to complete.
