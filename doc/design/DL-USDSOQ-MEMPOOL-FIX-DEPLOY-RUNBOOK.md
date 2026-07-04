# USDSOQ Mempool Crash Fix — Fleet Deploy Runbook

**Fix branch:** `consensus/usdsoq-mempool-crash-fix` (repo `soqucoin/soqucoin`), tip `5e5876763`
**Spec:** `doc/design/DL-USDSOQ-MEMPOOL-CRASH-FIX.md`
**Staged binary (REBUILT — Bug 2 + BUG-18 + BUG-19 + BUG-20 + mempool-flag mirror):** Services VPS `143.110.229.69:/usr/local/bin/soqucoind.usdsoqfix`
- version `v1.4.0.0-5e5876763`, sha256 `e5049bd89003ed883b2c04a3e0935ff86f75276bedf6e6fa2ed8093c28b2e2c1`
- Linux x86-64 ELF, built on the Services VPS from the fix branch.
- ⚠️ Supersedes `095b67c2…`, `e61e727c…`, `625ecd23…`. Deploy THIS one.

## What this fixes (FIVE bugs, all in this binary)

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

**BUG-21 — mempool accepted txs that block validation rejects (the real empty-block
cause; found live 2026-07-04).** `AcceptToMemoryPool` omitted `SCRIPT_VERIFY_PAT`,
`LATTICEFOLD`, `LATTICEBP` and `USDSOQ` — flags `ConnectBlock` enforces — so a v7
USDSOQ input was verified leniently (anyone-can-spend) at accept time. A mis-signed
v7 send (app signed the v7 input against the v1 scriptCode → NULLFAIL) therefore
relayed fine but could never be mined, stalling every block template → empty blocks
(live tx `daf9fd85`). Now the mempool mirrors ConnectBlock's flags (same activation),
so such a tx is rejected up front. **Deploy side effect (good): on restart, the
`mempool.dat` reload re-runs ATMP with the new flags, so the stuck mis-signed
`daf9fd85` is REJECTED on reload and auto-evicted — no manual mempool clearing
needed.** (The paired app-signing fix is soqucoin-ops `feat/usdsoq-balance-v7-index`
— the app now signs v7 inputs against OP_7; both are needed for a real send to work.)

All four consensus bugs are **backward-compatible** (block validity rules unchanged for any
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
5. Verify: `soqucoind ... --version` == `v1.4.0.0-5e5876763`; node reaches the
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
   `5e5876763` — a mixed fleet with an old node re-inflates the supply or
   re-accepts the mis-signed tx.
3. **Burn drops supply (BUG-20 proof):** run the drill's burn step and confirm
   `outstanding` DECREASES by the burned amount (before this binary a burn
   confirmed but supply stayed flat).

## App side (same handoff)

Rebuild SoquShield from `soqucoin-ops` branch `feat/usdsoq-balance-v7-index`
(carries the USDSOQ send asset-isolation + v7-input-scriptPubKey fixes, the
balance/UTXO API v7 queries, and the privacy de-claw). The node fix + the app
fix are BOTH required for the send to complete.

---

## 2026-07-04 ADDENDUM — the deploy was INCOMPLETE: the 3 Hetzner pool daemons were missed

**Incident (2026-07-04 16:41 UTC).** The drill's burn step (`d10c651d…566c`,
100 USDSOQ, authority burn = non-conserving by design) was broadcast from the
signer. It was ATMP-accepted and template-included on Broadcast (the BUG-20/21
policy behavior working as designed), then relayed over P2P to the SOQUPOOL
Hetzner daemons — which were still on `v1.4.0.0-8264181ef-dirty` (the v1.4.0
release merge, PRE-dating ALL five fixes). All three hit the exact Bug-2 assert:

```
soqucoind: txmempool.cpp:35: CTxMemPoolEntry: Assertion `inChainInputValue <= nValueIn' failed.
```

systemd auto-restarted all three within ~40s (NRestarts=1, no loop); pool
mining continued (blocks 7567/7568 found after). No payout impact. The burn tx
now sits ONLY in the fixed DO nodes' mempools — the pool nodes crashed during
acceptance, so it never entered their mempools and (having already been
announced once) will NOT re-relay on its own. **The burn cannot mine until the
Hetzner daemons run the fixed binary.**

**Second finding — pool-node supply DBs are CORRUPT.** On restart Hillsboro
logged `Restored supply from DB: total_minted=24800000000000` (248,000 USDSOQ;
true value: 1,000). The old build PERSISTED the BUG-18 dry-run leak (the
`!fJustCheck` persist gate does not exist at `8264181ef`), then re-added +1000
replaying block 7077. ⚠️ The "restart self-heals" note above applies only to
builds that HAVE the persist gate — the Hetzner builds do not. The only correct
repair is a reindex (or fresh resync): the chain is ~7.6k mostly-empty blocks,
so this is minutes-not-hours despite the usual reindex caution.

**Staged binaries (2026-07-04, built per-box from the branch @ `5e5876763` —
lib parity guaranteed):** `/opt/pool/bin/soqucoind.usdsoqfix` on each of
Hillsboro `5.78.192.237`, Nuremberg `116.203.230.200`, Singapore `5.223.50.163`.
All three are byte-identical: version `v1.4.0.0-5e58767`, sha256
`2442b590a9bdbea8be8e0146d4ba3ba94e654c13d429ab58d9420e0c21981b15`.
(The version string abbreviates the commit to 7 chars — same `5e5876763`.)

### Per-node completion steps (ROLLING, one box at a time — Casey/coordinated;
### stop/restart + reindex are DCG-gated)

For each of Hillsboro → Nuremberg → Singapore (2/3 keep mining SOQ while one
reindexes; LTC/DOGE stratum is unaffected):

1. `sha256sum /opt/pool/bin/soqucoind.usdsoqfix` — matches the build log.
2. `cp /opt/pool/bin/soqucoind /opt/pool/bin/soqucoind.bak-20260704`
3. `systemctl stop soqucoind` (pool-server stays up; SOQ jobs stall on this box only)
4. `cp /opt/pool/bin/soqucoind.usdsoqfix /opt/pool/bin/soqucoind`
5. One-time reindex to heal the supply DB: add `-reindex` to ExecStart (or run
   once via a drop-in), `systemctl daemon-reload && systemctl start soqucoind`,
   wait for tip (watch `getblockcount` — expect minutes), then REMOVE the
   `-reindex` flag and `daemon-reload` again (do NOT leave it — every future
   restart would reindex).
6. Verify: `--version` → `v1.4.0.0-5e5876763`; `getusdsoqstatus` →
   `total_minted=1000, outstanding=1000` (pre-burn) — the corrupt 249,000 is gone;
   journal clean of asserts.
7. Next box.

### After ALL THREE are upgraded — finish the burn drill

The burn will not re-announce by itself. Re-submit it once:

```
# on Broadcast (64.23.129.28):
RAW=$(soqucoin-cli getrawtransaction d10c651d86a30ab20a8f537215448e69111289336d5b1425af625a54a197566c 0)
# on any upgraded pool box:
soqucoin-cli sendrawtransaction $RAW
```

Then confirm it MINES and `getusdsoqstatus` shows
`total_burned=100, outstanding=900` on every node (BUG-20 live proof).

⚠️ Do NOT broadcast ANY further USDSOQ tx (send/burn/mint) until all three
Hetzner daemons run `5e5876763` — any non-conserving authority tx re-crashes
the unfixed miners (this is exactly what happened at 16:41 UTC).

---

## 2026-07-04 DEPLOY #3 — enforcement-height recalibration + BUG-22 (commit `92522497e`)

Status when this section was written: burn PROVEN (block 7595, supply 900),
full 8-instance fleet on `5e5876763`.

**What this deploy carries (two commits on top of `5e5876763`):**

1. **`c7f870cd9` — stagenet `nUSDSOQAuthorityEnforcementHeight` 37201 → 7700**
   (Casey-ratified 2026-07-04). The stale pre-reset value exempted authority-sig
   verification AND silently no-opped freeze/unfreeze registry application until
   ~block 37201. All existing authority txs (mint 6501, send 7077, burn 7595)
   stay below 7700, so historical validation is unchanged; full enforcement
   (mainnet-shape) engages at 7700. Mainnet untouched (height 0).
2. **`92522497e` — BUG-22: ATMP rejects spends of frozen USDSOQ outpoints.**
   Same divergence class as BUG-21: a frozen-coin spend is script-valid, so
   without this the first freeze drill's "try to spend the frozen coin" step
   would have relayed a template-poisoning tx → empty blocks (chain-halting
   DoS). Regression-tested; found by inspection before any freeze existed.
   Also fixes the unit-test fixture to wire the `pcoinsdbview` global like
   production (it was silently NULL in every unit test). Full suite 575/575.

**⏰ DEADLINE: all 8 instances must be restarted on `92522497e` BEFORE block
7700.** (Tip was 7611 when staged; ~16-20 blocks/h → several hours of margin.)
If 7700 is somehow crossed first: no immediate risk (only WE create authority
txs — do NOT fire any freeze/mint/burn until the fleet is uniform), finish the
rollout, then proceed.

**No reindex this time** — both changes affect only future blocks/mempool
policy. Plain rolling binary swap + restart, same order and steps as the
Hetzner completion above (skip step 5's reindex). Staged 2026-07-04:
- Hetzner (per-box builds, byte-identical x3): `/opt/pool/bin/soqucoind.usdsoqfix`
  version `v1.4.0.0-9252249`, sha256
  `cb5e26ec5357296dbcb88c43fd7c718a9ebafc4344f1c5850c42cdfb48f05017`
- Services (for the DO fleet, copy with lib parity as before):
  `/usr/local/bin/soqucoind.usdsoqfix` version `v1.4.0.0-92522497e`, sha256
  `31da956b21287e87765557132d2e05f6d93f09bca3a86fdce5ad674674113998`
Verify `--version` per node and that `getusdsoqstatus` still shows
minted 1000 / burned 100 / outstanding 900 after restart.

### FREEZE drill (after fleet uniform on `92522497e` AND tip ≥ 7700)

0. Casey guarded swap of the signer: `/usr/local/bin/soq-signer.freezefix`
   (sha `a885a6af…`, freeze/unfreeze endpoints) → `/usr/local/bin/soq-signer`,
   restart `soq-signer`. Also requires `SOQ_SIGNER_AUTHORITY_KEY_FILE` (already
   set for mint/burn).
1. Freeze the wallet's 900-USDSOQ UTXO:
   `POST /api/v1/freeze-usdsoq` with the outpoint
   `03dd0a3abf5c048732ae5df5cc3fb274df35701798e66e8412afaa292e737eef:1`.
2. Wait for the freeze tx to MINE; check the node journal for
   `USDSOQ: FREEZE applied — outpoint …` (this log line only appears ≥ 7700).
3. Attempt to spend the frozen coin from the app (or a signer send-usdsoq) —
   expect a CLEAN reject `bad-txns-spend-frozen-usdsoq` at broadcast (BUG-22),
   chain keeps mining non-empty.
4. `POST /api/v1/unfreeze-usdsoq` same outpoint → mine → journal
   `UNFREEZE applied` → repeat the spend → it must now relay and mine.
5. Supply must remain 900 throughout (freeze/unfreeze are supply-neutral).

⚠️ Ordering note (bead `kp5`): always let a FREEZE confirm before letting
wallets attempt spends of that outpoint. A spend that enters mempools before
the freeze confirms is not evicted until the poisoned node restarts.
