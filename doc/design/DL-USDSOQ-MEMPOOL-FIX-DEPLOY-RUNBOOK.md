# USDSOQ Mempool Crash Fix — Fleet Deploy Runbook (Buddy handoff)

**Fix branch:** `consensus/usdsoq-mempool-crash-fix` (repo `soqucoin/soqucoin`), tip `e860a6409`
**Spec:** `doc/design/DL-USDSOQ-MEMPOOL-CRASH-FIX.md`
**Staged binary (REBUILT — now contains Bug 2 + BUG-18):** Services VPS `143.110.229.69:/usr/local/bin/soqucoind.usdsoqfix`
- version `v1.4.0.0-e860a6409`, sha256 `e61e727ccac0bfaf6ab739f6ad6708fd138f537c4082e6c4a2cac066a2f3d6cd`
- Linux x86-64 ELF, built on the Services VPS from the fix branch.
- ⚠️ Supersedes the earlier `625ecd23…` binary (that one had only Bug 2). Deploy THIS one.

## What this fixes (TWO critical bugs, both in this binary)

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

Both are **backward-compatible** (block validity unchanged) and verified by unit
tests (`mempool_tests`, the v7 conservation harness incl. the dry-run-no-leak
regression, plus the USDSOQ/freeze suites — all green). NOT yet live-proven;
this deploy is the proof. NOTE: running nodes may hold an inflated in-memory
supply — a restart reloads the correct value from LevelDB (the persist was
always `!fJustCheck`-gated), so the redeploy self-heals it.

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
5. Verify: `soqucoind ... --version` == `v1.4.0.0-e860a6409`; node reaches the
   current tip and stays up (`getblockcount`, no assertion in the journal).

## Post-deploy verification (the live proof)

1. **Clean-reject, no crash:** submit a deliberately non-conserving USDSOQ tx
   (or just retry the app send below) and confirm the node returns
   `bad-txns-usdsoq-not-conserved` and STAYS UP (no `Assertion ... failed` in the
   journal, no systemd restart).
2. **Real send works** (needs the app fix too — repo `soqucoin-ops`, branch
   `feat/usdsoq-balance-v7-index`, rebuild the sim): SoquShield → Send → USDSOQ →
   100 to self → approve → broadcasts. Then verify on-chain the v7→v7 transfer
   conserved (supply unchanged) and both scripthashes re-indexed.

## App side (same handoff)

Rebuild SoquShield from `soqucoin-ops` branch `feat/usdsoq-balance-v7-index`
(carries the USDSOQ send asset-isolation + v7-input-scriptPubKey fixes, the
balance/UTXO API v7 queries, and the privacy de-claw). The node fix + the app
fix are BOTH required for the send to complete.
