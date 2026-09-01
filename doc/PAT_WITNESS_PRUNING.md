# PAT witness pruning — specification (route R1)

**Status:** SPECIFICATION, pre-implementation. Phase 5 of the PAT completion
epic (`pat-completion-epic-xlab`), ruled route **R1** (compaction rewrite) on
2026-08-31; route R2 (split witness storage) is a post-launch migration once R1
proves the semantics.

**Scope boundary, stated first because it shapes every rule below:** witness
pruning is **local node policy, not consensus**. No rule in this document
affects block validity, and none of it may move the consensus digest; the
implementation asserts that. What this document fixes precisely is the node's
own storage behaviour and, critically, what it tells the network it can serve.
A node that silently serves less than it advertises breaks other nodes' sync,
which is the one way local policy becomes a network problem.

**What it delivers.** The storage benefit PAT was researched for: a node may
discard the raw witness data (Dilithium signatures, ~2,420 bytes each, and
public keys, ~1,312 bytes) of attested spends past the finality horizon, while
retaining every transaction's base data and the per-block attestation. The
attestation commitment lives in a coinbase *output*
(`doc/PAT_BLOCK_ATTESTATION.md` §6), which is base data, so it survives witness
pruning with no special handling. That is a designed property, not a
coincidence.

---

## 1. Definitions

- **Witness-pruned block**: a block stored re-serialized with
  `SERIALIZE_TRANSACTION_NO_WITNESS`. Transaction ids (which exclude witness
  data by construction) and the block's transaction merkle root are unchanged;
  the block header is untouched. All witness data is removed, including the
  coinbase witness (the SegWit commitment nonce).
- **The horizon**: `nMaxReorgDepth` (288 on mainnet). A block is *eligible* for
  witness pruning when its depth below the active tip strictly exceeds the
  horizon and it has been fully validated by this node
  (`BLOCK_VALID_SCRIPTS`). Consensus already refuses reorganizations deeper
  than the horizon, so an eligible block's witnesses can never again be needed
  for validation by this node.
- **`BLOCK_WITNESS_PRUNED`**: a new `BlockStatus` flag (bit 256, the next free
  bit after `BLOCK_OPT_WITNESS`) recording per block-index entry that the
  stored data is the stripped form.

## 2. What a witness-pruned node can and cannot do

Retained, per block, forever:

- Every transaction's base serialization: ids, amounts, scripts, the UTXO
  history.
- The full coinbase including the PAT attestation commitment and the SegWit
  commitment output (the outputs are base data; only the witness *nonce* is
  stripped).
- Undo data (`rev*.dat`), untouched by this feature.

Lost, per pruned block, accepted deliberately:

- The ability to re-verify signatures, the SegWit witness commitment, or the
  PAT attestation of that block. The node trusts its own prior validation,
  exactly as whole-file pruning already does upstream. Consequently
  **`-reindex` on a witness-pruned datadir must refuse to start** with an
  error naming the redownload path; a reindex that silently skipped script
  validation would manufacture a node that believes without having checked.
- The ability to serve that block to peers (see §4).

## 3. Mechanics — R1 compaction

Granularity is the **block file**, matching the existing prune
infrastructure's unit: a `blk*.dat` file is compacted only when every block in
it is eligible (§1). Per-block rewriting inside a shared file would fragment
it and complicate crash recovery for no benefit at the finality horizon, where
whole trailing files age out together.

Compaction of file *n* writes the stripped data to a **new file number** *m*
(allocated from the same `blk*.dat` series; nothing requires file numbers to be
height-ordered, since every read goes through `nFile`/`nDataPos`). The original
file is never modified in place, which is what removes the crash window
entirely:

1. Read every block in file *n*; re-serialize each with
   `SERIALIZE_TRANSACTION_NO_WITNESS` into file *m*, with fresh per-block
   offsets. Flush and fsync file *m*.
2. Update every affected `CBlockIndex` entry (`nFile` = *m*, new `nDataPos`,
   `BLOCK_WITNESS_PRUNED`) and the `CBlockFileInfo` records, and flush the
   block index durably.
3. Delete file *n*, only after step 2 has succeeded.

Crash analysis, the property this ordering is chosen for: **at every instant
the index points only at data that exists on disk.** A crash before step 2
leaves the index on file *n*, which is intact; the partial or complete file
*m* is inert and is re-created or garbage-collected on the next pass. A crash
between steps 2 and 3 leaves the index durably on file *m*, which was fsynced
before the index moved; the original file *n* is an orphan, deleted on the
next pass. There is no state in which reads resolve into a file whose contents
do not match the recorded positions.

An earlier draft of this section renamed the replacement over file *n* and
ordered the index flush around the rename. Both orders of that design have a
broken window (index flushed first points at offsets the old file does not
have; rename first leaves old offsets against the new, smaller file), and
patching it requires a saved original and a startup recovery pass. Writing to
a fresh file number needs neither, because the only destructive operation is
the last step and it acts on data the index no longer references. Found in
review; recorded so the rename design does not come back as a simplification.

Compaction runs opportunistically at the same trigger points as
`FindFilesToPrune` (post-flush, off the validation hot path). It must never
hold `cs_main` across file I/O for a whole file; take positions under the
lock, rewrite outside it, retake to commit the index update.

`-reindex` refuses on any datadir whose index carries `BLOCK_WITNESS_PRUNED`
(§2). `getblock` and transaction RPCs serve the stripped form; witness fields
are absent, which is the truthful answer.

## 4. Network contract — the part that must not be improvised

The hazard named in the completion plan: a pruned node that keeps advertising
full service silently breaks other nodes' initial sync, because IBD peers need
witnesses to validate scripts. The window arithmetic is deliberate: the BIP159
`NODE_NETWORK_LIMITED` contract is "serves the last 288 blocks", and 288 is
exactly `nMaxReorgDepth` and therefore exactly the set of blocks this node
still holds in full. The alignment is adopted, not coincidental.

A node with witness pruning enabled:

- **Advertises `NODE_NETWORK_LIMITED` (bit 10, the BIP159 value) instead of
  `NODE_NETWORK`**, and keeps `NODE_WITNESS`: everything within the window is
  stored in full and served in full, witness included.

  The flag does not exist in this codebase yet, and the peer logic assumes the
  full/client dichotomy, so stage 2 is more than setting a bit. The concrete
  touchpoints, verified against the tree so the landing cannot silently be
  partial:

  1. `src/protocol.h`: define `NODE_NETWORK_LIMITED = (1 << 10)`; service
     flags currently end at `NODE_XTHIN = (1 << 4)` and bit 10 is free.
  2. `src/init.cpp:825` (`nLocalServices`): clear `NODE_NETWORK`, set
     `NODE_NETWORK_LIMITED` when witness pruning is enabled. Precedent two
     lines away: `init.cpp:1855` already does exactly this clearing for
     `-prune`.
  3. `src/net_processing.cpp:1465`: `fClient = !(nServices & NODE_NETWORK)`
     classifies a limited peer as a pure client, which would stop us
     requesting within-window blocks from limited peers. The classification
     must learn the third state (limited: usable for recent blocks, never for
     deep IBD).
  4. `src/init.cpp:820` (`nRelevantServices`) and `src/net.cpp:1598` (the DNS
     seed `requiredServiceBits` filter): outbound selection must still prefer
     full nodes while an IBD is in progress, or a fresh node can strand itself
     on limited peers that cannot serve its sync.
  5. The `getdata` block-serving path: enforce the window (§4, both message
     types answered `notfound` beyond it) regardless of what was advertised,
     so the contract holds even against peers that ignore service bits.
- Serves `getdata` for blocks **within** the window normally, both `MSG_BLOCK`
  and `MSG_WITNESS_BLOCK`.
- Answers `getdata` for any block **beyond** the window with `notfound`, for
  both message types, including `MSG_BLOCK`, even though the stripped base
  data exists locally. Serving base-only blocks to a peer that will attempt
  script validation manufactures the silent-break failure mode; the stripped
  data is for this node's own RPC and audit trail, not for relay. This matches
  the BIP159 contract peers already understand.
- Headers service is unaffected; headers are never pruned.

Fleet, pool, and seed nodes run unpruned. Witness pruning is for operators who
choose the trade, which is why the default is off.

## 5. Configuration

- `-witnessprune=1`: enable. Default **0** on every network.
- Mutually exclusive with `-prune`: whole-file pruning already deletes the
  base data this feature exists to retain, so combining them is a
  contradiction; init errors out rather than picking a winner.
- Mutually exclusive with `-txindex=0`? No: the transaction index is optional
  as always. The stripped block data remains readable either way.
- No consensus parameter exists for this feature, deliberately. There is
  nothing to activate and nothing to absorb into the digest.

## 6. Reorganizations at the boundary

Consensus refuses reorgs deeper than `nMaxReorgDepth`, and eligibility
requires depth strictly greater than the horizon, so a reorg can never need a
witness this node has discarded. This is the property that makes witness
pruning safe *at all*, and it is inherited from the finality rule rather than
implemented here. The implementation still asserts it: a request to disconnect
a `BLOCK_WITNESS_PRUNED` block is a hard failure with a named error, because
reaching that state means the finality rule itself was violated and the node
must halt loudly rather than improvise.

## 7. Test plan

1. **Round-trip unit test**: strip a block with attested spends, read it back;
   transaction ids, the merkle root, the PAT commitment output and the SegWit
   commitment output are unchanged; witness stacks are empty.
2. **Eligibility**: a block at depth exactly `nMaxReorgDepth` is not eligible;
   depth `nMaxReorgDepth + 1` is. Uses `UpdateRegtestMaxReorgDepth` to make
   the boundary reachable cheaply.
3. **Index consistency**: after compaction, every affected `CBlockIndex` reads
   back the stripped block from its new file and position; `BLOCK_WITNESS_PRUNED`
   set on exactly the compacted range; the original file number is gone and the
   replacement file number is recorded.
3b. **Crash-window simulation**: interrupt compaction after the replacement
   fsync but before the index flush, and separately after the index flush but
   before the original's deletion; in both states every indexed block reads
   back correctly on restart, and the next pass converges (re-compacts or
   garbage-collects the orphan).
4. **Reindex refusal**: `-reindex` on a pruned datadir fails with the named
   error.
5. **Serving rules, functional**: within-window `getdata` served with witness;
   beyond-window answered `notfound` for both message types; service bits
   advertise `NODE_NETWORK_LIMITED` and not `NODE_NETWORK`.
6. **Sync-from-unpruned, functional**: a fresh node performs IBD from an
   unpruned peer while a pruned node is also connected, and completes; the
   pruned node's presence must not degrade the sync.
7. **Digest**: unmoved before and after the feature, asserted in the same PR
   that lands it. Local policy must be provably local.
8. **Disconnect assertion**: driving a disconnect of a pruned block (regtest,
   reorg-depth setter) halts with the named error rather than proceeding.

## 8. Staging

- **Stage 1**: the stripping serializer round-trip, eligibility logic,
  `BLOCK_WITNESS_PRUNED`, and the compaction rewrite with its crash ordering.
  Everything local, behind the default-off flag. Unit tests 1–4.
- **Stage 2**: the network contract — service bits, `getdata` window rules —
  plus functional tests 5–6 and the digest assertion. The feature is not
  enableable on a network-connected node until stage 2 lands; stage 1 gates
  `-witnessprune` behind `-connect=0`/regtest so the storage semantics can
  soak without a node ever under-serving what it advertises.

---

Related: `doc/PAT_BLOCK_ATTESTATION.md`, `DL-PAT-COMPLETION-PLAN-2026-08-31.md`
(soqucoin-ops, §6), beads `pat-completion-epic-xlab`,
`pat-v2-anyone-can-spend-ae6u`.
