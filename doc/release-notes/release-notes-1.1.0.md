# Soqucoin Core 1.1.0

Soqucoin Core 1.1.0 is a security release fixing critical USDSOQ consensus bugs.
This release is **required** for all stagenet nodes and recommended for all
testnet/development installations.

## Upgrade Instructions

1. Stop your node: `systemctl stop soqucoind-<role>`
2. Replace binary: `cp soqucoind /usr/local/bin/`
3. Start your node: `systemctl start soqucoind-<role>`
4. No reindex required. No configuration changes needed.

## Security Fixes

### Critical (P0)

- **DisconnectBlock supply counter reversal (C1)**: During blockchain reorganizations,
  the USDSOQ supply counter read from LevelDB to "restore" pre-mint values. However,
  LevelDB already contained the post-ConnectBlock values, making the read circular and
  the reversal a no-op. After a reorg involving USDSOQ mints, the supply counter would
  show inflated `Outstanding()` values. Fixed by adding explicit `UndoMint()` and
  `UndoBurn()` methods with checked arithmetic.

- **Reversed burn count always zero (C2)**: The DisconnectBlock loop counted USDSOQ
  outputs being removed (reversed mints) but never iterated inputs to count reversed
  burns. The `nUSDSOQReversedBurn` variable was declared but never incremented, making
  the burn reversal guard dead code. Fixed by iterating `blockUndo.vtxundo` data.

### High (P1)

- **Authority TX script skip forgeability (H1)**: `CheckInputs()` skipped standard
  script verification for authority transactions based solely on witness stack
  heuristics (stack size ≥ 6, tag byte 0x55, 2420-byte blobs). These properties are
  forgeable by any transaction. A crafted non-authority TX could bypass script
  verification and enter the mempool. Fixed by adding a mandatory OP_5 output check
  as prerequisite.

- **Bootstrap re-entry guard (H2)**: When the authority outpoint was null (not yet
  bootstrapped), the bootstrap path accepted any input as authority carrier. If the
  outpoint was ever reset (DB corruption, partial reindex), the bootstrap path would
  reopen with different security properties. Fixed by checking LevelDB for an existing
  authority outpoint before allowing bootstrap.

- **Frozen UTXO guard scope (H3)**: The frozen mask check (`nVisibility & 0x80`)
  applied to all asset types. If a SOQ output somehow got the frozen bit set (future
  bug, database corruption), it would become permanently unspendable. Fixed by adding
  `nAssetType == ASSET_USDSOQ` check.

## New Features

- `CUSDSOQSupply::UndoMint(CAmount amount)` — Safely reverses a mint operation during
  DisconnectBlock. Uses checked arithmetic to prevent underflow.
- `CUSDSOQSupply::UndoBurn(CAmount amount)` — Safely reverses a burn operation during
  DisconnectBlock. Uses checked arithmetic to prevent underflow.

## Test Coverage

- **503 test cases**, all passing (up from 496 in v1.0.0)
- 7 new tests for supply counter undo operations:
  - `supply_mint_undo_roundtrip`
  - `supply_burn_undo_roundtrip`
  - `supply_undo_mint_rejects_excess`
  - `supply_undo_burn_rejects_excess`
  - `supply_undo_mint_respects_outstanding_invariant`
  - `supply_undo_rejects_zero_amount`
  - `supply_full_reorg_scenario`

## Files Changed

| File | Changes |
|------|---------|
| `src/consensus/usdsoq.h` | Added `UndoMint()`, `UndoBurn()` declarations |
| `src/consensus/usdsoq.cpp` | Added `UndoMint()`, `UndoBurn()` implementations (40 LOC) |
| `src/validation.cpp` | Fixed DisconnectBlock supply reversal, CheckInputs authority skip, bootstrap guard, frozen UTXO scope |
| `src/test/usdsoq_authority_tests.cpp` | Added 7 supply counter test cases |
| `src/clientversion.h` | Version bump 1.0.0 → 1.1.0 |
| `configure.ac` | Version bump, release date update |
| `CHANGELOG.md` | v1.1.0 entry |

## Credits

- Buddy (Antigravity AI) — audit, implementation, testing
- Casey Wilson — review, approval
