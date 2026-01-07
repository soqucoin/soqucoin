# Soqucoin Fee Recommendation

_Last updated for v1.0 (January 2026)_

The Soqucoin chain has a 1-minute block interval with ~1 megabyte blockspace and aims to provide an affordable means for post-quantum secure transactions.

## Recommended Defaults

Soqucoin Core implements the following fee defaults:

- **0.01 SOQ per kilobyte** transaction fee
- **0.01 SOQ** dust limit (discard threshold)
- **0.001 SOQ** replace-by-fee increments

The wallet rejects transactions with outputs under the dust limit and discards change to fee if it falls under this limit.

**Note**: Fees are calculated over the exact transaction size. For example, a 192-byte transaction pays `0.01 / 1000 * 192 = 0.00192` SOQ fee.

## Post-Quantum Considerations

Soqucoin uses Dilithium signatures (~2,420 bytes) which are larger than ECDSA (~71 bytes). This affects transaction size:

| Transaction Type | Approx. Size | Approx. Fee |
|------------------|--------------|-------------|
| Simple send (1 input, 2 outputs) | ~2.6 KB | ~0.026 SOQ |
| Multi-input (5 inputs, 2 outputs) | ~12 KB | ~0.12 SOQ |
| PAT-aggregated batch | Varies | Reduced via aggregation |

## Miner Default Inclusion Policies

The default minimum fee for block inclusion is **0.01 SOQ/kB**, matching the recommended fee.

## Relay and Mempool Policies

Relay policies are set lower than recommendations to allow future adjustments:

### Transaction Fee

- **Minimum relay fee**: 0.001 SOQ/kB (one-tenth of recommended)

### Dust Limits

- **Hard dust limit**: 0.001 SOQ — outputs under this are rejected
- **Soft dust limit**: 0.01 SOQ — outputs under this require additional fee

### Replace-by-Fee Increments

The RBF increment is set at one-tenth of the relay fee: **0.0001 SOQ**.

## Verification Cost Considerations

For transactions with advanced proof systems, verification costs are tracked separately from byte-based fees. See `pqestimatefeerate` RPC command for cost estimation.

---

*See [CONSENSUS_COST_SPEC.md](CONSENSUS_COST_SPEC.md) for detailed verification cost model.*
