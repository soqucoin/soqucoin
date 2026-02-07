# ECDSA Elimination Summary

> **Date**: February 6, 2026
> **Status**: Verified — no ECDSA signing paths reachable in consensus
> **Audience**: Halborn Auditors

---

## Why `secp256k1/` Is Still in the Source Tree

The full `libsecp256k1` library resides at `src/secp256k1/`. This is **inherited** from the Dogecoin Core / Bitcoin Core lineage. It is NOT compiled out because:

1. **Bulletproofs++ (BP++)** — Pedersen commitments use secp256k1 curve arithmetic for range proofs. This is a consensus-critical privacy feature.
2. **ECDSA Adaptor Signatures** — The `ecdsa_adaptor` and `ecdsa_s2c` modules exist in the tree but are not invoked by any Soqucoin consensus or wallet path.

---

## ECDSA Signing Paths: Removed

| Location | Evidence |
|----------|----------|
| `interpreter.cpp:513` | Comment: `"Strict post-quantum script verification — ECDSA paths completely removed"` |
| `init.cpp:697` | Comment: `"Dilithium-only: No ECDSA sanity checks needed"` |
| `init.cpp:1183` | Comment: `"Initialize randomness (Dilithium-only, no ECDSA)"` |
| `script_error.cpp:36` | Returns: `"Classical cryptography (ECDSA) is extinct"` |
| `wallet_tests.cpp:42-46` | Legacy ECDSA wallet tests disabled: `#if 0 // Disabled: ECDSA wallet tests` |

---

## What Remains (Not Reachable for Signing)

| Module | Path | Used For |
|--------|------|----------|
| `secp256k1/` core | `src/secp256k1/src/` | Curve arithmetic for BP++ Pedersen commitments |
| `ecdsa_s2c` | `src/secp256k1/src/modules/ecdsa_s2c/` | **Not invoked** — inherited module, no call sites |
| `ecdsa_adaptor` | `src/secp256k1/src/modules/ecdsa_adaptor/` | **Not invoked** — inherited module, no call sites |

---

## Consensus-Level Enforcement

All transaction signing in Soqucoin uses Dilithium (ML-DSA-44) exclusively:
- Key generation: `pqcrystals_dilithium2_ref_keypair()` via `pqwallet.cpp`
- Signing: `pqcrystals_dilithium2_ref_signature()` via `pqwallet.cpp`
- Verification: `pqcrystals_dilithium2_ref_verify()` via `interpreter.cpp`
- Script: `OP_CHECKSIG_PQ` validates Dilithium signatures only

Any attempt to submit an ECDSA-signed transaction fails at the script interpreter level with `SCRIPT_ERR_ECDSA_EXTINCT`.

---

*This document prepared for the Halborn security audit. See also: `SECURITY.md` for full constant-time analysis.*
