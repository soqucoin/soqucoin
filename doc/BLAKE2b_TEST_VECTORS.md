# BLAKE2b Test Vectors

> **Version**: 1.0 | **Updated**: February 6, 2026
> **Source**: RFC 7693 Appendix A, Python `hashlib.blake2b` reference
> **Code**: [`src/test/blake2b_tests.cpp`](file:///Users/caseymacmini/soqucoin-build/src/test/blake2b_tests.cpp) (10 test cases)

---

## Usage in Soqucoin

BLAKE2b-160 is used for address derivation: `pubkey (1312 bytes) → BLAKE2b-160 → 20-byte hash → Bech32m encoding`

---

## RFC 7693 Appendix A Vectors

### BLAKE2b-512

| Input | Input Hex | Expected Output |
|-------|-----------|-----------------|
| `""` (empty) | `` | `786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce` |
| `"abc"` | `616263` | `ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923` |

---

## BLAKE2b-256

| Input | Input Hex | Expected Output |
|-------|-----------|-----------------|
| `""` | `` | `0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8` |
| `"abc"` | `616263` | `bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319` |
| `\x00` | `00` | `03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314` |

---

## BLAKE2b-160 (Address Hashing — Primary Use Case)

Verified against Python `hashlib.blake2b(data, digest_size=20).hexdigest()`.

| Input | Input Hex | Expected Output (20 bytes) |
|-------|-----------|---------------------------|
| `""` | `` | `3345524abf6bbe1809449224b5972c41790b6cf2` |
| `"abc"` | `616263` | `384264f676f39536840523f284921cdc68b6846b` |
| `\x00` | `00` | `082ad992fb76871c33a1b9993a082952feaca5e6` |
| `"Soqucoin"` | `536f7175636f696e` | `ee9feab5b386b89406a46a8a5a261a78feda180f` |

---

## Golden Vector: Dilithium Pubkey Address

This is the exact computation used in Soqucoin address generation.

**Input**: 1,312-byte deterministic pubkey where `byte[i] = i & 0xFF`
**Output**: BLAKE2b-160 = `989e7da9710e15fa65054a22533ce84d5065bcde`

```python
# Verification
import hashlib
pubkey = bytes([i & 0xFF for i in range(1312)])
hashlib.blake2b(pubkey, digest_size=20).hexdigest()
# → '989e7da9710e15fa65054a22533ce84d5065bcde'
```

> [!IMPORTANT]
> If this value changes, **all testnet addresses are invalidated**. This vector must remain stable across builds.

---

## Long Input: 1M×`'a'`

**Input**: 1,000,000 bytes of `0x61` (`'a'`)
**Output**: BLAKE2b-512 = `98fb3efb7206fd19ebf69b6f312cf7b64e3b94dbe1a17107913975a793f177e1d077609d7fba363cbba00d05f7aa4e4fa8715d6428104c0a75643b0ff3fd3eaf`

---

## Test Methodology

Each vector is verified 3 ways in `blake2b_tests.cpp`:
1. **Single-pass**: Full input written at once
2. **Chunked**: Input split into ⅓-size chunks
3. **Byte-by-byte**: Single-byte writes (inputs ≤128 bytes)

This ensures the incremental/streaming API matches single-shot computation.

---

*Test vectors compiled for Halborn audit — February 2026*
