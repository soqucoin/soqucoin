# Soqucoin Wallet Cryptographic Specification

> **Version**: 2.0 | **Updated**: 2026-10-10
> **Classification**: Technical reference
> **Standards**: NIST FIPS 204 (ML-DSA), RFC 5869 (HKDF), RFC 2104 (HMAC), BIP 350 (bech32m), BIP 143 (signature hash)
> **Status**: every statement below is read from the code at soqucoin `main` `c21c94333` and cites the line that
> produces it. Version 1.x of this document described designs that were never implemented (a per-level HKDF
> chain, a nonce-based blinding derivation, a 20-byte address hash, deterministic signing); none of that text
> survives here.

---

## 0. Scope: two bodies of code

The repository holds two separate implementations, and an implementer has to know which one a statement is about.

**A. The node wallet.** `CKey` and `CPubKey` (`src/key.cpp`, `src/pubkey.cpp`), the script interpreter
(`src/script/interpreter.cpp`), address encoding (`src/utiladdress.cpp`, `src/chainparams.cpp`), `wallet.dat`
encryption (`src/wallet/crypter.cpp`, `src/wallet/wallet.cpp`) and the entropy source (`src/random.cpp`). This is
what `getnewaddress`, `sendtoaddress`, `signrawtransaction`, `encryptwallet`, `dumpprivkey` and `importprivkey`
run, and what consensus verifies. Sections 1 to 5.

**B. The post-quantum wallet library** in `src/wallet/pqwallet/`: HKDF seed derivation (`pqderive.cpp`),
`PQKeyPair::DeriveFromSeed`, `PQWallet`, the `WalletCrypto` file format (`pqcrypto.cpp`) and `PQAddress`. It is
compiled into the node (`src/Makefile.am:283-288`) and registers six RPCs (`pqvalidateaddress`,
`pqestimatefeerate`, `pqwalletinfo`, `pqestimatefee`, `pqchannelreserve`, `pqselectcoins`;
`rpc_pqwallet.cpp:493-500`), none of which derives a key, encrypts a file or encodes an address through the
library. At `c21c94333` no node code path calls `PQWallet::FromSeed`, `PQKeyPair::DeriveFromSeed`,
`WalletCrypto` or `PQAddress::Encode`; their callers are unit tests and fuzz harnesses. The library's seed
derivation is nevertheless the interoperability rule that seed-based wallets outside the node implement
(`pqderive.h:47-62`), so section 6 specifies it in full. Sections 7 and 8 describe the library's file format and
address encoder as library behaviour.

---

## 1. Signature scheme: ML-DSA-44

### 1.1 Implementation

The PQ-Crystals reference implementation of CRYSTALS-Dilithium, standardised as FIPS 204 ML-DSA, is vendored in
`src/crypto/dilithium/` (provenance and licence in `src/crypto/dilithium/LICENSE`). It is built in mode 2, the
ML-DSA-44 parameter set (`config.h:10`), under the symbol prefix `pqcrystals_dilithium2_ref` (`config.h:15-16`).
The vendored code is the FIPS 204 final algorithm: key generation absorbs the parameter bytes `k` and `l` with the
seed (`sign.c`, `crypto_sign_keypair` at `:33` and `crypto_sign_seed_keypair` at `:101`), the public-key hash `tr`
is 64 bytes (`params.h:8`), and signing takes a context string (`sign.c:359-378`).

### 1.2 Parameters (`src/crypto/dilithium/params.h`)

| Parameter | Value | Line |
|---|---|---|
| n (ring dimension) | 256 | `params.h:10` |
| q (modulus) | 8,380,417 | `params.h:11` |
| d (dropped bits) | 13 | `params.h:12` |
| (k, l) | (4, 4) | mode 2 block |
| η | 2 | mode 2 block |
| τ (challenge weight) | 39 | mode 2 block |
| β = τ·η | 78 | mode 2 block |
| γ₁ | 2¹⁷ | mode 2 block |
| γ₂ | (q − 1) / 88 | mode 2 block |
| ω (hint bound) | 80 | mode 2 block |
| c̃ length | 32 bytes | mode 2 block |
| seed ξ, K, rnd | 32 bytes | `params.h:6,9` |
| tr, μ (CRH output) | 64 bytes | `params.h:7-8` |

Sizes: public key 1,312 bytes, secret key 2,560 bytes (`api.h:7-8`), signature 2,420 bytes (`pubkey.cpp:19-22`).
Security category 2.

### 1.3 Key generation

Every key is a function of a 32-byte seed ξ: (ρ, ρ′, K) = SHAKE256(ξ ‖ k ‖ l), A = ExpandA(ρ), (s₁, s₂) from ρ′,
t = A·s₁ + s₂, pk = (ρ, t₁), sk = (ρ, K, tr, s₁, s₂, t₀) (`sign.c:33-99`; the seeded entry point
`crypto_sign_seed_keypair`, `sign.c:101`).

The node draws ξ from `GetStrongRandBytes` (section 5) and expands it through the seeded key generation, so every
key the node makes is reproducible from its seed (`key.cpp:33-44`). A public key whose first byte is `0xFF` is
the node's invalid-key marker (`pubkey.h`, `GetLen`); `CKey::SetSeed` refuses such a key and `MakeNewKey`
redraws (`key.cpp:46-61`). In memory a key is the secret key followed by the public key, 3,872 bytes, in a
`secure_allocator` vector (`key.h:47,53-54`).

### 1.4 Signing is hedged

The build defines `DILITHIUM_RANDOMIZED_SIGNING` (`config.h:5`). Each signature draws 32 fresh random bytes
`rnd` (`sign.c:369-384`) from the vendored `randombytes` (`randombytes.c`: `getrandom(2)` on Linux, `CryptGenRandom`
on Windows, `/dev/urandom` elsewhere; it aborts rather than continue without entropy). Then, per FIPS 204:

```
pre  = 0x00 ‖ len(ctx) ‖ ctx                       sign.c:373-378
μ    = SHAKE256-512(tr ‖ pre ‖ M)                   sign.c:255-260
ρ″   = SHAKE256-512(K ‖ rnd ‖ μ)                    sign.c:263-267
(c̃, z, h) by rejection sampling from ρ″, μ, sk     sign.c, crypto_sign_signature_internal
```

Two signatures of the same message by the same key differ. A test vector for signing is therefore a verification
vector (key, message, one valid signature), never an expected signature.

The node signs the 32-byte transaction signature hash as the message with an empty context
(`key.cpp:111-124`). Verification requires exactly 2,420 bytes and calls the reference verifier with an empty
context (`pubkey.cpp:13-33`).

### 1.5 Signatures in transactions

A transaction signature on the witness stack is the 2,420-byte ML-DSA-44 signature followed by one signature-hash
type byte, 2,421 bytes; 2,420 bytes (raw) and 0 bytes (the empty signature) are the only other sizes the script
layer accepts (`interpreter.cpp:94-100`, `SOQ-COV-011`). The message is the BIP 143 signature hash
(`interpreter.cpp:1311-1321`; witness version 1 spends sign with `SIGVERSION_WITNESS_V0`).

---

## 2. Private key serialisation (node)

`CKey` holds 3,872 bytes (`key.h:54`); its seed is 32 bytes (`key.h:57`). Base58Check with the network's
`SECRET_KEY` prefix carries one of two payloads (`base58.cpp:295-331`):

| Form | Payload | Behaviour |
|---|---|---|
| Seed form | 32-byte FIPS 204 seed ‖ `0x02` | expanded through the seeded key generation (`base58.cpp:301-302`) |
| Expanded form | 3,872 bytes, secret key ‖ public key | loaded as is; the public key must match (`base58.cpp:304-312`) |

Any other length, including a classical 32-byte or 33-byte WIF, is refused (`base58.cpp:322`). `dumpprivkey`
prints the expanded form; `importprivkey` accepts both; `dumpwallet` and `importwallet` round-trip every key
(release notes 2.5.1).

---

## 3. Addresses (node)

### 3.1 Output script and program

A standard single-key output is a witness version 1 program, `OP_1 <32 bytes>`
(`standard.cpp:101-104`, `TX_WITNESS_V1_SCRIPTHASH`; the destination type `WitnessV1ScriptHash`,
`standard.h:30,84`). The 32-byte program is the single SHA-256 of the 1,312-byte public key
(`rpcwallet.cpp:141-145` for `getnewaddress`; `utiladdress.cpp:95-104`, `EncodeDilithiumAddress`). No
RIPEMD-160, no double hash, no BLAKE2b in the address path.

### 3.2 Encoding

Bech32m (BIP 350). The human-readable part is the chain's `bech32HRP`: `sq` on mainnet, testnet and regtest
(`chainparams.cpp:195,715,986`), `ssq` on stagenet (`chainparams.cpp:1299`). The data part is the witness version
as one 5-bit value, `1`, followed by the 8-to-5 conversion of the 32-byte program (`utiladdress.cpp:44-56`). A
mainnet address is 62 characters and begins `sq1p`; a stagenet address is 63 characters and begins `ssq1p`.

### 3.3 Decoding

`DecodeDestination` (`utiladdress.cpp:62-78`) accepts an address only if all four hold: the encoding is bech32m;
the human-readable part equals this node's; the first data value is 1; the program converts to exactly 32 bytes.
Mixed case fails in `bech32::Decode`. `pqvalidateaddress` applies the same rule and reports the program as
`pubkey_hash` (release notes 2.5.1). Vectors: `WALLET_TEST_VECTORS.md` sections 2 and 6.

### 3.4 Spending

The witness stack of a version 1 spend is exactly two items, the signature and the public key
(`interpreter.cpp:1986-1991`). A 1,313-byte public key with a leading `0x00` is accepted and the byte stripped.
The verifier recomputes SHA-256 of the public key and compares it with the program
(`interpreter.cpp:2009-2011`), refuses the APO signature-hash type (`:2037`), and checks the signature
against the BIP 143 hash (`:2041`). One signature verification is budgeted per input
(`interpreter.cpp:1223-1232`).

---

## 4. Node wallet encryption (`wallet.dat`, `encryptwallet`)

The node wallet keeps the Bitcoin Core scheme with the key sizes of section 2.

- **Master key**: 32 random bytes from `GetStrongRandBytes`; salt 8 random bytes (`crypter.h:14-16`;
  `wallet.cpp:574-600`, `CWallet::EncryptWallet`).
- **Passphrase KDF**: OpenSSL `EVP_BytesToKey` with SHA-512 (`crypter.cpp:44-62`, `BytesToKeySHA512AES`,
  derivation method 0), producing the 32-byte key and the 16-byte IV that encrypt the master key. The round count
  is calibrated when the passphrase is set: a 25,000-round trial is timed and the count scaled to about 100 ms on
  that machine, never below 25,000, and stored with the master key as `nDeriveIterations`
  (`wallet.cpp`, `EncryptWallet` and `ChangeWalletPassphrase`, `:334-343`). `pqwalletinfo` reports
  `encryption` `AES-256-CBC` and `kdf` `SHA-512 EVP_BytesToKey` (`rpc_pqwallet.cpp`, `pqwalletinfo`).
- **Key encryption**: each private key (3,872 bytes) is encrypted with AES-256-CBC under the master key
  (`crypter.cpp:85,104`), the IV being the first 16 bytes of the public key's hash (`crypter.cpp:123-131,136`).
- **Decryption check**: the decrypted secret must be exactly 3,872 bytes and must reproduce the stored public key
  (`crypter.cpp:133-144`). There is no MAC; the public-key check is the integrity test. In 2.5.0 the length check
  read 32 bytes, so no key ever decrypted; 2.5.1 fixed it and a wallet encrypted by 2.5.0 unlocks (release notes
  2.5.1).

---

## 5. Entropy (node)

`GetStrongRandBytes` (`random.cpp:276-296`) returns at most 32 bytes: SHA-512 over three inputs, 32 bytes from OpenSSL's
RNG, 32 bytes from the operating system (`GetOSRand`, `random.cpp:200`: `getrandom(2)` on Linux, `getentropy` on BSD and macOS,
`CryptGenRandom` on Windows, with `/dev/urandom` as the Linux fallback, `random.cpp:180`; any failure calls
`RandFailure`, `random.cpp:47`, which aborts) and 32 bytes from the CPU's RDRAND when present (`random.cpp:76-113`). It feeds key
seeds (`key.cpp:41`), the wallet master key and salt (section 4) and the library's salts and IVs
(`pqcrypto.cpp`, `WalletCrypto::Encrypt`). Hedged signing draws from the vendored `randombytes` (section 1.4), a separate path to
the same operating-system sources.

---

## 6. Seed derivation (library; the rule for seed-based wallets)

### 6.1 Inputs and bounds

A seed of at least `MIN_SEED_BYTES` = 32 bytes (`pqderive.h:48`); a BIP-39 mnemonic gives 64. Every derivation
function throws `std::invalid_argument` for a shorter seed before reading it (`pqderive.cpp:187-193`,
`RequireSeed`); `PQKeyPair::DeriveFromSeed` returns `nullptr` for one (`pqderive.cpp:316-322`) and
`PQWallet::FromSeed` refuses one (`pqwallet.cpp:504-508`).

### 6.2 One HKDF-SHA256 per key

There is no per-level chain. Every derivation is a single RFC 5869 extract-and-expand with SHA-256
(`pqderive.cpp:34-160`):

```
salt = SHA-256(seed)                                   pqderive.cpp:202-205
PRK  = HMAC-SHA256(salt, seed)                         HKDFExtract
OKM  = HMAC-SHA256(PRK, info ‖ 0x01)                   HKDFExpand, 32 bytes, one block
```

The three functions differ only in `info`:

| Function | info | Lines |
|---|---|---|
| `DeriveKeyMaterial(seed, path, domain, retry)` | domain ‖ PathToBytes(path) [‖ retry, when retry > 0] | `pqderive.cpp:195-230` |
| `DeriveBlindingFactor(seed, index)` | `"soqucoin-blinding-v1"` ‖ index as 8 big-endian bytes | `pqderive.cpp:232-273` |
| `DeriveChannelKey(seed, channelId, keyType, index)` | `"soqucoin-v1/channel/" + channelId + "/" + keyType`, with `"/" + index` appended for `revoke` and `htlc` | `pqderive.cpp:275-314` |

Domain strings (`pqderive.cpp:22-25`): `soqucoin-pqwallet-v1` for signing keys, `soqucoin-blinding-v1`,
`soqucoin-v1/channel`, and `soqucoin-v1/watchtower` (defined, used by no function in this file).

`PathToBytes` (`pqderive.cpp:161-175`) is five big-endian 32-bit values: purpose, coin type and account each OR
`0x80000000` (hardened), then change and index unchanged. The default path is `m/44'/21329'/0'/0/i`
(`pqkeys.h:77-82`; `pqwallet.cpp:610-617`).

### 6.3 From material to key pair, and the `0xFF` rule

`PQKeyPair::DeriveFromSeed` (`pqderive.cpp:316-371`) derives 32 bytes of material under `soqucoin-pqwallet-v1`
and expands them with `pqcrystals_dilithium2_ref_seed_keypair`. If the public key's first byte is `0xFF`, the
node's invalid-key marker, it re-derives with the retry byte 1, 2, … up to `MAX_DERIVE_RETRIES` = 8 appended
to `info` (`pqderive.h:50-62`); the first key whose public key does not start with `0xFF` is the key for that
path, and after eight retries the function returns `nullptr`. Retry 0 is byte-identical to the scheme without
the rule. Every wallet deriving Soqucoin keys from a seed implements the same rule (`pqderive.h:59-62`).

### 6.4 Known answers

`test/pqderive-test --json-vectors` prints the vectors for the BIP-39 test seed; `WALLET_TEST_VECTORS.md`
section 1 publishes them and the unit suite `pqderive_seed_tests` pins the wallet key at path 0, the blinding
factors 0 to 2 and the channel funding key. The blinding factor at index 0 and the blinding-domain key at path 0
differ because their `info` strings differ (an 8-byte index against a 20-byte path).

---

## 7. Library wallet file encryption (`WalletCrypto`, format v2)

This is the library's own file format. The node never writes it; `wallet.dat` is section 4.

### 7.1 Layout (`pqcrypto.h:64-80`; `pqcrypto.cpp:23-24`)

```
magic "SQW2" (4) ‖ version 2 (4, big-endian) ‖ kdf_id (1) ‖ salt (16) ‖ iv (16) ‖ tag (16) ‖ ctlen (4) ‖ ciphertext
```

### 7.2 Passphrase KDF cascade

Encryption tries, in order, Argon2id (t = 3, m = 65,536 KiB, p = 4; `pqcrypto.h:49-52`; `pqcrypto.cpp:111`), scrypt
(N = 32,768, r = 8, p = 1; `pqcrypto.cpp:170-172`) and PBKDF2-HMAC-SHA256 with 600,000 iterations
(`pqcrypto.cpp:213-216`), through the OpenSSL 3 `EVP_KDF` API; with an older OpenSSL no KDF is available and
encryption refuses rather than derive a weak or all-zero key (`pqcrypto.cpp`, the `HAVE_OPENSSL3_KDF` block at `:33-48`; `pqcrypto.h:12-18`). The
identifier of the KDF that produced the key (`pqcrypto.h:56-59`) is stored in the file, and decryption uses that
KDF only, with no fallback (`pqcrypto.h`, the three-argument `DeriveKey`; `pqcrypto.cpp:529-550`, `Decrypt`). The
cost parameters are constants and are not stored (`pqcrypto.cpp`, the `KDF_VERSION` note at `:94-101`).

### 7.3 Cipher and tag

The 16-byte salt and 16-byte IV come from `GetStrongRandBytes`; the plaintext is PKCS#7 padded and encrypted with
AES-256-CBC under the 32-byte derived key (`pqcrypto.cpp:454-497`, `WalletCrypto::Encrypt`). The tag is
HMAC-SHA256, keyed with the same key, over version ‖ kdf_id ‖ salt ‖ iv ‖ ciphertext, truncated to 16 bytes
(`pqcrypto.cpp:498-512`). Decryption recomputes the tag and compares it in constant time (XOR-accumulate) before
any decryption, and fails closed on a KDF mismatch, a wrong tag or invalid padding (`pqcrypto.cpp`, `Decrypt`).

---

## 8. Library address encoder (`PQAddress`): do not implement

`PQAddress::Encode` (`pqwallet.cpp:343-369`) hashes the public key as section 3.1 does but pushes the version
byte into the 8-to-5 conversion, so its first data value is 0 and the program does not unpack to 32 bytes;
`DecodeDestination` refuses every address it produces. Its prefixes `tsq`, `sqp`, `sqsh`, `ssqp` and `ssqsh`
(`pqwallet.cpp:286-330`) belong to no chain. The node never calls it; the RPC that exposed it was removed in
2.5.1. Implementers follow section 3. Tracked for repair in the project's tracker.

---

## 9. Memory handling

- Node keys live in `secure_allocator` memory (`key.h:33,47`), and every temporary seed or secret key is
  wiped with `memory_cleanse` after use (`key.cpp:43,58,66`).
- The library's `SecureBytes` (`pqkeys.h:46-74`) locks its buffer with `mlock`, unlocks with `munlock` and wipes
  it with `memory_cleanse` on destruction (`pqwallet.cpp:117-141`); the derivation functions wipe salt, PRK,
  intermediate hashes and derived material (`pqderive.cpp`, throughout).
- Secrets are never logged. A failed `mlock` is reported on stderr and the program continues
  (`pqwallet.cpp:120-122`).

---

## 10. Test vectors

| Area | Where | State |
|---|---|---|
| Seed derivation (section 6) | `WALLET_TEST_VECTORS.md` section 1; `pqderive-test --json-vectors` | verified against the code, 2026-10-10 |
| Addresses (section 3) | `WALLET_TEST_VECTORS.md` sections 2 and 6 | regenerated from `utiladdress.cpp`, 2026-10-10 |
| Signatures, transactions, costs | `WALLET_TEST_VECTORS.md` sections 3 to 5 | placeholders; generation tracked in the project's tracker |
| BLAKE2b (PAT) | `doc/BLAKE2b_TEST_VECTORS.md` | unchanged |

---

## 11. Summary of guarantees

| Property | Mechanism | Where |
|---|---|---|
| Signature unforgeability | ML-DSA-44, FIPS 204, hedged signing | section 1 |
| Key reproducibility | every node key is a 32-byte seed expanded by seeded key generation | sections 1.3, 2 |
| Address binding | SHA-256 of the public key, bech32m with the chain's prefix, version 1 | section 3 |
| Wallet at rest (node) | AES-256-CBC under a 32-byte master key; passphrase through SHA-512 `EVP_BytesToKey` with a calibrated round count | section 4 |
| Wallet at rest (library) | AES-256-CBC with HMAC-SHA256 tag; Argon2id, scrypt or PBKDF2 with the KDF id persisted | section 7 |
| Seed derivation | one HKDF-SHA256 per key with domain-separated `info`; the `0xFF` retry rule | section 6 |
| Entropy | SHA-512 over OpenSSL, the operating system and RDRAND; abort on failure | section 5 |

---

## 12. References

1. NIST FIPS 204, Module-Lattice-Based Digital Signature Standard
2. RFC 5869, HKDF
3. RFC 2104, HMAC
4. BIP 143, transaction signature verification for version 0 witness program
5. BIP 350, bech32m
6. BIP 44, multi-account hierarchy for deterministic wallets (the path layout only)
7. PQ-Crystals, CRYSTALS-Dilithium reference implementation, https://github.com/pq-crystals/dilithium

---

*Soqucoin Wallet Cryptographic Specification v2.0 | October 2026*
