# Soqucoin Wallet Cryptographic Specification

> **Version**: 2.1 | **Updated**: 2026-10-10
> **Classification**: Technical reference
> **Standards**: NIST FIPS 204 (ML-DSA), RFC 5869 (HKDF), RFC 2104 (HMAC), BIP 350 (bech32m), BIP 143 (signature hash)
> **Status**: every statement below is read from the code at soqucoin `main` `c21c94333` and cites the line that
> produces it; a figure that is a standard's value rather than a code constant says so. Version 1.x of this
> document described designs that were never implemented (a per-level HKDF chain, a nonce-based blinding
> derivation, a 20-byte address hash behind a version byte, deterministic signing, a `SOQW` file format); none of
> that text survives here. Section 12 lists the documents this version supersedes.

---

## 0. Scope: two bodies of code

The repository holds two separate implementations, and an implementer has to know which one a statement is about.

**A. The node wallet.** `CKey` and `CPubKey` (`src/key.cpp`, `src/pubkey.cpp`), the script interpreter
(`src/script/interpreter.cpp`, `src/script/sign.cpp`), address encoding (`src/utiladdress.cpp`,
`src/chainparams.cpp`), `wallet.dat` encryption (`src/wallet/crypter.cpp`, `src/wallet/wallet.cpp`) and the
entropy source (`src/random.cpp`). This is what `getnewaddress`, `sendtoaddress`, `signrawtransaction`,
`encryptwallet`, `dumpprivkey` and `importprivkey` run, and what consensus verifies. Sections 1 to 5.

**B. The post-quantum wallet library** in `src/wallet/pqwallet/`: HKDF seed derivation (`pqderive.cpp`),
`PQKeyPair::DeriveFromSeed`, `PQWallet`, the `WalletCrypto` file format (`pqcrypto.cpp`) and `PQAddress`. It is
part of `libsoqucoin_wallet` (`src/Makefile.am:271-275,283-288`), so a `--disable-wallet` build contains none of
it. It registers six RPCs (`pqvalidateaddress`, `pqestimatefeerate`, `pqwalletinfo`, `pqestimatefee`,
`pqchannelreserve`, `pqselectcoins`; `rpc_pqwallet.cpp:494-502`), none of which derives a key, encrypts a file or
encodes an address through the library. At `c21c94333` no node code path reaches the library's key material:
`PQWallet::FromSeed` has no caller; `PQKeyPair::DeriveFromSeed` is called only by `PQWallet::GetNewAddress`
(`pqwallet.cpp:618`), itself uncalled, and by tests; `WalletCrypto` is called by a fuzz harness; the programs
`pqwallet-test` and `pqderive-test` are demonstration binaries outside `make check`
(`src/Makefile.test.include:318-334`). The library's seed derivation is nevertheless the rule that seed-based
wallets outside the node implement (section 6.5), so section 6 specifies it in full. Sections 7 and 8 describe
the library's file format and address encoder as library behaviour.

---

## 1. Signature scheme: ML-DSA-44

### 1.1 Implementation

The PQ-Crystals reference implementation of CRYSTALS-Dilithium, standardised as FIPS 204 ML-DSA, is vendored in
`src/crypto/dilithium/` (provenance and licence in `src/crypto/dilithium/LICENSE`). It is built in mode 2, the
ML-DSA-44 parameter set (`config.h:10`), under the symbol prefix `pqcrystals_dilithium2_ref` (`config.h:15-16`).
The vendored code is the FIPS 204 final algorithm: key generation absorbs the parameter bytes `k` and `l` with the
seed (`sign.c:33-99`, `crypto_sign_keypair`; the seeded entry point `crypto_sign_seed_keypair` at `sign.c:101`),
the public-key hash `tr` is 64 bytes (`params.h:8`), and signing takes a context string (`sign.c:359-378`).

### 1.2 Parameters (`src/crypto/dilithium/params.h`)

| Parameter | Value | Line |
|---|---|---|
| n (ring dimension) | 256 | `params.h:10` |
| q (modulus) | 8,380,417 | `params.h:11` |
| d (dropped bits) | 13 | `params.h:12` |
| (k, l) | (4, 4) | `params.h:15-24`, the mode 2 block |
| η | 2 | `params.h:15-24` |
| τ (challenge weight) | 39 | `params.h:15-24` |
| β = τ·η | 78 | `params.h:15-24` |
| γ₁ | 2¹⁷ | `params.h:15-24` |
| γ₂ | (q − 1) / 88 | `params.h:15-24` |
| ω (hint bound) | 80 | `params.h:15-24` |
| c̃ length | 32 bytes | `params.h:15-24` |
| seed ξ, K, rnd | 32 bytes | `params.h:6,9` |
| tr, μ (CRH output) | 64 bytes | `params.h:7-8` |

Sizes, derived from the parameters at `params.h:72-78` and fixed in the API at `api.h:7-8`: public key 1,312
bytes, secret key 2,560 bytes; signature 2,420 bytes (`pubkey.cpp:19-22`). ML-DSA-44 is FIPS 204 security
category 2, the standard's classification of this parameter set.

### 1.3 Key generation

Every key is a function of a 32-byte seed ξ: (ρ, ρ′, K) = SHAKE256(ξ ‖ k ‖ l), A = ExpandA(ρ), (s₁, s₂) from ρ′,
t = A·s₁ + s₂, pk = (ρ, t₁), sk = (ρ, K, tr, s₁, s₂, t₀) (`sign.c:33-99`; the seeded entry point
`crypto_sign_seed_keypair`, `sign.c:101`).

The node draws ξ from `GetStrongRandBytes` (section 5) and expands it through the seeded key generation
(`key.cpp:33-44`). A public key whose first byte is `0xFF` is the node's invalid-key marker (`pubkey.h`,
`GetLen`); `CKey::SetSeed` refuses such a key and `MakeNewKey` redraws (`key.cpp:46-61`). The seed is wiped as
soon as the key pair exists (`key.cpp:43`) and `CKey` keeps no seed member (`key.h:41-47`): in memory a key is
the secret key followed by the public key, 3,872 bytes, in a `secure_allocator` vector (`key.h:47,53-54`). A node
key therefore cannot be backed up as its seed; the seed form of section 2 is an import format.

### 1.4 Signing is hedged

The build defines `DILITHIUM_RANDOMIZED_SIGNING` (`config.h:5`). Each signature draws 32 fresh random bytes
`rnd` (`sign.c:369-384`) through the C symbol `randombytes`. The tree defines that symbol twice: the vendored
`src/crypto/dilithium/randombytes.c` (`getrandom(2)` on Linux, `CryptGenRandom` on Windows, `/dev/urandom` on
every other platform, `randombytes.c:20-79`; it aborts rather than continue without entropy) and
`src/pat/randombytes.cpp:4-6`, which forwards to `GetStrongRandBytes` (section 5). Both are static-library
members exporting the same symbol: `pat/randombytes.o` in `libsoqucoin_server` (`Makefile.am:229`), the first
archive of `soqucoind_LDADD`, and the vendored object in `libsoqucoin_crypto`, the last (`Makefile.am:474-482`).
The only reference to the symbol is `sign.o`, in that last archive; no member of `libsoqucoin_server` references
it. Which definition a binary carries is therefore the linker's archive rule. GNU ld extracts a member only for a
reference undefined when it scans the archive, and scans each archive once, so it passes over
`pat/randombytes.o` and satisfies `sign.o` from the vendored member beside it: the Linux and Windows release
binaries sign with the vendored source (`release.yml`; read in the v2.5.0 `linux-x64`, `linux-arm64` and
`windows-x64` artifacts, where `randombytes` is the `getrandom` system-call loop or the `CryptGenRandom` loop).
Apple's linker keeps every scanned archive's members available to later references, so the macOS binaries take
`pat/randombytes.o` and sign through `GetStrongRandBytes` (read in the v2.5.0 `macos-arm64` artifact and a
macOS build, where `randombytes` is a tail call into it). Either path aborts on failure. Then, per FIPS 204:

```
pre  = 0x00 ‖ len(ctx) ‖ ctx                       sign.c:373-378
μ    = SHAKE256-512(tr ‖ pre ‖ M)                   sign.c:255-261
ρ″   = SHAKE256-512(K ‖ rnd ‖ μ)                    sign.c:263-269
(c̃, z, h) by rejection sampling from ρ″, μ, sk     sign.c, crypto_sign_signature_internal
```

Two signatures of the same message by the same key differ. A test vector for signing is therefore a verification
vector (key, message, one valid signature), never an expected signature.

The node signs the 32-byte transaction signature hash as the message with an empty context
(`key.cpp:111-124`). Verification requires exactly 2,420 bytes and calls the reference verifier with an empty
context (`pubkey.cpp:13-33`).

### 1.5 Signatures in transactions

The witness item is the 2,420-byte ML-DSA-44 signature followed by one signature-hash type byte, 2,421 bytes:
the signer appends the type (`sign.cpp:37`), and the verifier strips the last byte unconditionally before
handing the rest to `CPubKey::Verify` (`interpreter.cpp:2076-2077`), which requires exactly 2,420 bytes
(`pubkey.cpp:20`). A 2,420-byte or empty witness item fails with `SCRIPT_ERR_SIG_NULLFAIL`
(`interpreter.cpp:2041-2042`). The size comments at `interpreter.cpp:94-100` belong to `CheckSignatureEncoding`,
which consensus never calls (its callers are `core_write.cpp:98` and tests).

The message is the BIP 143 signature hash (`interpreter.cpp:1311-1321`; witness version 1 spends use
`SIGVERSION_WITNESS_V0`), and the `scriptCode` the preimage commits to is the spent output's own `scriptPubKey`,
`OP_1 <32-byte program>` (or `OP_0 <32-byte program>`, the consensus-only form of section 3.1): the signer passes
it (`sign.cpp:213`), the verifier passes it (`interpreter.cpp:2016, 2041`), and `SignatureHash` serialises it as
given (`interpreter.cpp:1492, 2124`). BIP 143 defines no witness version 1 form; this is the one choice it leaves
to the program type.

---

## 2. Private key serialisation (node)

`CKey` holds 3,872 bytes (`key.h:54`); its seed is 32 bytes (`key.h:57`). Base58Check with the network's
`SECRET_KEY` version byte carries one of two payloads (`base58.cpp:295-331`):

| Form | Payload | Behaviour |
|---|---|---|
| Seed form | 32-byte FIPS 204 seed ‖ `0x02` | expanded through the seeded key generation (`base58.cpp:301-302`); import only, no RPC emits it |
| Expanded form | 3,872 bytes, secret key ‖ public key | loaded as is, and the trailing public key must match (`base58.cpp:304-319`) |

The version byte is 158 on mainnet, 241 on testnet, 239 on regtest and 253 on stagenet
(`chainparams.cpp:650,951,1201,1660`; checked at `base58.cpp:331`), so testnet and regtest, which share an
address prefix (section 3.2), differ here. Any other payload is refused (`base58.cpp:322`): a classical 32-byte
WIF fails on length, and a classical 33-byte WIF has the seed form's length but fails the `0x02` marker
(`base58.cpp:301`). `dumpprivkey` and `dumpwallet` print the expanded form (`rpcdump.cpp:624,706`);
`importprivkey` accepts both forms through `CBitcoinSecret` (`rpcdump.cpp:133-139`); `dumpwallet` writes each
key's address in the `addr=` field (`rpcdump.cpp:718`) and `dumpprivkey` accepts an address of either kind
named in section 3.5 (`rpcdump.cpp:611-616`).

---

## 3. Addresses (node)

### 3.1 Output script and program

The standard single-key output is a witness version 1 program, `OP_1 <32 bytes>` (`standard.cpp:101-104`,
`TX_WITNESS_V1_SCRIPTHASH`; the destination type `WitnessV1ScriptHash`, `standard.h:30,84`). The 32-byte
program is the single SHA-256 of the 1,312-byte public key (`rpcwallet.cpp:141-145` for `getnewaddress`;
`utiladdress.cpp:95-104`, `EncodeDilithiumAddress`). The address path uses no RIPEMD-160 and no BLAKE2b; the
double SHA-256 appears only as the wallet-encryption IV of section 4.

Consensus also spends `OP_0 <32 bytes>` with the same witness: `VerifyScript` treats a 34-byte `scriptPubKey`
beginning `OP_0` or `OP_1` alike (`interpreter.cpp:1567-1569`) and runs one verification path for both
(`interpreter.cpp:1986-2044`, whose comment names the path as shared by version 0 and version 1). The version 0
form is consensus-only: policy lists version 1 alone among the single-key forms, so a node relays no transaction
that creates it (`policy.cpp:35-63`); no address encodes or decodes it (`utiladdress.cpp:44-78`, and
`CTxDestination` has no version 0 type, `standard.h:84`); the node's wallet produces version 1 only
(`rpcwallet.cpp:141-145`). A block may still contain one, so an implementer that verifies blocks accepts it; an
implementer that produces outputs uses version 1 only.

### 3.2 Encoding

Bech32m (BIP 350). The human-readable part is the chain's `bech32HRP`: `sq` on mainnet, testnet and regtest
(`chainparams.cpp:195,715,986`), `ssq` on stagenet (`chainparams.cpp:1299`). The data part is the witness version
as one 5-bit value, `1`, followed by the 8-to-5 conversion of the 32-byte program (`utiladdress.cpp:44-58`). The
version value `1` is the character `p`, 32 bytes convert to 52 values and the checksum is six characters, so a
mainnet address is 62 characters beginning `sq1p` and a stagenet address 63 characters beginning `ssq1p`.

### 3.3 Decoding

`DecodeDestination` (`utiladdress.cpp:62-78`) accepts an address only if all four hold: the encoding is bech32m;
the human-readable part equals this node's; the first data value is 1; the program converts to exactly 32 bytes
under the strict rule of `ConvertBits` (`utiladdress.cpp:28-40`: more than four leftover bits, or non-zero
padding bits, is a failure). Mixed case fails in `bech32::Decode`. `pqvalidateaddress` applies the same rule and
reports the program as `pubkey_hash` (`rpc_pqwallet.cpp:72,80`). Vectors: `WALLET_TEST_VECTORS.md` sections 2
and 6.

### 3.4 Spending

The witness stack of a version 1 spend, and of the version 0 spend of section 3.1, is exactly two items, the
signature of section 1.5 and the public key
(`interpreter.cpp:1986-1991`). The node's signer pushes the public key as 1,313 bytes, a `0x00` prefix followed
by the 1,312-byte key (`sign.cpp:221-224`), so the prefixed form is the standard witness item; the verifier
strips the prefix for the program check (`interpreter.cpp:2000-2003`) and again in `CheckSig`
(`interpreter.cpp:2062-2064`), and a bare 1,312-byte key is accepted as well. The verifier recomputes SHA-256 of
the key and compares it with the program (`interpreter.cpp:2009-2011`), refuses the APO signature-hash type
(`:2037`), and checks the signature against the BIP 143 hash with the `scriptCode` of section 1.5 (`:2041`).
For block limits, a version 1 input counts as one signature operation (`CountWitnessSigOps`,
`interpreter.cpp:1223-1232`; applied at `validation.cpp:521`); this is accounting, and says nothing about how
many verifications run.

### 3.5 Legacy base58 paths that still exist

`CPubKey::GetID`, the Hash160 (SHA-256 then RIPEMD-160) key identifier, still keys the keystore and the address
book, and several RPCs emit or accept it as a base58 address: `getaccountaddress` and `getaddressesbyaccount`
return `CBitcoinAddress(pubKey.GetID())` (`rpcwallet.cpp:160`), `validateaddress` accepts a legacy base58 string
(`rpc/misc.cpp:202-212`), and `createrawtransaction` builds a pay-to-pubkey-hash output for one. Such an output
is refused at spend by the script interpreter (`interpreter.cpp:1646`, `SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO`)
and is non-standard on mainnet and stagenet. An implementer uses section 3.1 only; the base58 paths are tracked
for removal in the project's tracker.

---

## 4. Node wallet encryption (`wallet.dat`, `encryptwallet`)

The node wallet keeps the Bitcoin Core scheme with the key sizes of section 2.

- **Master key**: 32 random bytes from `GetStrongRandBytes`; salt 8 random bytes (`crypter.h:14-16`;
  `wallet.cpp:574-600`, `CWallet::EncryptWallet`).
- **Passphrase KDF**: an in-tree function (`crypter.cpp:17-42`, `BytesToKeySHA512AES`, derivation method 0),
  with no OpenSSL call: D = SHA-512(passphrase ‖ salt), then D = SHA-512(D) repeated until `count` digests have
  been computed; key = D[0:32] and IV = D[32:48] encrypt the master key with AES-256-CBC. The round count is
  calibrated when the wallet is encrypted: 25,000 rounds are timed, the count is scaled to 100 ms, timed again at
  the scaled count, the two estimates averaged, and the floor is 25,000 (`wallet.cpp:590-599`); a passphrase
  change repeats the calibration from the stored count (`wallet.cpp:334-343`). The count is stored with the
  master key as `nDeriveIterations`. `pqwalletinfo` reports `encryption` `AES-256-CBC` and `kdf`
  `SHA-512 EVP_BytesToKey` (`rpc_pqwallet.cpp`, `pqwalletinfo`).
- **Key encryption**: each private key (3,872 bytes) is encrypted with AES-256-CBC under the master key
  (`crypter.cpp:85,104`); the IV is the first 16 bytes of the double SHA-256 of the public key
  (`CPubKey::GetHash`, `pubkey.h:131-134`; `hash.h:20`; `crypter.cpp:123-131,136`).
- **Decryption check**: the decrypted secret must be exactly `CKey::SIZE`, 3,872 bytes (`crypter.cpp:139`), and
  must reproduce the stored public key (`crypter.cpp:145`). There is no MAC; the public-key check is the
  integrity test. At the v2.5.0 tag the length check read 32 bytes, so no key decrypted; at `c21c94333` it reads
  `CKey::SIZE`, and a wallet encrypted by 2.5.0 decrypts under this code.

---

## 5. Entropy (node)

`GetStrongRandBytes` (`random.cpp:276-296`) returns at most 32 bytes: SHA-512 over three inputs, 32 bytes from
OpenSSL's RNG, 32 bytes from the operating system (`GetOSRand`, `random.cpp:200-262`: `getrandom(2)` on Linux,
`getentropy` where the build found it and on macOS when present at run time, `sysctl` `KERN_ARND` on FreeBSD,
otherwise `/dev/urandom`, `random.cpp:180`; any failure calls `RandFailure`, `random.cpp:47`, which aborts) and
32 bytes from the CPU's RDRAND when present (`random.cpp:76-113`). `Random_SanityCheck` runs at start-up and a
failure stops the node (`random.cpp:361`; `init.cpp:712`). It feeds key seeds (`key.cpp:41`), the wallet master
key and salt (section 4), the library's salts and IVs (`pqcrypto.cpp`, `WalletCrypto::Encrypt`) and, through
`src/pat/randombytes.cpp`, hedged signing in the macOS binaries (section 1.4).

---

## 6. Seed derivation (library; the rule for seed-based wallets)

### 6.1 Inputs and bounds

A master seed of at least `MIN_SEED_BYTES` = 32 bytes (`pqderive.h:48`); the BIP-39 seed of a mnemonic is 64
bytes (`pqderive.h:45-46`), and the check is a length test on any seed. Every derivation function throws
`std::invalid_argument` for a shorter seed before reading it (`pqderive.cpp:187-193`, `RequireSeed`);
`PQKeyPair::DeriveFromSeed` returns `nullptr` for one (`pqderive.cpp:316-324`) and `PQWallet::FromSeed` refuses
one (`pqwallet.cpp:509-511`).

### 6.2 One HKDF-SHA256 per key

There is no per-level chain. Every derivation is a single RFC 5869 extract-and-expand with SHA-256
(`pqderive.cpp:34-160`):

```
salt = SHA-256(seed)                                   pqderive.cpp:205-207
PRK  = HMAC-SHA256(salt, seed)                         HKDFExtract
OKM  = HMAC-SHA256(PRK, info ‖ 0x01)                   HKDFExpand, 32 bytes, one block
```

The three functions differ only in `info`:

| Function | info | Lines |
|---|---|---|
| `DeriveKeyMaterial(seed, path, domain, retry)` | domain ‖ PathToBytes(path) [‖ retry, when retry > 0] | `pqderive.cpp:195-230` |
| `DeriveBlindingFactor(seed, index)` | `"soqucoin-blinding-v1"` ‖ index as 8 big-endian bytes | `pqderive.cpp:232-273` |
| `DeriveChannelKey(seed, channelId, keyType, index)` | `"soqucoin-v1/channel/" + channelId + "/" + keyType`, and for `revoke` and `htlc` `"/" + index` with the index as decimal text | `pqderive.cpp:275-314` (`:296-300`) |

Domain strings (`pqderive.cpp:22-25`): `soqucoin-pqwallet-v1` for signing keys, `soqucoin-blinding-v1`,
`soqucoin-v1/channel`, and `soqucoin-v1/watchtower` (defined, used by no function in this file).

`PathToBytes` (`pqderive.cpp:161-177`) is five big-endian 32-bit values: purpose, coin type and account each OR
`0x80000000` (hardened), then change and index unchanged. The default path is `m/44'/21329'/0'/0/i`
(`pqkeys.h:77-82`; `pqwallet.cpp:610-617`).

A wallet that derives blinding factors must never reuse an output index: the 64-bit index is the only input that
separates two factors of one seed, and the previous 32-bit truncation made indices n and n + 2³² collide
(`pqderive.cpp:236-240`).

### 6.3 From material to key pair, and the `0xFF` rule

`PQKeyPair::DeriveFromSeed` (`pqderive.cpp:316-371`) derives 32 bytes of material under `soqucoin-pqwallet-v1`
and expands them with `pqcrystals_dilithium2_ref_seed_keypair`. If the public key's first byte is `0xFF`, the
node's invalid-key marker, it re-derives with the retry byte 1, 2, … up to `MAX_DERIVE_RETRIES` = 8 appended
to `info` (`pqderive.h:49-68`); the first key whose public key does not start with `0xFF` is the key for that
path, and after eight retries the function returns `nullptr`. Retry 0 is byte-identical to the scheme without
the rule.

### 6.4 Known answers

`src/test/pqderive-test --json-vectors` prints the vectors for the BIP-39 test seed; `WALLET_TEST_VECTORS.md`
section 1 publishes them, and the unit suite `pqderive_seed_tests` pins five of them: the signing key at path 0,
the blinding factors 0 to 2 and the channel funding key (`src/wallet/test/pqderive_seed_tests.cpp:116-124`). The
blinding factor at index 0 and the blinding-domain key at path 0 differ because their `info` strings differ (an
8-byte index against a 20-byte path).

### 6.5 Who implements this rule

The header states that every wallet deriving Soqucoin keys from a seed implements the retry rule, naming
SoquShield and its SDK (`pqderive.h:65-66`). At `c21c94333` and the repositories beside it: the SoquShield
Dart key service and the pool site's `shield-crypto.js` implement retry 0 and the retry byte; the soqu.org web
wallet (`soqu-web/wallet/soq-derivation.js`, ops repository) implements retry 0 only, with no `0xFF` check, so
at about one index in 256 it shows an address whose key the node treats as invalid (tracked in the project's
tracker); the Go SDK (`keys/seed.go`) uses a different scheme altogether (HMAC-SHA256 under
`soqucoin-sdk/keys/seed/v2/` with the address prefix in the message, skipping an index on `0xFF`) and does not
produce this section's keys. An implementer of section 6 reproduces `pqderive-test` byte for byte.

---

## 7. Library wallet file encryption (`WalletCrypto`, format v2)

This is the library's own file format. The node never writes it; `wallet.dat` is section 4.

### 7.1 Layout (`pqcrypto.h:64-80`; `pqcrypto.cpp:23-24,345-375`)

```
magic "SQW2" (4) ‖ version 2 (4, big-endian) ‖ kdf_id (1) ‖ salt (16) ‖ iv (16) ‖ tag (16) ‖ ctlen (4, big-endian) ‖ ciphertext
```

`kdf_id` is 1 for PBKDF2, 2 for scrypt and 3 for Argon2id (`pqcrypto.h:57-59`). A reader refuses a file whose
header is shorter than 61 bytes, whose magic or version differ, whose `kdf_id` is none of the three, or whose
`ctlen` exceeds the bytes that follow (`pqcrypto.cpp:385-415`, `EncryptedData::Deserialize`).

### 7.2 Passphrase KDF cascade

Encryption tries, in order, Argon2id (t = 3, m = 65,536 KiB, p = 4; `pqcrypto.h:49-53`; `pqcrypto.cpp:111`),
scrypt (N = 32,768, r = 8, p = 1; `pqcrypto.cpp:170-172`) and PBKDF2-HMAC-SHA256 with 600,000 iterations
(`pqcrypto.cpp:213-220`), through the OpenSSL 3 `EVP_KDF` API; Argon2id exists in that API only from OpenSSL
3.2, so a build against 3.0 or 3.1 writes scrypt files with no other signal (`pqcrypto.cpp:52,117,258`), and
with an OpenSSL below 3 no KDF is available and encryption refuses rather than derive a weak or all-zero key
(`pqcrypto.cpp`, the `HAVE_OPENSSL3_KDF` block at `:33-48`; `pqcrypto.h:12-18`). The identifier of the KDF that
produced the key is stored in the file, and decryption uses that KDF only, with no fallback, so a file written
with Argon2id cannot be opened by a build whose OpenSSL lacks it (`pqcrypto.h`, the three-argument `DeriveKey`;
`pqcrypto.cpp:302-305,529-550`). The cost parameters are constants and are not stored (`pqcrypto.cpp`, the
`KDF_VERSION` note at `:94-101`).

### 7.3 Cipher and tag

The 16-byte salt and 16-byte IV come from `GetStrongRandBytes`; the plaintext is PKCS#7 padded and encrypted with
AES-256-CBC under the 32-byte derived key (`pqcrypto.cpp:454-497`, `WalletCrypto::Encrypt`). The tag is
HMAC-SHA256, keyed with the same key, over version ‖ kdf_id ‖ salt ‖ iv ‖ ciphertext, truncated to 16 bytes
(`pqcrypto.cpp:498-516`). Decryption recomputes the tag and compares it in constant time (XOR-accumulate) before
any decryption, and fails closed on a KDF mismatch, a wrong tag or invalid padding; every failure of `Decrypt`
and of `Deserialize` is the same bare empty result, so a caller cannot distinguish a wrong passphrase from a
corrupt file (`pqcrypto.cpp`, `Decrypt`).

---

## 8. Library address encoder (`PQAddress`): do not implement

`PQAddress::Encode` (`pqwallet.cpp:327`) and `EncodeFromHash` (`pqwallet.cpp:338-372`) hash the public key as
section 3.1 does but push the version byte into the 8-to-5 conversion (`pqwallet.cpp:350`), so the first data
value is 0 and the program does not unpack to 32 bytes; `DecodeDestination` refuses every address they produce,
and `PQWallet::GetNewAddress` (`pqwallet.cpp:597-631`) hands out exactly these addresses (`:628-631`). The
prefixes `tsq`, `tsqp`, `tsqsh`, `sqp`, `sqsh`, `ssqp` and `ssqsh` (`pqwallet.cpp:286-330`) belong to no chain.
The comments at `pqwallet.cpp:345-347` and `pqaddress.h:20` claiming compatibility with `DecodeDestination` are
wrong. No node code path calls any of this (section 0); the RPC that once exposed it is gone from `main`
(`rpc_pqwallet.cpp:494-502`). Implementers follow section 3. Tracked for repair in the project's tracker.

---

## 9. Memory handling

- Node keys live in `secure_allocator` memory (`key.h:33,47`), and every temporary seed or secret key is
  wiped with `memory_cleanse` after use (`key.cpp:43,58,66`).
- The library's `SecureBytes` (`pqkeys.h:46-74`) locks its buffer with `mlock`, unlocks with `munlock` and wipes
  it with `memory_cleanse` on destruction; the lock and unlock are compiled only outside Windows
  (`pqwallet.cpp:115-136`, under `#ifndef WIN32`), and a failed `mlock` is reported on stderr and the program
  continues (`pqwallet.cpp:120-122`). The derivation functions wipe salt, PRK, intermediate hashes and derived
  material (`pqderive.cpp`, throughout).
- Secrets are never logged.

---

## 10. Test vectors

| Area | Where | State |
|---|---|---|
| Seed derivation (section 6) | `WALLET_TEST_VECTORS.md` section 1; `src/test/pqderive-test --json-vectors` | the ten values are the program's output; five are pinned by `pqderive_seed_tests` |
| Addresses (section 3) | `WALLET_TEST_VECTORS.md` sections 2 and 6 | computed from the rule of `utiladdress.cpp` and recomputed independently; no unit test reads them |
| Signatures, transactions, costs | none | not generated; tracked in the project's tracker |
| BLAKE2b | `doc/BLAKE2b_TEST_VECTORS.md` | BLAKE2b is not in the address path (section 3.1); that document's statement that addresses use BLAKE2b-160 (`:11`) is superseded by this one, and PAT's hash is SHA3-256 (`doc/PAT_BLOCK_ATTESTATION.md:124`) |

---

## 11. Summary of guarantees

| Property | Mechanism | Where |
|---|---|---|
| Signature unforgeability | ML-DSA-44, FIPS 204, hedged signing | section 1 |
| Key generation | every node key is generated from a 32-byte seed that is consumed at generation and never stored | sections 1.3, 2 |
| Address binding | SHA-256 of the public key, bech32m with the chain's prefix, version 1 (consensus alone also spends the version 0 form); the preimage commits to the spent `scriptPubKey` | sections 1.5, 3 |
| Wallet at rest (node) | AES-256-CBC under a 32-byte master key; passphrase through iterated SHA-512 with a calibrated round count | section 4 |
| Wallet at rest (library) | AES-256-CBC with HMAC-SHA256 tag; Argon2id, scrypt or PBKDF2 with the KDF id persisted | section 7 |
| Seed derivation | one HKDF-SHA256 per key with domain-separated `info`; the `0xFF` retry rule | section 6 |
| Entropy | SHA-512 over OpenSSL, the operating system and RDRAND; abort on failure; a sanity check at start-up | section 5 |

---

## 12. Documents this version supersedes

Where one of these states an address prefix, an address hash, a signing mode or a file format, this document is
the one of record: `doc/specifications/ADDRESS_FORMAT_SPEC.md` (BLAKE2b-160, `tsq1`, `sqp1`, `sqsh1`, a version
byte); `doc/BLAKE2b_TEST_VECTORS.md:11` (BLAKE2b-160 addresses); `doc/wallet/WALLET_INTEGRATION_GUIDE.md`
(`tsq1`, `pqgetnewaddress`, PBKDF2 100,000, a 12-byte IV); `doc/wallet/WALLET_THREAT_MODEL.md` (deterministic
nonces); `doc/api-reference.md` (`sq1q`, witness version 0, a `0014` script); `doc/wallet/WALLET_API_SPEC.md`
(AES-256-GCM, Argon2id); `doc/wallet/WALLET_ROADMAP.md:62` (the pointer to the address specification). Their
correction is tracked in the project's tracker.

## 13. References

1. NIST FIPS 204, Module-Lattice-Based Digital Signature Standard
2. RFC 5869, HKDF
3. RFC 2104, HMAC
4. BIP 143, transaction signature verification for version 0 witness program
5. BIP 350, bech32m
6. BIP 44, multi-account hierarchy for deterministic wallets (the path layout only)
7. PQ-Crystals, CRYSTALS-Dilithium reference implementation, https://github.com/pq-crystals/dilithium

---

*Soqucoin Wallet Cryptographic Specification v2.1 | October 2026*
