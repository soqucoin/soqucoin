# Mainnet Genesis Ceremony (FC4)

The mainnet genesis block currently reuses the Dogecoin genesis template
(message "Nintondo", nTime 1386325540, nonce 99943, the original ECDSA P2PK
output). Launch checklist item A1 and bead z9vk ratify replacing it before
launch with a purpose-built genesis. This document is the complete procedure,
staged so the ceremony itself is a one-sitting operation. It is a
consensus-touching change: it lands inside Freeze Candidate 4 and shares that
candidate's soak.

## Why a dated headline

A genesis containing a same-day wire-service headline provably was not mined
before that date. On a chain whose fair-launch claim is load-bearing and whose
merge mining opens at height 0, this is the one artifact that mathematically
forecloses "they secretly mined early". It also removes a permanent optics
liability: after genesis the block is immutable, and every decoder would
otherwise display another chain's 2013 message and an ECDSA key on an
ECDSA-elimination chain forever.

## Inputs, chosen on ceremony day

1. `pszTimestamp`: a verifiable, dated headline, ideally quantum-computing
   related. Nothing clever. See **Choosing the headline** below, which records
   the byte budget, the date ladder and a pre-vetted fallback.
2. `nTime`: the actual UTC timestamp of the ceremony.
3. The output script: replace the Dogecoin ECDSA P2PK with a
   nothing-up-my-sleeve unspendable output. The genesis coinbase is excluded
   from the UTXO set regardless; this is about what decoders display.

## Choosing the headline

### The byte budget is 91 characters. This is consensus, not style.

`validation.cpp:558` rejects any coinbase whose `scriptSig` is under 2 or over
**100 bytes**. `CreateGenesisBlock` (chainparams.cpp:61) builds:

```
CScript() << 486604799 << CScriptNum(4) << <message bytes>
```

which costs 5 bytes for `486604799` (4 data + 1 opcode), 2 for `CScriptNum(4)`
(1 data + 1 opcode), and the message push: `1 + N` while `N <= 75`, or `2 + N`
from 76 up, where `OP_PUSHDATA1` adds a length byte. So:

| message length | scriptSig | verdict |
|---|---|---|
| N <= 75 | N + 8 | fits |
| 76 <= N <= 91 | N + 9 | fits |
| N >= 92 | N + 9 > 100 | **consensus-invalid** |

**Maximum message: 91 characters.** For calibration, Bitcoin's genesis message
is 69 characters, a 77-byte scriptSig.

⛔ Count it before the ceremony. An over-length `pszTimestamp` does not fail
loudly at mine time; it produces a block the network will reject.

### The date ladder

The headline's job is to prove the block was not mined before its date. A
headline older than the ceremony leaves a gap of exactly that age in which a
"they mined early" claim cannot be foreclosed by this artifact alone. So,
in preference order:

1. **Ceremony-day headline.** Gap of zero. This is what the section above means
   by immediacy, and it remains the strongest option.
2. **21 September 2026.** Founder's birthday, and a private meaning that is
   invisible to any reader, which is the good kind. Costs a gap equal to the
   distance from 21 Sep to the ceremony. ⚠️ Cannot be selected before that date
   arrives; check the majors on the day and keep anything usable. A Reuters, AP
   or Bloomberg quantum story carries more weight with exchange and federal
   readers than a trade outlet.
3. **The pre-vetted fallback below.** Use only if neither of the above produced
   something usable.

Any option other than (1) **should be paired with the Bitcoin anchor**, which
closes the gap cryptographically rather than journalistically.

### Pre-vetted fallback, locked 2026-08-27

Verified to exist, correctly dated, on-theme, and within budget:

```
CoinDesk 27/Aug/2026 Bitcoin researchers propose quantum fix
```

60 characters, 68-byte scriptSig, 32 characters spare.

Source: <https://www.coindesk.com/tech/2026/08/27/bitcoin-researchers-propose-quantum-fix-that-would-not-crowd-out-transactions>
The full headline ("... that would not crowd out transactions") is 98 characters
with the date prefix and does **not** fit; the trim above is deliberate and ends
on the load-bearing verb. The article covers SHRINCS, a hash-based post-quantum
signature proposal for Bitcoin by Blockstream researchers Jonas Nick and Mikhail
Kudinov, described as the first concrete post-quantum signature design specific
to Bitcoin.

Why it is on-theme without needing to say anything: it is dated evidence that in
August 2026 Bitcoin was still *proposing* its first concrete post-quantum
signature, in the genesis block of a chain that ships ML-DSA-44 live from height
zero. Same structure as Bitcoin quoting a bank-bailout headline in the block that
replaced the banks.

⛔ **Do not editorialise around it afterwards.** Bitcoin has the harder problem:
retrofitting post-quantum signatures without breaking fifteen years of UTXOs and
capacity. SHRINCS starts at 324 bytes against Schnorr's 64; ML-DSA-44 is 2,420.
Soqucoin did not beat anyone on signature size, it had a clean slate and designed
around the cost from block 0. The line states a dated fact. Overclaiming in
commentary is what would cheapen it.

### Optional: the Bitcoin block anchor

A recent Bitcoin block hash is a stronger timestamp than a newspaper. It is
verifiable forever from any node, does not depend on a publisher's archive, and
cannot be produced before that block existed. Kaspa uses this approach. Appending
one closes the premine gap to zero even when the headline is older:

```
CoinDesk 27/Aug/2026 Bitcoin researchers propose quantum fix BTC 921456 9f3ac1d2
```

80 characters, 89-byte scriptSig, 11 spare. Substitute the real height and a
short hash slice taken on the morning of the ceremony.

⚠️ Take the slice from a part of the hash that is not the leading zeros, which
carry no information. Record the full hash in the ceremony log so the prefix can
be checked later.

## Procedure

1. Branch from the FC4 candidate. All other FC4 consensus changes must
   already be in, so one soak covers everything.
2. Edit `src/chainparams.cpp` `CreateGenesisBlock` (the mainnet call site near
   line 433): new `pszTimestamp`, new `nTime`, nonce 0.
3. Mine the nonce: build, run with a temporary search loop (the pattern used
   for the 2025/2026 testnet and stagenet geneses; scrypt at nBits 0x1e0ffff0
   takes seconds), and record nonce, block hash, and merkle root.
4. Update every pin, in one commit:
   - `src/chainparams.cpp:439` mainnet `hashGenesisBlock` assert
   - `src/chainparams.cpp:440` mainnet `hashMerkleRoot` assert
   - the scrypt PoW hash recorded in the comment near line 435
   - `src/test/genesis_chainparams_tests.cpp` expected mainnet genesis values
   - `src/test/consensus_digest_tests.cpp` digest pins (the digest hashes
     `hashGenesisBlock`; the pinned digests WILL change and that is the
     tripwire working, not breaking)
5. Run the full unit suite. Expected result: everything green except exactly
   the three deliberate SoquObscura tripwires. Any fourth failure stops the
   ceremony.
6. Differential validation: replay the full stagenet history against the new
   binary and diff verdicts transaction by transaction (stagenet and testnet
   geneses are untouched, so history replays identically; this catches
   accidental spillover).
7. Tag the freeze candidate. The soak clock starts at fleet deploy.

## What does not change

Testnet, regtest, and stagenet genesis parameters. Message-start bytes,
ports, DNS seeds. Every deployment posture (dormancy_matrix_tests pins them).
The emission schedule.

## Rollback

Before the tag is published, rollback is `git revert` of the ceremony commit.
After mainnet launch there is no rollback; that is the entire reason this
happens now.
