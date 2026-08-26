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

1. `pszTimestamp`: a verifiable, dated headline from a major wire service,
   ideally quantum-computing related. Nothing clever. Chosen by the founder on
   the day of the ceremony; that immediacy is the point.
2. `nTime`: the actual UTC timestamp of the ceremony.
3. The output script: replace the Dogecoin ECDSA P2PK with a
   nothing-up-my-sleeve unspendable output. The genesis coinbase is excluded
   from the UTXO set regardless; this is about what decoders display.

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
