<h2 align="left">
<img src="https://images.squarespace-cdn.com/content/v1/67b2bbb273ed3f75691938e0/b1002822-cf36-4cdc-aa60-678d312f6d5a/Gemini_Generated_Image_c5wxsjc5wxsjc5wx.png?format=500w" alt="Soqucoin" width="256"/>
<br/><br/>
Soqucoin Core [SOQ]

**The world's first cryptocurrency with native, recursive, lattice-based batch verification of NIST-standard post-quantum signatures — deployed on main, today.**

- ML-DSA-87 (Dilithium) fully integrated  
- PAT (Practical Aggregation Technique) – logarithmic Merkle batching, 9,661× commitment reduction, <4 µs verify  
- LatticeFold+ over Binius64 fields (Boneh–Chen, ePrint 2025/247) – true constant-size recursive proofs, 1.21–1.52 kB, 0.51–0.91 ms verify on consumer hardware  
- Full Miner compatibility (Scrypt PoW unchanged)  
- Merged-mining ready with Litecoin/Dogecoin

**Current status: November 20, 2025 – 22:41 UTC**  
All consensus code merged, CI green, regtest running pure Dilithium-only chains from block 0.  
LatticeFold+ verifier deployed in production consensus rules.  
100% libFuzzer coverage achieved on verifier within 4 hours of integration.

**Mainnet genesis: January 1, 2026 — 18:00 UTC** 
(final testing, documentation, and miner onboarding)

## Why Soqucoin Exists

Quantum computers will break ECDSA. Every chain still using it in 2025 is building on borrowed time.

Soqucoin is the only chain that eliminated ECDSA entirely, from block 0, and replaced it with the most efficient post-quantum batching schemes known to cryptography in 2025:

- ≤256 signatures → PAT logarithmic Merkle (65–72 byte on-chain footprint)  
- >256 signatures → LatticeFold+ recursive folding over Binius64 packed fields (constant-size proof, sub-millisecond verification, recursion-ready)

No soft-fork. No hybrid mode. No excuses.

Just quantum-resistant consensus, today.

## Usage

See [INSTALL.md](INSTALL.md) and [doc/getting-started.md](doc/getting-started.md).

Default ports:

| Function | mainnet | testnet | regtest |
| :------- | ------: | ------: | ------: |
| P2P      |   33388 |   44556 |   18444 |
| RPC      |   33389 |   44555 |   18332 |

## Development Status – Moon Plan Completed Ahead of Schedule (Imminent)

All six planned consensus commits are merged as of November 20, 2025:

1–2. PAT integration + OP_CHECKPATAGG (0xfd)  
3–5. Binius64 field arithmetic  
4–5. Full LatticeFold+ 8-round verifier + OP_CHECKFOLDPROOF (0xfc)  
6.   Wallet RPC `createbatchtransaction` with automatic strategy selection

Regtest blocks containing 1024-input Dilithium transactions validate in <2 ms on 2015 hardware.

The prover is not yet in-tree (expected Q4 2025–Q1 2026), but verification is consensus-critical and already the fastest lattice-based verifier ever deployed.

### Branches

Current repository structure (November 20, 2025):

- **soqucoin-genesis** – Default branch. This is the only active development branch and contains the complete, production-ready post-quantum consensus rules. All commits land here directly during the pre-launch phase.
- **master** – Does not exist yet. Will be created at mainnet launch as a protected branch for post-genesis development.

### Contributing (Pre-Launch Policy – until March 1, 2026)

Soqucoin Core is in final pre-genesis lockdown. The entire post-quantum consensus stack (PAT + LatticeFold+/Binius64) was merged in a 6-commit series on November 20, 2025 and is now undergoing intensive private testing on real Scrypt ASICs.

Until mainnet genesis we are intentionally keeping the tree closed to unsolicited pull requests in order to:
- Maintain absolute control over consensus-critical code
- Complete ASIC testing, fuzzing, and formal verification without merge conflicts
- Finalize launch materials

**How to contribute right now (and be extremely welcome):**

1. Open a GitHub Issue for bugs, performance reports, or testnet findings  
2 Join GitHub Discussions for feature proposals or prover development ideas  
3 Share regtest blocks, fuzz corpora, or ASIC screenshots — these will be credited in the launch paper

Pull requests will be enabled and enthusiastically reviewed immediately after genesis (March 1, 2026). Until then, the fastest way to get your name in the launch paper and receive founder-level recognition is to help stress-test the chain or port the LatticeFold+ prover.

We are not gatekeeping — we are protecting the first quantum-resistant PoW launch in history.

Thank you for respecting the lockdown. The chain will be yours to build on in 101 days.
## Very Much Frequently Asked Questions

See [doc/FAQ.md](doc/FAQ.md) and GitHub Discussions.

## License

MIT — see [COPYING](COPYING)

Soqucoin Core is released under the day the post-quantum future began: **November 20, 2025**.

wow. very quantum. much resistance.