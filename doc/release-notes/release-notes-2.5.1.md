Soqucoin Core 2.5.1
===================

Soqucoin Core 2.5.1 is the mainnet launch release. It is 2.5.0 with the genesis
migration armed on mainnet at block 1, the block-1 launch time gate, and the
wallet, policy, tooling and packaging changes listed below. Every mainnet node
must run it: a 2.5.0 node rejects block 1 (`bad-cb-amount`) and cannot follow
the chain past genesis.

Mainnet block 1 is scheduled for 13 October 2026 at 15:00 UTC. The first day,
including when public peering opens, is described in `doc/node-operators.md`.

Upgrading
---------

Stop the running daemon, replace the binary, start it. No reindex is required.
A node run with `disablewallet=1` has no wallet data to back up; a node with a
wallet keeps its wallet file. A mainnet node starts on a fresh data directory;
stagenet, testnet and regtest data directories carry over.

Consensus, mainnet only
-----------------------

### Genesis migration armed at block 1

The one-shot allocation rule (`hashMigrationOutputs`, `nMigrationTotal`,
`nMigrationHeight`), inert on every network in 2.5.0, is armed on mainnet at
height 1 through the single `ArmMigration` call in `CMainParams`
(`src/chainparams.cpp`):

- `nMigrationHeight`: 1
- `nMigrationTotal`: 32,862,741,293,540,900 sats (328,627,412.935409 SOQ)
- `hashMigrationOutputs`: `4db916bf087e83351afa508ac1993718c602a84aca7cd2dba50d8df50c4789d6`
- 70 outputs, each a witness version 1 program

The vector is the published final set of the pSOQ to SOQ migration window of
29 September to 5 October 2026 (`soqucoin.org/migration/list/final/`:
`outputs.hex`, sha256
`6c0f6480a6d3797e9e5e3745b6922332a053f1d2268a9d418b8551f273610ce6`, and
`commitment.txt`, which carries the hash and the total). The coinbase of block 1
must carry the 70 outputs as `vout[1..70]` in that order, after the miner's
output and before any trailing block-commitment output, or the block is invalid
(`ConnectBlock`: `bad-cb-migration-missing`, `bad-cb-migration-outputs`,
`bad-cb-migration-total`, `bad-cb-migration-miner-value`). The miner's own
output at height 1 stays bounded by the subsidy plus fees.

A node built from these constants asserts at startup that the compiled-in
vector hashes to the constant and sums to the total; a mistranscribed vector
does not start. Before block 1, operators can compare nodes: `getblockchaininfo`
reports `genesis_migration` with `armed` true, `height` 1,
`hash_migration_outputs` and `total_sats` as above, and the startup log prints
`Genesis-migration allocation rule ARMED: height=1 total=32862741293540900
outputs=70 hash=4db916bf…`.

Stagenet, testnet and regtest are unchanged: the rule stays inert there, and
the regtest options `-migrationoutputs`, `-migrationheight` and
`-migrationtotal` behave as before.

### Block-1 time gate

The block at height 1 must carry a time at or after 1791903600
(2026-10-13T15:00:00Z): `Consensus::Params::nMinBlock1Time`, checked once in
`ContextualCheckBlockHeader`, before the generic timestamp rules. A block 1 timed
earlier is rejected as `block1-before-launch` with a DoS score of 100, the same
on every node, since the rule reads the block's own time and a constant and
never a clock. Later heights are unaffected; stagenet, testnet and regtest carry
0 (no gate). `getblocktemplate` reports `mintime` as the gate at height 1 when
the gate is later than the median time past plus one. The startup log prints
`Block 1 time gate: nTime >= 1791903600 (2026-10-13T15:00:00Z)`. Regtest arms a
gate with `-minblock1time=<unix time>` (0 through 4294967295) for the tests.

### Consensus digest

The digest pinned by `consensus_digest_tests` moves twice in this release, both
times on mainnet inputs: from `e7ea83dc…` to `04c245de…` for the time gate, and
from `04c245de…` to `bdc9cff6…` for the arming (the three migration
fields at every sampled mainnet height, from null, 0 and 0 to the constants
above). The pin's history paragraph records both moves. Testnet, stagenet and
regtest rules do not move: the time-gate move absorbs a new word that is 0 on
them, and the arming move touches mainnet's fields only.

Wallet and RPC
--------------

### An encrypted wallet of ML-DSA-44 keys unlocks with its passphrase

`encryptwallet`, `walletpassphrase` and `walletpassphrasechange` work with
ML-DSA-44 keys. In 2.5.0 the key decryption refused every decrypted private key
that was not 32 bytes long, so no encrypted key ever decrypted and an encrypted
wallet could not be unlocked with the right passphrase; the keys themselves were
intact, and a wallet encrypted by 2.5.0 unlocks with this release. `pqwalletinfo`
reports `encryption` as `AES-256-CBC` and `kdf` as `SHA-512 EVP_BytesToKey`,
which is what the wallet does; `kdf_params` is removed because the iteration
count is calibrated per wallet each time a passphrase is set.

### `pqgetnewaddress` removed; `pqvalidateaddress` decodes as the node does

`pqgetnewaddress` is removed: it kept no key and returned an address in a layout
the node itself refuses. Use `getnewaddress`, which returns a bech32m witness
version 1 address whose key the wallet holds. `pqvalidateaddress` decodes as
`sendtoaddress` does: valid only for this node's network prefix, witness version
1 and a 32-byte program; `pubkey_hash` is the witness program and `network` is
this node's network.

### ML-DSA private keys have a text form; witness v1 signing through the tools

`CBitcoinSecret` accepts two forms of an ML-DSA-44 private key and reproduces the
key from each: the seed form (base58check of the `SECRET_KEY` prefix, the 32-byte
FIPS 204 seed and a trailing `0x02` marker) and the expanded form (base58check of
the 3,872-byte key pair). A classical 32-byte WIF is refused. `dumpprivkey`
accepts a bech32m address and prints the expanded form; `importprivkey` accepts
both forms; `dumpwallet` and `importwallet` round-trip every key;
`signmessagewithprivkey` works with a supplied key; a new key is drawn as a seed
and expanded through the seeded key generation. `signrawtransaction` and
`soqucoin-tx sign=` produce witness version 1 spends the node accepts; before,
the witness they built was discarded on the way out and every such input failed
verification.

### The key derivation library refuses a seed shorter than 32 bytes

`DeriveKeyMaterial`, `DeriveBlindingFactor` and `DeriveChannelKey` throw
`std::invalid_argument` for a seed shorter than 32 bytes, and
`PQKeyPair::DeriveFromSeed` returns `nullptr` for one; before, each returned an
all-zero key. The wallet refuses such a seed before it derives anything, so the
node never reached that path, and a node run with `disablewallet=1` is
unaffected. Derivation for a seed of 32 bytes or more is unchanged byte for
byte. The blinding-factor vectors in `doc/wallet/WALLET_TEST_VECTORS.md` are
regenerated from `pqderive-test --json-vectors`: the published values dated
from before the March 2026 change to the output-index encoding and did not
match the library's output.

Policy
------

### Relay refuses outputs the script layer cannot spend

Where standardness is required (mainnet and stagenet), a transaction enters the
mempool only if every output is OP_RETURN data, a witness version 1 program, or a
program of a witness version whose deployment is active. Pay-to-pubkey,
pay-to-pubkey-hash, pay-to-script-hash, bare multisig and witness version 0
outputs are refused with the reason `scriptpubkey`, since nothing on this chain
can spend them. `-permitbaremultisig` is removed; a configuration line naming it
is ignored. A block may still contain such outputs: this is relay policy, not
consensus.

Build and packaging
-------------------

- The macOS packages are built on their own architecture (arm64 and x86_64),
  need macOS 15.0 or later, link their libraries statically and load only system
  libraries, so they start on a Mac without Homebrew. The v2.5.0 macOS x64
  package held arm64 binaries, and every v2.5.0 macOS binary needed a Homebrew
  library. A tag push runs a verification step before packaging; a workflow
  dispatch from a branch publishes nothing.
- The release no longer builds the solo miner. SOQUPOOL is the only supported
  way to mine SOQ at mainnet launch; support for other pools and for solo mining
  will be announced when it is ready.

Documentation and tests
-----------------------

- `doc/node-operators.md`: a node on stagenet now and on mainnet from launch,
  the first day, and how to check block 1.
- `doc/FOR_AI_REVIEWERS.md` and `doc/specifications/CONSENSUS_COST_SPEC.md`
  state the block 1 genesis migration beside the subsidy.
- The genesis-migration snapshot tool, its specification and the lists it reads
  are in `contrib/genesis-migration/` (specification version 5).
- A node-signed sighash vector for the SDK's fixtures; the repository's register
  check runs in CI; the macOS ARM64 CI job runs on macos-15.

Known limitations
-----------------

- The Linux release artifact is built on Ubuntu 22.04 and does not load on
  24.04 hosts (shared library versions). Node operators on other systems build
  from the tag until a portable artifact ships.
- Verification-cost budgeting for post-quantum signatures is defined but not
  enforced. The block weight limit and the sigop budget bound the verification
  work a block can demand (about 1,025 ML-DSA-44 inputs a block); peer limits
  and ban thresholds cover the rest. A fix is planned for the first post-launch
  release.
- The manual pages under `doc/man/` still describe an earlier release.

Credits
-------

Thanks to everyone who contributed to this release.
