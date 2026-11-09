# The node for a reviewer new to blockchains

A C++ engineer with a testing background can review this node without having run a blockchain
before. The node is a server with two properties to defend, determinism and safety under hostile
input. Most of a review is checking those two properties on every changed line. The steps for one
release or one pull request are in `doc/release-review-checklist.md`. Activation state, the test
inventory and the audit status are cited in `doc/FOR_AI_REVIEWERS.md`.

## 1. What the program is

`soqucoind` is a long-running server. It keeps an append-only log of blocks on disk. It validates
every block and every transaction against fixed rules. It talks to two kinds of client. Anonymous
peers reach it over TCP through the peer-to-peer protocol. An authenticated local client reaches
it over HTTP through JSON-RPC (`soqucoin-cli`). Many copies run on machines that nobody controls
together. The network is the set of copies that agree.

**Determinism.** Every node reaches the same verdict on every block and every transaction, forever.
Two nodes that disagree split the network into two chains. A chain split is the worst outcome the
software can produce. A rule that depends on the compiler or the operating system is a split
waiting for its trigger. The same holds for the clock, the locale and an uninitialized read.
Undefined behaviour in validation code is a consensus defect even when every compiler tested
agrees.

**Hostile input.** A peer can send any bytes. A message handler that allocates without a bound
gives a stranger a way to stop every node. The same holds for a loop without a bound and for an
exception nobody catches. A reviewer reads every input path as if an attacker wrote the input.

**Money is state.** The set of unspent transaction outputs (the UTXO set) is a database of coins.
Each coin is locked by a script. A transaction spends coins by satisfying their scripts. On this
chain the satisfying data is an ML-DSA-44 signature over the transaction. The transaction then
creates new coins with new locks. A block is a batch of transactions plus a header. The header
commits to the batch and carries proof of work. Validation is a function from the chain state and
a block to a verdict and a new state. The whole network runs that function in lockstep.

## 2. The vocabulary, in engineering terms

| Term | What it is here |
|---|---|
| Block | A header plus an ordered list of transactions. The header commits to the list through a Merkle root and to the previous block through its hash. `src/primitives/block.h`. |
| Chain tip, reorg | The tip is the last block of the chain with the most work. A reorg moves the tip to a competing chain. Blocks are disconnected, their transactions return to the mempool, and the competing blocks are connected. |
| Transaction | Inputs that spend existing coins and outputs that create new ones. The difference between the two sums is the fee. `src/primitives/transaction.h`. |
| UTXO set, chainstate | The coins that exist, kept in a LevelDB database. `src/coins.cpp`, `src/txdb.cpp`. |
| Coinbase, maturity | The first transaction of a block creates the block reward from nothing. Its outputs wait a fixed number of blocks before they can be spent. Both figures are per network in `src/chainparams.cpp`. |
| Script, interpreter | A small stack language that locks each coin. `src/script/interpreter.cpp` runs it. |
| Witness, witness version | The witness is the data that satisfies a script, carried beside the transaction (segregated witness). A witness version is a number in the output. It selects the rule set the interpreter applies. A scheduled version that is not yet active is anyone-can-spend at the script layer, and the relay layer refuses it. Every change that waits for its height takes this posture (`doc/FOR_AI_REVIEWERS.md`, section 2). |
| Signature | ML-DSA-44 (FIPS 204) and nothing else. ECDSA is removed. A public key is 1,312 bytes and a signature is 2,420 bytes (`src/crypto/dilithium/api.h:7` and `:9`). Those sizes drive every weight and fee figure on the chain. |
| Mempool | The valid, unconfirmed transactions a node holds and relays. `src/txmempool.cpp`. |
| Consensus, policy | Consensus rules decide whether a block is valid, and every node applies the same ones. Policy rules decide what this node accepts into its mempool and relays. Policy is stricter than consensus. A node can change its policy without splitting the chain. `src/policy/policy.cpp`. For every changed line, the review asks which of the two it belongs to. |
| Standard | The policy word for a transaction the mempool accepts. A non-standard output is valid in a block and refused at relay. |
| Soft fork, hard fork | A soft fork makes the set of valid blocks smaller, so nodes on the old release still accept the new blocks. A hard fork makes it larger, so old nodes reject the new blocks and the chain splits. Every scheduled change here is a soft fork. |
| Activation height, flag day | The block height H at which a scheduled rule starts to apply, set per network in `src/chainparams.cpp`. The release that carries H is the flag day. Defects live at the boundary. The tests a reviewer looks for cover H-1, H and a reorg across H. |
| Proof of work, AuxPoW | A block is valid when its header hashes under the target. On this chain the work can be done in a parent chain's block by pools that mine Litecoin. The AuxPoW section of the header proves it (merge mining, `src/auxpow.cpp`). Miners and pools produce blocks. A node validates them and never needs to mine. |
| Networks | Mainnet carries real coins. Testnet and stagenet are public rehearsal networks. Regtest is a private chain on your machine where you create blocks on demand. Each has its own parameters in `src/chainparams.cpp`. |
| Node, wallet, miner, pool | Four programs. The node validates and relays. The wallet, an optional module under `src/wallet/`, holds keys and builds transactions. A miner finds proof of work. A pool coordinates miners. A node on a server runs with `disablewallet=1`. |
| Initial block download | The state of a fresh node replaying the chain from the first block. |
| Peer, message | Another node, and the typed messages it sends. `src/net_processing.cpp` handles every message type and is the main hostile-input boundary. `src/net.cpp` is the socket layer. |
| RPC | The JSON-RPC interface under `src/rpc/`. Its clients are `soqucoin-cli`, the functional tests, explorers, pools and exchanges. |

## 3. Where things are

The tree is based on Dogecoin Core 1.14 with later backports. Dogecoin Core 1.14 is itself based
on Bitcoin Core 0.14. The inherited parts carry years of upstream review. The project's own parts
carry less. Review time goes there, and to every line a release changes.

| Area | Files | Origin |
|---|---|---|
| Validation: block connection, mempool acceptance, the per-deployment script flags | `src/validation.cpp` | Inherited, with the project's deployment flags |
| Script interpreter, including the dispatch on witness version | `src/script/interpreter.cpp` | Inherited, with the project's witness versions |
| Chain parameters: activation heights and per-network values | `src/chainparams.cpp`, `src/consensus/params.h` | Inherited structure, the project's values |
| Policy: standardness and relay limits | `src/policy/` | Inherited, with the project's limits |
| ML-DSA-44 | `src/crypto/dilithium/` | The FIPS 204 reference code |
| Other cryptography of the project | `src/crypto/blake2b.*`, `src/crypto/pat/`, `src/crypto/latticefold/`, `src/crypto/latticebp/`, `src/crypto/binius*/` | Project |
| Consensus modules of the project | `src/consensus/pat_attestation.*`, `src/consensus/usdsoq.*`, `src/consensus/btcsoq.*`, `src/consensus/soquobscura/`, `src/consensus/block_accumulator.*` | Project |
| PAT (batch attestation) keys and types | `src/pat/` | Project |
| Emission schedule and fees | `src/soqucoin.cpp`, `src/soqucoin-fees.cpp` | Project |
| Address format | `src/utiladdress.cpp` | Project |
| Merge mining | `src/auxpow.cpp`, `src/rpc/auxpow.cpp` | Dogecoin |
| Peer-to-peer | `src/net.cpp`, `src/net_processing.cpp`, `src/protocol.*` | Inherited |
| RPC | `src/rpc/` | Inherited. `pat.cpp`, `privacy.cpp`, `usdsoq.cpp` and `batch.cpp` are the project's. |
| Post-quantum wallet | `src/wallet/pqwallet/` | Project |
| Unit tests | `src/test/` (Boost.Test). `src/test/dilithium_chain_setup.h` is the fixture that builds a signed regtest chain. | Both |
| Fuzz targets and seed corpus | `src/test/fuzz/` | Project |
| Functional tests | `qa/rpc-tests/`, run by `qa/pull-tester/rpc-tests.py` | Both |
| Continuous integration | `.github/workflows/` | Project |
| Specifications and activation records | `doc/specifications/`, `doc/DEPLOYMENT_PRECONDITIONS.md` | Project |

Several modules in the tree are dormant on every network. Some are incomplete by their own
comments. `doc/FOR_AI_REVIEWERS.md` sections 3 and 10 list them with the lines. A finding in
dormant code is still a finding, with the lower urgency its reachability gives it.

## 4. The consensus boundary

A line is consensus-critical when a change to it can change the verdict on a block. Those lines
live in:

- `src/validation.cpp`, `src/script/` and `src/consensus/`
- `src/chainparams.cpp`, `src/pow.cpp` and `src/auxpow.cpp`
- `src/primitives/`, the serialization of blocks and transactions
- `src/coins.cpp` and `src/txdb.cpp`, the on-disk state
- `src/soqucoin.cpp`, the block subsidy that `ConnectBlock` checks against the coinbase
- every function those files call on the way to a verdict, under `src/crypto/` or anywhere else

New rules on this chain activate by a per-network height set in a coordinated release
(`doc/FOR_AI_REVIEWERS.md`, section 2). `CONTRIBUTING.md` states what a pull request that touches
validation has to say. It says what changes. It says what an attacker could do before and after.
It says how the test proves the difference. The reviewer checks those three statements against
the diff.

For each changed line, the questions:

1. Which layer is it in: consensus, policy, relay, RPC, wallet or test?
2. Can a peer reach it with a message, a transaction or a block?
3. Is the work it does bounded by a constant or by the input length?
4. Does its result depend on anything other than the chain state and the input?
5. Is it gated by a height, and do the tests cover H-1, H and a reorg across H?
6. What does a node on the previous release do with the same input?

## 5. Build and test on your machine

CI runs the same commands from `.github/workflows/ci.yml`. When a step there has changed, the
workflow is the reference.

### Linux (Ubuntu 22.04, the image CI uses)

```bash
sudo apt-get install -y build-essential libtool autotools-dev automake pkg-config bsdmainutils \
  python3 libssl-dev libevent-dev libboost-all-dev libminiupnpc-dev libzmq3-dev libsqlite3-dev \
  libdb++-dev python3-zmq python3-pip python3-setuptools python3-dev
./qa/pull-tester/install-deps.sh      # the scrypt hasher the functional tests need
./autogen.sh
./configure --without-gui --enable-zmq --enable-module-rangeproof --enable-module-generator --enable-experimental
make -j"$(nproc)"
```

### macOS (Apple silicon)

```bash
brew install automake libtool boost miniupnpc openssl@3 pkg-config libevent zeromq berkeley-db
pip3 install pyzmq                    # the functional tests import zmq
./qa/pull-tester/install-deps.sh      # the scrypt hasher the functional tests need
./autogen.sh
./configure --without-gui --with-incompatible-bdb --with-boost=/opt/homebrew/opt/boost \
  LDFLAGS=-L/opt/homebrew/lib CPPFLAGS=-I/opt/homebrew/include
make -j"$(sysctl -n hw.ncpu)"
```

CI builds the macOS binary without the tests and without the wallet. The configure line with
`--with-incompatible-bdb` builds both.

### Unit tests

```bash
make check                                        # the unit binary and the fuzz seed-corpus gate
src/test/test_soqucoin --list_content             # every suite and case
src/test/test_soqucoin --run_test=auxpow_tests    # one suite
src/test/test_soqucoin --run_test=auxpow_tests/<case> --log_level=all
```

`make check` runs `src/test/test_soqucoin` (Boost.Test) and the seed-corpus gate
`src/test/fuzz/run_seed_corpus.sh` (`src/Makefile.test.include`, the `TESTS` lines). With a
`--run_test` filter Boost prints every unselected suite as skipped. The skipped lines are the
filter at work. The unfiltered run executes them all.

### Functional tests

```bash
qa/pull-tester/rpc-tests.py auxpow.py pat_basic.py    # named tests
qa/pull-tester/rpc-tests.py                            # the default list
qa/pull-tester/rpc-tests.py -extended                  # plus the extended list
qa/pull-tester/rpc-tests.py -parallel=4                # four at a time
```

Each test starts one or more `soqucoind` processes on regtest and drives them over RPC. The
framework is `qa/rpc-tests/test_framework/`. CI runs the project-specific set listed in
`.github/workflows/ci.yml`. The default list has tests that date from the inherited code. Some of
them are disabled or absent from the runner (`doc/FOR_AI_REVIEWERS.md`, section 9).

### Regtest by hand

```bash
src/soqucoind -regtest -daemon
src/soqucoin-cli -regtest generate 101
src/soqucoin-cli -regtest getblockchaininfo
src/soqucoin-cli -regtest stop
```

Regtest serves mining work by default. Mainnet does not. A mainnet node that serves a pool opts
in with `-enablemining=1` (`src/init.cpp`, the option's help text).

### Coverage (Linux)

```bash
sudo apt-get install -y lcov python-is-python3   # configure refuses --enable-lcov without them
make clean                                       # objects built with other flags are kept otherwise
./configure --enable-lcov <the other flags>
make -j"$(nproc)" && make cov
```

`make cov` writes `test_bitcoin.coverage/` for the unit suite and `total.coverage/` for the unit
and functional suites together (`Makefile.am`, the `cov` target). The functional half ignores a
failing test run (`Makefile.am`, the `rpc_test.info` recipe). Read the runner's output before
trusting the report. CI has no coverage job.

### Sanitizers

No configure option enables them. Run `make clean` first, or build in a fresh clone. Objects
built with other flags are kept otherwise, and the loop would run uninstrumented code. Pass the
flags:

```bash
make clean
./configure <the other flags> \
  CFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" \
  CXXFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" \
  LDFLAGS="-fsanitize=address,undefined"
make -j"$(nproc)"
for s in $(src/test/test_soqucoin --list_content 2>&1 | grep -v '^ ' | tr -d '*'); do
  src/test/test_soqucoin --run_test="$s" > "san-$s.log" 2>&1 || echo "$s"
done
```

The address sanitizer stops the binary at its first report. One suite per process shows every
report instead of the first one. CI has no sanitizer job.

### Fuzzing

`src/test/fuzz/fuzz` is built with the tests. `src/test/fuzz/fuzz --list` prints the registered
targets. `FUZZ=<target> src/test/fuzz/fuzz < <file>` runs one input through one target. The driver reads
the input from standard input (`src/test/fuzz/Fuzz.cpp`, `main`).
`make check` runs every target over the seed corpus under `src/test/fuzz/corpus` once, as a smoke
gate. The script states what that run does and does not prove. A fuzzing campaign needs a
per-target corpus and an engine. The engines are libFuzzer through clang's `-fsanitize=fuzzer`,
or AFL as `doc/fuzzing.md` describes for the older `test_soqucoin_fuzzy` harness.

### Static checks

`./configure --enable-werror` turns warnings into errors. CodeQL runs on the repository
(`.github/workflows/codeql-analysis.yml`). The lint job in CI checks whitespace on changed lines,
compiles the Python tests and runs shellcheck on the project's scripts.

## 6. Where a finding goes

| Finding | Channel |
|---|---|
| A crash, a hang or unbounded memory from a peer message or a block. Two nodes reaching different verdicts. A spend without the key. Coins from nothing. Anything else a stranger could trigger on mainnet. | GitHub private vulnerability reporting, as `.github/SECURITY.md` describes. A public issue or a public review comment would publish the defect before the fix. The fix is built in a private fork. |
| A security defect that needs RPC access, a local file or a configuration flag. Key leakage, weak derivation, an authentication bypass. | The same private channel. The policy's scope covers wallet and key management and RPC authentication (`.github/SECURITY.md`). |
| A bug with no security consequence. A wrong result on a local command, a wrong help text, a crash on a malformed configuration file. | An issue with the file, the line, a reproducer and a falsifiable claim. |
| A changed line no test executes. A test that would pass with garbage input. Dead code or duplicate logic. A comment that disagrees with the code. | A review comment on the pull request, or an issue. |

Text in a pull request passes the `register` check (`CONTRIBUTING.md`). The check reads the
title, the body, the commit messages and the file names. Maintainers merge. A pull request that
changes only tests is welcome at any point in the release cycle.

## 7. A first month

1. Build from `main` on Linux, and on macOS if a machine is at hand. Run `make check`, the CI
   functional list, then the full default list. File what fails or flakes. Record the platform,
   the compiler and the versions.
2. The sanitizer build and the same suites, one unit suite per process. File each report through
   the channel its reachability selects.
3. A coverage report. List the lines under `src/consensus/`, `src/script/`, `src/crypto/` and in
   `src/validation.cpp` that no test executes. A test that covers one is a pull request of its own.
4. From then on, a review of every pull request that touches the consensus boundary and of every
   release branch, with `doc/release-review-checklist.md`.

CI runs no sanitizer build and no coverage report today. A workflow that adds either runs on every
pull request from then on. It costs nothing on a public repository. Both are open work for anyone
who wants them.
