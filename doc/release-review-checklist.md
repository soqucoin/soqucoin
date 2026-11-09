# Reviewing a release or a consensus pull request

A release branch `release/vX.Y.Z` or a pull request against `main` arrives with a base, a head and
a set of claims. The review checks the claims, the diff and the tests. It ends in a report. The
vocabulary and the build commands are in `doc/reviewer-guide.md`.

## What arrives

- The base: the previous release tag, or `main` for a pull request. The head: the branch's last
  commit, by hash.
- The draft release notes under `doc/release-notes/`, or the pull request body. For a change to
  validation the body states three things (`CONTRIBUTING.md`). What changes. What an attacker
  could do before and after. How the test proves the difference.
- The size, to plan the evenings. Two readings for scale, each from one command:

```
git diff --stat v2.6.0..v2.6.1 | tail -1    # 17 files changed, 618 insertions(+), 81 deletions(-)
git diff --stat v2.5.3..v2.6.0 | tail -1    # 47 files changed, 2225 insertions(+), 244 deletions(-)
```

## The steps, in order

### 1. List the claims

Read the notes or the body before the diff. Write down every claim. Examples: "no consensus
change" or "the RPC interface is unchanged". Also "activates at height H" or "inert on mainnet".
Each claim becomes a check in step 9.

### 2. Enumerate the diff

```
git diff --stat <base>..<head>
git diff <base>..<head> -- src ':!src/test' ':!src/qt'
```

For every function added or changed outside the tests, name its sibling. The sibling is the other
site that applies the same rule or handles the same value on another path. The block path and the
mempool path. Serialize and unserialize. The accept branch and the reject branch. Connect and
disconnect. A fix applied at one site and missed at its sibling is a common shape of defect.

### 3. Build and run from the head, clean

Build on Linux and on macOS from the exact head commit. Run `make check`, then the CI functional
list, then the full default list. Record the platform and the compiler with its version. Record
the case counts, every failure, every flake and the wall time. A test that fails once and passes
on rerun is a finding, with the log attached.

### 4. The same suites under sanitizers

Use the address and undefined-behaviour build from `doc/reviewer-guide.md`. Run one unit suite
per process, then the functional list. Every report is a finding. A report in inherited code is
still a finding.

### 5. Coverage of the changed lines

Build with `--enable-lcov`, run the suites, and open the report at every changed file. Each changed
line outside the tests is executed by a test, or the review names it. A test that executes the
line without asserting on its result counts as no coverage.

### 6. Hostile input

For every changed function that a peer can reach with a message, a transaction or a block, and
for every changed RPC:

- Sizes are checked before use. A wrong size is rejected before any allocation.
- Allocations are bounded by a constant or by the input length.
- Loops are bounded by the input length or by a constant.
- Integer widths and conversions. `size_t` against `int`. Signed overflow. A shift by the full
  width. A multiplication before a bounds check.
- Serialization round-trips: unserialize then serialize gives the same bytes. A truncated input
  and an oversized input are rejected with an exception the caller catches.
- Exceptions: every exception thrown on the input path is caught at the boundary. The peer that
  caused it is penalised or disconnected.
- Locks. Which lock the function holds (`cs_main` for the chain state). What else waits on it.
  How long the function can hold it on the largest input.

### 7. Determinism

For every changed line inside the consensus boundary (`doc/reviewer-guide.md`, section 4):

- No clock, locale or environment variable. No file other than the chain state.
- No floating point.
- No platform-dependent width. `long`, `size_t` in a serialized value, or `int` where the value
  can exceed 31 bits.
- No iteration over an unordered container where the order reaches the verdict.
- No uninitialized read and no undefined behaviour, shown by the sanitizer run.
- No configuration argument that changes a verdict. The exception is an argument the code accepts
  on regtest only. A private network uses it to rehearse a height.
- The same input gives the same verdict on the old release and on the new one for every block
  before H.

### 8. The activation boundary

For every rule gated by a height H:

- At H-1 the node accepts the old behaviour and refuses nothing new.
- At H the rule is enforced, and a test shows a block that H-1 accepts and H rejects.
- A reorg across H (disconnect the block at H, connect a competing one) leaves the chain state
  consistent.
- Before H the new output form is refused at relay (non-standard) and accepted in a block.
- Two binaries on one regtest chain, the previous release and the candidate, agree on every block
  before H.
- The height and its date in the release notes match `src/chainparams.cpp`.
  `doc/DEPLOYMENT_PRECONDITIONS.md` has the deployment's entry.

### 9. The claims

Each claim from step 1 has a test or a run that shows it, or the report marks it unverified. "No
consensus change" is shown by a diff that touches nothing inside the consensus boundary. "The RPC
interface is unchanged" is shown by a diff that touches no RPC handler and no response-building
helper. The handlers live under `src/rpc/` and `src/wallet/` (`rpcwallet.cpp`, `rpcdump.cpp`,
`rpcusdsoq.cpp` and `pqwallet/rpc_pqwallet.cpp`). The help text records the interface. "Inert on
mainnet" is shown by the mainnet activation height in `src/chainparams.cpp` and by the relay rule.

### 10. Release mechanics (release branches only)

- The version in `configure.ac` and `src/clientversion.h`.
- The release notes carry the height and its date, and how a node operator confirms the upgrade.
- `nMinimumChainWork` and `defaultAssumeValid` in `src/chainparams.cpp`, as
  `doc/release-process.md` describes. A replay from the first block under `assumevalid=0` on a
  copy of a data directory confirms them.
- The supported-versions table in `.github/SECURITY.md`.
- `doc/node-operators.md`, where behaviour an operator sees has changed.
- `doc/specifications/WITNESS_VERSION_FORK_CLASS.md`, where a witness version changes state.

### 11. The report

```
Candidate: soqucoin/soqucoin <branch> <head sha>, base <tag or sha>
Platforms: <os and version, compiler and version>
Unit suite: <cases run, failed, skipped>
Functional: <list run, passed, failed>; flakes: <name, log>
Sanitizers: <address: n reports, undefined: n reports>; logs attached
Coverage: <changed lines executed / changed lines>, uncovered: <file:line ...>
Claims: <claim> -> <test, run or command that shows it | unverified>
Findings:
| # | Class | File:line | Claim | Reproducer | Channel |
Unverified: <what the review could not check, and why>
Time: <hours>
```

A finding states what the code does, what it should do, and the input that shows the difference.
A finding with a file, a line and a reproducer gets the fastest response (`doc/FOR_AI_REVIEWERS.md`,
"Reporting findings").

## Severity, in this chain's terms

| Class | Example | Channel |
|---|---|---|
| Consensus divergence | Two nodes reach different verdicts on one block, and the network splits. | Private report |
| Supply | Coins created outside the emission schedule. | Private report |
| Theft | A coin spent without the key that locks it, or a signature check skipped. | Private report |
| Remote stop | A crash, a hang or unbounded memory from a peer message or a block. | Private report |
| Local security | Key leakage, weak derivation or an authentication bypass. Any defect with a security consequence that needs RPC access or a local file. | Private report |
| Local bug | A wrong result or a crash with no security consequence, reached through a local command or file. | Issue |
| Test gap | A changed line no test executes. A test that passes with garbage input. | Issue or review comment |
| Quality | Dead code or duplicate logic. A comment that disagrees with the code. A warning. | Review comment |

Private report: GitHub private vulnerability reporting, as `.github/SECURITY.md` describes.

## What blocks a merge

A finding in code, in a test, or a false claim in a tracked file blocks the merge until it is fixed
or shown wrong. A sentence in a pull request body is corrected in place. A review runs two rounds
at most. The first is on the diff. The second is on the fixes and the delta they add. What remains
after the second round becomes a tracked issue.

## Time

Steps 1 to 4 on a release the size of 2.6.1 fit in one evening. Steps 5 to 11 fit in a second.
The sanitizer build and the coverage build each take longer than a regular build, so start them
before reading the diff.
