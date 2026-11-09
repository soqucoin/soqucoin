# Contributing to Soqucoin

Soqucoin is a post-quantum cryptocurrency. Its mainnet has run since 13 October 2026. Contributions are welcome. The rules below are strict because a mistake in this code moves money.

## Security policy

**Do not report security vulnerabilities publicly.** Report them privately as described in [.github/SECURITY.md](.github/SECURITY.md).

## Development workflow

1. **Fork and branch**: create a feature branch from `main`, the default branch. Pull requests target `main`.
2. **Code style**: Bitcoin Core's conventions, written up in [doc/developer-notes.md](doc/developer-notes.md). A C++14 compiler is required (`configure` checks for it); C++17 is optional with `--enable-c++17`. 4-space indentation, no trailing whitespace.
3. **Testing**: the CI workflow runs on every pull request. Run the same checks first:
   * `make check` for the unit tests;
   * `qa/pull-tester/rpc-tests.py` for the functional tests. CI runs the Soqucoin-specific set: `auxpow.py`, `pat_basic.py`, `unspendable-outputs.py`, `witness-prune-serving.py`, `witness-prune-ibd.py`, `wallet-encryption.py`, `pq-address-rpcs.py`, `pq-wallet-key-handling.py`, `block1-time-gate.py`, `chainid-required-height.py` and `latticefold_basic.py`;
   * a change to behaviour comes with a test that fails without it.
4. **Post-quantum cryptography**:
   * **No ECDSA**: a pull request that reintroduces `secp256k1` or the legacy opcodes is rejected.
   * **ML-DSA-44 only**: every signature in the transaction path is ML-DSA-44 (Dilithium).
5. **Consensus changes** get the hardest review. A pull request that touches validation states in its body what it changes, what an attacker could do before and after it, and how the test proves the difference. It must be a change that nodes already on the network accept. A change that would split the chain from existing nodes is rejected.

## Reviewing

A reviewer new to this codebase starts at [doc/reviewer-guide.md](doc/reviewer-guide.md). A release branch or a pull request that touches validation is reviewed with [doc/release-review-checklist.md](doc/release-review-checklist.md).

## Pull request process

1. One change per pull request. Build it on Linux and on macOS (Apple silicon) before opening it.
2. The title and body say what changed and why. Commit messages describe the change; the reasoning goes in the body.
3. The required `register` check lints the title, the body, the commit messages and the changed file names against this repository's writing rules: no AI attribution lines, no internal review vocabulary, no em dashes in prose. A failing run names the line.
4. Update the documentation under `doc/` when behaviour changes.
5. Sign your commits with GPG if possible.
6. Copilot reviews every pull request when it opens; answer each of its threads. A maintainer's approving review is required before a merge, and maintainers merge.

## License

Soqucoin is released under the MIT License. See [COPYING](COPYING).
