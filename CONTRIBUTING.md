# Contributing to Soqucoin Core

Soqucoin is a hard-fork of Dogecoin with NIST-standard post-quantum signatures and recursive batch verification. Consensus code is sacred. We follow Bitcoin Core contribution standards with zero tolerance for slop.

## Code Style

- Follow the [Bitcoin Core Developer Guidelines](https://github.com/bitcoin/bitcoin/blob/master/CONTRIBUTING.md) exactly.
- C++14, no exceptions, no RTTI
- `clang-format` with the .clang-format in this repo (run `clang-format -i -style=file <file>` before committing)
- All new files must have copyright header:
  ```cpp
  // Copyright (c) 2025-2026 The Soqucoin developers
  // Distributed under the MIT software license, see the accompanying file COPYING or https://opensource.org/licenses/MIT
  ```

## Branch Strategy

- `master` is dead — never commit to it
- Default branch: `soqucoin-genesis`
- Feature branches: `feature/<descriptive-name>`
- All consensus or cryptographic changes require a signed tag and review by at least two core maintainers

## Pull Requests

- One logical change per PR
- Rebase, never merge commit
- Linear history required
- Sign your commits (`git commit -S`)
- Include release notes in `doc/release-notes/`
- Crypto-related PRs require review by @odenrider and at least one external auditor

## Testing

- `make check` must pass
- `test/functional` must pass
- All new consensus rules must have functional tests
- PQ-related code must have property-based tests using test/fuzz

## Cryptography & Consensus Code

- Any change touching `src/consensus/`, `src/script/`, `src/pat/`, or `src/primitives/transaction.cpp` requires **two independent reviews** and a signed tag from @odenrider.
- No new cryptography without a published paper or NIST standard reference.
- All new opcodes require a detailed design doc in `doc/design/`

## Issue & PR Template

Use the templates in `.github/` — do not delete or disable them.

Thank you for helping make Soqucoin the first production-ready post-quantum Scrypt-PoW chain.

– The Soqucoin Core Team
