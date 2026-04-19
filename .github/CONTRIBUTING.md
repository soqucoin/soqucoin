# Contributing to Soqucoin Core

Thank you for considering contributing to Soqucoin Core. This document outlines
the process for contributing to this project.

## Getting Started

1. Fork the repository
2. Create a feature branch from `main`: `git checkout -b feature/my-feature`
3. Make your changes
4. Run the test suite: `make check`
5. Submit a Pull Request against `main`

## Development Setup

### Prerequisites

- C++17 compatible compiler (GCC 10+, Clang 12+, MSVC 2019+)
- autotools (`autoconf`, `automake`, `libtool`)
- Boost 1.70+
- OpenSSL 1.1+
- libevent 2.1+

### Build

```bash
./autogen.sh
./configure --without-gui
make -j$(nproc)
make check
```

## Pull Request Guidelines

- **One logical change per PR** — don't mix unrelated changes
- **Include tests** — every bug fix and feature should come with tests
- **Update CHANGELOG.md** — add an entry under `[Unreleased]`
- **Sign your commits** — use `git commit -s` (DCO sign-off)
- **Follow existing style** — match the code style of surrounding code
- **Consensus-critical changes** require review from @odenrider

## Commit Message Format

```
component: Short description (50 chars max)

Longer explanation of the change, if needed. Wrap at 72 characters.
Reference relevant issues: Fixes #123

Signed-off-by: Your Name <you@example.com>
```

**Component prefixes:** `consensus:`, `wallet:`, `rpc:`, `p2p:`, `build:`, `ci:`,
`doc:`, `test:`, `crypto:`, `pat:`, `privacy:`

## Code Review

All submissions require review. We use GitHub Pull Requests for this purpose.

### Review Priorities

| Priority | Scope |
|----------|-------|
| **P0 — Critical** | Consensus bugs, key leakage, chain splits |
| **P1 — High** | New crypto primitives, protocol changes |
| **P2 — Normal** | Features, optimizations, refactoring |
| **P3 — Low** | Documentation, typos, comments |

## Security Vulnerabilities

**Do NOT open a public issue.** See [SECURITY.md](SECURITY.md) for the
responsible disclosure process.

## License

By contributing to Soqucoin Core, you agree that your contributions will be
licensed under the MIT License.
