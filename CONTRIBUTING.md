# Contributing to Soqucoin

Soqucoin is a post-quantum cryptocurrency. We welcome contributions, but please note the following strict guidelines due to the security-critical nature of the project.

## Security Policy

**DO NOT REPORT SECURITY VULNERABILITIES PUBLICLY.**
If you discover a vulnerability, please email `security@soqu.org`.

## Development Workflow

1.  **Fork and Branch**: Create a feature branch from `soqucoin-genesis`.
2.  **Code Style**: We follow the Bitcoin Core coding standards.
3.  **Testing**: All PRs must pass the `overnight_suite.sh` test suite.
    *   Run `make check` for unit tests.
    *   Run `test/functional/test_runner.py` for functional tests.
4.  **Post-Quantum Cryptography**:
    *   **NO ECDSA**: Any re-introduction of `secp256k1` or legacy opcodes will be rejected.
    *   **Dilithium Only**: All consensus changes must use ML-DSA-44.

## Pull Request Process

1.  Ensure your code compiles on Linux and macOS (Apple Silicon).
2.  Update documentation (`doc/`) if you change behavior.
3.  Sign your commits with GPG if possible.
4.  Request review from core maintainers.

## License

Soqucoin is released under the MIT License.
