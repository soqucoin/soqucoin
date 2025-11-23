# PAT Benchmark Report — Regtest (2025-11-20)

## Environment
 - Host: Apple Silicon M4 (Darwin 24.6.0)
- Codebase: soqucoin-genesis @ `b5e4d2ed2`
- Build: `./configure --without-gui --disable-wallet --with-boost=/opt/homebrew/opt/boost@1.85 && make -j16`
- Node: `src/soqucoind -regtest -datadir=.regtest -rpcuser=soq -rpcpassword=bench`
- Benchmark runtime: `PYTHONPATH=src/pat .venv/bin/python src/pat/pat_benchmark.py` (module-driven)

## Test Inputs
- Signature count: **256**
- PAT strategies: threshold, merkle_batch, logarithmic, stacked_multi
- Reference schemes: ECDSA (secp256k1), Dilithium ML-DSA-44
- Data source: `benchmarks/pat_benchmark_regtest_2025-11-20.json`

## Results Summary
| Scheme / Strategy | Avg Sign (ms) | Avg Verify (ms) | Batch Verify (ms) | Total Size (bytes) | Aggregated Size (bytes) | Compression |
|-------------------|---------------|-----------------|-------------------|--------------------|-------------------------|-------------|
| ECDSA             | 0.72          | 0.51            | —                 | 26,628             | —                       | 1.0×        |
| Dilithium         | 16.85         | 3.50            | —                 | 627,968            | —                       | 1.0×        |
| PAT Threshold     | 18.28         | 3.48            | 0.0031            | 627,968            | 69                      | 9,101×      |
| PAT Merkle Batch  | 18.55         | 3.49            | 0.772             | 627,968            | 65                      | 9,661×      |
| PAT Logarithmic   | 17.94         | 3.48            | 0.0023            | 627,968            | 69                      | 9,101×      |
| PAT Stacked Multi | 17.57         | 3.48            | 34.65             | 627,968            | 620,577                 | 1.01×       |

## Observations
1. **Compression** — Merkle batch delivered the best compression (≈9,661×) while logarithmic matched threshold’s 9,101× savings. Stacked multi offers negligible size reduction (<2%).
2. **Latency** — PAT signing latency mirrors Dilithium because aggregation happens after individual PQ signatures. Batch verification of logarithmic/threshold outputs stays in microseconds, supporting on-chain OP_CHECKBATCHSIG.
3. **Size Impact** — Aggregated artifacts shrink Dilithium’s 628 KB payload to ~70 bytes, easily fitting in standard scriptSigs for mass multisig transactions.
4. **Operational Notes** — Stack multi’s batch verification penalty (~34 ms) makes it unsuitable for consensus-critical validation despite matching single-sign performance.

## Reproduction Steps
1. `python3 -m venv .venv && .venv/bin/pip install dilithium-py numpy pandas ecdsa cryptography psutil`
2. `PYTHONPATH=src/pat .venv/bin/python - <<'PY' ...` (see `benchmarks/pat_benchmark_regtest_2025-11-20.json` script for full snippet).
3. Publish JSON + Markdown in `benchmarks/` and `documents/benchmarks/`.

## Next Actions
- Wire `PATBenchmark` CLI so `--test basic` runs benchmarks instead of unit tests only.
- Add regression test invoking `PatBenchmark.benchmark_pat_aggregation()` for CI sanity.
- Extend report automation: emit CSV + Markdown from script to avoid manual formatting.
