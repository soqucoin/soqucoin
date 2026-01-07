# Docker Reproducible Build Guide

> **Version**: 1.0 | **Updated**: January 2026
> **Purpose**: Auditor-friendly reproducible build instructions

---

## Quick Start

### Build and Run Tests

```bash
cd /path/to/soqucoin-build

# Build audit image (includes tests)
docker build -f docker/Dockerfile.audit --target builder -t soqucoin-audit .

# Build and run tests automatically (tests run during build)
docker build -f docker/Dockerfile.audit --target builder -t soqucoin-test .
```

### Run Benchmarks

```bash
# Build benchmark image
docker build -f docker/Dockerfile.audit --target benchmark -t soqucoin-bench .

# Run benchmarks (outputs CSV to current directory)
docker run --rm -v $(pwd):/out soqucoin-bench
```

### Build Runtime (Production)

```bash
# Build minimal runtime image
docker build -f docker/Dockerfile.audit --target runtime -t soqucoin-runtime .

# Run testnet node
docker run -d -p 18333:18333 --name soqucoind soqucoin-runtime soqucoind -testnet -printtoconsole
```

---

## Build Stages

| Stage | Target | Purpose | Output |
|-------|--------|---------|--------|
| `builder` | `--target builder` | Compile with tests + benchmarks | Full build with verification |
| `benchmark` | `--target benchmark` | Run performance benchmarks | CSV results |
| `runtime` | `--target runtime` | Production node | Minimal footprint |

---

## Verification Checklist

```bash
# 1. Build with tests (runs unit tests during build)
docker build -f docker/Dockerfile.audit --target builder -t soqucoin-audit .

# 2. Run benchmarks
docker build -f docker/Dockerfile.audit --target benchmark -t soqucoin-bench .
docker run --rm -v $(pwd):/out soqucoin-bench

# 3. Verify binary hashes (reproducibility check)
docker run --rm soqucoin-audit sha256sum /soqucoin/src/soqucoind

# 4. Run specific benchmark
docker run --rm soqucoin-bench bench_bitcoin --filter='Dilithium*'
```

---

## Expected Benchmark Output

```
Benchmark                          Time (ns)    Iterations
------------------------------------------------------------
DilithiumSign                        142000         10000
DilithiumVerify                      198000         10000
Bulletproofs_GenRangeProof          2100000          1000
Bulletproofs_VerifyRangeProof        890000          1000
```

---

## Build Configuration

The audit Dockerfile uses the following configure flags:

```bash
./configure \
  --without-gui \
  --with-incompatible-bdb \
  --enable-tests \
  --enable-bench \
  CXXFLAGS="-O2 -g" \
  CFLAGS="-O2 -g"
```

| Flag | Purpose |
|------|---------|
| `--without-gui` | Skip Qt GUI (smaller image) |
| `--with-incompatible-bdb` | Use system BerkeleyDB |
| `--enable-tests` | Compile unit tests |
| `--enable-bench` | Compile benchmarks |
| `-O2 -g` | Optimization + debug symbols |

> **Note**: As of January 2026, Soqucoin requires **C++17** (set in `src/Makefile.am`)
> for the PQ wallet library's use of `std::optional` and other modern features.

---

## Docker Compose (Optional)

For running a full testnet environment:

```bash
cd docker
docker-compose up -d
```

This starts:
- `soqucoind`: Testnet node
- `stratum_bridge`: Mining stratum proxy

---

## Troubleshooting

### Build fails on ARM (M1/M2/M4 Mac)

Use Docker's `--platform` flag:

```bash
docker build --platform linux/amd64 -f docker/Dockerfile.audit --target builder -t soqucoin-audit .
```

### Tests fail

Check the test log:

```bash
docker run --rm soqucoin-audit cat /soqucoin/src/test/test_bitcoin.log
```

---

*Prepared for security auditors*
*Soqucoin Development Team — January 2026*
