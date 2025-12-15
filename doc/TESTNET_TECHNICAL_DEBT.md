# Testnet Technical Debt & Pre-Mainnet Requirements

> [!CAUTION]
> Items in this document MUST be addressed before mainnet launch. While testnet can proceed with these workarounds, they represent incomplete or bypassed functionality that affects production readiness.

## Document Status

| Field | Value |
|-------|-------|
| **Created** | 2025-12-15 |
| **Last Updated** | 2025-12-15 |
| **Phase** | Testnet (4-week window) |
| **Target Resolution** | Pre-Mainnet |

---

## Category 1: CI Test Skips

### 1.1 RPC Integration Tests (SKIPPED)

**Location**: `.github/workflows/ci.yml` (3 matrix entries)  
**Commit**: `5be26b3d6`

**What's Skipped**:
```yaml
# qa/pull-tester/install-deps.sh
# qa/pull-tester/rpc-tests.py --coverage
```

**Why Skipped**:
- `generate(1)` RPC requires wallet + legacy address generation
- Dilithium-only builds produce incompatible addresses
- When `generate()` fails, soqucoind processes hang indefinitely

**Risk Level**: 🟡 Medium
- Unit tests still pass (core cryptographic validation)
- RPC functionality not exercised in automated tests

**Required Fix**:
```python
# qa/rpc-tests/test_framework/util.py - Line 285
# Change from:
rpcs[peer].generate(1)

# To:
dilithium_addr = rpcs[peer].getnewaddress()  # Gets Dilithium address
rpcs[peer].generatetoaddress(1, dilithium_addr)
```

**Additional Requirements**:
1. Update `qa/rpc-tests/test_framework/test_framework.py` to use `generatetoaddress`
2. Verify test wallet generates Dilithium addresses (not ECDSA legacy)
3. Update all `generate(N)` calls in test scripts to `generatetoaddress(N, addr)`
4. Add process cleanup timeout to prevent hangs

**Testnet Exercise Plan**:
- [ ] Run RPC tests manually on testnet node
- [ ] Document which tests pass/fail
- [ ] Fix failing tests before mainnet

---

### 1.2 Native CI Smoke Tests (MODIFIED)

**Location**: `.github/workflows/ci-native-macos.yml`, `ci-native-windows.yml`  
**Commit**: `606f7a1ae`

**What's Modified**:
- `soqucoin-cli --version` removed from smoke tests
- Only tests file existence for `soqucoin-cli`

**Why Modified**:
- `soqucoin-cli --version` returns non-zero exit code even with output
- Causes false CI failures

**Risk Level**: 🟢 Low
- Binary is built and exists
- Version output works (just exit code is wrong)

**Required Fix**:
- [ ] Investigate why `soqucoin-cli` returns non-zero on `--version`
- [ ] Fix exit code handling in `soqucoin-cli.cpp`

---

## Category 2: Build System Workarounds

### 2.1 Autoconf Boost Header-Only Patch

**Location**: `build-aux/m4/ax_boost_system.m4`  
**Commit**: `5eed0b223`

**What's Patched**:
- Added Boost version detection for 1.69+
- Skips library linking for header-only `boost::system`

**Risk Level**: 🟢 Low
- Patch is correct and follows Boost documentation
- Modern Boost (1.69+) has header-only system
- Backward compatible with older Boost

**Long-Term Solution**:
- [ ] Migrate to CMake (see `doc/build-system/CMAKE_MIGRATION_ROADMAP.md`)
- [ ] Follow Bitcoin Core's CMake migration (v29, 2025)

---

### 2.2 Symbol Check Expansions

**Location**: `contrib/devtools/symbol-check.py`  
**Commit**: `8c9b57582`

**What's Modified**:
- Added C++ standard library symbols to `IGNORE_EXPORTS`
- Added `libstdc++.so.6` and `libdouble-conversion.so.3` to allowed libs

**Why Modified**:
- Qt static linking exports internal C++ symbols
- These are legitimate and expected

**Risk Level**: 🟢 Low
- Correctly identifies Qt integration requirements
- No security implications

---

## Category 3: Consensus Hacks (MUST REVERT)

> [!WARNING]
> These changes were made for isolated testnet operation and MUST be reverted for public testnet/mainnet.

### 3.1 Disabled Peer Requirements

**Location**: `src/chainparams.cpp`

| Change | Value | Risk |
|--------|-------|------|
| `fMiningRequiresPeers` | `false` | 🔴 Critical |
| `nMinimumChainWork` | `0x00` | 🔴 Critical |
| Checkpoints | Cleared | 🔴 Critical |
| `nCoinbaseMaturity` | Reduced | 🟡 Medium |

**Reversion Required**: Before connecting to public testnet

---

### 3.2 Mining RPC Modifications

**Location**: `src/rpc/mining.cpp`

| Change | Purpose | Keep/Revert |
|--------|---------|-------------|
| Removed connection count check | Allow solo mining | **Revert** |
| Removed IBD check | Allow mining immediately | **Revert** |
| Added `coinbasetxn` field | Stratum compatibility | **Keep** |
| Dilithium `scriptDummy` | Proper address format | **Keep** |

---

### 3.3 Validation Overrides

**Location**: `src/validation.cpp`

| Change | Purpose | Keep/Revert |
|--------|---------|-------------|
| `IsWitnessEnabled` always true | Force SegWit | **Revert** (use activation) |
| Disabled premature coinbase spend | Fast testing | **Revert** |

---

## Category 4: Dependency Fixes

### 4.1 ltc-scrypt URL

**Location**: `qa/pull-tester/install-deps.sh`  
**Commit**: `1b510a282`

**What's Fixed**:
- Changed URL from `soqucoin/ltc-scrypt` (404) to `dogecoin/ltc-scrypt`

**Risk Level**: 🟢 Low
- Correct upstream source
- Same checksum, verified package

**Future Consideration**:
- [ ] Fork to `soqucoin/ltc-scrypt` for long-term maintenance
- [ ] Or vendor the package in-tree

---

## Category 5: Incomplete Features

### 5.1 Pre-built Binary Distribution

**Status**: Not Implemented

**Required**:
- [ ] Reproducible builds (gitian or Docker)
- [ ] Release workflow for signed binaries
- [ ] Provide .exe, .dmg, .AppImage downloads

### 5.2 Build Verification Script

**Status**: Not Implemented

**Required**:
- [ ] Create `scripts/verify-build.sh`
- [ ] Tests: daemon starts, RPC responds, basic operations

### 5.3 User Documentation

**Status**: Incomplete

**Required**:
- [ ] User guide for building on each OS
- [ ] Troubleshooting common build issues

---

## Testnet Validation Matrix

| Item | Can Proceed to Testnet? | Must Fix Before Mainnet? |
|------|-------------------------|--------------------------|
| RPC test skips | ✅ Yes | ✅ Yes |
| Smoke test modification | ✅ Yes | 🟡 Nice-to-have |
| Boost patch | ✅ Yes | 🟢 No (patch is correct) |
| Symbol check expansion | ✅ Yes | 🟢 No |
| Consensus hacks | ✅ Yes (isolated) | ✅ Yes (MUST revert) |
| ltc-scrypt URL | ✅ Yes | 🟢 No (fixed) |
| Pre-built binaries | ✅ Yes | ✅ Yes |
| Build verification | ✅ Yes | ✅ Yes |
| User documentation | ✅ Yes | ✅ Yes |

---

## Testnet Exercise Checklist

During the 4-week testnet, validate these items:

- [ ] Manual RPC test execution and documentation
- [ ] Multi-node P2P synchronization
- [ ] Dilithium transaction sending/receiving
- [ ] Block mining with L7 ASIC
- [ ] Wallet backup and restore
- [ ] Chain reorganization handling
- [ ] Memory/CPU profiling under load
- [ ] Stratum bridge stability (24+ hours)

---

## References

- [CMake Migration Roadmap](file:///Users/caseymacmini/soqucoin-build/doc/build-system/CMAKE_MIGRATION_ROADMAP.md)
- [Native CI Build Notes](file:///Users/caseymacmini/soqucoin-build/.github/workflows/NATIVE_CI_BUILD_NOTES.md)
- [Testnet Launch Plan](testnet_launch_plan.md)
