# IDE Error Checklist

**Last Updated**: 2025-11-29  
**Total Warnings**: 54

## Summary

All 54 warnings are from clangd and fall into two categories:
- **Unused includes** (48 warnings): Headers included but not directly used
- **Unused variables/functions** (6 warnings): Declared but never referenced

These are all **warnings**, not errors. The code compiles and tests pass successfully.

---

## Category 1: Unused Includes (48 warnings)

These headers are likely used by other included headers (indirect dependencies) or are defensive includes for future use. Consider reviewing and removing if truly unnecessary.

### Core Files

#### [chainparams.cpp](file:///Users/caseymacmini/soqucoin-build/src/chainparams.cpp)
- [ ] Line 11: `util.h` not used directly

#### [consensus/params.h](file:///Users/caseymacmini/soqucoin-build/src/consensus/params.h)
- [ ] Line 12: `map` not used directly
- [ ] Line 13: `string` not used directly

---

### Cryptography Files

#### [crypto/binius64/field.cpp](file:///Users/caseymacmini/soqucoin-build/src/crypto/binius64/field.cpp)
- **No unused includes** (see unused variable below)

#### [crypto/latticefold/verifier.cpp](file:///Users/caseymacmini/soqucoin-build/src/crypto/latticefold/verifier.cpp)
- [ ] Line 8: `utilstrencodings.h` not used directly
- [ ] Line 9: `iostream` not used directly

#### [crypto/latticefold/verifier.h](file:///Users/caseymacmini/soqucoin-build/src/crypto/latticefold/verifier.h)
- [ ] Line 9: `script.h` not used directly

#### [crypto/pat/logarithmic.h](file:///Users/caseymacmini/soqucoin-build/src/crypto/pat/logarithmic.h)
- [ ] Line 120: `script.h` not used directly

---

### Mining Files

#### [miner.cpp](file:///Users/caseymacmini/soqucoin-build/src/miner.cpp)
- [ ] Line 13: `coins.h` not used directly
- [ ] Line 17: `hash.h` not used directly
- [ ] Line 34: `queue` not used directly

#### [rpc/mining.cpp](file:///Users/caseymacmini/soqucoin-build/src/rpc/mining.cpp)
- [ ] Line 10: `base58.h` not used directly
- [ ] Line 17: `init.h` not used directly
- [ ] Line 23: `util.h` not used directly

---

### Script Files

#### [script/interpreter.cpp](file:///Users/caseymacmini/soqucoin-build/src/script/interpreter.cpp)
- [ ] Line 12: `chainparams.h` not used directly (first occurrence)
- [ ] Line 118: `chainparams.h` not used directly (second occurrence)

#### [script/interpreter.h](file:///Users/caseymacmini/soqucoin-build/src/script/interpreter.h)
- [ ] Line 12: `stdint.h` not used directly
- [ ] Line 13: `string` not used directly

#### [script/script.h](file:///Users/caseymacmini/soqucoin-build/src/script/script.h)
- [ ] Line 13: `climits` not used directly

---

### Test Files

#### [test/audit_tests.cpp](file:///Users/caseymacmini/soqucoin-build/src/test/audit_tests.cpp)
- [ ] Line 6: `validation.h` not used directly

#### [test/latticefold_tests.cpp](file:///Users/caseymacmini/soqucoin-build/src/test/latticefold_tests.cpp)
- [ ] Line 5: `iostream` not used directly

#### [test/multisig_tests.cpp](file:///Users/caseymacmini/soqucoin-build/src/test/multisig_tests.cpp)
- [ ] Line 5: `key.h` not used directly
- [ ] Line 6: `keystore.h` not used directly
- [ ] Line 7: `policy.h` not used directly
- [ ] Line 8: `interpreter.h` not used directly
- [ ] Line 9: `ismine.h` not used directly
- [ ] Line 10: `script.h` not used directly
- [ ] Line 11: `script_error.h` not used directly
- [ ] Line 12: `sign.h` not used directly
- [ ] Line 13: `test_bitcoin.h` not used directly
- [ ] Line 14: `uint256.h` not used directly

#### [test/pat_script_tests.cpp](file:///Users/caseymacmini/soqucoin-build/src/test/pat_script_tests.cpp)
- [ ] Line 7: `utilstrencodings.h` not used directly

#### [test/pat_tests.cpp](file:///Users/caseymacmini/soqucoin-build/src/test/pat_tests.cpp)
- [ ] Line 5: `iostream` not used directly

#### [test/script_tests.cpp](file:///Users/caseymacmini/soqucoin-build/src/test/script_tests.cpp)
- [ ] Line 9: `keystore.h` not used directly
- [ ] Line 10: `server.h` not used directly
- [ ] Line 15: `util.h` not used directly
- [ ] Line 22: `fstream` not used directly
- [ ] Line 23: `stdint.h` not used directly

---

### Validation Files

#### [validation.cpp](file:///Users/caseymacmini/soqucoin-build/src/validation.cpp)
- [ ] Line 23: `pureheader.h` not used directly
- [ ] Line 25: `random.h` not used directly
- [ ] Line 45: `sstream` not used directly

---

### Wallet Files

#### [wallet/rpcwallet.cpp](file:///Users/caseymacmini/soqucoin-build/src/wallet/rpcwallet.cpp)
- [ ] Line 19: `timedata.h` not used directly

#### [wallet/test/wallet_tests.cpp](file:///Users/caseymacmini/soqucoin-build/src/wallet/test/wallet_tests.cpp)
- [ ] Line 6: `txmempool.h` not used directly
- [ ] Line 10: `stdint.h` not used directly
- [ ] Line 15: `test_bitcoin.h` not used directly
- [ ] Line 16: `validation.h` not used directly
- [ ] Line 17: `wallet_test_fixture.h` not used directly

#### [wallet/wallet.cpp](file:///Users/caseymacmini/soqucoin-build/src/wallet/wallet.cpp)
- [ ] Line 12: `consensus.h` not used directly
- [ ] Line 14: `fs.h` not used directly

---

### Zero-Knowledge Files

#### [zk/rctTypes.h](file:///Users/caseymacmini/soqucoin-build/src/zk/rctTypes.h)
- [ ] Line 11: `array` not used directly

---

## Category 2: Unused Variables (5 warnings)

These should be reviewed and either removed or used. They may indicate incomplete functionality or debugging code left behind.

### [crypto/binius64/field.cpp](file:///Users/caseymacmini/soqucoin-build/src/crypto/binius64/field.cpp#L94)
- [ ] Line 94: Variable `k` declared but never used
  - **Action**: Review context and remove if truly unused

### [miner.cpp](file:///Users/caseymacmini/soqucoin-build/src/miner.cpp#L155)
- [ ] Line 155: Variable `nChainId` declared but never used
  - **Action**: May be legacy code from chain ID functionality

### [script/interpreter.cpp](file:///Users/caseymacmini/soqucoin-build/src/script/interpreter.cpp#L139)
- [ ] Line 139: Variable `pend` declared but never used
  - **Action**: Could be iterator/pointer that was refactored

### [test/script_tests.cpp](file:///Users/caseymacmini/soqucoin-build/src/test/script_tests.cpp#L37)
- [ ] Line 37: Variable `flags` declared but never used
  - **Action**: Likely test setup variable that became unused

---

## Category 3: Unused Functions (1 warning)

### [validation.cpp](file:///Users/caseymacmini/soqucoin-build/src/validation.cpp#L3336)
- [ ] Line 3336: Function `IsSuperMajority` defined but never used
  - **Action**: Legacy Bitcoin function - candidate for removal if truly unused

---

## Recommendations

### Priority 1: Unused Variables & Functions (High)
Remove or use these 6 items as they represent dead code:
1. Review `field.cpp:94` - unused variable `k`
2. Review `miner.cpp:155` - unused variable `nChainId`
3. Review `interpreter.cpp:139` - unused variable `pend`
4. Review `script_tests.cpp:37` - unused variable `flags`
5. Review `validation.cpp:3336` - unused function `IsSuperMajority`

### Priority 2: Unused Includes (Medium)
Consider batch removal of truly unused headers:
- Start with obvious ones like `iostream` in non-logging code
- Remove duplicate includes (e.g., `chainparams.h` twice in interpreter.cpp)
- Clean up test files which have the most unused includes

### Priority 3: Documentation (Low)
- Keep this checklist updated as issues are resolved
- Consider adding include-what-you-use (IWYU) tool to CI/CD

---

## Notes

- All warnings are **non-blocking** - code compiles and tests pass
- These are LSP/clangd warnings, not compiler errors
- Some "unused" includes may be defensive programming or future-proofing
- Test files tend to include comprehensive headers for flexibility
- Consider using `#include` guards and forward declarations where appropriate
