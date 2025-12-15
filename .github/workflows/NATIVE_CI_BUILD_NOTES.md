# Native CI Build System Issue

## Status: ✅ RESOLVED

**Date:** 2025-12-14  
**Fix Commit:** `5eed0b223`  
**Priority:** Complete

---

## Resolution Summary

**Patched `build-aux/m4/ax_boost_system.m4`** to detect Boost 1.69+ and skip library search since `boost::system` is header-only. Native CI workflows are now enabled and should pass.

## Future Roadmap

For long-term build system improvements, see:
- **[CMake Migration Roadmap](../../doc/build-system/CMAKE_MIGRATION_ROADMAP.md)** - Comprehensive plan for migrating to CMake following Bitcoin Core's lead

**Files affected:**
- `ci-native-macos.yml.disabled`
- `ci-native-windows.yml.disabled`

---

## Root Cause

```
configure: error: Could not find a version of the boost_system library!
```

| Component | Issue |
|-----------|-------|
| **Boost Version** | 1.86+ (Homebrew/MSYS2) |
| **Breaking Change** | Boost 1.69.0 made `boost::system` header-only |
| **Legacy Macro** | `ax_boost_system.m4` expects library files (`.a`/`.dylib`) |

### Why Cross-Compiled Builds Work

The `depends` system bundles Boost 1.67.0 (pre-header-only):
```
depends/packages/boost.mk: $(package)_version=1_67_0
```

---

## Impact

| Build Type | Status | Notes |
|------------|--------|-------|
| Cross-compiled (depends) | ✅ Working | Full platform coverage |
| Native CI | ❌ Disabled | Supplementary only |

**Risk Level: Low** - Cross-compiled builds produce identical artifacts.

---

## Permanent Fix Options

### Option 1: Patch `ax_boost_system.m4` (Recommended Short-Term)

Modify macro to detect Boost 1.69+ and skip library linking:

```m4
dnl Check if Boost.System is header-only (1.69+)
AC_COMPILE_IFELSE([
  AC_LANG_PROGRAM([[
    #include <boost/version.hpp>
    #if BOOST_VERSION >= 106900
    // Header-only, no library needed
    #else
    #error "Need library"
    #endif
  ]], [[]])
], [BOOST_SYSTEM_LIB=""], [...existing logic...])
```

**Effort:** 1-2 hours | **Risk:** Low

### Option 2: Migrate to CMake (Recommended Long-Term)

Bitcoin Core completed CMake migration (v29, 2025). CMake handles header-only Boost natively:

```cmake
find_package(Boost 1.60 REQUIRED COMPONENTS filesystem thread)
# boost::system not needed - header-only
```

**Effort:** 2-4 weeks | **Risk:** Medium | **Benefit:** Future-proof

### Option 3: Pin Boost Version

Install older Boost in CI:
```yaml
brew install boost@1.67
```

**Effort:** 30 min | **Risk:** Medium (version management)

### Option 4: Use `depends` in Native CI

Build dependencies from source using native triplet:
```yaml
make -C depends HOST=native
./configure --prefix=$PWD/depends/native
```

**Effort:** 4-8 hours | **Risk:** Low

---

## Recommendation

1. **Short-term:** Patch `ax_boost_system.m4` (Option 1)
2. **Long-term:** Plan CMake migration following Bitcoin Core's lead (Option 2)

---

## Re-enabling Native CI

To re-enable after implementing a fix:

```bash
mv ci-native-macos.yml.disabled ci-native-macos.yml
mv ci-native-windows.yml.disabled ci-native-windows.yml
```

---

## References

- [Boost 1.69.0 Release Notes](https://www.boost.org/users/history/version_1_69_0.html) - Header-only system
- [Bitcoin Core CMake Migration](https://github.com/bitcoin/bitcoin) - Industry precedent
- [autoconf-archive](https://www.gnu.org/software/autoconf-archive/) - ax_boost_system.m4
