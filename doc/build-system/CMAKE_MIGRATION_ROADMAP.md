# CMake Migration Roadmap

## Document Status

| Field | Value |
|-------|-------|
| **Status** | Planned - Post-Testnet |
| **Priority** | Medium |
| **Target** | Q2 2025 |
| **Prerequisites** | Testnet completion, stable cross-platform builds |

---

## Executive Summary

This document provides a comprehensive roadmap for migrating Soqucoin's build system from GNU Autotools to CMake, following the industry precedent set by Bitcoin Core's migration (completed in v29, early 2025).

---

## Why CMake?

### Current Issues with Autotools

1. **Header-only Boost compatibility** - Required patching `ax_boost_system.m4` (commit `5eed0b223`)
2. **Stale autoconf-archive macros** - Upstream updates are infrequent
3. **Poor IDE integration** - No `compile_commands.json` generation
4. **Complex cross-compilation** - Requires separate `depends` system
5. **Windows support** - Relies on MSYS2/MinGW compatibility layer

### CMake Benefits

1. **Modern C++ ecosystem standard** - Native package manager support (vcpkg, Conan)
2. **Native Boost support** - `find_package(Boost)` handles header-only correctly
3. **IDE integration** - Generates `compile_commands.json`, native VS/Xcode projects
4. **Cross-platform** - Single build system for all platforms
5. **Active development** - Regular CMake releases with new features
6. **Bitcoin Core precedent** - Can adapt their implementation

---

## Industry Precedent: Bitcoin Core

### Timeline

| Date | Milestone |
|------|-----------|
| 2020-2021 | Initial CMake exploration |
| 2022-2023 | Parallel CMake support added |
| 2024 | CMake becomes primary build system |
| Early 2025 | v29 release - Autotools deprecated |

### Key Contributors

- **Hennadii Stepanov (hebasto)** - Primary architect
- Multi-year effort with careful backward compatibility

### Repository Reference

- **Branch:** `master` (post-v29)
- **CMakeLists.txt location:** Repository root
- **Key files to study:**
  - `CMakeLists.txt` - Root build configuration
  - `cmake/` - CMake modules and helpers
  - `src/CMakeLists.txt` - Source tree configuration

---

## Migration Phases

### Phase 1: Preparation (1-2 weeks)

**Objective:** Establish CMake infrastructure without disrupting existing builds

**Tasks:**

1. **Create `cmake/` directory structure**
   ```
   cmake/
   ├── modules/
   │   ├── FindSecp256k1.cmake
   │   ├── FindDilithium.cmake
   │   ├── FindEvent.cmake
   │   └── ...
   ├── scripts/
   │   └── generate_version.cmake
   └── config.h.cmake.in
   ```

2. **Add root CMakeLists.txt (parallel support)**
   ```cmake
   cmake_minimum_required(VERSION 3.18)
   project(Soqucoin
       VERSION 1.14.99
       LANGUAGES C CXX
   )
   
   # C++ standard
   set(CMAKE_CXX_STANDARD 14)
   set(CMAKE_CXX_STANDARD_REQUIRED ON)
   
   # Options
   option(BUILD_DAEMON "Build soqucoind" ON)
   option(BUILD_CLI "Build soqucoin-cli" ON)
   option(BUILD_TX "Build soqucoin-tx" ON)
   option(BUILD_GUI "Build soqucoin-qt" OFF)
   option(BUILD_WALLET "Build with wallet support" OFF)
   option(BUILD_TESTS "Build unit tests" ON)
   option(ENABLE_HARDENING "Enable security hardening flags" ON)
   ```

3. **Study Bitcoin Core's CMake implementation**
   - Clone and analyze Bitcoin Core v29+ CMakeLists.txt
   - Document applicable patterns for Soqucoin-specific features

### Phase 2: Core Build System (2-3 weeks)

**Objective:** Replicate autoconf functionality in CMake

**Tasks:**

1. **Implement dependency detection**
   ```cmake
   # Modern Boost detection (handles header-only)
   find_package(Boost 1.60 REQUIRED COMPONENTS
       filesystem
       thread
       program_options
       chrono
   )
   # boost::system is header-only since 1.69, no component needed
   
   # Other dependencies
   find_package(OpenSSL REQUIRED)
   find_package(Libevent REQUIRED)
   find_package(PkgConfig REQUIRED)
   pkg_check_modules(SECP256K1 REQUIRED libsecp256k1)
   ```

2. **Port compile flags and definitions**
   ```cmake
   # Platform detection
   if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
       add_definitions(-DMAC_OSX)
   elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
       add_definitions(-DWIN32 -D_WIN32)
       add_definitions(-DSECP256K1_STATIC)
   endif()
   
   # Security hardening
   if(ENABLE_HARDENING)
       add_compile_options(-fstack-protector-all)
       add_compile_definitions(_FORTIFY_SOURCE=2)
   endif()
   ```

3. **Create library targets**
   ```cmake
   # Consensus library
   add_library(soqucoin_consensus STATIC
       src/consensus/merkle.cpp
       src/consensus/tx_verify.cpp
       # ... more files
   )
   target_compile_definitions(soqucoin_consensus PRIVATE
       SECP256K1_STATIC
   )
   
   # Common library
   add_library(soqucoin_common STATIC
       src/base58.cpp
       src/chainparams.cpp
       # ... more files
   )
   ```

4. **Create executable targets**
   ```cmake
   # soqucoind
   add_executable(soqucoind
       src/soqucoind.cpp
   )
   target_link_libraries(soqucoind PRIVATE
       soqucoin_server
       soqucoin_common
       soqucoin_consensus
       Boost::filesystem
       Boost::thread
       OpenSSL::SSL
       OpenSSL::Crypto
       ${SECP256K1_LIBRARIES}
   )
   ```

### Phase 3: Testing & Validation (1-2 weeks)

**Objective:** Ensure CMake builds produce identical binaries

**Tasks:**

1. **Binary comparison tests**
   - Build with both autoconf and CMake
   - Compare binary checksums (accounting for timestamps)

2. **CI integration**
   - Add CMake-based CI workflow (parallel to autoconf)
   - Test on all three platforms (Windows, macOS, Linux)

3. **Cross-compilation support**
   - Create CMake toolchain files for cross-compilation
   - Consider integration with `depends` system or replacement

### Phase 4: Transition (1 week)

**Objective:** Make CMake the primary build system

**Tasks:**

1. **Update documentation**
   - `INSTALL.md` - Primary CMake instructions
   - Keep autoconf as "legacy" option initially

2. **CI switch**
   - CMake becomes primary CI build method
   - Autoconf kept for backward compatibility testing

3. **Communicate to users**
   - Update README with new build instructions
   - Release notes for first CMake-built version

### Phase 5: Deprecation (Post-stabilization)

**Objective:** Remove autoconf when CMake is proven stable

**Tasks:**

1. **Deprecation warning** in autoconf build
2. **Remove autoconf files** after 2-3 release cycles

---

## Technical Details

### Soqucoin-Specific Considerations

| Feature | Autoconf Handling | CMake Equivalent |
|---------|-------------------|------------------|
| Dilithium | Custom linking | FindDilithium.cmake module |
| LatticeFold | Header includes | target_include_directories |
| PAT | CPPFLAGS | target_compile_definitions |
| secp256k1 | SECP256K1_STATIC | target_compile_definitions |

### Files to Create

```
CMakeLists.txt                      # Root configuration
src/CMakeLists.txt                  # Source tree
src/secp256k1/CMakeLists.txt        # secp256k1 (likely exists)
cmake/modules/FindSecp256k1.cmake   # Find module
cmake/modules/FindDilithium.cmake   # Dilithium detection
cmake/config.h.cmake.in             # Config header template
```

### Files to Eventually Remove

```
configure.ac
Makefile.am
src/Makefile.am
build-aux/m4/*.m4
acinclude.m4
autogen.sh
```

---

## Resources

### Bitcoin Core Reference

- **Repository:** https://github.com/bitcoin/bitcoin
- **CMake discussion:** https://github.com/bitcoin/bitcoin/issues/
- **Developer docs:** https://github.com/bitcoin-core/bitcoin-devwiki

### CMake Documentation

- **Official docs:** https://cmake.org/documentation/
- **Modern CMake:** https://cliutils.gitlab.io/modern-cmake/

### Boost CMake Support

- **find_package(Boost):** https://cmake.org/cmake/help/latest/module/FindBoost.html
- **Header-only note:** Boost 1.69+ boost::system needs no linking

---

## Success Criteria

1. ✅ All binaries build successfully on Windows, macOS, Linux
2. ✅ Unit tests pass
3. ✅ Cross-compilation works (or alternative provided)
4. ✅ IDE integration (compile_commands.json)
5. ✅ Native CI faster than depends-based builds
6. ✅ No regression in binary functionality

---

## Document History

| Date | Author | Change |
|------|--------|--------|
| 2025-12-14 | Build System | Created roadmap based on Bitcoin Core research |

---

## Next Steps for Future Agents

1. **Study Bitcoin Core v29 CMakeLists.txt** - Primary reference
2. **Start with Phase 1** - Minimal parallel support
3. **Prioritize Windows** - Most complex platform
4. **Test thoroughly** - Binary comparison essential
5. **Maintain backward compatibility** - Keep autoconf working during transition
