# liblatticebp — Standalone Shared Library Build
# Copyright (c) 2026 Soqucoin Labs Inc.
#
# Builds the Lattice-BP++ crypto primitives as a standalone shared library
# for FFI consumption by SoquShield (dart:ffi) and third-party integrations.
#
# Targets:
#   macOS arm64:   liblatticebp.dylib
#   iOS arm64:     LatticeBp.xcframework (static)
#   Android:       liblatticebp.so (arm64-v8a, x86_64)
#
# Usage:
#   mkdir build && cd build
#   cmake .. -DCMAKE_BUILD_TYPE=Release
#   cmake --build .
#
# Cross-compile iOS:
#   cmake .. -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake -DPLATFORM=OS64
#
# Cross-compile Android:
#   cmake .. -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
#            -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24

cmake_minimum_required(VERSION 3.16)
project(latticebp VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ── Source files ──
set(LBP_SOURCES
    commitment.cpp
    range_proof.cpp
    ring_signature.cpp
    stealth_address.cpp
    standalone_shim.cpp
    capi.cpp
)

set(LBP_HEADERS
    commitment.h
    range_proof.h
    ring_signature.h
    stealth_address.h
    capi.h
)

# ── Build mode: shared (mobile FFI) or static (iOS framework) ──
option(LBP_BUILD_SHARED "Build shared library" ON)
option(LBP_BUILD_STATIC "Build static library" OFF)
option(LBP_BUILD_TESTS  "Build test harness" ON)

# Define standalone build mode (no soqucoind dependencies)
add_definitions(-DLATTICEBP_STANDALONE)

if(LBP_BUILD_SHARED)
    add_library(latticebp SHARED ${LBP_SOURCES})
    target_include_directories(latticebp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    set_target_properties(latticebp PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 1
        PUBLIC_HEADER "${LBP_HEADERS}"
    )
    # Export only C API symbols
    if(APPLE)
        set_target_properties(latticebp PROPERTIES
            LINK_FLAGS "-exported_symbols_list ${CMAKE_CURRENT_SOURCE_DIR}/exports.txt"
        )
        # Link Security framework for SecRandomCopyBytes (standalone CSPRNG)
        target_link_libraries(latticebp PRIVATE "-framework Security")
    endif()
endif()

if(LBP_BUILD_STATIC)
    add_library(latticebp_static STATIC ${LBP_SOURCES})
    target_include_directories(latticebp_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    set_target_properties(latticebp_static PROPERTIES
        OUTPUT_NAME latticebp
        PUBLIC_HEADER "${LBP_HEADERS}"
    )
endif()

# ── Test harness ──
if(LBP_BUILD_TESTS)
    add_executable(test_capi test_capi.c)
    if(LBP_BUILD_SHARED)
        target_link_libraries(test_capi latticebp)
    else()
        target_link_libraries(test_capi latticebp_static)
    endif()
    target_include_directories(test_capi PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

    enable_testing()
    add_test(NAME capi_tests COMMAND test_capi)
endif()

# ── Install ──
if(LBP_BUILD_SHARED)
    install(TARGETS latticebp
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include/latticebp
    )
elseif(LBP_BUILD_STATIC)
    install(TARGETS latticebp_static
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include/latticebp
    )
endif()
