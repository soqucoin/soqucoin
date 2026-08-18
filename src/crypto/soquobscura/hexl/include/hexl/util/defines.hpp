// Copyright (C) 2020 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//
// Hand-written in place of the CMake-generated header. Soqucoin builds HEXL in the GNU,
// non-debug, NON-AVX-512 configuration, so HEXL_DEBUG and every HEXL_HAS_AVX512* macro are
// deliberately left undefined. See src/crypto/soquobscura/NOTICE.
#pragma once
#define HEXL_USE_GNU
// #define HEXL_DEBUG            - intentionally off
// #define HEXL_HAS_AVX512DQ     - intentionally off (portability: -march=x86-64-v3)
// #define HEXL_HAS_AVX512IFMA   - intentionally off
// #define HEXL_HAS_AVX512VBMI2  - intentionally off
#define HEXL_UNUSED(x) (void)(x)
