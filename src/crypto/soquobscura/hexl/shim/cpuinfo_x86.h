// Soqucoin shim replacing Google cpu_features. HEXL's kernels include this
// unconditionally to runtime-dispatch AVX-512 paths. We compile NO AVX-512 kernels
// (HEXL_HAS_AVX512* are undefined), so reporting every feature absent is not a
// simplification, it is the only consistent answer: there is no AVX-512 code to select.
// Vendoring the real library would add thousands of lines to the audit scope for a
// dispatch that cannot fire.
//
// BONUS HARDENING: upstream cpu-features.hpp also reads the environment variables
// HEXL_DISABLE_AVX512DQ / IFMA / VBMI2 to steer dispatch at runtime. An environment
// variable must never be able to change consensus behaviour. With this shim the
// dispatch is a compile-time constant and those variables are inert.
#pragma once
namespace cpu_features {
// EXACTLY the five fields HEXL consults (derived from util/cpu-features.hpp, not guessed):
// avx512f, avx512dq, avx512vl, avx512ifma, avx512vbmi2.
struct X86Features {
  bool avx512f = false;
  bool avx512dq = false;
  bool avx512vl = false;
  bool avx512ifma = false;
  bool avx512vbmi2 = false;
};
struct X86Info { X86Features features; };
inline X86Info GetX86Info() { return X86Info{}; }
}  // namespace cpu_features
