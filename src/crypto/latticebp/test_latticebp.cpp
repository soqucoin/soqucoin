// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// Lattice-BP++ Test Harness
// Stage 3 R&D - Unit tests for core primitives
//

#include "commitment.h"
#include <cassert>
#include <chrono>
#include <iostream>

using namespace latticebp;

// ============================================================================
// HKDF stub for testing (actual implementation in crypto/hmac_sha256.cpp)
// ============================================================================

extern "C" {
void HKDF_SHA256(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len)
{
    // Simple deterministic expansion for testing
    // NOT cryptographically secure - replace with real HKDF
    uint64_t state = 0;
    for (size_t i = 0; i < ikm_len; i++)
        state ^= (uint64_t)ikm[i] << (i % 56);
    for (size_t i = 0; i < info_len; i++)
        state ^= (uint64_t)info[i] << (i % 56);

    for (size_t i = 0; i < okm_len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        okm[i] = (state >> 33) & 0xFF;
    }
}
}

// ============================================================================
// Test Cases
// ============================================================================

void test_ring_element_addition()
{
    std::cout << "Testing RingElement addition... ";

    RingElement a = RingElement::sampleUniform();
    RingElement b = RingElement::sampleUniform();
    RingElement c = a + b;
    RingElement d = b + a; // Commutative

    // Check commutativity
    bool commutative = true;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        if (c.coeffs[i] != d.coeffs[i]) {
            commutative = false;
            break;
        }
    }

    assert(commutative && "Addition should be commutative");
    std::cout << "PASSED" << std::endl;
}

void test_ring_element_subtraction()
{
    std::cout << "Testing RingElement subtraction... ";

    RingElement a = RingElement::sampleUniform();
    RingElement b = a - a;

    // a - a should be zero
    bool is_zero = true;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        if (b.coeffs[i] % LatticeParams::Q != 0) {
            is_zero = false;
            break;
        }
    }

    assert(is_zero && "a - a should be zero");
    std::cout << "PASSED" << std::endl;
}

void test_ring_element_multiplication()
{
    std::cout << "Testing RingElement NTT multiplication... ";

    // Test multiplicative identity
    RingElement one;
    one.coeffs[0] = 1; // Polynomial "1"

    RingElement a = RingElement::sampleUniform();
    RingElement b = a * one;

    // a * 1 should equal a
    bool equals = true;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        int64_t diff = (a.coeffs[i] - b.coeffs[i]) % LatticeParams::Q;
        if (diff < 0) diff += LatticeParams::Q;
        if (diff != 0 && diff != LatticeParams::Q) {
            equals = false;
            break;
        }
    }

    assert(equals && "Multiplication by 1 should be identity");
    std::cout << "PASSED" << std::endl;
}

void test_gaussian_sampling()
{
    std::cout << "Testing Gaussian sampling... ";

    RingElement g = RingElement::sampleGaussian(LatticeParams::SIGMA);

    // Check that samples are small (within ~4σ with high probability)
    int64_t max_coeff = 0;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        int64_t val = g.coeffs[i];
        if (val > LatticeParams::Q / 2) val -= LatticeParams::Q;
        if (std::abs(val) > max_coeff) max_coeff = std::abs(val);
    }

    // With σ=2, max should typically be < 20
    assert(max_coeff < 100 && "Gaussian samples should be small");
    std::cout << "PASSED (max_coeff=" << max_coeff << ")" << std::endl;
}

void test_commitment_creation()
{
    std::cout << "Testing LatticeCommitment creation... ";

    std::array<uint8_t, 32> seed = {};
    for (int i = 0; i < 32; i++)
        seed[i] = i;

    auto params = LatticeCommitment::PublicParams::generate(seed);

    uint64_t value = 1000000; // 1 million SOQ
    RingElement randomness = RingElement::sampleGaussian();

    LatticeCommitment c = LatticeCommitment::commit(value, randomness, params);

    // Verify the commitment opens correctly
    bool valid = c.verify(value, randomness, params);
    assert(valid && "Commitment should verify with correct opening");

    // Verify wrong value fails
    bool invalid = c.verify(value + 1, randomness, params);
    assert(!invalid && "Commitment should fail with wrong value");

    std::cout << "PASSED" << std::endl;
}

void test_commitment_homomorphism()
{
    std::cout << "Testing commitment homomorphism... ";

    std::array<uint8_t, 32> seed = {};
    auto params = LatticeCommitment::PublicParams::generate(seed);

    uint64_t v1 = 500;
    uint64_t v2 = 300;
    RingElement r1 = RingElement::sampleGaussian();
    RingElement r2 = RingElement::sampleGaussian();

    LatticeCommitment c1 = LatticeCommitment::commit(v1, r1, params);
    LatticeCommitment c2 = LatticeCommitment::commit(v2, r2, params);

    // c1 + c2 should commit to v1 + v2
    LatticeCommitment c_sum = c1 + c2;
    RingElement r_sum = r1 + r2;

    bool valid = c_sum.verify(v1 + v2, r_sum, params);
    assert(valid && "Commitment sum should verify for value sum");

    std::cout << "PASSED" << std::endl;
}

void test_serialization()
{
    std::cout << "Testing serialization... ";

    RingElement a = RingElement::sampleUniform();
    auto serialized = a.serialize();
    RingElement b = RingElement::deserialize(serialized);

    bool equals = true;
    for (size_t i = 0; i < LatticeParams::N; i++) {
        if (a.coeffs[i] != b.coeffs[i]) {
            equals = false;
            break;
        }
    }

    assert(equals && "Serialization should preserve coefficients");
    std::cout << "PASSED (size=" << serialized.size() << " bytes)" << std::endl;
}

void benchmark_ntt_multiplication()
{
    std::cout << "\nBenchmarking NTT multiplication... ";

    RingElement a = RingElement::sampleUniform();
    RingElement b = RingElement::sampleUniform();

    const int iterations = 10000;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        RingElement c = a * b;
        (void)c; // Prevent optimization
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    double per_op = (double)duration.count() / iterations;
    std::cout << per_op << " µs per multiplication" << std::endl;
}

void benchmark_commitment()
{
    std::cout << "Benchmarking commitment generation... ";

    std::array<uint8_t, 32> seed = {};
    auto params = LatticeCommitment::PublicParams::generate(seed);
    RingElement r = RingElement::sampleGaussian();

    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        LatticeCommitment c = LatticeCommitment::commit(1000000, r, params);
        (void)c;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    double per_op = (double)duration.count() / iterations;
    std::cout << per_op << " µs per commitment" << std::endl;
}

// ============================================================================
// Main
// ============================================================================

int main()
{
    std::cout << "===========================================\n";
    std::cout << "  Lattice-BP++ Stage 3 R&D Test Harness    \n";
    std::cout << "===========================================\n\n";

    std::cout << "Parameters:\n";
    std::cout << "  Ring dimension (n): " << LatticeParams::N << "\n";
    std::cout << "  Modulus (q):        " << LatticeParams::Q << "\n";
    std::cout << "  Module rank (k):    " << LatticeParams::K << "\n";
    std::cout << "  Gaussian σ:         " << LatticeParams::SIGMA << "\n\n";

    // Unit tests
    std::cout << "Running unit tests:\n";
    test_ring_element_addition();
    test_ring_element_subtraction();
    test_ring_element_multiplication();
    test_gaussian_sampling();
    test_commitment_creation();
    test_commitment_homomorphism();
    test_serialization();

    // Benchmarks
    std::cout << "\nRunning benchmarks:\n";
    benchmark_ntt_multiplication();
    benchmark_commitment();

    std::cout << "\n===========================================\n";
    std::cout << "  All tests PASSED                          \n";
    std::cout << "===========================================\n";

    return 0;
}
