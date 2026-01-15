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
// Ring Signature Tests
// ============================================================================

#include "ring_signature.h"

void test_key_image_generation()
{
    std::cout << "Testing KeyImage generation... ";

    // Create a mock public key
    LatticePublicKey pk;
    for (size_t i = 0; i < LatticeParams::K; i++) {
        pk.key[i] = RingElement::sampleUniform();
    }

    // Create a private key (small coefficients)
    RingElement sk = RingElement::sampleGaussian();

    // Generate key image
    KeyImage ki1 = KeyImage::generate(sk, pk);
    KeyImage ki2 = KeyImage::generate(sk, pk);

    // Same key should produce same image
    assert(ki1 == ki2 && "Same key should produce same key image");

    // Different key should produce different image
    RingElement sk2 = RingElement::sampleGaussian();
    KeyImage ki3 = KeyImage::generate(sk2, pk);

    bool different = !(ki1 == ki3);
    assert(different && "Different keys should produce different images");

    std::cout << "PASSED" << std::endl;
}

void test_ring_signature_basic()
{
    std::cout << "Testing ring signature (size=3)... ";

    const size_t ring_size = 3;

    // Generate ring of public keys
    std::vector<LatticePublicKey> ring(ring_size);
    for (size_t i = 0; i < ring_size; i++) {
        for (size_t j = 0; j < LatticeParams::K; j++) {
            ring[i].key[j] = RingElement::sampleUniform();
        }
    }

    // Real signer is at index 1
    size_t real_index = 1;
    RingElement private_key = RingElement::sampleGaussian();

    // Update public key to match private key (P = x * G, simplified)
    for (size_t j = 0; j < LatticeParams::K; j++) {
        ring[real_index].key[j] = private_key;
    }

    // Create message to sign
    std::array<uint8_t, 32> message = {};
    for (int i = 0; i < 32; i++)
        message[i] = i;

    // Sign
    LatticeRingSignature sig = LatticeRingSignature::sign(
        message, ring, real_index, private_key);

    // Check signature has correct structure
    assert(sig.responses.size() == ring_size && "Should have response per ring member");

    std::cout << "PASSED (sig_size=" << sig.size() << " bytes)" << std::endl;
}

void test_ring_signature_large()
{
    std::cout << "Testing ring signature (size=11)... ";

    const size_t ring_size = 11; // Monero-style ring size

    // Generate ring of public keys
    std::vector<LatticePublicKey> ring(ring_size);
    for (size_t i = 0; i < ring_size; i++) {
        for (size_t j = 0; j < LatticeParams::K; j++) {
            ring[i].key[j] = RingElement::sampleUniform();
        }
    }

    // Real signer is at random index
    size_t real_index = 7;
    RingElement private_key = RingElement::sampleGaussian();

    // Update public key to match private key
    for (size_t j = 0; j < LatticeParams::K; j++) {
        ring[real_index].key[j] = private_key;
    }

    // Create message to sign
    std::array<uint8_t, 32> message = {};
    for (int i = 0; i < 32; i++)
        message[i] = 0x42;

    // Sign
    LatticeRingSignature sig = LatticeRingSignature::sign(
        message, ring, real_index, private_key);

    assert(sig.responses.size() == ring_size && "Should have 11 responses");

    std::cout << "PASSED (sig_size=" << sig.size() / 1024 << " KB)" << std::endl;
}

void test_ring_signature_serialization()
{
    std::cout << "Testing ring signature serialization... ";

    const size_t ring_size = 3;

    // Generate ring and signature
    std::vector<LatticePublicKey> ring(ring_size);
    for (size_t i = 0; i < ring_size; i++) {
        for (size_t j = 0; j < LatticeParams::K; j++) {
            ring[i].key[j] = RingElement::sampleUniform();
        }
    }

    RingElement private_key = RingElement::sampleGaussian();
    for (size_t j = 0; j < LatticeParams::K; j++) {
        ring[0].key[j] = private_key;
    }

    std::array<uint8_t, 32> message = {};
    LatticeRingSignature sig = LatticeRingSignature::sign(message, ring, 0, private_key);

    // Serialize and deserialize
    auto serialized = sig.serialize();
    LatticeRingSignature sig2 = LatticeRingSignature::deserialize(serialized);

    // Check key images match
    assert(sig.key_image == sig2.key_image && "Key images should match");
    assert(sig.responses.size() == sig2.responses.size() && "Response counts should match");

    std::cout << "PASSED" << std::endl;
}

void benchmark_ring_signature()
{
    std::cout << "Benchmarking ring signature (size=11)... ";

    const size_t ring_size = 11;

    // Setup
    std::vector<LatticePublicKey> ring(ring_size);
    for (size_t i = 0; i < ring_size; i++) {
        for (size_t j = 0; j < LatticeParams::K; j++) {
            ring[i].key[j] = RingElement::sampleUniform();
        }
    }

    RingElement private_key = RingElement::sampleGaussian();
    for (size_t j = 0; j < LatticeParams::K; j++) {
        ring[5].key[j] = private_key;
    }

    std::array<uint8_t, 32> message = {};

    const int iterations = 10;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        LatticeRingSignature sig = LatticeRingSignature::sign(
            message, ring, 5, private_key);
        (void)sig;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    double per_op = (double)duration.count() / iterations;
    std::cout << per_op << " ms per signature" << std::endl;
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

    // Unit tests - Commitments
    std::cout << "Running commitment tests:\n";
    test_ring_element_addition();
    test_ring_element_subtraction();
    test_ring_element_multiplication();
    test_gaussian_sampling();
    test_commitment_creation();
    test_commitment_homomorphism();
    test_serialization();

    // Unit tests - Ring Signatures
    std::cout << "\nRunning ring signature tests:\n";
    test_key_image_generation();
    test_ring_signature_basic();
    test_ring_signature_large();
    test_ring_signature_serialization();

    // Benchmarks
    std::cout << "\nRunning benchmarks:\n";
    benchmark_ntt_multiplication();
    benchmark_commitment();
    benchmark_ring_signature();

    std::cout << "\n===========================================\n";
    std::cout << "  All tests PASSED                          \n";
    std::cout << "===========================================\n";

    return 0;
}
