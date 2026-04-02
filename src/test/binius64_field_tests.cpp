// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license
//
// Test suite for GF(2^128) field arithmetic with NIST pentanomial
// x^128 + x^7 + x^2 + x + 1 (same as AES-GCM GHASH)
//
// Validates fixes for SOQ-A001 through SOQ-A006 (Halborn Extension Audit).

#include "crypto/binius64/field.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <array>
#include <cstring>

BOOST_FIXTURE_TEST_SUITE(binius64_field_tests, BasicTestingSetup)

// ============================================================================
// 1. Field axioms
// ============================================================================

BOOST_AUTO_TEST_CASE(additive_identity)
{
    // a + 0 == a for several values
    Binius64 a(0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL);
    Binius64 result = a + Binius64::zero();
    BOOST_CHECK(result == a);
}

BOOST_AUTO_TEST_CASE(additive_self_inverse)
{
    // In GF(2^128), a + a == 0 for all a (characteristic 2)
    Binius64 a(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);
    Binius64 result = a + a;
    BOOST_CHECK(result == Binius64::zero());
}

BOOST_AUTO_TEST_CASE(multiplicative_identity)
{
    // a * 1 == a
    Binius64 a(0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL);
    Binius64 result = a * Binius64::one();
    BOOST_CHECK(result == a);

    // 1 * a == a (commutativity check as well)
    result = Binius64::one() * a;
    BOOST_CHECK(result == a);
}

BOOST_AUTO_TEST_CASE(multiplicative_zero)
{
    // a * 0 == 0
    Binius64 a(0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL);
    Binius64 result = a * Binius64::zero();
    BOOST_CHECK(result == Binius64::zero());
}

BOOST_AUTO_TEST_CASE(commutativity)
{
    // a * b == b * a
    Binius64 a(0x1234567890ABCDEFULL, 0xFEDCBA0987654321ULL);
    Binius64 b(0xAAAAAAAABBBBBBBBULL, 0xCCCCCCCCDDDDDDDDULL);
    BOOST_CHECK(a * b == b * a);
}

BOOST_AUTO_TEST_CASE(associativity)
{
    // (a * b) * c == a * (b * c)
    Binius64 a(0x1111111111111111ULL, 0x2222222222222222ULL);
    Binius64 b(0x3333333333333333ULL, 0x4444444444444444ULL);
    Binius64 c(0x5555555555555555ULL, 0x6666666666666666ULL);
    BOOST_CHECK((a * b) * c == a * (b * c));
}

BOOST_AUTO_TEST_CASE(distributivity)
{
    // a * (b + c) == a*b + a*c
    Binius64 a(0xABCDEF0123456789ULL, 0x9876543210FEDCBAULL);
    Binius64 b(0x1111111111111111ULL, 0x2222222222222222ULL);
    Binius64 c(0x3333333333333333ULL, 0x4444444444444444ULL);
    BOOST_CHECK(a * (b + c) == (a * b) + (a * c));
}

// ============================================================================
// 2. SOQ-A001: No zero divisors with NIST pentanomial
// ============================================================================

BOOST_AUTO_TEST_CASE(no_zero_divisors_old_trinomial_element)
{
    // The element x^2+x+1 (binary: 0b111 = 7) was a zero divisor under the
    // old REDUCIBLE trinomial x^128+x^7+1. With the NIST pentanomial,
    // multiplying it by anything nonzero must NOT produce zero.
    Binius64 old_zero_divisor(7, 0); // x^2 + x + 1

    // Multiply by several nonzero elements — none should give zero
    Binius64 test_values[] = {
        Binius64(1, 0),
        Binius64(0, 1),
        Binius64(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL),
        Binius64(0x123456789ABCDEF0ULL, 0x0FEDCBA987654321ULL),
        Binius64(7, 0), // multiply by itself
    };

    for (const auto& v : test_values) {
        if (v == Binius64::zero()) continue;
        Binius64 product = old_zero_divisor * v;
        BOOST_CHECK_MESSAGE(product != Binius64::zero(),
            "Zero divisor found! x^2+x+1 should NOT be a zero divisor under NIST pentanomial");
    }
}

BOOST_AUTO_TEST_CASE(no_zero_divisors_stress)
{
    // Test a spread of nonzero elements — none should be zero divisors
    // Use a simple PRNG (xorshift64) for reproducible test vectors
    uint64_t state = 0xBAADF00DCAFEBEEFULL;
    auto xorshift = [&]() -> uint64_t {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    };

    for (int i = 0; i < 50; ++i) {
        Binius64 a(xorshift(), xorshift());
        Binius64 b(xorshift(), xorshift());
        if (a == Binius64::zero() || b == Binius64::zero()) continue;
        Binius64 product = a * b;
        BOOST_CHECK_MESSAGE(product != Binius64::zero(),
            "Zero divisor found in random test at iteration " + std::to_string(i));
    }
}

// ============================================================================
// 3. SOQ-A003: Second reduction pass (high-bit-density operands)
// ============================================================================

BOOST_AUTO_TEST_CASE(high_bit_density_multiplication)
{
    // All-ones * all-ones exercises every bit in the 256-bit product,
    // maximizing the overflow bits that require the second reduction pass.
    Binius64 all_ones(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);
    Binius64 result = all_ones * all_ones;

    // The result must be a valid 128-bit field element (nonzero because
    // all_ones is nonzero and the polynomial is irreducible)
    BOOST_CHECK(result != Binius64::zero());

    // Verify: result * result_inverse == 1
    Binius64 inv = result.mont_inverse();
    BOOST_CHECK(result * inv == Binius64::one());
}

BOOST_AUTO_TEST_CASE(top_bits_set)
{
    // Elements with only the top bits set exercise the x^7 shift overflow
    Binius64 top(0, 0xFE00000000000000ULL); // bits 121-127 set in high limb
    Binius64 result = top * top;
    BOOST_CHECK(result != Binius64::zero());

    // Cross-check: (top * top) * top_inv == top
    Binius64 inv = top.mont_inverse();
    BOOST_CHECK(top * inv == Binius64::one());
}

// ============================================================================
// 4. SOQ-A004: mont_inverse() correctness (final squaring)
// ============================================================================

BOOST_AUTO_TEST_CASE(inverse_basic)
{
    // a * a^(-1) == 1 for several representative elements
    Binius64 test_values[] = {
        Binius64(1, 0),     // identity
        Binius64(2, 0),     // x
        Binius64(7, 0),     // x^2+x+1 (old zero divisor)
        Binius64(0, 1),     // x^64
        Binius64(0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL),
        Binius64(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL),
        Binius64(0x8000000000000000ULL, 0x8000000000000000ULL),
        Binius64(0x0000000000000001ULL, 0x8000000000000000ULL), // x^127 + 1
    };

    for (const auto& a : test_values) {
        Binius64 inv = a.mont_inverse();
        BOOST_CHECK_MESSAGE(a * inv == Binius64::one(),
            "Inverse failed for element");
        // Double inverse should return original
        BOOST_CHECK_MESSAGE(inv.mont_inverse() == a,
            "Double inverse failed");
    }
}

BOOST_AUTO_TEST_CASE(inverse_of_zero)
{
    // Convention: inverse of zero returns zero
    Binius64 inv = Binius64::zero().mont_inverse();
    BOOST_CHECK(inv == Binius64::zero());
}

BOOST_AUTO_TEST_CASE(inverse_stress)
{
    // Random inverse test — 20 elements
    uint64_t state = 0x0A1B2C3D4E5F6789ULL;
    auto xorshift = [&]() -> uint64_t {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    };

    for (int i = 0; i < 20; ++i) {
        Binius64 a(xorshift(), xorshift());
        if (a == Binius64::zero()) continue;
        Binius64 inv = a.mont_inverse();
        BOOST_CHECK_MESSAGE(a * inv == Binius64::one(),
            "Inverse stress test failed at iteration " + std::to_string(i));
    }
}

// ============================================================================
// 5. SOQ-A006: batch_inverse() correctness (no const_cast UB)
// ============================================================================

BOOST_AUTO_TEST_CASE(batch_inverse_consistency)
{
    // batch_inverse should produce the same results as individual mont_inverse
    std::array<Binius64, 64> elements;
    uint64_t state = 0xCAFEBABEDEADBEEFULL;
    auto xorshift = [&]() -> uint64_t {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    };

    // Fill with nonzero random elements
    for (int i = 0; i < 64; ++i) {
        uint64_t lo = xorshift();
        uint64_t hi = xorshift();
        if (lo == 0 && hi == 0) lo = 1; // avoid zero
        elements[i] = Binius64(lo, hi);
    }

    // Compute individual inverses for comparison
    std::array<Binius64, 64> individual_inverses;
    for (int i = 0; i < 64; ++i) {
        individual_inverses[i] = elements[i].mont_inverse();
    }

    // Run batch inverse (modifies elements in place)
    Binius64::batch_inverse(elements);

    // Compare
    for (int i = 0; i < 64; ++i) {
        BOOST_CHECK_MESSAGE(elements[i] == individual_inverses[i],
            "batch_inverse mismatch at index " + std::to_string(i));
    }
}

// ============================================================================
// 6. NIST SP 800-38D AES-GCM test vector (GF(2^128) multiplication)
// ============================================================================

BOOST_AUTO_TEST_CASE(nist_gcm_test_vector)
{
    // NIST SP 800-38D, Example 1 (AES-128-GCM)
    // The GCM GHASH function uses GF(2^128) multiplication with the
    // SAME polynomial x^128 + x^7 + x^2 + x + 1.
    //
    // NOTE: GHASH uses a bit-reflected representation. In the standard
    // representation used here, we verify the algebraic properties instead.
    //
    // Known multiplication in standard (non-reflected) representation:
    // Let H = x (represented as {2, 0}) and X = x+1 (represented as {3, 0})
    // H * X = x*(x+1) = x^2+x = {6, 0} (bits: 110)
    Binius64 H(2, 0);   // x
    Binius64 X(3, 0);   // x + 1
    Binius64 expected(6, 0); // x^2 + x
    BOOST_CHECK(H * X == expected);

    // Another: x^2 * x^2 = x^4
    Binius64 x2(4, 0);   // x^2
    Binius64 x4(16, 0);  // x^4
    BOOST_CHECK(x2 * x2 == x4);

    // x^63 * x^63 = x^126 (no reduction needed, still < x^128)
    Binius64 x63(0x8000000000000000ULL, 0);  // bit 63
    Binius64 x126(0, 0x4000000000000000ULL); // bit 126 (high limb bit 62)
    BOOST_CHECK(x63 * x63 == x126);

    // x^64 * x^64 = x^128 ≡ x^7 + x^2 + x + 1 (mod pentanomial)
    // x^128 mod p = x^7+x^2+x+1 = 0b10000111 = 0x87
    Binius64 x64(0, 1);     // bit 64 (high limb bit 0)
    Binius64 x128_reduced(0x87, 0); // x^7+x^2+x+1
    BOOST_CHECK(x64 * x64 == x128_reduced);

    // x^127 * x = x^128 ≡ x^7 + x^2 + x + 1
    Binius64 x127(0, 0x8000000000000000ULL); // bit 127
    Binius64 x1(2, 0);
    BOOST_CHECK(x127 * x1 == x128_reduced);
}

BOOST_AUTO_TEST_CASE(reduction_polynomial_identity)
{
    // Verify the polynomial identity: x^128 + x^7 + x^2 + x + 1 = 0
    // In the field, this means x^128 = x^7 + x^2 + x + 1.
    // We compute x^128 by multiplying x^64 * x^64 and check the result.
    Binius64 x64(0, 1);
    Binius64 x128 = x64 * x64;
    // x^7 + x^2 + x + 1 = 10000111 binary = 0x87
    BOOST_CHECK(x128 == Binius64(0x87, 0));

    // Also verify x^129 = x * x^128 = x * (x^7+x^2+x+1) = x^8+x^3+x^2+x
    // = 100001110 binary = 0x10E
    Binius64 x(2, 0);
    Binius64 x129 = x * x128;
    Binius64 x129_expected(0x10E, 0); // x^8+x^3+x^2+x
    BOOST_CHECK(x129 == x129_expected);
}

// ============================================================================
// 7. Multilinear evaluation (regression test — not changed by audit)
// ============================================================================

BOOST_AUTO_TEST_CASE(multilinear_eval_trivial)
{
    // All-zero polynomial evaluates to zero everywhere
    std::array<Binius64, 256> poly;
    poly.fill(Binius64::zero());
    std::array<Binius64, 8> point;
    point.fill(Binius64::one());
    BOOST_CHECK(eval_multilinear_packed(poly, point) == Binius64::zero());

    // Constant polynomial (all entries = c) evaluates to c everywhere
    Binius64 c(42, 0);
    poly.fill(c);
    point.fill(Binius64::zero());
    // With all point coords = 0, evaluation selects poly[0] = c
    BOOST_CHECK(eval_multilinear_packed(poly, point) == c);
}

BOOST_AUTO_TEST_SUITE_END()
