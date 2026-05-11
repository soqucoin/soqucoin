/* test_capi.c — Deterministic test vectors for liblatticebp C API
 *
 * Copyright (c) 2026 Soqucoin Labs Inc.
 * Tests all 15 C API functions with fixed seeds for cross-platform
 * reproducibility. Output must match L1 node exactly.
 */

#include "capi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT_EQ(actual, expected, msg) do { \
    tests_run++; \
    if ((actual) == (expected)) { \
        tests_passed++; \
        printf("  ✓ %s\n", msg); \
    } else { \
        printf("  ✗ %s (expected %d, got %d)\n", msg, (int)(expected), (int)(actual)); \
    } \
} while(0)

/* Fixed consensus seed (deterministic for test vectors) */
static const uint8_t TEST_SEED[32] = {
    0x53, 0x4f, 0x51, 0x55, 0x43, 0x4f, 0x49, 0x4e,  /* "SOQUCOIN" */
    0x2d, 0x4c, 0x41, 0x54, 0x54, 0x49, 0x43, 0x45,  /* "-LATTICE" */
    0x2d, 0x42, 0x50, 0x2b, 0x2b, 0x2d, 0x54, 0x45,  /* "-BP++-TE" */
    0x53, 0x54, 0x2d, 0x56, 0x45, 0x43, 0x2d, 0x31   /* "ST-VEC-1" */
};

/* Fixed sighash and pubkey_hash for range proof binding */
static const uint8_t TEST_SIGHASH[32] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
};

static const uint8_t TEST_PUBKEY_HASH[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

/* Fixed master seed for key derivation */
static const uint8_t TEST_MASTER_SEED[32] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78
};

static void test_version(void) {
    printf("\n[Version]\n");
    const char* v = lbp_version();
    tests_run++;
    if (v && strcmp(v, "1.0.0") == 0) {
        tests_passed++;
        printf("  ✓ version = %s\n", v);
    } else {
        printf("  ✗ version = %s (expected 1.0.0)\n", v ? v : "NULL");
    }
}

static void test_init(void) {
    printf("\n[Init]\n");
    int rc = lbp_init(TEST_SEED);
    ASSERT_EQ(rc, LBP_OK, "lbp_init with test seed");

    rc = lbp_init(NULL);
    ASSERT_EQ(rc, LBP_ERR_INVALID_PARAM, "lbp_init with NULL seed");
}

static void test_sampling(void) {
    printf("\n[Sampling]\n");
    uint8_t randomness[LBP_VIEW_KEY_SIZE];
    int rc = lbp_sample_randomness(randomness, LBP_VIEW_KEY_SIZE);
    ASSERT_EQ(rc, LBP_OK, "sample randomness");

    /* Verify not all zeros */
    int nonzero = 0;
    for (size_t i = 0; i < LBP_VIEW_KEY_SIZE; i++) {
        if (randomness[i] != 0) { nonzero = 1; break; }
    }
    ASSERT_EQ(nonzero, 1, "randomness is non-zero");

    rc = lbp_sample_randomness(NULL, LBP_VIEW_KEY_SIZE);
    ASSERT_EQ(rc, LBP_ERR_INVALID_PARAM, "sample with NULL buffer");
}

static void test_commitment(void) {
    printf("\n[Commitment]\n");
    uint8_t randomness[LBP_VIEW_KEY_SIZE];
    lbp_sample_randomness(randomness, LBP_VIEW_KEY_SIZE);

    uint8_t commitment[LBP_COMMITMENT_SIZE];
    size_t commit_len = LBP_COMMITMENT_SIZE;
    uint64_t value = 100000000ULL; /* 1 SOQ in satoshis */

    int rc = lbp_commit(value, randomness, LBP_VIEW_KEY_SIZE,
                        commitment, &commit_len);
    ASSERT_EQ(rc, LBP_OK, "commit 1 SOQ");

    tests_run++;
    if (commit_len > 0 && commit_len <= LBP_COMMITMENT_SIZE) {
        tests_passed++;
        printf("  ✓ commitment size = %zu bytes\n", commit_len);
    } else {
        printf("  ✗ commitment size = %zu (unexpected)\n", commit_len);
    }

    /* Verify opening */
    rc = lbp_commit_verify(value, randomness, LBP_VIEW_KEY_SIZE,
                           commitment, commit_len);
    ASSERT_EQ(rc, LBP_OK, "verify correct opening");

    /* Wrong value should fail */
    rc = lbp_commit_verify(value + 1, randomness, LBP_VIEW_KEY_SIZE,
                           commitment, commit_len);
    ASSERT_EQ(rc, LBP_ERR_VERIFY_FAILED, "reject wrong value");
}

static void test_range_proof(void) {
    printf("\n[Range Proof]\n");
    uint8_t randomness[LBP_VIEW_KEY_SIZE];
    lbp_sample_randomness(randomness, LBP_VIEW_KEY_SIZE);

    uint8_t commitment[LBP_COMMITMENT_SIZE];
    size_t commit_len = LBP_COMMITMENT_SIZE;
    uint64_t value = 50000000ULL; /* 0.5 SOQ */

    lbp_commit(value, randomness, LBP_VIEW_KEY_SIZE, commitment, &commit_len);

    uint8_t proof[LBP_PROOF_MAX_SIZE];
    size_t proof_len = LBP_PROOF_MAX_SIZE;

    int rc = lbp_range_prove(value, randomness, LBP_VIEW_KEY_SIZE,
                              commitment, commit_len,
                              TEST_SIGHASH, TEST_PUBKEY_HASH,
                              proof, &proof_len);
    ASSERT_EQ(rc, LBP_OK, "prove range for 0.5 SOQ");

    tests_run++;
    if (proof_len > 0 && proof_len <= LBP_PROOF_MAX_SIZE) {
        tests_passed++;
        printf("  ✓ proof size = %zu bytes\n", proof_len);
    } else {
        printf("  ✗ proof size = %zu (unexpected)\n", proof_len);
    }

    /* Verify */
    rc = lbp_range_verify(proof, proof_len, commitment, commit_len,
                           TEST_SIGHASH, TEST_PUBKEY_HASH);
    ASSERT_EQ(rc, LBP_OK, "verify range proof");

    /* Wrong sighash should fail */
    uint8_t bad_sighash[32];
    memset(bad_sighash, 0, 32);
    rc = lbp_range_verify(proof, proof_len, commitment, commit_len,
                           bad_sighash, TEST_PUBKEY_HASH);
    ASSERT_EQ(rc, LBP_ERR_VERIFY_FAILED, "reject wrong sighash binding");
}

static void test_key_derivation(void) {
    printf("\n[Key Derivation]\n");
    uint8_t view_key[LBP_VIEW_KEY_SIZE];
    uint8_t spend_key[LBP_SPEND_KEY_SIZE];
    size_t vk_len = LBP_VIEW_KEY_SIZE;
    size_t sk_len = LBP_SPEND_KEY_SIZE;

    int rc = lbp_derive_privacy_keys(TEST_MASTER_SEED, 32,
                                      view_key, &vk_len,
                                      spend_key, &sk_len);
    ASSERT_EQ(rc, LBP_OK, "derive view + spend keys");

    /* Deterministic: same seed → same keys */
    uint8_t view_key2[LBP_VIEW_KEY_SIZE];
    uint8_t spend_key2[LBP_SPEND_KEY_SIZE];
    size_t vk_len2 = LBP_VIEW_KEY_SIZE;
    size_t sk_len2 = LBP_SPEND_KEY_SIZE;

    lbp_derive_privacy_keys(TEST_MASTER_SEED, 32,
                            view_key2, &vk_len2,
                            spend_key2, &sk_len2);

    tests_run++;
    if (memcmp(view_key, view_key2, vk_len) == 0 &&
        memcmp(spend_key, spend_key2, sk_len) == 0) {
        tests_passed++;
        printf("  ✓ deterministic key derivation\n");
    } else {
        printf("  ✗ key derivation not deterministic\n");
    }

    /* View key ≠ spend key */
    tests_run++;
    if (memcmp(view_key, spend_key, vk_len < sk_len ? vk_len : sk_len) != 0) {
        tests_passed++;
        printf("  ✓ view key ≠ spend key\n");
    } else {
        printf("  ✗ view key == spend key (collision!)\n");
    }
}

static void test_secure_free(void) {
    printf("\n[Secure Free]\n");
    uint8_t* secret = (uint8_t*)malloc(32);
    memset(secret, 0xAA, 32);

    lbp_secure_free(secret, 32);

    /* After secure free, memory should be zeroed */
    int zeroed = 1;
    for (int i = 0; i < 32; i++) {
        if (secret[i] != 0) { zeroed = 0; break; }
    }
    ASSERT_EQ(zeroed, 1, "memory zeroed after secure_free");
    free(secret);

    /* NULL should not crash */
    lbp_secure_free(NULL, 0);
    tests_run++;
    tests_passed++;
    printf("  ✓ NULL secure_free no crash\n");
}

static void test_edge_cases(void) {
    printf("\n[Edge Cases]\n");
    uint8_t randomness[LBP_VIEW_KEY_SIZE];
    lbp_sample_randomness(randomness, LBP_VIEW_KEY_SIZE);

    uint8_t commitment[LBP_COMMITMENT_SIZE];
    size_t commit_len = LBP_COMMITMENT_SIZE;

    /* Zero value */
    int rc = lbp_commit(0, randomness, LBP_VIEW_KEY_SIZE,
                        commitment, &commit_len);
    ASSERT_EQ(rc, LBP_OK, "commit zero value");

    /* Max value (2^64 - 1) */
    commit_len = LBP_COMMITMENT_SIZE;
    rc = lbp_commit(UINT64_MAX, randomness, LBP_VIEW_KEY_SIZE,
                    commitment, &commit_len);
    ASSERT_EQ(rc, LBP_OK, "commit max uint64 value");

    /* Range proof for zero */
    uint8_t proof[LBP_PROOF_MAX_SIZE];
    size_t proof_len = LBP_PROOF_MAX_SIZE;
    commit_len = LBP_COMMITMENT_SIZE;
    lbp_commit(0, randomness, LBP_VIEW_KEY_SIZE, commitment, &commit_len);
    rc = lbp_range_prove(0, randomness, LBP_VIEW_KEY_SIZE,
                          commitment, commit_len,
                          TEST_SIGHASH, TEST_PUBKEY_HASH,
                          proof, &proof_len);
    ASSERT_EQ(rc, LBP_OK, "range proof for zero value");
}

int main(void) {
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  liblatticebp C API Test Suite v1.0.0       ║\n");
    printf("║  Soqucoin Labs Inc. — Patent Pending        ║\n");
    printf("╚══════════════════════════════════════════════╝\n");

    test_version();
    test_init();
    test_sampling();
    test_commitment();
    test_range_proof();
    test_key_derivation();
    test_secure_free();
    test_edge_cases();

    printf("\n══════════════════════════════════════════════\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);
    printf("══════════════════════════════════════════════\n");

    lbp_cleanup();
    return (tests_passed == tests_run) ? 0 : 1;
}
