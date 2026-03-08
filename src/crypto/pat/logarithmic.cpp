#include <algorithm>
#include <crypto/pat/logarithmic.h>
#include <crypto/sha3.h>
#include <cstdint>
#include <numeric>

using namespace std;
using namespace pat;

static uint256 PatHash(const CValType& data)
{
    SHA3_256 hasher;
    hasher.Write(data.data(), data.size());
    uint256 hash;
    hasher.Finalize(hash.begin());
    return hash;
}

static uint256 LeafHash(uint32_t idx, const CValType& sig, const CValType& pk, const CValType& msg)
{
    CValType buf;
    buf.reserve(1 + 4 + sig.size() + pk.size() + msg.size());
    buf.push_back(0x00); // domain separator
    uint32_t le_idx = htole32(idx);
    buf.insert(buf.end(), (uint8_t*)&le_idx, (uint8_t*)&le_idx + 4);
    buf.insert(buf.end(), sig.begin(), sig.end());
    buf.insert(buf.end(), pk.begin(), pk.end());
    buf.insert(buf.end(), msg.begin(), msg.end());
    return PatHash(buf);
}

// NOTE: PortableCountBits was removed (FIND-002) — no longer needed after
// sibling path depth calculation was replaced with full tree rebuild.

// Helper for power of two (works on both 32-bit and 64-bit systems)
static size_t NextPowerOfTwo(size_t n)
{
    if (n == 0) return 1;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
#if SIZE_MAX > UINT32_MAX
    n |= n >> 32; // Only shift 32 on 64-bit systems
#endif
    n++;
    return n;
}


/**
 * Helper: Reconstruct a Merkle tree node hash from two child hashes
 * Uses domain separation (0x01 prefix) to distinguish from leaf hashes (0x00 prefix)
 */
static uint256 NodeHash(const uint256& left, const uint256& right)
{
    CValType buf;
    buf.reserve(1 + 64);
    buf.push_back(0x01); // domain separator for internal nodes
    buf.insert(buf.end(), left.begin(), left.end());
    buf.insert(buf.end(), right.begin(), right.end());
    return PatHash(buf);
}

// NOTE (Halborn FIND-002): ReconstructMerkleRoot() was removed.
// The previous implementation verified only leaf 0 via a sibling path,
// allowing an attacker to forge leaves 1..n-1. The verifier now rebuilds
// the entire Merkle tree from all n tuples — no sibling path needed.

/**
 * Helper: Compute XOR of all public key hashes
 * This binding prevents rogue-key attacks by ensuring all keys contribute to the proof
 */
static uint256 ComputePkXor(const std::vector<CValType>& vPks)
{
    uint256 xor_result = uint256(); // Initialize to all zeros

    for (const auto& pk : vPks) {
        if (pk.size() < 32) continue; // Skip invalid keys

        uint256 pk_hash;
        memcpy(pk_hash.begin(), pk.data(), 32);

        // XOR into result
        for (int i = 0; i < 32; i++) {
            xor_result.begin()[i] ^= pk_hash.begin()[i];
        }
    }

    return xor_result;
}

/**
 * Helper: Compute message root as hash of concatenated messages
 * Provides defense-in-depth commitment to all messages in the batch
 */
static uint256 ComputeMsgRoot(const std::vector<CValType>& vMsgs)
{
    // Concatenate all messages
    CValType buf;
    for (const auto& msg : vMsgs) {
        buf.insert(buf.end(), msg.begin(), msg.end());
    }

    return PatHash(buf);
}

bool pat::CreateLogarithmicProof(
    const vector<CValType>& vSignatures,
    const vector<CValType>& vPublicKeys,
    const vector<CValType>& vMessages,
    CValType& vchProofOut)
{
    size_t n = vSignatures.size();
    if (n == 0 || n > 1 << 20 || n != vPublicKeys.size() || n != vMessages.size()) return false;

    // Sort indices by message hash (canonical order)
    vector<uint32_t> order(n);
    iota(order.begin(), order.end(), 0);
    sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
        return PatHash(vMessages[a]) < PatHash(vMessages[b]);
    });

    // Build leaves and XOR binding
    vector<uint256> leaves(n);
    uint256 xor_binding = uint256();
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t pos = order[i];
        leaves[i] = LeafHash(i, vSignatures[pos], vPublicKeys[pos], vMessages[pos]);

        uint256 rho;
        if (vPublicKeys[pos].size() >= 32) {
            memcpy(rho.begin(), vPublicKeys[pos].data(), 32);
            for (int k = 0; k < 32; k++) {
                xor_binding.begin()[k] ^= rho.begin()[k];
            }
        }
    }

    // Standard Merkle tree with power-of-two padding
    size_t tree_size = NextPowerOfTwo(n);
    vector<uint256> tree(tree_size * 2);
    copy(leaves.begin(), leaves.end(), tree.begin() + tree_size);

    // SECURITY NOTE (Halborn FIND-005): Pad with last-leaf replication per spec
    // (logarithmic.h L76). Zero-padding diverges from spec-compliant implementations
    // and would cause chain splits for non-power-of-2 batch sizes.
    const uint256& last_leaf = leaves.back();
    for (size_t i = tree_size + n; i < tree_size * 2; ++i)
        tree[i] = last_leaf;

    for (size_t layer = tree_size; layer > 1; layer >>= 1) {
        for (size_t i = layer; i < layer * 2; i += 2) {
            // Hash pair using NodeHash (includes domain separator 0x01)
            tree[i / 2] = NodeHash(tree[i], tree[i + 1]);
        }
    }

    // FIND-002: Sibling path generation removed.
    // The verifier now rebuilds the entire tree from claimed tuples,
    // so no externally-supplied sibling path is needed.

    LogarithmicProof proof;
    proof.merkle_root = tree[1];
    proof.pk_xor = xor_binding;

    // Compute message root from sorted order (matches canonical ordering in Merkle tree)
    std::vector<CValType> sorted_msgs(n);
    for (uint32_t i = 0; i < n; ++i) {
        sorted_msgs[i] = vMessages[order[i]];
    }
    proof.msg_root = ComputeMsgRoot(sorted_msgs);
    proof.count = n;

    vchProofOut.clear();
    vchProofOut.insert(vchProofOut.end(), proof.merkle_root.begin(), proof.merkle_root.end());
    vchProofOut.insert(vchProofOut.end(), proof.pk_xor.begin(), proof.pk_xor.end());
    vchProofOut.insert(vchProofOut.end(), proof.msg_root.begin(), proof.msg_root.end());
    uint32_t le_n = htole32(n);
    vchProofOut.insert(vchProofOut.end(), (uint8_t*)&le_n, (uint8_t*)&le_n + 4);
    // Total 32+32+32+4 = 100 bytes.

    return true;
}

bool pat::ParseLogarithmicProof(const CValType& vchProof, LogarithmicProof& proofOut)
{
    if (vchProof.size() != 100) return false;

    memcpy(proofOut.merkle_root.begin(), vchProof.data(), 32);
    memcpy(proofOut.pk_xor.begin(), vchProof.data() + 32, 32);
    memcpy(proofOut.msg_root.begin(), vchProof.data() + 64, 32);

    uint32_t le_n;
    memcpy(&le_n, vchProof.data() + 96, 4);
    proofOut.count = le32toh(le_n);

    // SECURITY (Halborn FIND-001): Reject structurally invalid proof counts
    // at the parser level — this is the single entry gate covering all callers.
    // count == 0: empty proofs have no cryptographic meaning; prevents UB from
    //   zero-length vector dereference at VerifyLogarithmicProof:362.
    // count > MAX_PAT_PROOF_COUNT: prevents OOM from attacker-crafted values;
    //   matches the limit enforced in CreateLogarithmicProof.
    if (proofOut.count == 0 || proofOut.count > MAX_PAT_PROOF_COUNT)
        return false;

    return true;
}


/**
 * Full PAT Verification with Merkle Reconstruction
 *
 * This function performs cryptographic verification of a PAT logarithmic proof by:
 * 1. Parsing and validating the proof structure
 * 2. Recomputing the message root and verifying against proof
 * 3. Recomputing the PK XOR binding and verifying against proof
 * 4. Reconstructing the Merkle root from witness data and verifying against proof
 *
 * Security Properties:
 * - Merkle root binding: Ensures all signatures are included and in correct order
 * - XOR binding: Prevents rogue-key attacks where attacker substitutes keys
 * - Message binding: Commits to all messages, prevents message substitution
 *
 * @param vchProof Serialized 100-byte proof (merkle_root || pk_xor || msg_root || count)
 * @param vClaimedSigs Signature commitments (32 bytes each)
 * @param vClaimedPks Public key hashes (32 bytes each)
 * @param vClaimedMsgs Message digests (32 bytes each)
 * @return true if proof is valid, false otherwise
 */
bool pat::VerifyLogarithmicProof(
    const CValType& vchProof,
    const std::vector<CValType>& vClaimedSigs,
    const std::vector<CValType>& vClaimedPks,
    const std::vector<CValType>& vClaimedMsgs)
{
    // Step 1: Parse the proof
    LogarithmicProof proof;
    if (!ParseLogarithmicProof(vchProof, proof)) {
        return false;
    }

    uint32_t n = proof.count;

    // SECURITY (Halborn FIND-001): Belt-and-suspenders bounds check.
    // ParseLogarithmicProof already rejects invalid counts, but we enforce
    // the same invariant here as defense-in-depth per auditor recommendation.
    if (n == 0 || n > MAX_PAT_PROOF_COUNT) {
        return false;
    }

    // Step 2: Validate input sizes match proof count
    if (vClaimedSigs.size() != n ||
        vClaimedPks.size() != n ||
        vClaimedMsgs.size() != n) {
        return false;
    }

    // Step 3: Apply canonical ordering (CRITICAL FOR SECURITY)
    // Sort indices by message hash to match CreateLogarithmicProof
    // This ensures deterministic verification and prevents proof malleability
    std::vector<uint32_t> order(n);
    std::iota(order.begin(), order.end(), 0);
    std::sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
        return PatHash(vClaimedMsgs[a]) < PatHash(vClaimedMsgs[b]);
    });

    // Create sorted views of the witness data
    std::vector<CValType> sorted_sigs(n), sorted_pks(n), sorted_msgs(n);
    for (uint32_t i = 0; i < n; ++i) {
        sorted_sigs[i] = vClaimedSigs[order[i]];
        sorted_pks[i] = vClaimedPks[order[i]];
        sorted_msgs[i] = vClaimedMsgs[order[i]];
    }

    // Step 4: Validate all field sizes (all must be exactly 32 bytes)
    for (uint32_t i = 0; i < n; i++) {
        if (vClaimedSigs[i].size() != 32) {
            return false;
        }
        if (vClaimedPks[i].size() != 32) {
            return false;
        }
        if (vClaimedMsgs[i].size() != 32) {
            return false;
        }
    }

    // Step 5: Recompute and verify message root
    // NOTE: msg_root is computed from sorted (canonical) order to match Create
    uint256 computed_msg_root = ComputeMsgRoot(sorted_msgs);
    if (computed_msg_root != proof.msg_root) {
        return false;
    }

    // Step 6: Recompute and verify PK XOR binding (using sorted order)
    uint256 computed_pk_xor = ComputePkXor(sorted_pks);
    if (computed_pk_xor != proof.pk_xor) {
        return false;
    }

    // Step 7 (Halborn FIND-002): REBUILD entire Merkle tree from ALL n tuples.
    //
    // SECURITY: Previously, only leaf 0 was verified via a sibling path,
    // allowing an attacker to forge leaves 1..n-1. The verifier now
    // independently rebuilds the complete tree and compares the root.
    // No externally-supplied sibling path is needed or trusted.
    //
    // Domain separation: 0x00 prefix for leaves, 0x01 prefix for internal nodes
    // (enforced by LeafHash and NodeHash helpers).
    size_t tree_size = NextPowerOfTwo(n);
    std::vector<uint256> tree(tree_size * 2);

    // Compute ALL leaf hashes from claimed tuples
    for (uint32_t i = 0; i < n; ++i) {
        tree[tree_size + i] = LeafHash(i, sorted_sigs[i], sorted_pks[i], sorted_msgs[i]);
    }
    // SECURITY NOTE (Halborn FIND-005): Pad with last-leaf replication per spec.
    // Must match CreateLogarithmicProof padding exactly.
    const uint256& last_leaf = tree[tree_size + n - 1];
    for (size_t i = tree_size + n; i < tree_size * 2; ++i) {
        tree[i] = last_leaf;
    }
    // Build tree bottom-up
    for (size_t layer = tree_size; layer > 1; layer >>= 1) {
        for (size_t i = layer; i < layer * 2; i += 2) {
            tree[i / 2] = NodeHash(tree[i], tree[i + 1]);
        }
    }

    uint256 computed_root = tree[1];
    if (computed_root != proof.merkle_root) {
        return false;
    }

    // Step 8: All checks passed
    return true;
}

bool pat::VerifyLogarithmicProof(
    const LogarithmicProof& proof,
    const CValType& agg_pk,
    const CValType& msg_root)
{
    // PROTOTYPE VERIFIER (v1.0)
    // In a full implementation, this would verify the logarithmic proof steps
    // (Fiat-Shamir challenges, folding, etc.) to prove that 'agg_pk' is the
    // correct aggregation of keys in the Merkle tree with root 'proof.merkle_root'.

    // For v1, we enforce basic consistency checks:
    // 1. The claimed aggregate public key must match the XOR binding in the proof.
    //    (Assuming simple XOR aggregation for this prototype phase)

    // SECURITY (Halborn FIND-001): Consistency check in simple verifier.
    // Even though simple mode doesn't allocate based on count, rejecting
    // invalid counts here ensures no caller path accepts structurally malformed proofs.
    if (proof.count == 0 || proof.count > MAX_PAT_PROOF_COUNT) return false;

    if (agg_pk.size() != 32) return false;

    // Check if agg_pk matches proof.pk_xor
    // proof.pk_xor is uint256, agg_pk is CValType (vector)
    if (memcmp(agg_pk.data(), proof.pk_xor.begin(), 32) != 0) {
        return false;
    }

    // 2. The message root must be non-empty (basic sanity)
    if (msg_root.empty()) return false;

    // Check if msg_root matches proof.msg_root
    if (msg_root.size() != 32) return false;
    if (memcmp(msg_root.data(), proof.msg_root.begin(), 32) != 0) {
        return false;
    }

    // 3. Merkle root must be non-null
    if (proof.merkle_root.IsNull()) return false;

    return true;
}
