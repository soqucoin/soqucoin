/**
 * PAT (Practical Attestation Technique) - Logarithmic Merkle-based Signature Aggregation
 *
 * OVERVIEW
 * ========
 * PAT allows batching of n Dilithium signatures into a compact logarithmic proof.
 * The proof consists of a Merkle tree commitment and cryptographic bindings that
 * prevent rogue-key attacks and ensure message integrity.
 *
 * A PAT proof commits a batch of n signatures to 100 bytes. Re-verifying the
 * PROOF takes the proof plus its witness data: a logarithmic Merkle path and a
 * linear set of 96-byte tuples, each three 32-byte commitments of
 * (sig, pk, msg) (see WITNESS DATA below). Because that witness contains only
 * commitments, the artifact attests the batch; it cannot verify a signature.
 * On the chain, witnesses carry the FULL signatures and every node verifies
 * each one natively.
 *
 * PROOF FORMAT (100 bytes total)
 * ================================
 * merkle_root (32 bytes): Root of Merkle tree over (idx, sig, pk, msg) tuples
 * pk_agg      (32 bytes): SHA3-256 hash of all public keys (prevents key substitution)
 * msg_root    (32 bytes): Hash of concatenated messages (defense-in-depth)
 * count       (4 bytes):  Number of signatures in batch (little-endian uint32_t)
 *
 * The proof can be verified in two modes:
 * 1. Simple Mode: Trust the proof structure, validate commitments only
 * 2. Full Mode: Verify witness data and reconstruct Merkle tree from scratch
 *
 * WITNESS DATA (Full Mode Only)
 * ==============================
 * To verify a proof cryptographically, the verifier needs:
 * - The proof itself (100 bytes)
 * - A Merkle sibling path (32 * depth bytes, where depth = ceil(log2(n)))
 * - All (sig, pk, msg) tuples (96 * n bytes, using 32-byte commitments)
 *
 * Total witness size: 100 + 32*log2(n) + 96*n bytes
 * Example for n=1024: 100 + 320 + 98,304 = ~98KB (vs ~2.5MB for full signatures)
 *
 * SECURITY PROPERTIES
 * ===================
 * 1. Unforgeability: Cannot create valid proof without possessing valid signatures
 *    - Merkle tree binding ensures all signatures are committed
 *    - Leaf hashes include signature commitments (first 32 bytes)
 *
 * 2. Rogue-key resistance: pk_agg binding prevents key substitution attacks
 *    - SHA3-256(pk_1||...||pk_n) is collision-resistant (FIND-007)
 *    - Attacker cannot change a public key without breaking pk_agg commitment
 *
 * 3. Message binding: msg_root ensures all messages are immutably committed
 *    - Defense-in-depth: even if Merkle tree is compromised, msg_root fails
 *    - Prevents message substitution or reordering attacks
 *
 * 4. Non-malleability: Canonical ordering prevents proof malleability
 *    - All inputs sorted before tree construction by the TOTAL key
 *      (PatHash(message), PatHash(pk), PatHash(sig)), with the entry's original
 *      position as a final tie-break
 *    - Same batch always produces identical proof regardless of input order
 *
 *    ⛔ The key is the full triple, not PatHash(message) alone. Keying on the
 *    message left entries over the SAME message comparing equivalent, and
 *    std::sort gives no guarantee about the relative order of equivalent
 *    elements, so identical input could produce different proofs on different
 *    standard-library implementations. That is a chain split once the block
 *    attestation makes every node recompute this from block data. Do not
 *    narrow this key. See CanonicalOrder in logarithmic.cpp and bead
 *    pat-canonical-ordering-not-total-97dz.
 *
 * PERFORMANCE
 * ===========
 * - Proof size: O(1) - always 100 bytes regardless of batch size
 * - Verification time (Simple mode): O(1) - < 4µs constant time
 * - Verification time (Full mode): O(log n) - tree traversal + hash computation
 * - Creation time: O(n log n) - sorting + tree construction
 * - Byte ledger (the public ratios measure different things):
 *   network bandwidth is UNCHANGED by PAT (full signatures cross the wire and
 *   are verified natively); retained storage after witness pruning past the
 *   finality horizon is ~25x smaller (base data + attestation kept, raw
 *   signatures discarded; the public figure of record); the Full-Mode proof
 *   verification artifact for n=1024 is ~98KB (100 + 32*ceil(log2(n)) + 96*n
 *   bytes, an internal quantity, not on-chain bytes). The 100-byte commitment alone
 *   is not the on-chain footprint; the "~9,661x" comparison was retracted.
 *
 * MERKLE TREE CONSTRUCTION
 * ========================
 * Leaf Hash (domain-separated):
 *   LeafHash(i, sig, pk, msg) = SHA3-256(
 *       i (4 bytes, little-endian) ||
 *       sig (32 bytes) ||
 *       pk (32 bytes) ||
 *       msg (32 bytes)
 *   )
 *
 * Internal Node Hash (domain-separated):
 *   NodeHash(left, right) = SHA3-256(0x01 || left || right)
 *
 * Tree Structure:
 *   - Complete binary tree (pad to next power of 2)
 *   - Padding: replicate last leaf to fill tree
 *   - Root at depth = ceil(log2(count))
 *
 * USAGE EXAMPLE
 * =============
 * // Creating a proof (off-chain or by prover)
 * std::vector<CValType> sigs, pks, msgs;
 * // ... populate with n signatures/keys/messages ...
 *
 * CValType proof_data;
 * std::vector<CValType> sibling_path;
 * bool created = pat::CreateLogarithmicProof(sigs, pks, msgs, proof_data, sibling_path);
 *
 * // Verifying (on-chain or by validator)
 * bool valid = pat::VerifyLogarithmicProof(proof_data, sibling_path, sigs, pks, msgs);
 *
 * // Simple verification (trust proof, just validate commitments)
 * pat::LogarithmicProof proof;
 * pat::ParseLogarithmicProof(proof_data, proof);
 * bool valid_simple = pat::VerifyLogarithmicProof(proof, agg_pk, msg_root);
 *
 * CONSENSUS INTEGRATION
 * =====================
 * The OP_CHECKPATAGG opcode (0xfd) validates PAT proofs in Bitcoin scripts:
 *
 * Simple Mode Stack: <proof> <agg_pk> <msg_root> OP_CHECKPATAGG
 * Full Mode Stack:   <sigs...> <pks...> <msgs...> <sibling_path> <count>
 *                    <proof> <agg_pk> <msg_root> OP_CHECKPATAGG
 *
 * REFERENCES
 * ==========
 * - Soqucoin Whitepaper Section 4.2: "Practical Attestation Technique"
 * - Test Vectors: test/pat_tests.cpp
 * - Wire Format Spec: doc/pat-specification.md
 * - Integration Tests: test/pat_script_tests.cpp
 *
 * NOTES
 * =====
 * - This implementation uses 32-byte commitments (hashes) rather than full signatures
 * - Actual Dilithium signature verification happens off-chain before proof creation
 * - The proof only commits to signatures; it doesn't verify them cryptographically
 * - For production use, pair PAT with Dilithium signature verification in the signer
 */

#include "script/script.h"
#include "uint256.h"
#include <vector>

namespace pat
{

typedef std::vector<unsigned char> CValType;

struct LogarithmicProof {
    uint256 merkle_root;
    uint256 pk_agg;   // SHA3-256(pk_1 || pk_2 || ... || pk_n) — FIND-007
    uint256 msg_root; // Root of the message tree (or commitment)
    uint32_t count;   // number of signatures
    // 100 bytes total (32+32+32+4)
};

/**
 * Maximum number of (sig, pk, msg) tuples in a single PAT proof.
 *
 * SECURITY: This constant is the consensus-level upper bound on batch size.
 * It matches the limit enforced in CreateLogarithmicProof and prevents OOM
 * from attacker-crafted proof.count values. The value 1,048,576 (2^20) is
 * generous for forward compatibility while remaining safe for allocation:
 *   - Memory: ~96 bytes/tuple × 1M = ~96 MB (safe for single-verification)
 *   - Practical limit: MAX_PROOF_BYTES_PER_TX (64KB) / 96 ≈ 680 tuples
 *
 * Halborn FIND-001 Remediation: Bounds validation on proof.count.
 */
static const uint32_t MAX_PAT_PROOF_COUNT = 1 << 20; // 1,048,576

bool ParseLogarithmicProof(const CValType& vchProof, LogarithmicProof& proofOut);

bool CreateLogarithmicProof(
    const std::vector<CValType>& vSignatures,
    const std::vector<CValType>& vPublicKeys,
    const std::vector<CValType>& vMessages,
    CValType& vchProofOut);

// Full verification: rebuilds entire Merkle tree from claimed tuples (FIND-002 fix).
// Verification is O(n) hashes — no sibling path needed.
bool VerifyLogarithmicProof(
    const CValType& vchProof,
    const std::vector<CValType>& vClaimedSigs,
    const std::vector<CValType>& vClaimedPks,
    const std::vector<CValType>& vClaimedMsgs);

bool VerifyLogarithmicProof(
    const LogarithmicProof& proof,
    const CValType& agg_pk,
    const CValType& msg_root);

} // namespace pat
