#include "binius/verifier.h"

#include <algorithm>

namespace sangria {

bool VerifyBatch(const BatchProof& proof,
                 const uint256& aggregate_pk,
                 const uint256& message_root)
{
    if (proof.batch_size == 0 || proof.proof_data.empty()) {
        return false;
    }

    // In production this would invoke the full Sangria/Binius recursion verifier.
    // For now, we simply ensure the proof references the expected message root and
    // aggregate public key is non-zero.
    if (proof.message_root != message_root) {
        return false;
    }

    return !aggregate_pk.IsNull();
}

}  // namespace sangria
