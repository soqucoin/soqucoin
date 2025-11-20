#pragma once

#include "binius/commitment.h"
#include "pat/types.h"

namespace sangria {

struct BatchProof {
    valtype proof_data;           // 1–2 kB serialized
    uint32_t batch_size;
    uint256 message_root;
};

bool VerifyBatch(const BatchProof& proof,
                 const uint256& aggregate_pk,
                 const uint256& message_root);

}  // namespace sangria
