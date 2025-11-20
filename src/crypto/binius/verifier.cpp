#include "binius/verifier.h"

#include <algorithm>

#include "binius/commitment.h"
#include "binius/proof.h"
#include "hash.h"
#include "serialize.h"

namespace sangria {
namespace {

binius::FieldElement FieldFromUint256(const uint256& value)
{
    binius::FieldElement fe{};
    std::copy(value.begin(), value.end(), fe.begin());
    return fe;
}

uint256 TranscriptDigest(const BatchProof& proof, const uint256& aggregate_pk)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << aggregate_pk;
    hasher << proof.batch_size;
    hasher << proof.message_root;
    hasher.write(reinterpret_cast<const char*>(proof.proof_data.data()),
                 proof.proof_data.size());
    return hasher.GetHash();
}

}  // namespace

bool VerifyBatch(const BatchProof& proof,
                 const uint256& aggregate_pk,
                 const uint256& message_root)
{
    if (proof.batch_size == 0 || proof.proof_data.empty()) {
        return false;
    }

    if (aggregate_pk.IsNull() || proof.message_root != message_root) {
        return false;
    }

    const uint256 transcript = TranscriptDigest(proof, aggregate_pk);

    std::vector<binius::FieldElement> openings;
    openings.emplace_back(FieldFromUint256(transcript));
    openings.emplace_back(FieldFromUint256(message_root));

    std::vector<uint256> challenges = {aggregate_pk, message_root};
    const binius::Commitment commitment = binius::commit(openings);

    return binius::verify_commitment(commitment, openings, challenges);
}

}  // namespace sangria
