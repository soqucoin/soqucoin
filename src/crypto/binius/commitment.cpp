#include "binius/commitment.h"

#include <algorithm>

#include "hash.h"

namespace binius {
namespace {

Commitment HashFieldElements(const std::vector<FieldElement>& poly)
{
    CHashWriter hasher(SER_GETHASH, 0);
    for (const auto& fe : poly) {
        hasher.write(reinterpret_cast<const char*>(fe.data()), fe.size());
    }
    return hasher.GetHash();
}

FieldElement FieldFromUint256(const uint256& value)
{
    FieldElement fe{};
    std::copy(value.begin(), value.end(), fe.begin());
    return fe;
}

}  // namespace

Commitment commit(const std::vector<FieldElement>& poly)
{
    return HashFieldElements(poly);
}

bool verify_commitment(const Commitment& comm,
                       const std::vector<FieldElement>& openings,
                       const std::vector<uint256>& challenges)
{
    std::vector<FieldElement> transcript = openings;
    transcript.reserve(openings.size() + challenges.size());
    for (const auto& challenge : challenges) {
        transcript.emplace_back(FieldFromUint256(challenge));
    }

    return comm == HashFieldElements(transcript);
}

}  // namespace binius
