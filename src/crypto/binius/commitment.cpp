#include "binius/commitment.h"

#include "hash.h"

namespace binius {

namespace {

Commitment HashFieldElements(const std::vector<FieldElement>& poly)
{
    CHashWriter hasher(SER_GETHASH, 0);
    for (const auto& fe : poly) {
        hasher.write(reinterpret_cast<const char*>(fe.data()), fe.size());
    }
    return Commitment(hasher.GetHash());
}

} // namespace

Commitment commit(const std::vector<FieldElement>& poly)
{
    return HashFieldElements(poly);
}

bool verify_commitment(const Commitment& comm,
                       const std::vector<FieldElement>& openings,
                       const std::vector<uint256>& /*challenges*/)
{
    return comm == HashFieldElements(openings);
}

}  // namespace binius
