#pragma once

#include <array>
#include <vector>

#include "uint256.h"

namespace binius {

using FieldElement = std::array<uint8_t, 32>;  // Binius tiny field

struct Commitment : public uint256 {
    using uint256::uint256;
};

Commitment commit(const std::vector<FieldElement>& poly);

bool verify_commitment(const Commitment& comm,
                       const std::vector<FieldElement>& openings,
                       const std::vector<uint256>& challenges);

}  // namespace binius
