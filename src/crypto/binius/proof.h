#pragma once

#include <vector>

#include "crypto/binius/commitment.h"

namespace binius {

struct Proof {
    Commitment commitment;
    std::vector<FieldElement> evaluations;
};

}  // namespace binius
