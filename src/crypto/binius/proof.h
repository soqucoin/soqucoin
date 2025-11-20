#pragma once

#include <vector>

#include "binius/commitment.h"

namespace binius {

struct Proof {
    Commitment commitment;
    std::vector<FieldElement> evaluations;
};

}  // namespace binius
