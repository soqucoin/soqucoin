#pragma once

#include <vector>

#include "crypto/binius/commitment.h"

namespace binius {

std::vector<FieldElement> fold_round(const std::vector<FieldElement>& layer,
                                     const FieldElement& challenge);

}  // namespace binius
