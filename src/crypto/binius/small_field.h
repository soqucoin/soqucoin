#pragma once

#include <crypto/binius/packed_field.h>
#include <vector>

namespace binius
{

class SmallField
{
public:
    // Multilinear evaluation
    // eval(x_1, ..., x_n) where poly is given by evaluations on the boolean hypercube
    static BinaryField64b EvaluateMultilinear(
        const std::vector<BinaryField64b>& evaluations,
        const std::vector<BinaryField64b>& point);

    // Extension field helpers
    // ...
};

} // namespace binius
