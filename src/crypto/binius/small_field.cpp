#include <crypto/binius/small_field.h>

namespace binius
{

BinaryField64b SmallField::EvaluateMultilinear(
    const std::vector<BinaryField64b>& evaluations,
    const std::vector<BinaryField64b>& point)
{
    // Standard O(n) multilinear evaluation
    // evaluations size must be 2^n where n = point.size()

    size_t n = point.size();
    if (evaluations.size() != (1ULL << n)) {
        return {0}; // Error
    }

    std::vector<BinaryField64b> current_layer = evaluations;

    for (size_t i = 0; i < n; ++i) {
        BinaryField64b x = point[i];
        size_t layer_size = current_layer.size() / 2;
        for (size_t j = 0; j < layer_size; ++j) {
            // val = (1-x)*left + x*right
            //     = left + x*(left + right)  in characteristic 2
            BinaryField64b left = current_layer[2 * j];
            BinaryField64b right = current_layer[2 * j + 1];

            BinaryField64b sum = PackedField::Add(left, right);
            BinaryField64b term = PackedField::Mul(sum, x);
            current_layer[j] = PackedField::Add(left, term);
        }
        current_layer.resize(layer_size);
    }

    return current_layer[0];
}

} // namespace binius
