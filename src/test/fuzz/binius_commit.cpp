#include <algorithm>
#include <crypto/binius/commitment.h>
#include <cstdint>
#include <cstring>
#include <test/fuzz/fuzz.h>
#include <vector>

void binius_commit(fuzzer::FuzzBuffer& buffer) noexcept
{
    if (buffer.size() < 32) return;

    const uint8_t* data = buffer.data();
    size_t size = buffer.size();

    // Interpret input as vector of FieldElement (32 bytes each)
    std::vector<binius::FieldElement> elements;
    size_t num_elements = size / 32;
    elements.reserve(num_elements);

    for (size_t i = 0; i < num_elements; ++i) {
        binius::FieldElement elem;
        std::memcpy(elem.data(), data + i * 32, 32);
        elements.push_back(elem);
    }

    if (elements.empty()) return;

    // Commit
    binius::Commitment comm = binius::commit(elements);

    // Verify (self-test with dummy challenges/openings for fuzzing stability check)
    // In a real test we'd generate valid openings. Here we just call verify to ensure no crash on bad inputs if possible,
    // but verify_commitment expects valid openings matching challenges.
    // Given the API: bool verify_commitment(comm, openings, challenges)
    // We can try to pass empty or random vectors to check for robustness.

    std::vector<binius::FieldElement> openings; // Empty
    std::vector<uint256> challenges;            // Empty

    (void)binius::verify_commitment(comm, openings, challenges);
}
