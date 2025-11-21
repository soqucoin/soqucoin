#ifndef BITCOIN_TEST_FUZZ_FUZZ_H
#define BITCOIN_TEST_FUZZ_FUZZ_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace fuzzer
{
struct FuzzBuffer {
    const uint8_t* data_ptr;
    size_t size_val;

    FuzzBuffer(const uint8_t* d, size_t s) : data_ptr(d), size_val(s) {}

    const uint8_t* data() const { return data_ptr; }
    size_t size() const { return size_val; }
};
} // namespace fuzzer

using FuzzTarget = std::function<void(fuzzer::FuzzBuffer&)>;

#endif // BITCOIN_TEST_FUZZ_FUZZ_H