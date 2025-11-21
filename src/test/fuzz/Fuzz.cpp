#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <test/fuzz/fuzz.h>

// Forward declarations
void latticefold_verifier(fuzzer::FuzzBuffer& buffer) noexcept;

static const std::map<std::string, FuzzTarget> g_fuzz_targets = {
    {"latticefold_verifier", latticefold_verifier},
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static const char* target_name = std::getenv("FUZZ");
    if (!target_name) {
        // Default to latticefold_verifier if not set, for easier testing
        target_name = "latticefold_verifier";
    }

    static const auto it = g_fuzz_targets.find(target_name);
    if (it == g_fuzz_targets.end()) {
        std::cerr << "Unknown fuzz target: " << target_name << std::endl;
        return 0;
    }

    fuzzer::FuzzBuffer buffer(data, size);
    it->second(buffer);
    return 0;
}

#ifndef __LIBFUZZER__
#include <vector>
int main(int argc, char** argv)
{
    // Simple driver for standalone execution
    std::vector<uint8_t> buffer;
    char buf[4096];
    while (std::cin.read(buf, sizeof(buf))) {
        buffer.insert(buffer.end(), buf, buf + std::cin.gcount());
    }
    buffer.insert(buffer.end(), buf, buf + std::cin.gcount());

    LLVMFuzzerTestOneInput(buffer.data(), buffer.size());
    return 0;
}
#endif