#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <test/fuzz/fuzz.h>

// Forward declarations for existing fuzz targets (commented out - not built yet)
// void latticefold_verifier(fuzzer::FuzzBuffer& buffer) noexcept;
// void dilithium_verify(fuzzer::FuzzBuffer& buffer) noexcept;

// Forward declarations for wallet fuzz targets
void pqaddress_validate(fuzzer::FuzzBuffer& buffer) noexcept;
void pqaddress_decode(fuzzer::FuzzBuffer& buffer) noexcept;
void bech32m_roundtrip(fuzzer::FuzzBuffer& buffer) noexcept;
void pqaddress_hash(fuzzer::FuzzBuffer& buffer) noexcept;
void pqaddress_network_detect(fuzzer::FuzzBuffer& buffer) noexcept;

static const std::map<std::string, FuzzTarget> g_fuzz_targets = {
    // TODO: Enable when crypto fuzz targets are built
    // {"latticefold_verifier", latticefold_verifier},
    // {"dilithium_verify", dilithium_verify},
    // Wallet fuzz targets
    {"pqaddress_validate", pqaddress_validate},
    {"pqaddress_decode", pqaddress_decode},
    {"bech32m_roundtrip", bech32m_roundtrip},
    {"pqaddress_hash", pqaddress_hash},
    {"pqaddress_network_detect", pqaddress_network_detect},
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static const char* target_name = std::getenv("FUZZ");
    if (!target_name) {
        // Default to pqaddress_validate if not set
        target_name = "pqaddress_validate";
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