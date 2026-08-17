#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <test/fuzz/fuzz.h>

// Crypto fuzz targets.
//
// ⛔ THESE WERE COMPILED BUT UNREACHABLE. Until 2026-08-17 the declarations and
// the map entries below were commented out with the note "not built yet" — which
// was FALSE: all four are listed in test_fuzz_fuzz_SOURCES (Makefile.test.include)
// and their object files were being produced on every build. So the fuzzers for
// the LatticeFold verifier, Dilithium verification, the Binius commitment and PAT
// aggregation existed, compiled, and could never be selected, because
// g_fuzz_targets is the only way LLVMFuzzerTestOneInput can reach a target.
//
// That is the same defect class as the rest of this subsystem: code that is
// present, reviews as present, and never executes. `latticefold_verifier` in
// particular fuzzes the verifier family in which a zero-witness forgery was later
// proven by hand — it should have been running the whole time.
//
// ⚠️ A target added here MUST also be reachable from the seed-corpus runner
// (test/fuzz/run_seed_corpus.sh, wired into TESTS) or it is unreachable again by
// a different route.
void latticefold_verifier(fuzzer::FuzzBuffer& buffer) noexcept;
void dilithium_verify(fuzzer::FuzzBuffer& buffer) noexcept;
void binius_commit(fuzzer::FuzzBuffer& buffer) noexcept;
void pat_aggregate(fuzzer::FuzzBuffer& buffer) noexcept;

// Forward declarations for wallet fuzz targets
void pqaddress_validate(fuzzer::FuzzBuffer& buffer) noexcept;
void pqaddress_decode(fuzzer::FuzzBuffer& buffer) noexcept;
void bech32m_roundtrip(fuzzer::FuzzBuffer& buffer) noexcept;
void pqaddress_hash(fuzzer::FuzzBuffer& buffer) noexcept;
void pqaddress_network_detect(fuzzer::FuzzBuffer& buffer) noexcept;

static const std::map<std::string, FuzzTarget> g_fuzz_targets = {
    // Crypto/consensus targets
    {"latticefold_verifier", latticefold_verifier},
    {"dilithium_verify", dilithium_verify},
    {"binius_commit", binius_commit},
    {"pat_aggregate", pat_aggregate},
    // Wallet fuzz targets
    {"pqaddress_validate", pqaddress_validate},
    {"pqaddress_decode", pqaddress_decode},
    {"bech32m_roundtrip", bech32m_roundtrip},
    {"pqaddress_hash", pqaddress_hash},
    {"pqaddress_network_detect", pqaddress_network_detect},
};

//! Enumerate every registered target, so the seed-corpus runner cannot silently
//! cover a subset. Printed by `fuzz --list`.
static void ListTargets()
{
    for (const auto& kv : g_fuzz_targets) std::cout << kv.first << "\n";
}

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
    // `fuzz --list` enumerates registered targets, so the seed-corpus runner can
    // assert it covered all of them rather than a hardcoded subset that drifts.
    if (argc >= 2 && std::strcmp(argv[1], "--list") == 0) {
        ListTargets();
        return 0;
    }

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