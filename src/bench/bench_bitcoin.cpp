// Copyright (c) 2015-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h" // for BenchRunner
#include "random.h"
#include "util.h" // for SetupEnvironment, fPrintToDebugLog

int main(int argc, char** argv)
{
    RandomInit();
    // Post-quantum: ECC_Start removed
    SetupEnvironment();
    fPrintToDebugLog = false; // don't want to write to debug.log file

    std::string filter = "";
    if (argc > 1) filter = argv[1];
    benchmark::BenchRunner::RunAll(1.0, filter);

    // Post-quantum: ECC_Stop removed
}
