// Soqucoin shim replacing easyloggingpp. HEXL includes it unconditionally from
// logging.hpp, but with HEXL_DEBUG off every logging macro expands to nothing, so the
// real library (a ~9k line header) would be linked in purely to be unused. Providing
// the two symbols HEXL's header touches keeps it out of the audit scope entirely.
#pragma once
#define INITIALIZE_EASYLOGGINGPP
#define START_EASYLOGGINGPP(argc, argv) (void)0
namespace el {
class Loggers { public: static void reconfigureAllLoggers(int, const char*) {} };
}  // namespace el
