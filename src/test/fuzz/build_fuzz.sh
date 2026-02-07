#!/bin/bash
# Build pqwallet fuzz harness using pre-built libraries
# Usage: ./build_fuzz.sh

set -e

cd "$(dirname "$0")/../.."

# Build options
CXX="${CXX:-clang++}"
CXXFLAGS="-std=c++17 -g -O2 -Wall -I. -I/usr/include"

# Detect Homebrew OpenSSL paths (macOS)
if [ -d "/opt/homebrew/opt/openssl@3" ]; then
    CXXFLAGS="$CXXFLAGS -I/opt/homebrew/opt/openssl@3/include"
    LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
elif [ -d "/opt/homebrew/opt/openssl" ]; then
    CXXFLAGS="$CXXFLAGS -I/opt/homebrew/opt/openssl/include"
    LDFLAGS="-L/opt/homebrew/opt/openssl/lib"
else
    LDFLAGS=""
fi

# Detect Homebrew boost paths (macOS)
if [ -d "/opt/homebrew/opt/boost/lib" ]; then
    CXXFLAGS="$CXXFLAGS -I/opt/homebrew/opt/boost/include"
    LDFLAGS="$LDFLAGS -L/opt/homebrew/opt/boost/lib"
fi

# Detect Homebrew BerkeleyDB paths (macOS)
if [ -d "/opt/homebrew/opt/berkeley-db@4/lib" ]; then
    CXXFLAGS="$CXXFLAGS -I/opt/homebrew/opt/berkeley-db@4/include"
    LDFLAGS="$LDFLAGS -L/opt/homebrew/opt/berkeley-db@4/lib"
elif [ -d "/opt/homebrew/opt/berkeley-db/lib" ]; then
    CXXFLAGS="$CXXFLAGS -I/opt/homebrew/opt/berkeley-db/include"
    LDFLAGS="$LDFLAGS -L/opt/homebrew/opt/berkeley-db/lib"
fi

LIBS="-lssl -lcrypto -lboost_filesystem -lboost_thread -lboost_program_options -lboost_chrono -lpthread -ldb_cxx"

echo "Building pqwallet fuzz harness..."

# Compile fuzz framework (has main())
echo "  Compiling test/fuzz/Fuzz.cpp..."
$CXX $CXXFLAGS -c test/fuzz/Fuzz.cpp -o test/fuzz/Fuzz.o

# Compile fuzz harness
echo "  Compiling test/fuzz/pqwallet_fuzz.cpp..."
$CXX $CXXFLAGS -c test/fuzz/pqwallet_fuzz.cpp -o test/fuzz/pqwallet_fuzz.o

# Link with pre-built libraries (order matters for static linking!)
echo "  Linking with soqucoin libraries..."
$CXX $CXXFLAGS $LDFLAGS \
    -o test/fuzz/pqwallet_fuzz \
    test/fuzz/Fuzz.o \
    test/fuzz/pqwallet_fuzz.o \
    libsoqucoin_wallet.a \
    libsoqucoin_server.a \
    libsoqucoin_common.a \
    libsoqucoin_util.a \
    libsoqucoin_consensus.a \
    crypto/libsoqucoin_crypto.a \
    secp256k1/.libs/libsecp256k1.a \
    univalue/.libs/libunivalue.a \
    leveldb/libleveldb.a \
    leveldb/libmemenv.a \
    $LIBS 2>&1

if [ -f test/fuzz/pqwallet_fuzz ]; then
    echo "✓ Built test/fuzz/pqwallet_fuzz"
    ls -la test/fuzz/pqwallet_fuzz
    echo ""
    echo "Run with: ./test/fuzz/pqwallet_fuzz [input_file]"
else
    echo "✗ Build failed"
    exit 1
fi
