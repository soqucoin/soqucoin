#!/bin/bash
# Build pqwallet fuzz harness using pre-built libraries
# Usage: ./build_fuzz.sh

set -e

cd "$(dirname "$0")/../.."

# Build options
CXX="${CXX:-g++}"
CXXFLAGS="-std=c++17 -g -O2 -Wall -I. -I/usr/include"
LDFLAGS=""
LIBS="-lssl -lcrypto -lboost_filesystem -lboost_system -lboost_thread -lboost_program_options -lboost_chrono -lpthread -ldl"

echo "Building pqwallet fuzz harness..."

# Compile fuzz harness
echo "  Compiling test/fuzz/pqwallet_fuzz.cpp..."
$CXX $CXXFLAGS -c test/fuzz/pqwallet_fuzz.cpp -o test/fuzz/pqwallet_fuzz.o

# Link with pre-built libraries (order matters for static linking!)
echo "  Linking with soqucoin libraries..."
$CXX $CXXFLAGS $LDFLAGS \
    -o test/fuzz/pqwallet_fuzz \
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
else
    echo "✗ Build failed"
    exit 1
fi
