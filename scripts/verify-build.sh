#!/bin/bash
# Soqucoin Build Verification Script
# Run after building to verify your node works correctly
#
# Usage: ./scripts/verify-build.sh [--datadir DIR]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
DATADIR=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --datadir)
            DATADIR="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Find binaries
if [ -x "./src/soqucoind" ]; then
    SOQUCOIND="./src/soqucoind"
    SOQUCOIN_CLI="./src/soqucoin-cli"
elif [ -x "./soqucoind" ]; then
    SOQUCOIND="./soqucoind"
    SOQUCOIN_CLI="./soqucoin-cli"
elif command -v soqucoind &> /dev/null; then
    SOQUCOIND="soqucoind"
    SOQUCOIN_CLI="soqucoin-cli"
else
    echo -e "${RED}ERROR: Cannot find soqucoind binary${NC}"
    echo "Run this script from the build directory or install soqucoind in PATH"
    exit 1
fi

echo ""
echo "=============================================="
echo "  Soqucoin Build Verification Script"
echo "=============================================="
echo ""
echo "Using binaries:"
echo "  soqucoind:    $SOQUCOIND"
echo "  soqucoin-cli: $SOQUCOIN_CLI"
echo ""

TESTS_PASSED=0
TESTS_FAILED=0

# Test function
run_test() {
    local name="$1"
    local cmd="$2"
    
    printf "%-50s" "Testing: $name..."
    
    if eval "$cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}PASSED${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# === Test 1: Binaries Exist ===
run_test "soqucoind binary exists" "[ -x \"$SOQUCOIND\" ]"
run_test "soqucoin-cli binary exists" "[ -x \"$SOQUCOIN_CLI\" ]"

# === Test 2: Version Output ===
run_test "soqucoind --version runs" "$SOQUCOIND --version 2>&1 | grep -qi 'soqucoin'"
run_test "soqucoin-cli --version runs" "$SOQUCOIN_CLI --version 2>&1 | grep -qi 'soqucoin'"

# === Test 3: Help Output ===
run_test "soqucoind --help works" "$SOQUCOIND --help 2>&1 | grep -q 'Options:'"

# === Test 4: Regtest Startup ===
echo ""
echo "Starting daemon in regtest mode for functional tests..."

# Create temp datadir if not specified
if [ -z "$DATADIR" ]; then
    DATADIR=$(mktemp -d)
    CLEANUP_DATADIR=true
else
    CLEANUP_DATADIR=false
fi

echo "Using datadir: $DATADIR"

# Start daemon
$SOQUCOIND -regtest -datadir="$DATADIR" -daemon -rpcuser=test -rpcpassword=test123 2>&1
sleep 5

# Wait for RPC to be ready
for i in {1..30}; do
    if $SOQUCOIN_CLI -regtest -datadir="$DATADIR" -rpcuser=test -rpcpassword=test123 \
        getblockchaininfo > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# === Test 5: RPC Works ===
run_test "RPC getblockchaininfo" \
    "$SOQUCOIN_CLI -regtest -datadir=\"$DATADIR\" -rpcuser=test -rpcpassword=test123 getblockchaininfo"

run_test "RPC getnetworkinfo" \
    "$SOQUCOIN_CLI -regtest -datadir=\"$DATADIR\" -rpcuser=test -rpcpassword=test123 getnetworkinfo"

run_test "RPC getmininginfo" \
    "$SOQUCOIN_CLI -regtest -datadir=\"$DATADIR\" -rpcuser=test -rpcpassword=test123 getmininginfo"

# === Test 6: Block Generation (Regtest Mining) ===
run_test "Generate 1 block (regtest mining)" \
    "$SOQUCOIN_CLI -regtest -datadir=\"$DATADIR\" -rpcuser=test -rpcpassword=test123 generate 1"

# === Test 7: Block Count Increased ===
BLOCKCOUNT=$($SOQUCOIN_CLI -regtest -datadir="$DATADIR" -rpcuser=test -rpcpassword=test123 \
    getblockcount 2>/dev/null || echo "0")
run_test "Block count is 1 after mining" "[ \"$BLOCKCOUNT\" -ge 1 ]"

# === Test 8: Wallet Creation (if wallet support) ===
if $SOQUCOIN_CLI -regtest -datadir="$DATADIR" -rpcuser=test -rpcpassword=test123 \
    help createwallet > /dev/null 2>&1; then
    run_test "Create new wallet" \
        "$SOQUCOIN_CLI -regtest -datadir=\"$DATADIR\" -rpcuser=test -rpcpassword=test123 createwallet \"test_wallet\""
fi

# === Test 9: Clean Shutdown ===
echo ""
echo "Shutting down daemon..."
$SOQUCOIN_CLI -regtest -datadir="$DATADIR" -rpcuser=test -rpcpassword=test123 stop 2>/dev/null || true
sleep 3

# Verify shutdown
if ! pgrep -f "soqucoind.*$DATADIR" > /dev/null 2>&1; then
    run_test "Clean daemon shutdown" "true"
else
    run_test "Clean daemon shutdown" "false"
    pkill -f "soqucoind.*$DATADIR" 2>/dev/null || true
fi

# Cleanup
if [ "$CLEANUP_DATADIR" = true ]; then
    rm -rf "$DATADIR"
fi

# === Summary ===
echo ""
echo "=============================================="
echo "  Summary"
echo "=============================================="
echo ""
echo -e "  Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "  Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  ALL TESTS PASSED - BUILD VERIFIED!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Your Soqucoin build is working correctly."
    echo "You can now run: $SOQUCOIND -daemon"
    exit 0
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  SOME TESTS FAILED - CHECK BUILD${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    echo "Review the failed tests above and check your build."
    exit 1
fi
