#!/bin/bash
# =============================================================================
# Soqucoin PQ Wallet Integration Test Suite
# =============================================================================
#
# This script tests the post-quantum wallet functionality on testnet3/stagenet.
# Run on a node that has completed initial sync.
#
# Usage:
#   ./wallet_integration_test.sh [testnet|stagenet]
#
# Prerequisites:
#   - soqucoind running with -testnet or -stagenet
#   - Wallet enabled (default)
#   - At least 0.1 SOQ balance for transaction tests
#
# Exit codes:
#   0 = All tests passed
#   1 = Test failure (see output)
#   2 = Node not running
#
# =============================================================================

set -e

# Configuration
NETWORK="${1:-testnet}"
CLI="./src/soqucoin-cli"
LOG_FILE="wallet_integration_test_${NETWORK}_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Logging function
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

pass() {
    log "${GREEN}✓ PASS${NC}: $1"
    ((TESTS_PASSED++))
}

fail() {
    log "${RED}✗ FAIL${NC}: $1"
    ((TESTS_FAILED++))
}

warn() {
    log "${YELLOW}⚠ WARN${NC}: $1"
}

# =============================================================================
# Pre-flight Checks
# =============================================================================

log "=============================================="
log "Soqucoin PQ Wallet Integration Tests"
log "Network: $NETWORK"
log "Date: $(date)"
log "=============================================="
log ""

# Check CLI exists
if [[ ! -x "$CLI" ]]; then
    log "${RED}ERROR: soqucoin-cli not found at $CLI${NC}"
    exit 2
fi

# Check node is running
if ! $CLI -$NETWORK getblockcount &>/dev/null; then
    log "${RED}ERROR: Node not running or not reachable${NC}"
    log "Start with: ./src/soqucoind -$NETWORK -daemon"
    exit 2
fi

BLOCK_HEIGHT=$($CLI -$NETWORK getblockcount)
log "Node is running. Block height: $BLOCK_HEIGHT"
log ""

# =============================================================================
# Test 1: PQ Wallet Info
# =============================================================================

log "--- Test 1: PQ Wallet Info ---"

if WALLET_INFO=$($CLI -$NETWORK pqwalletinfo 2>&1); then
    log "Response: $WALLET_INFO"
    
    # Check for expected fields
    if echo "$WALLET_INFO" | grep -q "dilithium_mode"; then
        pass "pqwalletinfo returns dilithium_mode"
    else
        fail "pqwalletinfo missing dilithium_mode"
    fi
    
    if echo "$WALLET_INFO" | grep -q "ML-DSA-44"; then
        pass "Dilithium mode is ML-DSA-44"
    else
        fail "Unexpected Dilithium mode"
    fi
else
    fail "pqwalletinfo command failed: $WALLET_INFO"
fi
log ""

# =============================================================================
# Test 2: Generate New PQ Address
# =============================================================================

log "--- Test 2: Generate New PQ Address ---"

if NEW_ADDR=$($CLI -$NETWORK pqgetnewaddress 2>&1); then
    log "Response: $NEW_ADDR"
    
    # Extract address from JSON
    ADDRESS=$(echo "$NEW_ADDR" | grep -o '"address": *"[^"]*"' | cut -d'"' -f4)
    log "Generated address: $ADDRESS"
    
    # Check address prefix
    if [[ "$NETWORK" == "testnet" ]] && [[ "$ADDRESS" == tsq1* ]]; then
        pass "Testnet address has correct prefix (tsq1)"
    elif [[ "$NETWORK" == "stagenet" ]] && [[ "$ADDRESS" == ssq1* ]]; then
        pass "Stagenet address has correct prefix (ssq1)"
    elif [[ "$NETWORK" == "mainnet" ]] && [[ "$ADDRESS" == sq1* ]]; then
        pass "Mainnet address has correct prefix (sq1)"
    else
        fail "Address prefix mismatch: $ADDRESS"
    fi
    
    # Check address length (Bech32m with 32-byte hash)
    ADDR_LEN=${#ADDRESS}
    if [[ $ADDR_LEN -ge 50 && $ADDR_LEN -le 62 ]]; then
        pass "Address length is valid ($ADDR_LEN characters)"
    else
        fail "Address length invalid: $ADDR_LEN"
    fi
else
    fail "pqgetnewaddress failed: $NEW_ADDR"
fi
log ""

# =============================================================================
# Test 3: Validate Address
# =============================================================================

log "--- Test 3: Validate Address ---"

if [[ -n "$ADDRESS" ]]; then
    if VALIDATE=$($CLI -$NETWORK pqvalidateaddress "$ADDRESS" 2>&1); then
        log "Response: $VALIDATE"
        
        # Check isvalid
        if echo "$VALIDATE" | grep -q '"isvalid": *true'; then
            pass "Address validation returns true"
        else
            fail "Address validation returned false"
        fi
        
        # Check network detection
        if echo "$VALIDATE" | grep -q "\"network\": *\"$NETWORK\""; then
            pass "Network detected correctly"
        else
            warn "Network detection mismatch"
        fi
    else
        fail "pqvalidateaddress failed: $VALIDATE"
    fi
else
    fail "No address to validate (previous test failed)"
fi
log ""

# =============================================================================
# Test 4: Fee Estimation
# =============================================================================

log "--- Test 4: Fee Estimation ---"

if FEE_EST=$($CLI -$NETWORK pqestimatefeerate 5 10 2>&1); then
    log "Response: $FEE_EST"
    
    # Check verify_cost is present
    if echo "$FEE_EST" | grep -q '"verify_cost"'; then
        pass "Fee estimation returns verify_cost"
    else
        fail "Fee estimation missing verify_cost"
    fi
    
    # Check breakdown is present
    if echo "$FEE_EST" | grep -q '"signature_cost"'; then
        pass "Fee estimation includes cost breakdown"
    else
        fail "Fee estimation missing breakdown"
    fi
    
    # Check recommendation
    if echo "$FEE_EST" | grep -q '"recommendation"'; then
        pass "Fee estimation includes recommendation"
    else
        warn "Fee estimation missing recommendation"
    fi
else
    fail "pqestimatefeerate failed: $FEE_EST"
fi
log ""

# =============================================================================
# Test 5: Invalid Address Rejection
# =============================================================================

log "--- Test 5: Invalid Address Rejection ---"

INVALID_ADDR="tsq1invalidaddress123"
if INVALID_CHECK=$($CLI -$NETWORK pqvalidateaddress "$INVALID_ADDR" 2>&1); then
    log "Response: $INVALID_CHECK"
    
    if echo "$INVALID_CHECK" | grep -q '"isvalid": *false'; then
        pass "Invalid address correctly rejected"
    else
        fail "Invalid address not rejected properly"
    fi
else
    fail "pqvalidateaddress failed on invalid input: $INVALID_CHECK"
fi
log ""

# =============================================================================
# Test 6: Multiple Address Generation (Uniqueness)
# =============================================================================

log "--- Test 6: Address Uniqueness ---"

ADDR1=$($CLI -$NETWORK pqgetnewaddress 2>&1 | grep -o '"address": *"[^"]*"' | cut -d'"' -f4)
ADDR2=$($CLI -$NETWORK pqgetnewaddress 2>&1 | grep -o '"address": *"[^"]*"' | cut -d'"' -f4)
ADDR3=$($CLI -$NETWORK pqgetnewaddress 2>&1 | grep -o '"address": *"[^"]*"' | cut -d'"' -f4)

log "Address 1: $ADDR1"
log "Address 2: $ADDR2"
log "Address 3: $ADDR3"

if [[ "$ADDR1" != "$ADDR2" && "$ADDR2" != "$ADDR3" && "$ADDR1" != "$ADDR3" ]]; then
    pass "All generated addresses are unique"
else
    fail "Duplicate addresses generated (security issue!)"
fi
log ""

# =============================================================================
# Test 7: Standard Wallet Commands Still Work
# =============================================================================

log "--- Test 7: Standard Wallet Compatibility ---"

if BALANCE=$($CLI -$NETWORK getbalance 2>&1); then
    log "Wallet balance: $BALANCE SOQ"
    pass "Standard getbalance works"
else
    fail "Standard getbalance failed: $BALANCE"
fi

if WALLET_INFO=$($CLI -$NETWORK getwalletinfo 2>&1); then
    log "Wallet info retrieved successfully"
    pass "Standard getwalletinfo works"
else
    fail "Standard getwalletinfo failed"
fi
log ""

# =============================================================================
# Test 8: Network-Specific Prefixes
# =============================================================================

log "--- Test 8: Network Prefix Verification ---"

case "$NETWORK" in
    testnet)
        EXPECTED_PREFIX="tsq1"
        ;;
    stagenet)
        EXPECTED_PREFIX="ssq1"
        ;;
    *)
        EXPECTED_PREFIX="sq1"
        ;;
esac

# Generate with explicit network parameter
if EXPLICIT_ADDR=$($CLI -$NETWORK pqgetnewaddress "$NETWORK" 2>&1); then
    ADDR=$(echo "$EXPLICIT_ADDR" | grep -o '"address": *"[^"]*"' | cut -d'"' -f4)
    if [[ "$ADDR" == ${EXPECTED_PREFIX}* ]]; then
        pass "Explicit network parameter produces correct prefix ($EXPECTED_PREFIX)"
    else
        fail "Explicit network parameter failed: got $ADDR, expected ${EXPECTED_PREFIX}..."
    fi
else
    fail "pqgetnewaddress with network param failed"
fi
log ""

# =============================================================================
# Summary
# =============================================================================

log "=============================================="
log "TEST SUMMARY"
log "=============================================="
log "Passed: $TESTS_PASSED"
log "Failed: $TESTS_FAILED"
log "Total:  $((TESTS_PASSED + TESTS_FAILED))"
log ""
log "Log saved to: $LOG_FILE"
log "=============================================="

if [[ $TESTS_FAILED -gt 0 ]]; then
    log "${RED}SOME TESTS FAILED${NC}"
    exit 1
else
    log "${GREEN}ALL TESTS PASSED${NC}"
    exit 0
fi
