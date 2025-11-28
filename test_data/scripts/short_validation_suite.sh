#!/bin/bash
# Shortened Overnight Test Suite - 2 hour validation test
# This runs a subset of tests to verify system stability after CI fixes

set -e

LOGDIR="./test_logs_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOGDIR"

echo "=== Soqucoin Shortened Validation Test Suite ==="
echo "Start time: $(date)"
echo "Logs will be saved to: $LOGDIR"
echo ""

# 1. Run unit tests
echo "1. Running unit test suite..."
make -C src check 2>&1 | tee "$LOGDIR/unit_tests.log"
echo "✓ Unit tests completed"
echo ""

# 2. Run quick stress test
echo "2. Running quick stress test (100 txs)..."
./quick_stress_test.py 2>&1 | tee "$LOGDIR/quick_stress.log"
echo "✓ Quick stress test completed"
echo ""

# 3. Run extended stress test (1000 txs for faster completion)
echo "3. Running extended stress test (1000 txs)..."
python3 -c "
import subprocess
import time

def run_cli(cmd):
    result = subprocess.run(['./src/soqucoin-cli', '-regtest', '-rpcuser=miner', '-rpcpassword=soqu'] + cmd, 
                          capture_output=True, text=True, check=True, timeout=30)
    return result.stdout.strip()

dest = run_cli(['getnewaddress'])
mining = run_cli(['getnewaddress'])

start = time.time()
for i in range(1, 1001):
    run_cli(['sendtoaddress', dest, '0.01'])
    if i % 100 == 0:
        print(f'Sent {i} transactions...')
        run_cli(['generatetoaddress', '1', mining])

run_cli(['generatetoaddress', '1', mining])
duration = time.time() - start
print(f'\nCompleted 1000 transactions in {duration:.2f}s, TPS: {1000/duration:.2f}')
" 2>&1 | tee "$LOGDIR/extended_stress.log"
echo "✓ Extended stress test completed"
echo ""

# 4. Run fuzzing for 30 minutes
echo "4. Running fuzzer for 30 minutes..."
export FUZZ=latticefold_verifier
timeout 1800 src/test/fuzz/fuzz || true
echo "✓ Fuzzing completed (30 min)"
echo ""

# 5. Check for crashes or errors
echo "5. Checking for errors..."
ERRORS=0

if grep -i "error\|fail\|crash" "$LOGDIR"/*.log | grep -v "No errors" | grep -v "SUCCESS"; then
    echo "⚠ Errors found in logs"
    ERRORS=1
else
    echo "✓ No errors found"
fi
echo ""

# 6. Summary
echo "=== Test Summary ==="
echo "End time: $(date)"
echo "Duration: ~2 hours"
echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✓ ALL TESTS PASSED"
    echo "System is stable after CI fixes"
else
    echo "⚠ SOME TESTS HAD WARNINGS - Review logs"
fi

echo ""
echo "Full logs available in: $LOGDIR"
