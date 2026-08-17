#!/bin/sh
# Run every registered fuzz target over the seed corpus once, deterministically.
#
# =============================================================================
# WHY THIS EXISTS
#
# Until 2026-08-17 this project built TWO fuzz binaries on every `make check` and
# ran NEITHER. `TESTS` contained only test/test_soqucoin; test/fuzz/fuzz and
# test/test_soqucoin_fuzzy were noinst_PROGRAMS, so they were compiled and
# discarded. On top of that, the four crypto targets (latticefold_verifier,
# dilithium_verify, binius_commit, pat_aggregate) were commented out of the
# dispatch table in Fuzz.cpp behind a stale "not built yet" note, so even running
# the binary by hand could not reach them.
#
# The net effect was that the fuzzer for the LatticeFold verifier family -- the
# family in which a zero-witness forgery was later proven by hand -- had never
# executed a single input.
#
# This is NOT a fuzzing campaign. It is a smoke gate: it proves every registered
# target still links, runs, and survives the seed corpus. Actual coverage needs a
# per-target structured corpus and a real fuzzing engine, which is a follow-up.
# Do not mistake a green run here for "the verifiers are fuzzed".
#
# ⛔ THREE ANTI-VACUOUS GUARDS, and they are the point of the script. A test that
# silently covers nothing passes CI forever and reports success. So:
#   1. the target list comes from `fuzz --list`, never a hardcoded list here, so
#      a newly registered target cannot be silently skipped;
#   2. an empty corpus or an empty target list is a FAILURE, not a pass;
#   3. THE CORPUS MUST CONTAIN A LARGE INPUT. This guard exists because the first
#      version of this gate DID pass vacuously. Every seed was 32 bytes, and the
#      crypto targets bail out early on short input:
#           latticefold_verifier  needs 168 B
#           pat_aggregate         needs 136 B
#           dilithium_verify      needs 3732 B (ML-DSA-44 pk 1312 + sig 2420)
#           binius_commit         needs 32 B
#      so "90 runs, no crashes" actually exercised ONE of the four crypto
#      targets and returned immediately from the other three -- including the
#      LatticeFold one, which is the whole reason this gate was written. If
#      someone later prunes the corpus back to small inputs, this guard fails
#      loudly instead of quietly reporting success again.
# =============================================================================
set -u

SRCDIR="${srcdir:-.}"
FUZZ_BIN="${FUZZ_BIN:-./test/fuzz/fuzz}"
CORPUS="${FUZZ_CORPUS:-${SRCDIR}/test/fuzz/corpus}"

if [ ! -x "$FUZZ_BIN" ]; then
    echo "FAIL: fuzz binary not found or not executable: $FUZZ_BIN" >&2
    exit 1
fi

if [ ! -d "$CORPUS" ]; then
    echo "FAIL: seed corpus directory not found: $CORPUS" >&2
    exit 1
fi

TARGETS=$("$FUZZ_BIN" --list 2>/dev/null)
if [ -z "$TARGETS" ]; then
    echo "FAIL: '$FUZZ_BIN --list' returned no targets. Either --list is broken or" >&2
    echo "      g_fuzz_targets is empty; both mean this gate covers nothing." >&2
    exit 1
fi

n_seeds=$(find "$CORPUS" -type f | wc -l | tr -d ' ')
if [ "$n_seeds" -eq 0 ]; then
    echo "FAIL: seed corpus '$CORPUS' is empty, so this gate would pass vacuously." >&2
    exit 1
fi

# Guard 3: the corpus must contain an input large enough that no registered
# target can bail out on size alone. 4096 covers the largest known minimum
# (dilithium_verify, 3732 bytes). See the header for why this guard exists.
MIN_LARGE_SEED=4096
largest=0
for seed in $(find "$CORPUS" -type f); do
    sz=$(wc -c < "$seed" | tr -d ' ')
    [ "$sz" -gt "$largest" ] && largest=$sz
done
if [ "$largest" -lt "$MIN_LARGE_SEED" ]; then
    echo "FAIL: largest seed in '$CORPUS' is $largest bytes; need >= $MIN_LARGE_SEED." >&2
    echo "      The crypto fuzz targets return immediately on short input, so this" >&2
    echo "      gate would run them and cover NOTHING while reporting success." >&2
    echo "      Minimums: dilithium_verify 3732, latticefold_verifier 168," >&2
    echo "                pat_aggregate 136, binius_commit 32." >&2
    exit 1
fi

n_targets=$(echo "$TARGETS" | wc -l | tr -d ' ')
echo "fuzz seed-corpus gate: $n_targets targets x $n_seeds seeds (largest ${largest}B)"

failures=0
runs=0
for target in $TARGETS; do
    for seed in $(find "$CORPUS" -type f); do
        runs=$((runs + 1))
        # Capture the status directly. `if ! cmd; then rc=$?` reports the status of
        # the negation, not the command, so it always printed exit=0 even for a
        # SIGABRT. Assign first, test second.
        FUZZ="$target" "$FUZZ_BIN" < "$seed" > /dev/null 2>&1
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "FAIL: target=$target seed=$(basename "$seed") exit=$rc" >&2
            failures=$((failures + 1))
        fi
    done
done

# A run count that does not match the product means the loops silently skipped
# work -- treat that as a failure rather than reporting a partial pass as green.
expected=$((n_targets * n_seeds))
if [ "$runs" -ne "$expected" ]; then
    echo "FAIL: executed $runs runs, expected $expected. Coverage was skipped." >&2
    exit 1
fi

if [ "$failures" -ne 0 ]; then
    echo "FAIL: $failures of $runs fuzz runs crashed or exited non-zero." >&2
    exit 1
fi

echo "PASS: $runs fuzz runs, no crashes ($n_targets targets, $n_seeds seeds)"
exit 0
