#!/bin/sh
# Fixtures for run_seed_corpus.sh: its guards, each way a report can show, and a
# healthy run. Each runs the script against a stand-in for the fuzz binary and a
# corpus made here, and names the exit status it expects.
#
# Run from anywhere: sh src/test/fuzz/run_seed_corpus_selftest.sh
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
GATE="$HERE/run_seed_corpus.sh"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/seed-corpus-selftest.XXXXXX") || exit 2

# The stand-in. FAULT selects what goes wrong.
cat > "$WORK/stub" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "--list" ]; then
    if [ "$FAULT" = "no-targets" ]; then exit 0; fi
    echo "target_one"
    if [ "$FAULT" = "listing-stops" ]; then exit 134; fi
    echo "target_two"
    if [ "$FAULT" = "listing-reports" ]; then echo "l.cpp:1:1: runtime error: signed integer overflow" >&2; fi
    exit 0
fi
cat > /dev/null
if [ "$FAULT" = "run-fails" ] && [ "$FUZZ" = "target_two" ]; then exit 134; fi
if [ "$FAULT" = "run-reports" ] && [ "$FUZZ" = "target_one" ]; then
    echo "z.cpp:3:3: runtime error: applying non-zero offset 64 to null pointer" >&2
    exit 0
fi
if [ "$FAULT" = "run-warns" ] && [ "$FUZZ" = "target_two" ]; then echo "WARNING: ThreadSanitizer: data race (pid=1)" >&2; exit 0; fi
if [ "$FAULT" = "run-errors" ] && [ "$FUZZ" = "target_two" ]; then echo "==1==ERROR: LeakSanitizer: detected memory leaks" >&2; exit 0; fi
if [ "$FAULT" = "run-summary" ] && [ "$FUZZ" = "target_two" ]; then echo "SUMMARY: MemorySanitizer: use-of-uninitialized-value z.cpp:3" >&2; exit 0; fi
if [ "$FAULT" = "run-chatters" ]; then echo "an ordinary line on standard error" >&2; fi
exit 0
EOF
chmod +x "$WORK/stub"

mkdir "$WORK/corpus" "$WORK/corpus-small" "$WORK/corpus-empty"
head -c 5000 /dev/zero > "$WORK/corpus/large"
printf 'abc' > "$WORK/corpus/small"
printf 'abc' > "$WORK/corpus-small/small"

failed=0
total=0
# check <label> <expected exit> <fault> <corpus>
check() {
    total=$((total + 1))
    FAULT="$3" FUZZ_BIN="$WORK/stub" FUZZ_CORPUS="$4" sh "$GATE" > "$WORK/out.$total" 2>&1
    got=$?
    if [ "$got" -ne "$2" ]; then
        failed=$((failed + 1))
        echo "FAIL: $1: exit $got (expected $2)"
        sed 's/^/    /' "$WORK/out.$total"
    fi
}

check "every run passes"                                0 none          "$WORK/corpus"
check "an ordinary line on standard error is no report" 0 run-chatters  "$WORK/corpus"
check "a run exits non-zero"                            1 run-fails     "$WORK/corpus"
check "a run exits 0 with a sanitizer report"           1 run-reports   "$WORK/corpus"
check "a run exits 0 with a thread sanitizer warning"   1 run-warns     "$WORK/corpus"
check "a run exits 0 with a leak sanitizer error"       1 run-errors    "$WORK/corpus"
check "a run exits 0 with a summary line alone"         1 run-summary   "$WORK/corpus"
check "the listing stops part way with a status"        1 listing-stops   "$WORK/corpus"
check "the listing carries a sanitizer report"          1 listing-reports "$WORK/corpus"
check "the binary lists no target"                      1 no-targets    "$WORK/corpus"
check "the corpus is empty"                             1 none          "$WORK/corpus-empty"
check "the corpus holds no large input"                 1 none          "$WORK/corpus-small"

echo "$((total - failed))/$total fixtures behave"
rm -r "$WORK"
[ "$failed" -eq 0 ]
