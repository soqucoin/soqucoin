#!/bin/sh
# Run every case of the unit test binary in a process of its own.
#
# WHY: the address sanitizer stops a process at its first report. One run of the
# whole binary therefore shows one report and never reaches the cases after it,
# and one run per suite still hides a second report inside the same suite. A
# process per case shows every report. The undefined-behaviour sanitizer prints
# a report and carries on, so a case can exit 0 with a report in its output:
# such a case is a failure here.
#
# The script is of use on a regular build too: a case that passes only because
# an earlier case left state behind fails when it runs alone.
#
# Usage, from src/:
#   test/run_unit_cases.sh [-j <processes>] [-o <log directory>] [-x <file>]
#     -j  cases run at one time (default 4)
#     -o  where each case's output goes, one file a case (default: a new
#         directory under ${TMPDIR:-/tmp})
#     -x  a file of case names to leave out, one "suite/case" a line; a line
#         that begins with # is a comment. Every name left out is printed.
#   TEST_BIN  the unit binary (default ./test/test_soqucoin)
#
# Exit status: 0 when every case exits 0 with no sanitizer report, 1 otherwise,
# 2 on a usage or setup error.
#
# GUARDS, so that a run which covered nothing cannot pass:
#   1. the case list comes from the binary's own --list_content;
#   2. an empty case list is a failure;
#   3. the number of cases that reported an exit status must equal the number
#      of cases started;
#   4. a name in the -x file that the binary does not list is a failure, so a
#      renamed case cannot stay left out by accident.
#
# A suite nested inside a suite is run as one process for the inner suite. The
# tree has none today.
set -u

JOBS=4
LOG_DIR=""
SKIP_FILE=""
while getopts "j:o:x:" opt; do
    case "$opt" in
        j) JOBS="$OPTARG" ;;
        o) LOG_DIR="$OPTARG" ;;
        x) SKIP_FILE="$OPTARG" ;;
        *) echo "usage: $0 [-j <processes>] [-o <log directory>] [-x <file>]" >&2; exit 2 ;;
    esac
done

TEST_BIN="${TEST_BIN:-./test/test_soqucoin}"
if [ ! -x "$TEST_BIN" ]; then
    echo "FAIL: unit binary not found or not executable: $TEST_BIN" >&2
    exit 2
fi
if [ -z "$LOG_DIR" ]; then
    LOG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/unit-cases.XXXXXX") || exit 2
fi
mkdir -p "$LOG_DIR" || exit 2
if [ -n "$(ls -A "$LOG_DIR" 2>/dev/null)" ]; then
    echo "FAIL: the log directory is not empty: $LOG_DIR" >&2
    exit 2
fi

# What a sanitizer writes when it reports: the undefined-behaviour line, and the
# header and summary lines of the address, leak, memory and thread sanitizers.
SANITIZER_REPORT='runtime error:|ERROR: [A-Za-z]+Sanitizer|SUMMARY: [A-Za-z]+Sanitizer'

ALL="$LOG_DIR/cases-listed.txt"
RUN="$LOG_DIR/cases-run.txt"
CODES="$LOG_DIR/exit-codes.txt"

"$TEST_BIN" --list_content 2>&1 \
    | awk '/^[^ ]/{s=$1} /^    [^ ]/{print s"/"$1}' | tr -d '*' > "$ALL"
n_all=$(wc -l < "$ALL" | tr -d ' ')
if [ "$n_all" -eq 0 ]; then
    echo "FAIL: '$TEST_BIN --list_content' listed no case, so this run would cover nothing." >&2
    exit 1
fi

n_skip=0
if [ -n "$SKIP_FILE" ]; then
    if [ ! -f "$SKIP_FILE" ]; then
        echo "FAIL: the -x file does not exist: $SKIP_FILE" >&2
        exit 2
    fi
    SKIP="$LOG_DIR/cases-left-out.txt"
    grep -v -E '^[[:space:]]*(#|$)' "$SKIP_FILE" > "$SKIP"
    unknown=$(grep -v -x -F -f "$ALL" "$SKIP")
    if [ -n "$unknown" ]; then
        echo "FAIL: the -x file names a case the binary does not list:" >&2
        printf '%s\n' "$unknown" >&2
        exit 1
    fi
    n_skip=$(wc -l < "$SKIP" | tr -d ' ')
    if [ "$n_skip" -gt 0 ]; then
        echo "left out by $SKIP_FILE:"
        sed 's/^/  /' "$SKIP"
        grep -v -x -F -f "$SKIP" "$ALL" > "$RUN"
    else
        cp "$ALL" "$RUN"
    fi
else
    cp "$ALL" "$RUN"
fi
n_run=$(wc -l < "$RUN" | tr -d ' ')
if [ "$n_run" -eq 0 ]; then
    echo "FAIL: every case is left out, so this run would cover nothing." >&2
    exit 1
fi

: > "$CODES"
export TEST_BIN LOG_DIR
# One process a case. The status is written by the same shell that ran the case.
RUN_ONE='c="$1"
f="$LOG_DIR/$(printf "%s" "$c" | sed "s|/|__|g; s|[^A-Za-z0-9_.-]|_|g").log"
"$TEST_BIN" --run_test="$c" > "$f" 2>&1
echo "$? $c" >> "$LOG_DIR/exit-codes.txt"'
xargs -P "$JOBS" -I{} sh -c "$RUN_ONE" _ {} < "$RUN"

n_done=$(wc -l < "$CODES" | tr -d ' ')
if [ "$n_done" -ne "$n_run" ]; then
    echo "FAIL: $n_run cases were started and $n_done reported an exit status." >&2
    exit 1
fi

failures=0
while read -r code name; do
    f="$LOG_DIR/$(printf '%s' "$name" | sed 's|/|__|g; s|[^A-Za-z0-9_.-]|_|g').log"
    if [ "$code" -ne 0 ]; then
        echo "FAIL: $name exit=$code" >&2
        grep -E "$SANITIZER_REPORT|error: in \"|fatal error" "$f" | head -n 4 >&2
        failures=$((failures + 1))
    elif grep -q -E "$SANITIZER_REPORT" "$f"; then
        echo "FAIL: $name exit=0 with a sanitizer report" >&2
        grep -E "$SANITIZER_REPORT" "$f" | head -n 3 >&2
        failures=$((failures + 1))
    fi
done < "$CODES"

if [ "$failures" -ne 0 ]; then
    echo "FAIL: $failures of $n_run cases failed or carried a sanitizer report. Logs: $LOG_DIR" >&2
    exit 1
fi
echo "PASS: $n_run cases, each in its own process, no failure and no sanitizer report ($n_all listed, $n_skip left out). Logs: $LOG_DIR"
exit 0
