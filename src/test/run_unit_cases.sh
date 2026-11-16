#!/bin/sh
# Run every enabled case of the unit test binary in a process of its own.
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
# WHICH CASES: the ones `make check` runs. The binary's --list_content marks an
# enabled test unit with a star. A case without the star is disabled in the
# source; it is printed and not run, since --run_test would enable it.
#
# GUARDS, so that a run which covered less than the suite cannot pass:
#   1. the case list comes from the binary's own --list_content, and a listing
#      that exits non-zero or carries a sanitizer report is a failure;
#   2. a listing line this script cannot place is a failure (a name followed
#      by a description, a name with a space in it, a unit nested deeper than a
#      case), and a test unit at the top level with nothing under it is run by
#      its own name, so a case outside every suite is not passed over;
#   3. an empty case list is a failure;
#   4. the number of cases that reported an exit status must equal the number
#      of cases started;
#   5. each case writes to a log named by its number in the list, so two names
#      cannot share a log, and a log that is missing or unreadable is a failure;
#   6. a name in the -x file that the binary does not list as enabled is a
#      failure, so a renamed case cannot stay left out by accident.
#
# A suite nested inside a suite is refused by guard 2: its cases sit at a depth
# this script does not read. The tree has none today.
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
LOG_DIR=$(cd "$LOG_DIR" && pwd) || exit 2

# What a sanitizer writes when it reports: the undefined-behaviour line, the
# line that opens a report of the address and leak sanitizers (ERROR:) and of
# the memory and thread sanitizers (WARNING:), and the summary line of each.
SANITIZER_REPORT='runtime error:|(ERROR|WARNING): [A-Za-z]+Sanitizer|SUMMARY: [A-Za-z]+Sanitizer'

LISTING="$LOG_DIR/list-content.txt"
ENABLED="$LOG_DIR/cases-enabled.txt"
DISABLED="$LOG_DIR/cases-disabled.txt"
RUN="$LOG_DIR/cases-run.txt"
NUMBERED="$LOG_DIR/cases-numbered.txt"
CODES="$LOG_DIR/exit-codes.txt"

# The listing is kept whole and judged before a case list is made from it: a
# listing that stopped part way would give a list that passes while covering
# a part of the suite.
"$TEST_BIN" --list_content > "$LISTING" 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "FAIL: '$TEST_BIN --list_content' exit=$rc, so the case list may be partial." >&2
    tail -n 5 "$LISTING" >&2
    exit 1
fi
if grep -q -E "$SANITIZER_REPORT" "$LISTING"; then
    echo "FAIL: '$TEST_BIN --list_content' carried a sanitizer report." >&2
    grep -E "$SANITIZER_REPORT" "$LISTING" | head -n 3 >&2
    exit 1
fi

# One line a test unit: no indent for a unit at the top level, four spaces for
# a unit inside it. A top-level unit followed by indented lines is a suite and
# those lines are its cases. A top-level unit with nothing under it is run by
# its own name. Output: "E name" for an enabled case, "D name" for a disabled
# one, "? line" for a line that fits neither shape. A line with more than the
# name on it fits neither: the binary prints a description after the name of a
# unit that has one, and keeps the spaces of a template name.
awk '
function flush() { if (top != "" && kids == 0) print (topstar ? "E " : "D ") top }
/^[ \t]*$/ { next }
NF != 1 { print "? " $0; next }
/^[^ ]/ {
    flush()
    top = $1; topstar = (top ~ /\*$/); sub(/\*$/, "", top); kids = 0
    next
}
/^    [^ ]/ {
    if (top == "") { print "? " $0; next }
    name = $1; star = (name ~ /\*$/); sub(/\*$/, "", name); kids++
    print ((star && topstar) ? "E " : "D ") top "/" name
    next
}
{ print "? " $0 }
END { flush() }
' "$LISTING" > "$LOG_DIR/cases-parsed.txt"

if grep -q '^? ' "$LOG_DIR/cases-parsed.txt"; then
    echo "FAIL: the listing holds lines this script cannot place, so the case list may be partial:" >&2
    grep '^? ' "$LOG_DIR/cases-parsed.txt" | head -n 5 >&2
    exit 1
fi
sed -n 's/^E //p' "$LOG_DIR/cases-parsed.txt" > "$ENABLED"
sed -n 's/^D //p' "$LOG_DIR/cases-parsed.txt" > "$DISABLED"
n_enabled=$(wc -l < "$ENABLED" | tr -d ' ')
n_disabled=$(wc -l < "$DISABLED" | tr -d ' ')
if [ "$n_disabled" -gt 0 ]; then
    echo "disabled in the source, not run:"
    sed 's/^/  /' "$DISABLED"
fi

n_skip=0
if [ -n "$SKIP_FILE" ]; then
    if [ ! -f "$SKIP_FILE" ]; then
        echo "FAIL: the -x file does not exist: $SKIP_FILE" >&2
        exit 2
    fi
    SKIP="$LOG_DIR/cases-left-out.txt"
    grep -v -E '^[[:space:]]*(#|$)' "$SKIP_FILE" > "$SKIP"
    unknown=$(grep -v -x -F -f "$ENABLED" "$SKIP")
    if [ -n "$unknown" ]; then
        echo "FAIL: the -x file names a case the binary does not list as enabled:" >&2
        printf '%s\n' "$unknown" >&2
        exit 1
    fi
    n_skip=$(wc -l < "$SKIP" | tr -d ' ')
    if [ "$n_skip" -gt 0 ]; then
        echo "left out by $SKIP_FILE:"
        sed 's/^/  /' "$SKIP"
        grep -v -x -F -f "$SKIP" "$ENABLED" > "$RUN"
    else
        cp "$ENABLED" "$RUN"
    fi
else
    cp "$ENABLED" "$RUN"
fi
n_run=$(wc -l < "$RUN" | tr -d ' ')
if [ "$n_run" -eq 0 ]; then
    echo "FAIL: no case to run: the listing holds no enabled case, or every one is left out." >&2
    exit 1
fi

# Each case gets its number in the list. The log and the temporary directory
# are named by the number, so no two cases share either.
awk '{ printf "%05d %s\n", NR, $0 }' "$RUN" > "$NUMBERED"
: > "$CODES"
mkdir "$LOG_DIR/tmp" || exit 2
export TEST_BIN LOG_DIR
# One process a case. The status is written by the same shell that ran the case.
RUN_ONE='n=${1%% *}
c=${1#* }
mkdir "$LOG_DIR/tmp/$n" || exit 1
TMPDIR="$LOG_DIR/tmp/$n" "$TEST_BIN" --run_test="$c" > "$LOG_DIR/$n.log" 2>&1
echo "$? $n $c" >> "$LOG_DIR/exit-codes.txt"
rmdir "$LOG_DIR/tmp/$n" 2>/dev/null'
xargs -P "$JOBS" -I{} sh -c "$RUN_ONE" _ {} < "$NUMBERED"

n_done=$(wc -l < "$CODES" | tr -d ' ')
if [ "$n_done" -ne "$n_run" ]; then
    echo "FAIL: $n_run cases were started and $n_done reported an exit status." >&2
    exit 1
fi

failures=0
while read -r code n name; do
    f="$LOG_DIR/$n.log"
    grep -q -E "$SANITIZER_REPORT" "$f" 2>/dev/null
    reported=$?
    if [ "$reported" -gt 1 ]; then
        echo "FAIL: $name: its log is missing or cannot be read ($f), so its output cannot be judged" >&2
        failures=$((failures + 1))
    elif [ "$code" -ne 0 ]; then
        echo "FAIL: $name exit=$code ($f)" >&2
        grep -E "$SANITIZER_REPORT|error: in \"|fatal error" "$f" | head -n 4 >&2
        failures=$((failures + 1))
    elif [ "$reported" -eq 0 ]; then
        echo "FAIL: $name exit=0 with a sanitizer report ($f)" >&2
        grep -E "$SANITIZER_REPORT" "$f" | head -n 3 >&2
        failures=$((failures + 1))
    fi
done < "$CODES"

if [ "$failures" -ne 0 ]; then
    echo "FAIL: $failures of $n_run cases failed or carried a sanitizer report. Logs: $LOG_DIR" >&2
    exit 1
fi
echo "PASS: $n_run cases, each in its own process, no failure and no sanitizer report ($n_enabled enabled, $n_disabled disabled in the source, $n_skip left out). Logs: $LOG_DIR"
exit 0
