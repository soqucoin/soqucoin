#!/bin/sh
# Fixtures for run_unit_cases.sh. Each runs the script against a stand-in for the
# unit binary and names the exit status it expects, and where the count is fixed
# the number of cases it expects to be started. The stand-in answers
# --list_content and --run_test=<case> the way the unit binary does, with one
# fault a fixture.
#
# Run from anywhere: sh src/test/run_unit_cases_selftest.sh
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
RUNNER="$HERE/run_unit_cases.sh"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/unit-cases-selftest.XXXXXX") || exit 2

# The stand-in. FAULT selects what goes wrong; RAN records every case started
# and RAN.tmp the temporary directory each was given.
# Its listing: two suites, one case disabled in the second, one case outside
# every suite, and a case whose name begins with another case's name.
cat > "$WORK/stub" <<'EOF'
#!/bin/sh
case "$1" in
  --list_content)
    if [ "$FAULT" = "empty-listing" ]; then exit 0; fi
    echo "alpha_tests*" >&2
    echo "    first*" >&2
    echo "    first_more*" >&2
    if [ "$FAULT" = "listing-spaced-name" ]; then echo "    sized<unsigned int>*" >&2; fi
    echo "    second*" >&2
    if [ "$FAULT" = "listing-stops" ]; then exit 1; fi
    if [ "$FAULT" = "listing-described-suite" ]; then echo "beta_tests*: the second suite" >&2; else echo "beta_tests*" >&2; fi
    if [ "$FAULT" = "listing-described-case" ]; then echo "    third*: checks the third thing" >&2; else echo "    third*" >&2; fi
    echo "    legacy" >&2
    if [ "$FAULT" = "listing-deeper" ]; then echo "        nested*" >&2; fi
    if [ "$FAULT" = "collide-reports" ]; then
        echo "gamma_tests*" >&2
        echo "    x__y*" >&2
        echo "gamma_tests__x*" >&2
        echo "    y*" >&2
    fi
    echo "solo_case*" >&2
    if [ "$FAULT" = "listing-reports" ]; then echo "x.cpp:1:1: runtime error: signed integer overflow" >&2; fi
    exit 0 ;;
  --run_test=*)
    name=${1#--run_test=}
    echo "$name" >> "$RAN"
    echo "${TMPDIR:-}" >> "$RAN.tmp"
    echo "Running 1 test case..."
    if [ "$FAULT" = "case-fails" ] && [ "$name" = "alpha_tests/second" ]; then echo 'error: in "alpha_tests/second"'; exit 201; fi
    if [ "$FAULT" = "case-reports" ] && [ "$name" = "beta_tests/third" ]; then echo "y.cpp:2:2: runtime error: left shift" >&2; exit 0; fi
    if [ "$FAULT" = "case-warns" ] && [ "$name" = "beta_tests/third" ]; then echo "WARNING: ThreadSanitizer: data race (pid=1)" >&2; exit 0; fi
    if [ "$FAULT" = "case-summary" ] && [ "$name" = "beta_tests/third" ]; then echo "SUMMARY: MemorySanitizer: use-of-uninitialized-value z.cpp:3" >&2; exit 0; fi
    if [ "$FAULT" = "case-aborts" ] && [ "$name" = "alpha_tests/first" ]; then echo "==1==ERROR: AddressSanitizer: stack-buffer-overflow" >&2; exit 1; fi
    if [ "$FAULT" = "case-errors-exit-0" ] && [ "$name" = "alpha_tests/first" ]; then echo "==1==ERROR: LeakSanitizer: detected memory leaks" >&2; exit 0; fi
    if [ "$FAULT" = "solo-reports" ] && [ "$name" = "solo_case" ]; then echo "s.cpp:4:4: runtime error: signed integer overflow" >&2; exit 0; fi
    if [ "$FAULT" = "collide-reports" ] && [ "$name" = "gamma_tests/x__y" ]; then echo "c.cpp:5:5: runtime error: signed integer overflow" >&2; exit 0; fi
    if [ "$FAULT" = "shell-dies" ] && [ "$name" = "alpha_tests/second" ]; then kill -9 "$PPID"; sleep 1; fi
    if [ "$FAULT" = "log-removed" ] && [ "$name" = "solo_case" ]; then rm -f "$LOG_DIR"/0*.log; fi
    echo "*** No errors detected"
    exit 0 ;;
esac
exit 2
EOF
chmod +x "$WORK/stub"

failed=0
total=0
# check <label> <expected exit> <expected count of cases started, or - > <fault> [runner options...]
check() {
    label="$1"; want="$2"; want_ran="$3"; fault="$4"; shift 4
    total=$((total + 1))
    RAN="$WORK/ran.$total"; : > "$RAN"; : > "$RAN.tmp"
    FAULT="$fault" RAN="$RAN" TEST_BIN="$WORK/stub" sh "$RUNNER" -j 2 -o "$WORK/logs.$total" "$@" > "$WORK/out.$total" 2>&1
    got=$?
    got_ran=$(wc -l < "$RAN" | tr -d ' ')
    if [ "$got" -ne "$want" ] || { [ "$want_ran" != "-" ] && [ "$got_ran" -ne "$want_ran" ]; }; then
        failed=$((failed + 1))
        echo "FAIL: $label: exit $got (expected $want), $got_ran cases started (expected $want_ran)"
        sed 's/^/    /' "$WORK/out.$total"
    fi
}

printf '# one case left out\nalpha_tests/first\n' > "$WORK/leave-out"
printf 'gamma_tests/missing\n' > "$WORK/leave-out-unknown"
printf 'beta_tests/legacy\n' > "$WORK/leave-out-disabled"
printf 'alpha_tests/first\nalpha_tests/first_more\nalpha_tests/second\nbeta_tests/third\nsolo_case\n' > "$WORK/leave-out-all"

# Five cases are enabled: three in alpha_tests, one in beta_tests, and solo_case.
check "every enabled case passes, the disabled one is not started"  0 5 none
HEALTHY="$WORK/ran.$total"; HEALTHY_LOGS=$(cd "$WORK/logs.$total" && pwd)
check "a case exits non-zero"                                       1 5 case-fails
check "a case exits 0 with an undefined-behaviour report"           1 5 case-reports
check "a case exits 0 with a thread sanitizer warning"              1 5 case-warns
check "a case exits 0 with a summary line alone"                    1 5 case-summary
check "a case stopped by the address sanitizer"                     1 5 case-aborts
check "a case exits 0 with a leak sanitizer error"                  1 5 case-errors-exit-0
check "a case outside every suite is run, and its report counts"    1 5 solo-reports
check "two names that differ only where a slash stands"             1 7 collide-reports
check "the listing stops part way with a status"                    1 0 listing-stops
check "the listing carries a sanitizer report"                      1 0 listing-reports
LISTING_REPORT_OUT="$WORK/out.$total"
check "the listing is empty"                                        1 0 empty-listing
check "the listing holds a line deeper than a case"                 1 0 listing-deeper
check "the listing holds a case with a description after its name"  1 0 listing-described-case
check "the listing holds a suite with a description after its name" 1 0 listing-described-suite
check "the listing holds a name with a space in it"                 1 0 listing-spaced-name
check "a case whose shell dies before it reports its status"        1 - shell-dies
check "a log that is gone when the run is judged"                   1 - log-removed
check "a case left out is not started"                              0 4 none -x "$WORK/leave-out"
LEFT_OUT="$WORK/ran.$total"
check "a left-out name the binary does not list"                    1 0 none -x "$WORK/leave-out-unknown"
check "a left-out name the binary lists as disabled"                1 0 none -x "$WORK/leave-out-disabled"
check "every case left out"                                         1 0 none -x "$WORK/leave-out-all"

# Leaving out alpha_tests/first leaves alpha_tests/first_more in: a name is matched whole.
total=$((total + 1))
if ! grep -q -x 'alpha_tests/first_more' "$LEFT_OUT" || grep -q -x 'alpha_tests/first' "$LEFT_OUT"; then
    failed=$((failed + 1)); echo "FAIL: a left-out name is matched whole"
fi

# A report in the listing is named as a report, and so is told from a line that cannot be placed.
total=$((total + 1))
if ! grep -q 'carried a sanitizer report' "$LISTING_REPORT_OUT"; then
    failed=$((failed + 1)); echo "FAIL: a report in the listing is named as one"
fi

# The disabled case is never started, in any fixture.
total=$((total + 1))
if cat "$WORK"/ran.[0-9]* | grep -q -x 'beta_tests/legacy'; then
    failed=$((failed + 1)); echo "FAIL: the case disabled in the listing was started"
fi

# Each case of the healthy run was given a temporary directory of its own, under the log directory.
total=$((total + 1))
n_tmp=$(sort -u "$HEALTHY.tmp" | wc -l | tr -d ' ')
n_under=$(grep -c "^$HEALTHY_LOGS/tmp/" "$HEALTHY.tmp")
if [ "$n_tmp" -ne 5 ] || [ "$n_under" -ne 5 ]; then
    failed=$((failed + 1)); echo "FAIL: a temporary directory a case: $n_tmp distinct, $n_under under the log directory"
fi

# A log directory with something in it is refused before any case starts.
total=$((total + 1))
mkdir -p "$WORK/used" && : > "$WORK/used/earlier.log"
RAN="$WORK/ran.used"; : > "$RAN"
FAULT=none RAN="$RAN" TEST_BIN="$WORK/stub" sh "$RUNNER" -o "$WORK/used" > "$WORK/out.used" 2>&1
if [ "$?" -ne 2 ] || [ -s "$RAN" ]; then
    failed=$((failed + 1)); echo "FAIL: a log directory that is not empty"
fi

echo "$((total - failed))/$total fixtures behave"
rm -r "$WORK"
[ "$failed" -eq 0 ]
