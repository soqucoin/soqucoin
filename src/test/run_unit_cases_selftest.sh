#!/bin/sh
# Fixtures for run_unit_cases.sh. Each runs the script against a stand-in for the
# unit binary and names the exit status it expects. The stand-in answers
# --list_content and --run_test=<case> the way the unit binary does, with one
# fault a fixture.
#
# Run from anywhere: sh src/test/run_unit_cases_selftest.sh
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
RUNNER="$HERE/run_unit_cases.sh"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/unit-cases-selftest.XXXXXX") || exit 2

# The stand-in. FAULT selects what goes wrong; RAN records every case started.
cat > "$WORK/stub" <<'EOF'
#!/bin/sh
case "$1" in
  --list_content)
    if [ "$FAULT" = "empty-listing" ]; then exit 0; fi
    echo "alpha_tests*" >&2
    echo "    first*" >&2
    echo "    second*" >&2
    if [ "$FAULT" = "listing-stops" ]; then exit 1; fi
    echo "beta_tests*" >&2
    echo "    third*" >&2
    if [ "$FAULT" = "listing-reports" ]; then echo "x.cpp:1:1: runtime error: signed integer overflow" >&2; fi
    exit 0 ;;
  --run_test=*)
    name=${1#--run_test=}
    echo "$name" >> "$RAN"
    echo "Running 1 test case..."
    if [ "$FAULT" = "case-fails" ] && [ "$name" = "alpha_tests/second" ]; then echo 'error: in "alpha_tests/second"'; exit 201; fi
    if [ "$FAULT" = "case-reports" ] && [ "$name" = "beta_tests/third" ]; then echo "y.cpp:2:2: runtime error: left shift" >&2; exit 0; fi
    if [ "$FAULT" = "case-aborts" ] && [ "$name" = "alpha_tests/first" ]; then echo "==1==ERROR: AddressSanitizer: stack-buffer-overflow" >&2; exit 1; fi
    echo "*** No errors detected"
    exit 0 ;;
esac
exit 2
EOF
chmod +x "$WORK/stub"

failed=0
total=0
# check <label> <expected exit> <expected count of cases started> <fault> [runner options...]
check() {
    label="$1"; want="$2"; want_ran="$3"; fault="$4"; shift 4
    total=$((total + 1))
    RAN="$WORK/ran.$total"; : > "$RAN"
    FAULT="$fault" RAN="$RAN" TEST_BIN="$WORK/stub" sh "$RUNNER" -j 2 -o "$WORK/logs.$total" "$@" > "$WORK/out.$total" 2>&1
    got=$?
    got_ran=$(wc -l < "$RAN" | tr -d ' ')
    if [ "$got" -ne "$want" ] || [ "$got_ran" -ne "$want_ran" ]; then
        failed=$((failed + 1))
        echo "FAIL: $label: exit $got (expected $want), $got_ran cases started (expected $want_ran)"
        sed 's/^/    /' "$WORK/out.$total"
    fi
}

printf '# one case left out\nalpha_tests/second\n' > "$WORK/leave-out"
printf 'gamma_tests/missing\n' > "$WORK/leave-out-unknown"
printf 'alpha_tests/first\nalpha_tests/second\nbeta_tests/third\n' > "$WORK/leave-out-all"

check "every case passes"                              0 3 none
check "a case exits non-zero"                          1 3 case-fails
check "a case exits 0 with a sanitizer report"         1 3 case-reports
check "a case stopped by the address sanitizer"        1 3 case-aborts
check "the listing stops part way with a status"       1 0 listing-stops
check "the listing carries a sanitizer report"         1 0 listing-reports
check "the listing is empty"                           1 0 empty-listing
check "a case left out is not started"                 0 2 none -x "$WORK/leave-out"
check "a left-out name the binary does not list"       1 0 none -x "$WORK/leave-out-unknown"
check "every case left out"                            1 0 none -x "$WORK/leave-out-all"

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
