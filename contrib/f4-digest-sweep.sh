#!/bin/bash
# F4 cross-build digest sweep — bead v7xm fork-risk class F4, bead 71z6.
#
# WHAT THIS IS FOR. consensus_digest_tests computes one SHA256 over everything
# the consensus rules are made of, and executes the code that derives it rather
# than only reading constants back. Its second job is to be diffed ACROSS BUILDS:
# an nh6m-class defect is invisible to functional tests because each build is
# internally self-consistent, so the only way to see it is to compare a build
# against another build.
#
# nh6m was not hypothetical. A strict-aliasing violation in AES-CTR nonce setup
# made the seed-derived statement matrix depend on the optimisation level: gcc
# -O2 and -Os derived a DIFFERENT matrix and rejected every honest proof. That is
# a chain split from a compiler flag.
#
# ⛔ THIS SWEEP WAS NOT MEANINGFUL FOR THE SCRIPT PATH UNTIL 2026-08-27. Before
# bead 71z6 the digest absorbed only witness-program dispatch and bailed on shape
# checks before running any consensus cryptography, so identical digests across
# builds proved far less than they appeared to. Re-run it now that
# AbsorbOpcodeVerdicts executes PAT and the custom opcodes.
#
# USAGE
#   bash contrib/f4-digest-sweep.sh                 # default levels
#   bash contrib/f4-digest-sweep.sh -O0 -O2 -O3     # explicit levels
#   SOQ_CONFIGURE_EXTRA="..." bash contrib/f4-digest-sweep.sh   # non-brew host
#
# Each level gets a CLEAN EXPORT of HEAD via `git archive`, built in its own
# directory. Not a VPATH build: autotools refuses an out-of-tree build against an
# already-configured source tree ("source directory already configured; run make
# distclean there first"), and running distclean in the working tree would
# destroy the developer's build. A fresh export per level is also what makes the
# levels genuinely independent of each other.
#
# ⚠️ Only committed content is swept, because that is what `git archive` exports.
# Commit before sweeping, or the sweep measures a different tree than the one in
# front of you.
#
# PASS: every level prints the same digest.
# FAIL: any difference is an nh6m-class defect and a launch blocker. Do not
#       "just re-pin". Bisect which absorbed input diverged.

set -u

SRC="$(cd "$(dirname "$0")/.." && pwd)"
LEVELS=("$@")
if [ ${#LEVELS[@]} -eq 0 ]; then
    LEVELS=(-O0 -O1 -O2 -O3 -Os)
fi

# Build directories live beside the source, never under /tmp: macOS clears /tmp
# and a half-cleared build directory produces confusing failures.
WORK="${SRC}/../soqucoin-f4-sweep"
mkdir -p "$WORK"

echo "=== F4 cross-build consensus digest sweep ==="
echo "source: $SRC"
echo "commit: $(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "levels: ${LEVELS[*]}"
if [ -n "$(git -C "$SRC" status --porcelain 2>/dev/null)" ]; then
    echo "⚠️  working tree is DIRTY — the sweep exports HEAD, not your edits"
fi
echo

declare -a RESULTS
FAILED=0
NPROC="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"

for lvl in "${LEVELS[@]}"; do
    bd="${WORK}/build${lvl}"
    echo "--- ${lvl} : exporting and building in ${bd} ---"

    # No deletion anywhere in this script. A stale directory is moved aside so a
    # previous run's artifacts can never be mistaken for this run's evidence,
    # and nothing is ever destroyed.
    if [ -e "$bd" ]; then
        mv "$bd" "${bd}.prev.$$" || { echo "    could not move stale dir aside"; FAILED=1; continue; }
        echo "    (stale build moved to ${bd}.prev.$$)"
    fi
    mkdir -p "$bd"

    (
        cd "$SRC" || exit 1
        git archive HEAD | tar -x -C "$bd" || exit 1
        cd "$bd" || exit 1
        ./autogen.sh >autogen.log 2>&1 || {
            echo "    autogen FAILED, see ${bd}/autogen.log"; exit 1; }
        # ⚠️ A fresh export does not inherit the working tree's configure
        # environment, so boost and the homebrew include/lib paths must be given
        # explicitly or configure dies on "Need at least boost 1.60.0". These
        # mirror the options recorded in the working tree's config.status.
        # Override with SOQ_CONFIGURE_EXTRA if your host differs.
        BREW_PREFIX="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"
        EXTRA="${SOQ_CONFIGURE_EXTRA:---with-incompatible-bdb --with-boost=${BREW_PREFIX}/opt/boost --without-gui}"
        # shellcheck disable=SC2086
        ./configure $EXTRA \
            CXXFLAGS="${lvl} -g" CFLAGS="${lvl} -g" \
            LDFLAGS="-L${BREW_PREFIX}/lib" CPPFLAGS="-I${BREW_PREFIX}/include" \
            >configure.log 2>&1 || {
            echo "    configure FAILED, see ${bd}/configure.log"; exit 1; }
        make -j"${NPROC}" -C src test/test_soqucoin >build.log 2>&1 || {
            echo "    build FAILED, see ${bd}/build.log"; exit 1; }
    ) || { RESULTS+=("${lvl} BUILD-FAILED"); FAILED=1; continue; }

    # A PASSING digest test prints nothing, so ask for the value directly: the
    # suite prints the computed digest on failure, and on success it equals the
    # pin. Read the pin from the exported source so a stale working-tree edit
    # cannot contaminate the comparison.
    out="$("${bd}/src/test/test_soqucoin" --run_test=consensus_digest_tests 2>&1)"
    if echo "$out" | grep -q "No errors detected"; then
        dg="$(grep -A2 'const std::string expected' \
              "${bd}/src/test/consensus_digest_tests.cpp" \
              | grep -oE '[0-9a-f]{64}' | head -1)"
    else
        dg="$(echo "$out" | grep -oE 'digest is [0-9a-f]{64}' | grep -oE '[0-9a-f]{64}' | head -1)"
    fi
    if [ -z "$dg" ]; then
        echo "    could not extract a digest from the test output"
        RESULTS+=("${lvl} NO-DIGEST"); FAILED=1; continue
    fi
    echo "    ${lvl} -> ${dg}"
    RESULTS+=("${lvl} ${dg}")
done

echo
echo "=== RESULT ==="
printf '%s\n' "${RESULTS[@]}"
echo

# ⛔ A FAILED BUILD IS NOT A PASS. The first version of this script counted
# unique result strings, and "BUILD-FAILED" is itself a single unique value, so a
# sweep in which EVERY level failed to build printed PASS. That is precisely the
# defect class this sweep exists to catch — an instrument reporting green while
# measuring nothing — so it is now guarded explicitly rather than implicitly.
if [ "$FAILED" != "0" ]; then
    echo "⛔ INCONCLUSIVE: at least one level did not produce a digest, so no"
    echo "   comparison was made. This is NOT a pass. Logs are under ${WORK}."
    exit 2
fi
if [ "${#RESULTS[@]}" -lt 2 ]; then
    echo "⛔ INCONCLUSIVE: fewer than two levels produced a digest, so there was"
    echo "   nothing to compare. This is NOT a pass."
    exit 2
fi

uniq_count=$(printf '%s\n' "${RESULTS[@]}" | awk '{print $2}' | sort -u | wc -l | tr -d ' ')
if [ "$uniq_count" = "1" ]; then
    echo "PASS: one digest across all ${#RESULTS[@]} levels. Evidence of build-independence."
else
    echo "⛔ FAIL: digests differ across optimisation levels."
    echo "   This is an nh6m-class defect and a LAUNCH BLOCKER."
    echo "   Bisect the absorbed inputs; do not re-pin the constant."
    exit 1
fi
