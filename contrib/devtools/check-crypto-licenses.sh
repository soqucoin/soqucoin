#!/usr/bin/env bash
# Assert every cryptographic module directory carries a LICENSE file.
#
# Catches the "a new crypto dir shipped without a license" gap — the exact way
# src/crypto/sangria/ slipped past the 2026-06 structure audit. Run in CI via
# .github/workflows/license-check.yml, or locally:  bash contrib/devtools/check-crypto-licenses.sh
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2

# Dirs whose license is provided via per-file headers (no dir-level LICENSE needed).
ALLOWLIST=("src/crypto/ctaes")

is_allow() { local d="$1" a; for a in "${ALLOWLIST[@]}"; do [ "$d" = "$a" ] && return 0; done; return 1; }

fail=0
for base in src/crypto src/pat; do
  [ -d "$base" ] || continue
  for d in "$base"/*/; do
    d="${d%/}"
    # Only directories that actually contain C/C++ source files.
    if ! find "$d" -maxdepth 1 -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \) | grep -q .; then
      continue
    fi
    if is_allow "$d"; then
      echo "ok (per-file headers): $d"
      continue
    fi
    if [ -f "$d/LICENSE" ] || [ -f "$d/COPYING" ] || [ -f "$d/LICENSE.txt" ]; then
      echo "ok: $d"
    else
      echo "MISSING LICENSE: $d"
      fail=1
    fi
  done
done

if [ "$fail" -ne 0 ]; then
  echo "FAIL: one or more crypto module directories lack a LICENSE file (see ATTRIBUTION.md)."
  exit 1
fi
echo "PASS: all crypto module directories carry a license."
