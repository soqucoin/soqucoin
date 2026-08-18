#!/usr/bin/env python3
"""Prune the functions a NO-INLINE build proves unreachable.

Why no-inline: with inlining on, `--gc-sections` also discards functions that were inlined
into their callers, whose source is still required. That premise broke the first attempt (241
functions deleted, link failed). With -fno-inline every call is a real call, so a discarded
section means genuinely nothing reaches it.

Precondition, checked by the caller: the no-inline build must itself pass the 64-vector gate.
It did not until bead nh6m was fixed.

Extent detection uses this codebase's uniform GNU style - name at column 0, closing brace at
column 0 - and prunes ONLY when the name resolves to exactly one file.
"""
import os, re, sys, json, bisect

GCLOG = sys.argv[1]
EX = sys.argv[2] if len(sys.argv) > 2 else "/opt/lazer-extract"
OUTJSON = sys.argv[3] if len(sys.argv) > 3 else "/tmp/prune-ni-report.json"

discarded = set()
for line in open(GCLOG, errors="ignore"):
    if "removing unused section" not in line or "lazer_static.o" not in line:
        continue
    m = re.search(r"removing unused section '\.text\.([A-Za-z_][A-Za-z0-9_.]*)'", line)
    if m:
        discarded.add(m.group(1).split(".")[0])
print(f"no-inline discard list: {len(discarded)} distinct symbols")

lazer_c = open(f"{EX}/src/lazer.c").read()
files = re.findall(r'^#include "([A-Za-z0-9._/-]+\.c)"', lazer_c, re.M)
cache = {f: open(f"{EX}/src/{f}").read().split("\n") for f in files}
print(f"live unity sources: {len(files)}")

def find_def(lines, name):
    pat = re.compile(r"^" + re.escape(name) + r"\s*\(")
    for i, ln in enumerate(lines):
        if not pat.match(ln):
            continue
        s = i
        while s > 0:
            prev = lines[s - 1].rstrip()
            if prev == "" or prev.endswith(";") or prev.endswith("}") or prev.endswith("{") or prev.startswith("#"):
                break
            s -= 1
        if s > 0 and lines[s - 1].rstrip().endswith("*/"):
            j = s - 1
            while j > 0 and "/*" not in lines[j]:
                j -= 1
            if "/*" in lines[j]:
                s = j
        k = i
        while k < len(lines) and not lines[k].startswith("{"):
            if lines[k].rstrip().endswith(";"):
                return None
            k += 1
        if k >= len(lines):
            return None
        e = k + 1
        while e < len(lines) and not lines[e].startswith("}"):
            e += 1
        if e >= len(lines):
            return None
        return (s, e)
    return None

located, ambiguous, notfound = {}, [], []
for name in sorted(discarded):
    hits = [f for f in files if find_def(cache[f], name)]
    if len(hits) == 1:
        located.setdefault(hits[0], []).append(name)
    elif len(hits) > 1:
        ambiguous.append((name, hits))
    else:
        notfound.append(name)
print(f"located in exactly one file: {sum(len(v) for v in located.values())}"
      f" · ambiguous {len(ambiguous)} · not in any .c {len(notfound)}")

total, report = 0, {}
for f, names in sorted(located.items()):
    lines = cache[f]
    spans = []
    for n in names:
        sp = find_def(lines, n)
        if sp:
            spans.append((sp[0], sp[1], n))
    spans.sort(reverse=True)
    prev_start, kept = None, []
    for s, e, n in spans:
        if prev_start is not None and e >= prev_start:
            print(f"  !! overlap skipped in {f}: {n}")
            continue
        kept.append((s, e, n)); prev_start = s
    removed = 0
    for s, e, n in kept:
        removed += e - s + 1
        lines[s:e + 1] = [f"/* option-4 prune (no-inline reachability): ld discarded .text.{n} */"]
    open(f"{EX}/src/{f}", "w").write("\n".join(lines))
    report[f] = {"functions": len(kept), "lines": removed}
    total += removed
    print(f"  {f:<22} {len(kept):>3} functions, {removed:>5} lines")
print(f"\nTOTAL LINES REMOVED THIS ROUND: {total}")
json.dump({"report": report, "total": total, "ambiguous": ambiguous, "notfound": notfound},
          open(OUTJSON, "w"), indent=2)
