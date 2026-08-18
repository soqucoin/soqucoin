#!/usr/bin/env python3
"""⛔⛔ THIS TOOL IS BASED ON A WRONG PREMISE. KEPT AS A RECORD OF THE TRAP, DO NOT RUN AS-IS.

It deletes function bodies that `--gc-sections` reported as discarded. That criterion is
WRONG at -O2 and above: the compiler INLINES those functions into their callers, so the
standalone .text.<name> section becomes unused and the linker discards it WHILE THE CODE
LIVES ON INSIDE THE CALLERS. Deleting the source therefore removes code that is genuinely
required, and the link fails with undefined references to exactly those symbols
(coder_enc_urandom2, intvec_mod, poly_addmul, lin_verifier_set_statement_A, ...).

Run on the extracted tree 2026-08-17 it deleted 241 functions / 6,066 lines and broke the
build; the tree was restored from backup.

To make this correct, the discard list must come from a build with inlining DISABLED
(-fno-inline -fno-inline-functions -fno-inline-small-functions -fno-inline-functions-called-once).
⚠️ But that path is currently blocked by bead statement-matrix-opt-level-divergence-nh6m: the
no-inline build derives a DIFFERENT statement matrix and fails the gate, so it cannot yet be
used as a reachability oracle. Root-cause that first.

Original (wrong) rationale follows.

Authority: --gc-sections. If ld discarded .text.<name>, then nothing retained references it,
so removing the source cannot break a retained caller. The gate is still the final oracle.

Extent detection relies on this codebase's GNU style, which is uniform:
    static void
    name (args)
    {
      ...
    }
i.e. the name starts at column 0 and the closing brace is at column 0. A function is pruned
ONLY if its name is found at column 0 in exactly one file; ambiguous or absent names are
skipped and reported rather than guessed at.
"""
import os, re, sys, json

EX = "/opt/lazer-extract"
GCLOG = "/tmp/gc.log"

# 1. what did the linker discard, out of lazer_static.o?
discarded = set()
for line in open(GCLOG, errors="ignore"):
    if "removing unused section" not in line or "lazer_static.o" not in line:
        continue
    m = re.search(r"removing unused section '\.text\.([A-Za-z_][A-Za-z0-9_.]*)'", line)
    if m:
        name = m.group(1)
        # gcc suffixes clones: foo.constprop.0, foo.isra.0 -> the source symbol is foo
        base = name.split(".")[0]
        discarded.add(base)
print(f"linker discarded {len(discarded)} distinct .text symbols from lazer_static.o")

# 2. the live unity sources
lazer_c = open(f"{EX}/src/lazer.c").read()
files = [m for m in re.findall(r'^#include "([A-Za-z0-9._/-]+\.c)"', lazer_c, re.M)]
print(f"live unity sources: {len(files)}")

def find_def(lines, name):
    """Return (start, end) line indices inclusive for a function definition, or None."""
    pat = re.compile(r"^" + re.escape(name) + r"\s*\(")
    for i, ln in enumerate(lines):
        if not pat.match(ln):
            continue
        # walk back over the return type / qualifiers, and any attached comment block
        s = i
        while s > 0:
            prev = lines[s - 1].rstrip()
            if prev == "":
                break
            # a declaration-ish line: no statement terminator, not a closing brace
            if prev.endswith(";") or prev.endswith("}") or prev.endswith("{"):
                break
            if prev.startswith("#"):
                break
            s -= 1
        # attached block comment immediately above
        if s > 0 and lines[s - 1].rstrip().endswith("*/"):
            j = s - 1
            while j > 0 and "/*" not in lines[j]:
                j -= 1
            if "/*" in lines[j]:
                s = j
        # forward to the opening brace, then to the matching '}' at column 0
        k = i
        while k < len(lines) and not lines[k].startswith("{"):
            if lines[k].rstrip().endswith(";"):
                return None          # a prototype, not a definition
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

# 3. locate each discarded symbol in exactly one file
located, ambiguous, notfound = {}, [], []
cache = {f: open(f"{EX}/src/{f}").read().split("\n") for f in files}
for name in sorted(discarded):
    hits = []
    for f in files:
        if find_def(cache[f], name):
            hits.append(f)
    if len(hits) == 1:
        located.setdefault(hits[0], []).append(name)
    elif len(hits) > 1:
        ambiguous.append((name, hits))
    else:
        notfound.append(name)

print(f"located in exactly one file: {sum(len(v) for v in located.values())}")
print(f"ambiguous (skipped):         {len(ambiguous)}")
print(f"not found in any .c (skipped, likely static inline in a header): {len(notfound)}")

# 4. prune, deleting from the bottom up so indices stay valid
total_removed = 0
report = {}
for f, names in sorted(located.items()):
    lines = cache[f]
    spans = []
    for n in names:
        sp = find_def(lines, n)
        if sp:
            spans.append((sp[0], sp[1], n))
    spans.sort(reverse=True)
    # reject overlaps rather than silently mangling
    prev_start = None
    kept = []
    for s, e, n in spans:
        if prev_start is not None and e >= prev_start:
            print(f"  !! overlap skipped in {f}: {n} ({s}-{e})")
            continue
        kept.append((s, e, n))
        prev_start = s
    removed_here = 0
    for s, e, n in kept:
        removed_here += (e - s + 1)
        lines[s:e + 1] = [f"/* option-4 prune: unreachable, ld discarded .text.{n} */"]
    open(f"{EX}/src/{f}", "w").write("\n".join(lines))
    report[f] = {"functions": len(kept), "lines_removed": removed_here}
    total_removed += removed_here
    print(f"  {f:<22} {len(kept):>3} functions, {removed_here:>5} lines")

print(f"\nTOTAL LINES REMOVED: {total_removed}")
json.dump({"report": report, "ambiguous": ambiguous, "notfound": notfound,
           "total_lines_removed": total_removed},
          open("/opt/lazer-evidence/option4-2026-08-17/prune-report.json", "w"), indent=2)
