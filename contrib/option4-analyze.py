#!/usr/bin/env python3
"""Attribute a linked binary's surviving code back to LaZer source files and lines.

Input artifacts produced by option4-reachability.sh in /opt/lazer-evidence/option4-2026-08-17:
  kat_nogc.nm  / kat_gcsec.nm     nm -S --defined-only output
  kat_nogc.lines / kat_gcsec.lines  objdump --dwarf=decodedline output
  unity-files.txt                 the 33 .c files that src/lazer.c #includes
  unity-loc.txt                   wc -l of those files

Two questions, answered separately because they cost differently:
  1. FUNCTIONS: how many text symbols survive --gc-sections, per source file?
  2. LINES: how many DISTINCT source lines does surviving code map to, per source file?
     This is the number that matters for an audit quote, because auditors read lines.

Line attribution uses the DWARF line table intersected with surviving function address
ranges, so inlined code is captured at the site it was inlined into - which is correct
for "what would a reviewer have to read".
"""
import os
import re
import sys
from collections import defaultdict

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/lazer-evidence/option4-2026-08-17"


def load_nm(path):
    """-> list of (start, size, name). nm -S gives 'addr size type name'."""
    out = []
    for line in open(path, errors="ignore"):
        p = line.split()
        if len(p) < 4:
            continue
        addr, size, typ, name = p[0], p[1], p[2], " ".join(p[3:])
        if typ not in ("T", "t"):
            continue
        try:
            out.append((int(addr, 16), int(size, 16), name))
        except ValueError:
            continue
    return out


def load_lines(path):
    """-> list of (file, line, addr) from objdump --dwarf=decodedline."""
    rows = []
    cu_dir = ""
    for line in open(path, errors="ignore"):
        line = line.rstrip("\n")
        if line.startswith("CU:"):
            cu_dir = os.path.dirname(line[3:].strip().rstrip(":"))
            continue
        if not line or line.startswith("File name") or line.startswith("Decoded dump"):
            continue
        m = re.match(r"^(\S+)\s+(\d+)\s+(0x[0-9a-fA-F]+)", line)
        if not m:
            continue
        f, ln, addr = m.group(1), int(m.group(2)), int(m.group(3), 16)
        if not f.startswith("/") and cu_dir:
            f = os.path.join(cu_dir, f)
        rows.append((f, ln, addr))
    return rows


def attribute(nm_path, lines_path, interesting):
    funcs = load_nm(nm_path)
    rows = load_lines(lines_path)
    rows.sort(key=lambda r: r[2])
    addrs = [r[2] for r in rows]
    import bisect

    per_file_lines = defaultdict(set)   # lines with emitted code (lower bound)
    per_file_funcs = defaultdict(set)
    per_file_spans = defaultdict(set)   # whole retained function bodies (review bound)
    for start, size, name in funcs:
        if size <= 0:
            continue
        i = bisect.bisect_left(addrs, start)
        j = bisect.bisect_left(addrs, start + size)
        seen = defaultdict(list)
        for f, ln, _a in rows[i:j]:
            b = os.path.basename(f)
            if b in interesting:
                per_file_lines[b].add(ln)
                seen[b].append(ln)
        if seen:
            # attribute the function to whichever file it has the most lines in
            owner = max(seen, key=lambda b: len(seen[b]))
            per_file_funcs[owner].add(name)
            # a reviewer reads the whole body, not only the codegen'd lines
            for b, lns in seen.items():
                per_file_spans[b].update(range(min(lns), max(lns) + 1))
    return per_file_funcs, per_file_lines, len(funcs), per_file_spans


def main():
    unity = [l.strip() for l in open(f"{OUT}/unity-files.txt") if l.strip()]
    interesting = {os.path.basename(u) for u in unity}
    # the top-level unity file itself plus its headers matter too
    interesting.add("lazer.c")

    total_loc = {}
    for line in open(f"{OUT}/unity-loc.txt", errors="ignore"):
        p = line.split()
        # skip wc -l's trailing "total" row - counting it double-counts every file
        if len(p) == 2 and p[0].isdigit() and p[1] != "total":
            total_loc[os.path.basename(p[1])] = int(p[0])

    res = {}
    for b in ("kat_nogc", "kat_gcsec"):
        nm_p, ln_p = f"{OUT}/{b}.nm", f"{OUT}/{b}.lines"
        if not (os.path.exists(nm_p) and os.path.exists(ln_p)):
            print(f"MISSING artifacts for {b}")
            return 1
        res[b] = attribute(nm_p, ln_p, interesting)

    fn_gc, ln_gc, tot_gc, sp_gc = res["kat_gcsec"]
    fn_no, ln_no, tot_no, sp_no = res["kat_nogc"]

    # Which reachable code is proof-system-specific (must be reimplemented or extracted)
    # versus generic primitives (replaceable with well-understood standard components)?
    PROOF = {"lin-proofs.c", "lnp-quad.c", "lnp-quad-many.c", "lnp-quad-eval.c",
             "lnp-tbox.c", "lnp.c", "quad.c", "abdlop.c", "dcompress.c",
             "rejection.c", "brandom.c", "blindsig.c"}
    ARITH = {"poly.c", "polyvec.c", "polymat.c", "polyring.c", "spolymat.c",
             "spolyvec.c", "intvec.c", "intmat.c", "int.c"}
    PRIM = {"shake128.c", "coder.c", "aes256ctr.c", "aes256ctr-amd64.c", "rng.c",
            "grandom.c", "urandom.c", "bytes.c", "memory.c", "dump.c",
            "stopwatch.c", "version.c", "lazer.c"}

    print("=" * 100)
    print("REACHABLE SUBSET OF LaZer ON THE SOQUOBSCURA VERIFY PATH")
    print("measured by -ffunction-sections + --gc-sections, i.e. link-time reachability,")
    print("NOT corpus coverage. Gate re-run after trimming: 64/64 KAT-GATE-PASSED.")
    print("=" * 100)
    print(f"text symbols in binary:  no-gc {tot_no}   after --gc-sections {tot_gc}")
    print()
    hdr = (f"{'source file':<22}{'LOC':>6}{'codegen':>9}{'body':>7}{'body%':>7}"
           f"{'fn':>5}{'fn0':>5}  {'class':<7}")
    print(hdr)
    print("-" * len(hdr))
    files = sorted(set(list(total_loc.keys()) + list(ln_gc.keys())),
                   key=lambda f: -len(sp_gc.get(f, ())))
    sum_loc = sum_cg = sum_body = 0
    cls_body = defaultdict(int)
    cls_loc = defaultdict(int)
    for f in files:
        loc = total_loc.get(f, 0)
        cg = len(ln_gc.get(f, ()))
        body = len(sp_gc.get(f, ()))
        if loc == 0 and cg == 0:
            continue
        cls = "proof" if f in PROOF else "arith" if f in ARITH else "prim"
        pct = (100.0 * body / loc) if loc else 0.0
        sum_loc += loc
        sum_cg += cg
        sum_body += body
        cls_body[cls] += body
        cls_loc[cls] += loc
        print(f"{f:<22}{loc:>6}{cg:>9}{body:>7}{pct:>6.1f}%"
              f"{len(fn_gc.get(f,())):>5}{len(fn_no.get(f,())):>5}  {cls:<7}"
              + ("  <-- DEAD" if body == 0 and loc else ""))
    print("-" * len(hdr))
    print(f"{'TOTAL':<22}{sum_loc:>6}{sum_cg:>9}{sum_body:>7}"
          f"{(100.0*sum_body/sum_loc if sum_loc else 0):>6.1f}%")
    print()
    dead = [f for f in files if total_loc.get(f, 0) and not len(sp_gc.get(f, ()))]
    print(f"ENTIRELY DEAD FILES: {len(dead)} files, {sum(total_loc[f] for f in dead)} LOC")
    print("  " + ", ".join(sorted(dead)))
    print()
    print("BY CLASS (reachable function bodies):")
    for c in ("proof", "arith", "prim"):
        print(f"  {c:<7} {cls_body[c]:>6} reachable of {cls_loc[c]:>6} LOC")
    print()
    print(f"==> LOWER BOUND (lines with emitted code): {sum_cg}")
    print(f"==> REVIEW SURFACE (whole reachable function bodies): {sum_body}")
    print(f"==> proof-system-specific portion of that: {cls_body['proof']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
