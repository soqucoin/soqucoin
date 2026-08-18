#!/usr/bin/env python3
"""Emit EXECUTED-EVIDENCE.json: proof that the vendored corpus bytes were actually run.

Binds three things together so the record cannot silently go stale:
  * the sha256 of every corpus file that was executed
  * the identity of the verifier that executed them (tree, archive, binary, toolchain)
  * the per-vector verdict observed
If a corpus file is regenerated, its hash changes and the in-repo test goes red until the
vectors are re-executed. That is the difference between "someone ran this once" and "the repo
knows whether the current bytes have been run".
"""
import hashlib, json, os, re, subprocess, sys

CORPUS = "/opt/lazer-evidence/repo-corpus"
EX = "/opt/lazer-extract"
BIN = "/tmp/o4x/classrun"
FILES = ["range.jsonl", "balance.jsonl", "ve.jsonl", "degenerate.jsonl"]

def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()

out = subprocess.run([BIN] + [os.path.join(CORPUS, f) for f in FILES],
                     capture_output=True, text=True)
if out.returncode != 0:
    sys.exit("verifier run failed:\n" + out.stdout[-2000:])

verdicts = []
for line in out.stdout.split("\n"):
    m = re.match(r"^\s{2}(\S+)\s+(ACCEPT|reject)\s+expect=(accept|reject)\s+(\S+)", line)
    if m:
        vid, got, exp, status = m.groups()
        verdicts.append({"id": vid, "got": "accept" if got == "ACCEPT" else "reject",
                         "expect": exp, "ok": status == "ok"})

n_ok = sum(1 for v in verdicts if v["ok"])
gcc = subprocess.run(["gcc", "--version"], capture_output=True, text=True).stdout.split("\n")[0]
uname = subprocess.run(["uname", "-srm"], capture_output=True, text=True).stdout.strip()

ev = {
    "what": "execution evidence for the vendored SoquObscura KAT corpus and its "
            "degenerate-witness reject class",
    "why": "the in-repo corpus test cannot verify proofs, because there is deliberately no "
           "consensus verifier in-tree yet. This record is how the repo knows the vendored "
           "bytes have actually been run, and against what.",
    "executed_utc_date": "2026-08-18",
    "corpus_sha256": {f: sha(os.path.join(CORPUS, f)) for f in FILES},
    "verifier": {
        "identity": "option-4 extracted LaZer subset",
        "tree": "162.243.115.28:/opt/lazer-extract",
        "unity_source_files": 22,
        "unity_loc": 9018,
        "derived_from_upstream": "2fa3dfb1de7c",
        "carries_patches": [
            "hexl-util.cmake: capability probe tested the build host (-march=native)",
            "hexl/CMakeLists.txt: -march=native as a PRIVATE compile option",
            "aes256ctr-amd64.c: strict-aliasing violation in _aes256ctr_init (bead nh6m)",
        ],
        "liblazer_a_sha256": sha(f"{EX}/liblazer.a"),
        "harness_binary_sha256": sha(BIN),
        "build_flags": "-O3 -g -march=x86-64-v3 -maes -mtune=generic -fomit-frame-pointer "
                       "-ffunction-sections -fdata-sections, linked -Wl,--gc-sections",
        "toolchain": gcc,
        "host": uname,
    },
    "summary": {
        "vectors_executed": len(verdicts),
        "correct": n_ok,
        "wrong": len(verdicts) - n_ok,
        "accept_expected": sum(1 for v in verdicts if v["expect"] == "accept"),
        "reject_expected": sum(1 for v in verdicts if v["expect"] == "reject"),
    },
    "verdicts": verdicts,
}
path = "/opt/lazer-evidence/repo-corpus/EXECUTED-EVIDENCE.json"
json.dump(ev, open(path, "w"), indent=2, sort_keys=True)
open(path, "a").write("\n")
print(f"wrote {path}")
print(json.dumps(ev["summary"], indent=2))
