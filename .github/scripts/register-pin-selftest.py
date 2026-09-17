#!/usr/bin/env python3
"""Every pattern in register-lint.py must be pinned by a fixture in its corpus.

A corpus that exercises the checker but leaves most of its patterns untouched reads as a
guard and behaves as a sample. This neutralises one pattern at a time and requires the
corpus to notice. A pattern the corpus does not notice is one that can be deleted while
every check stays green.

Run it against a checker and a corpus that sit in the same directory, which is how both
the Register workflow and the Test workflow arrange them.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "register-lint.py")
CORPUS = os.path.join(HERE, "register-lint-selftest.py")

# A pattern that compiles and matches nothing, so neutralising a pattern leaves the list
# the same length and the checker otherwise intact.
DEAD = 'r"(?!x)x"'


def literals(checker_text):
    """Every regex literal in the pattern lists, as it is written in the source."""
    spec = importlib.util.spec_from_file_location("pin_lint", CHECKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    found = []
    for name in ("ATTRIBUTION", "NARRATIVE", "PATHS"):
        found += [(name, p) for p in getattr(mod, name)]
    found += [("REGISTER", p) for p, _ in mod.REGISTER]

    for name in ("ATTRIBUTION", "NARRATIVE", "PATHS", "REGISTER"):
        if not [x for x in found if x[0] == name]:
            print(f"::error title=Register pins::{name} is empty, so this check would report "
                  f"every pattern in it pinned by saying nothing about any")
            return None

    out = []
    for name, pat in found:
        forms = [f'r"{pat}"', f"r'{pat}'"]
        written = next((f for f in forms if f in checker_text), None)
        if written is None:
            print(f"::error::pattern {pat!r} in {name} is not a plain r-string literal in the "
                  f"source, so this check cannot neutralise it and cannot speak for it")
            return None
        out.append((name, pat, written))
    return out


def main():
    with open(CHECKER, encoding="utf-8") as fh:
        checker_text = fh.read()
    with open(CORPUS, encoding="utf-8") as fh:
        corpus_text = fh.read()

    pats = literals(checker_text)
    if pats is None:
        return 1

    tmp = tempfile.mkdtemp(prefix="register-pin-")
    unpinned = []
    try:
        for name, pat, written in pats:
            d = tempfile.mkdtemp(dir=tmp)
            with open(os.path.join(d, "register-lint.py"), "w", encoding="utf-8") as fh:
                fh.write(checker_text.replace(written, DEAD, 1))
            with open(os.path.join(d, "register-lint-selftest.py"), "w", encoding="utf-8") as fh:
                fh.write(corpus_text)
            r = subprocess.run(
                [sys.executable, os.path.join(d, "register-lint-selftest.py")],
                capture_output=True, text=True)
            # A non-zero status is not enough. Neutralising a pattern has to flip a named
            # fixture; a corpus that crashed instead says nothing about coverage.
            if r.returncode == 0 or "FAIL |" not in r.stdout:
                unpinned.append((name, pat, r.returncode))
    finally:
        subprocess.run(["rm", "-rf", tmp], check=False)

    for name, pat, rc in unpinned:
        why = ("is pinned by no fixture" if rc == 0
               else "breaks the corpus when neutralised rather than flipping a fixture")
        print(f"::error title=Register pins::{name} pattern {pat!r} {why}. "
              f"Add one to register-lint-selftest.py that this pattern alone catches.")
    print(f"\n{len(pats) - len(unpinned)}/{len(pats)} patterns pinned by a fixture")
    return 1 if unpinned else 0


if __name__ == "__main__":
    sys.exit(main())
