#!/usr/bin/env python3
"""Does a change touch anything but documentation?

Reads the changed paths on standard input, one a line, and prints `code=true` or
`code=false` for the workflow's output file. The build and test jobs of ci.yml run when
the answer is true. The gate job reads the same answer, so that it can tell a job that
was skipped because the change is documentation from a job that did not run.

A path is documentation when it ends in .md or lies under doc/, with two exceptions that
`make` reads: a build input under doc/ (a Makefile.am or another automake, autoconf or make
file), and anything under doc/man/, whose pages `make` installs and needs to be present.
The workflow's `paths-ignore` carried `**/*.md` and `doc/**` before this script and so
skipped a change to doc/man/Makefile.am and the removal of a manual page.

The answer is `false` only when there is at least one path and every path is
documentation. No path at all means the comparison could not be made, and the answer is
`true`: every job runs.

The caller lists the paths with `git diff --name-only --no-renames`, so that a source file
renamed into doc/ shows its old path too.
"""
import sys


BUILD_INPUT_SUFFIXES = (".am", ".in", ".ac", ".m4", ".mk")


def is_build_input(path):
    name = path.rsplit("/", 1)[-1]
    return name in ("Makefile", "GNUmakefile") or name.endswith(BUILD_INPUT_SUFFIXES)


def is_documentation(path):
    if path.startswith("doc/man/"):
        return False
    if path.endswith(".md"):
        return True
    return path.startswith("doc/") and not is_build_input(path)


def touches_code(paths):
    paths = [p.strip() for p in paths if p.strip()]
    if not paths:
        return True
    return not all(is_documentation(p) for p in paths)


def main():
    paths = sys.stdin.read().splitlines()
    code = touches_code(paths)
    kept = [p.strip() for p in paths if p.strip()]
    sys.stderr.write("%d changed path(s); %d outside the documentation\n" % (
        len(kept), sum(1 for p in kept if not is_documentation(p))))
    print("code=%s" % ("true" if code else "false"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
