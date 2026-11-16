#!/usr/bin/env python3
"""Does a change touch anything but documentation?

Reads the changed paths on standard input, one a line, and prints `code=true` or
`code=false` for the workflow's output file. The build and test jobs of ci.yml run when
the answer is true. The gate job reads the same answer, so that it can tell a job that
was skipped because the change is documentation from a job that did not run.

A path is documentation when it ends in .md or lies under doc/. That is the rule the
workflow's `paths-ignore` carried before this script: `**/*.md` and `doc/**`.

The answer is `false` only when there is at least one path and every path is
documentation. No path at all means the comparison could not be made, and the answer is
`true`: every job runs.

The caller lists the paths with `git diff --name-only --no-renames`, so that a source file
renamed into doc/ shows its old path too.
"""
import sys


def is_documentation(path):
    return path.endswith(".md") or path.startswith("doc/")


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
