#!/usr/bin/env python3
"""The verdict of ci.yml's gate job: one check that reports for every other job.

Branch protection can require one check by name. A required check that never reports
leaves its pull request waiting, and the build and test jobs do not run for a change
that is documentation alone. The gate job always runs, reads the results of the jobs
it needs and gives one verdict, so it is the check to require.

Input: NEEDS_JSON, the workflow's `toJSON(needs)`: for each needed job its result
(success, failure, cancelled or skipped) and its outputs. The job `changes` carries the
output `code`, `true` when the change touches anything but documentation.

The verdict passes in two cases and no other:
  - `changes` succeeded with code=true, and every other job succeeded;
  - `changes` succeeded with code=false, and every other job was skipped.

Everything else fails, by name: a job that failed or was cancelled, a job that was
skipped although the change touches code (the way a gate passes while covering
nothing), a job that ran although the change is documentation alone (the workflow and
this script disagree about what runs), an unknown result, no job besides `changes`,
and input that cannot be read.
"""
import json
import os
import sys

KNOWN = ("success", "failure", "cancelled", "skipped")


def verdict(needs):
    """(passes, lines) for a needs mapping; lines say why, one a job."""
    if not isinstance(needs, dict) or "changes" not in needs:
        return False, ["the needs context carries no `changes` job"]
    changes = needs["changes"]
    if not isinstance(changes, dict) or changes.get("result") != "success":
        return False, ["changes: %r, so there is no answer on what the change touches"
                       % (changes.get("result") if isinstance(changes, dict) else changes)]
    code = (changes.get("outputs") or {}).get("code")
    if code not in ("true", "false"):
        return False, ["changes: the output `code` is %r, neither true nor false" % (code,)]
    others = sorted(name for name in needs if name != "changes")
    if not others:
        return False, ["no job besides `changes`, so the gate would report on nothing"]

    ok = True
    lines = ["changes: success, code=%s" % code]
    for name in others:
        job = needs[name]
        result = job.get("result") if isinstance(job, dict) else None
        if result not in KNOWN:
            ok = False
            lines.append("%s: unknown result %r" % (name, result))
        elif code == "true" and result == "success":
            lines.append("%s: success" % name)
        elif code == "false" and result == "skipped":
            lines.append("%s: skipped, the change is documentation alone" % name)
        elif code == "true" and result == "skipped":
            ok = False
            lines.append("%s: SKIPPED although the change touches code" % name)
        elif code == "false":
            ok = False
            lines.append("%s: %s, yet the change is documentation alone and the job was to be skipped"
                         % (name, result))
        else:
            ok = False
            lines.append("%s: %s" % (name, result.upper()))
    return ok, lines


def main():
    raw = os.environ.get("NEEDS_JSON", "")
    try:
        needs = json.loads(raw)
    except ValueError:
        print("ci-gate: NEEDS_JSON is not JSON, so there is nothing to judge; this fails closed")
        return 1
    ok, lines = verdict(needs)
    for line in lines:
        print(line)
    print("ci-gate: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
