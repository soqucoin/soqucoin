#!/usr/bin/env python3
"""Fixtures for ci-changes.py and ci-gate.py, and the shape of ci.yml that both rely on.

The gate job is the one check branch protection requires for the build and test jobs.
It protects nothing if it can pass while a job failed, while a job never ran, or while a
job is absent from the list it reads. Each of those is a fixture here, and each fixture
names the verdict it expects. The workflow file is read as text, since a runner's Python
carries no YAML parser by default.

Run: python3 .github/scripts/ci-selftest.py
"""
import importlib.util
import os
import re
import sys

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
WORKFLOW = os.path.join(HERE, "..", "workflows", "ci.yml")


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHANGES = load("ci-changes")
GATE = load("ci-gate")

# ---------------------------------------------------------------- ci-changes.py
# (paths, touches code)
CHANGE_FIXTURES = [
    (["README.md"], False),
    (["doc/release-notes/release-notes-2.6.1.md"], False),
    (["doc/fuzzing.md", "INSTALL.md", "src/test/README.md"], False),
    (["doc/img/logo.png"], False),                       # under doc/, as `doc/**` was
    (["src/validation.cpp"], True),
    (["README.md", "src/validation.cpp"], True),         # one code path among documentation
    ([".github/workflows/ci.yml"], True),                # a workflow change is a code change
    (["qa/rpc-tests/auxpow.py"], True),
    (["docs/notes.txt"], True),                          # docs/ is another directory
    (["doc"], True),                                     # a file named doc at the root
    (["src/doc/x.cpp"], True),                           # doc/ counts at the root alone
    (["doc/moved.cpp", "src/moved.cpp"], True),          # a source file moved into doc/: --no-renames lists both
    (["CHANGELOG.MD"], True),                            # the suffix is matched as written
    ([], True),                                          # no path: the comparison failed, every job runs
    (["", "   "], True),                                 # blank lines alone are no path
]

# ------------------------------------------------------------------ ci-gate.py
JOBS = ["lint", "build-linux-x64", "build-linux-arm64", "build-windows-x64", "build-macos-arm64", "sanitizers"]


def needs(code, default, changes="success", **overrides):
    out = {"changes": {"result": changes, "outputs": {"code": code} if code is not None else {}}}
    for job in JOBS:
        out[job] = {"result": overrides.get(job.replace("-", "_"), default), "outputs": {}}
    return out


# (label, needs, passes)
GATE_FIXTURES = [
    ("every job succeeded on a code change", needs("true", "success"), True),
    ("every job skipped on a documentation change", needs("false", "skipped"), True),
    ("one job failed", needs("true", "success", build_linux_x64="failure"), False),
    ("one job cancelled", needs("true", "success", sanitizers="cancelled"), False),
    ("one job skipped on a code change", needs("true", "success", build_macos_arm64="skipped"), False),
    ("every job skipped on a code change", needs("true", "skipped"), False),
    ("a job ran on a documentation change", needs("false", "skipped", lint="success"), False),
    ("a job failed on a documentation change", needs("false", "skipped", lint="failure"), False),
    ("changes failed", needs("true", "success", changes="failure"), False),
    ("changes skipped", needs("true", "success", changes="skipped"), False),
    ("changes gave no answer", needs(None, "success"), False),
    ("changes gave an answer that is neither", needs("maybe", "success"), False),
    ("an unknown result", needs("true", "success", lint="neutral"), False),
    ("no job besides changes", {"changes": {"result": "success", "outputs": {"code": "true"}}}, False),
    ("no changes job", {"lint": {"result": "success", "outputs": {}}}, False),
    ("not a mapping", ["success"], False),
    ("a job that is not a mapping", dict(needs("true", "success"), lint="success"), False),
]

# ---------------------------------------------------------- the shape of ci.yml
CODE_IF = "needs.changes.outputs.code == 'true'"


def workflow_findings(text):
    """What is wrong with a ci.yml for the gate's purpose; an empty list when nothing is."""
    findings = []
    head, _, body = text.partition("\njobs:\n")
    if not body:
        return ["no jobs: section"]
    if re.search(r"^\s+paths(-ignore)?:", head, re.M):
        findings.append("a path filter on the trigger: the gate would not report for a filtered change")
    blocks = {}
    current = None
    for line in body.splitlines():
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            current = m.group(1)
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    for required in ("changes", "gate"):
        if required not in blocks:
            findings.append("no `%s` job" % required)
    if findings:
        return findings

    def job_needs(name):
        for line in blocks[name]:
            m = re.match(r"^    needs:\s*(.+?)\s*$", line)
            if m:
                value = m.group(1)
                if value.startswith("["):
                    return [v.strip() for v in value.strip("[]").split(",") if v.strip()]
                return [value]
        return []

    def job_if(name):
        for line in blocks[name]:
            m = re.match(r"^    if:\s*(.+?)\s*$", line)
            if m:
                return m.group(1)
        return ""

    others = sorted(name for name in blocks if name != "gate")
    if sorted(job_needs("gate")) != others:
        missing = sorted(set(others) - set(job_needs("gate")))
        extra = sorted(set(job_needs("gate")) - set(others))
        findings.append("the gate's needs do not equal the other jobs (missing %s, unknown %s)" % (missing, extra))
    if job_if("gate") != "always()":
        findings.append("the gate's condition is %r; with anything but always() a failed job skips the gate" % job_if("gate"))
    for name in blocks:
        if not any(re.match(r"^    timeout-minutes:\s*\d+\s*$", line) for line in blocks[name]):
            findings.append("%s: no timeout-minutes" % name)
        if name in ("changes", "gate"):
            continue
        if "changes" not in job_needs(name):
            findings.append("%s: does not need `changes`" % name)
        if CODE_IF not in job_if(name):
            findings.append("%s: its condition does not read the answer of `changes`" % name)
    return findings


GOOD = """name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  changes:
    timeout-minutes: 10
    runs-on: ubuntu-22.04
  lint:
    needs: changes
    if: needs.changes.outputs.code == 'true'
    timeout-minutes: 10
  build:
    needs: changes
    if: needs.changes.outputs.code == 'true'
    timeout-minutes: 60
  gate:
    if: always()
    needs: [changes, lint, build]
    timeout-minutes: 5
"""

# (label, the text that replaces a part of GOOD, the part it replaces, a word of the finding it must raise)
WORKFLOW_ATTACKS = [
    ("a job left out of the gate's needs", "needs: [changes, lint]", "needs: [changes, lint, build]", "missing"),
    ("a job the gate needs that does not exist", "needs: [changes, lint, build, ghost]", "needs: [changes, lint, build]", "unknown"),
    ("a gate that a failed job skips", "    if: success()\n    needs: [changes", "    if: always()\n    needs: [changes", "always()"),
    ("a path filter on the trigger", "  pull_request:\n    paths-ignore:\n      - 'doc/**'\n    branches: [main]", "  pull_request:\n    branches: [main]", "path filter"),
    ("a job that runs whatever the change is", "  build:\n    needs: changes\n    timeout-minutes: 60", "  build:\n    needs: changes\n    if: needs.changes.outputs.code == 'true'\n    timeout-minutes: 60", "condition"),
    ("a job that does not wait for the answer", "  build:\n    if: needs.changes.outputs.code == 'true'\n    timeout-minutes: 60", "  build:\n    needs: changes\n    if: needs.changes.outputs.code == 'true'\n    timeout-minutes: 60", "does not need"),
    ("a job with no time limit", "  lint:\n    needs: changes\n    if: needs.changes.outputs.code == 'true'\n  build:", "  lint:\n    needs: changes\n    if: needs.changes.outputs.code == 'true'\n    timeout-minutes: 10\n  build:", "timeout-minutes"),
    ("no gate at all", "", "  gate:\n    if: always()\n    needs: [changes, lint, build]\n    timeout-minutes: 5\n", "no `gate` job"),
]


def main():
    failed = 0
    total = 0

    for paths, expected in CHANGE_FIXTURES:
        total += 1
        got = CHANGES.touches_code(paths)
        if got != expected:
            failed += 1
            print("FAIL ci-changes: %r gave %s, expected %s" % (paths, got, expected))

    for label, context, expected in GATE_FIXTURES:
        total += 1
        got, lines = GATE.verdict(context)
        if got != expected:
            failed += 1
            print("FAIL ci-gate: %s gave %s, expected %s: %s" % (label, got, expected, "; ".join(lines)))

    total += 1
    if workflow_findings(GOOD):
        failed += 1
        print("FAIL shape: the sound sample raises %r" % workflow_findings(GOOD))
    for label, new, old, word in WORKFLOW_ATTACKS:
        total += 1
        if GOOD.count(old) != 1:
            failed += 1
            print("FAIL shape fixture: %s does not apply to the sample once" % label)
            continue
        found = workflow_findings(GOOD.replace(old, new))
        if not any(word in f for f in found):
            failed += 1
            print("FAIL shape: %s raised %r, expected a finding with %r" % (label, found, word))

    total += 1
    with open(WORKFLOW, encoding="utf-8") as handle:
        live = workflow_findings(handle.read())
    if live:
        failed += 1
        for finding in live:
            print("FAIL ci.yml: %s" % finding)

    print("%d/%d fixtures behave" % (total - failed, total))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
