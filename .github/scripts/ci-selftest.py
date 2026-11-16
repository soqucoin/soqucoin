#!/usr/bin/env python3
"""Fixtures for ci-changes.py and ci-gate.py, and the shape of ci.yml that both rely on.

The gate job is the one check for branch protection to require for the build and test jobs.
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
    (["doc/man/Makefile.am"], True),                     # an automake input: make reads it
    (["doc/release-notes.md", "doc/man/Makefile.am"], True),
    (["doc/Makefile"], True),
    (["doc/build.mk"], True),
    (["doc/man/soqucoind.1"], True),                     # a manual page: make installs it
    (["doc/man/notes.md"], True),                        # under doc/man/, whatever its suffix
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
GROUP_LINE = ("group: ${{ github.workflow }}-"
              "${{ github.event_name == 'pull_request' && github.ref || github.sha }}")
NEEDS_LINE = "NEEDS_JSON: ${{ toJSON(needs) }}"
DIFF = "git diff --name-only --no-renames"
GATE_RUN = "run: python3 .github/scripts/ci-gate.py"


def workflow_findings(text):
    """What is wrong with a ci.yml for the gate's purpose; an empty list when nothing is."""
    findings = []
    head, _, body = text.partition("\njobs:\n")
    if not body:
        return ["no jobs: section"]
    live = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    if any(re.search(r"(^|[\s{,'\"-])paths(-ignore)?['\"]?\s*:", line) for line in live):
        findings.append("a path filter on the trigger: the gate would not report for a filtered change")
    groups = [line.strip() for line in live if re.search(r"(^|[\s{,'\"])group['\"]?\s*:", line)]
    if groups != [GROUP_LINE]:
        findings.append("the concurrency group does not give a push a run of its own: "
                        "a later push would cancel the one run of a merged tree (found %r)" % groups)
    if any("continue-on-error" in line for line in live):
        findings.append("continue-on-error, under which a failed job or step can read as a success")
    if DIFF not in body:
        findings.append("the changed paths are not listed with --no-renames: "
                        "a source file moved into doc/ would show its new path alone")
    blocks = {}
    current = None
    for line in body.splitlines():
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            current = m.group(1)
            blocks[current] = []
        elif re.match(r"^  [^ #]", line):
            # Two spaces of indent is where a job's key sits. A key written any other way
            # (quoted, with a comment after it, as a flow mapping) is a job this check would
            # not see, so it is refused here.
            findings.append("a job-level line this check cannot read: %r" % line.strip())
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
    gate_runs = [line.strip() for line in blocks["gate"] if "ci-gate.py" in line]
    if gate_runs != [GATE_RUN]:
        findings.append("the gate's verdict step is %r, expected the one line %r" % (gate_runs, GATE_RUN))
    if [line.strip() for line in blocks["gate"] if "NEEDS_JSON" in line] != [NEEDS_LINE]:
        findings.append("the gate's verdict step does not read the results of the jobs it needs")
    if any(re.match(r"^\s{5,}-?\s*if\s*:", line) for line in blocks["gate"]):
        findings.append("a condition on a step of the gate: the verdict step could be skipped")
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

concurrency:
  group: ${{ github.workflow }}-${{ github.event_name == 'pull_request' && github.ref || github.sha }}
  cancel-in-progress: true

jobs:
  # a comment between jobs is read as a comment
  changes:
    timeout-minutes: 10
    runs-on: ubuntu-22.04
    steps:
      - run: files=$(git diff --name-only --no-renames "$base" HEAD)
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
    steps:
      - name: verdict
        env:
          NEEDS_JSON: ${{ toJSON(needs) }}
        run: python3 .github/scripts/ci-gate.py
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
    ("no gate at all", "", "  gate:\n    if: always()\n    needs: [changes, lint, build]\n    timeout-minutes: 5\n    steps:\n      - name: verdict\n        env:\n          NEEDS_JSON: ${{ toJSON(needs) }}\n        run: python3 .github/scripts/ci-gate.py\n", "no `gate` job"),
    ("a job whose key carries a comment", "  build:  # the main build\n    needs: changes", "  build:\n    needs: changes", "cannot read"),
    ("a job whose key is quoted", '  "build":\n    needs: changes', "  build:\n    needs: changes", "cannot read"),
    ("a job written as a flow mapping", "  extra: {runs-on: ubuntu-22.04}\n  gate:", "  gate:", "cannot read"),
    ("a job that may fail and read as a success", "  build:\n    needs: changes\n    continue-on-error: true", "  build:\n    needs: changes", "continue-on-error"),
    ("a gate whose verdict is thrown away", "        run: python3 .github/scripts/ci-gate.py || true", "        run: python3 .github/scripts/ci-gate.py", "verdict step"),
    ("a path filter written as a flow mapping", "  pull_request: {branches: [main], paths-ignore: ['doc/**']}", "  pull_request:\n    branches: [main]", "path filter"),
    ("a push that shares its run group with the next push", "group: ${{ github.workflow }}-${{ github.ref }}", "group: ${{ github.workflow }}-${{ github.event_name == 'pull_request' && github.ref || github.sha }}", "run of its own"),
    ("a comparison that follows renames", "git diff --name-only \"$base\" HEAD", "git diff --name-only --no-renames \"$base\" HEAD", "--no-renames"),
    ("continue-on-error with its key quoted", "  build:\n    needs: changes\n    \"continue-on-error\": true", "  build:\n    needs: changes", "continue-on-error"),
    ("continue-on-error on the gate's step", "        continue-on-error: true\n        run: python3 .github/scripts/ci-gate.py", "        run: python3 .github/scripts/ci-gate.py", "continue-on-error"),
    ("a path filter on a trigger written below the jobs", "        run: python3 .github/scripts/ci-gate.py\non:\n  pull_request:\n    paths-ignore:\n      - 'doc/**'\n", "        run: python3 .github/scripts/ci-gate.py\n", "path filter"),
    ("the old run group, with the new expression kept in a comment", "group: ${{ github.workflow }}-${{ github.ref }}  # github.event_name == 'pull_request' && github.ref || github.sha", "group: ${{ github.workflow }}-${{ github.event_name == 'pull_request' && github.ref || github.sha }}", "run of its own"),
    ("a job with a run group of its own", "  build:\n    concurrency:\n      group: build-${{ github.ref }}\n      cancel-in-progress: true\n    needs: changes", "  build:\n    needs: changes", "run of its own"),
    ("a condition on the gate's verdict step", "      - name: verdict\n        if: false", "      - name: verdict", "condition on a step"),
    ("a verdict step that reads a constant", "          NEEDS_JSON: '{}'", "          NEEDS_JSON: ${{ toJSON(needs) }}", "does not read the results"),
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
