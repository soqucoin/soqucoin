#!/usr/bin/env python3
"""Fixture corpus for the cross-run step of the Register workflow.

Each case builds a head checkout whose checker has been edited the way a pull request could
edit it, runs the step against it, and requires the step to reach the right verdict for the
right reason.

The step under test is read out of .github/workflows/register.yml and executed, rather than
restated here. The step's body has to live in the workflow: the Register job checks out the
base of the pull request, and the base of the change that would add a script beside it does
not carry that script, so the step would fail on its own run. Reading the block back is what
keeps these cases honest about the thing that actually runs.

Offline: nothing here reaches the network. It runs in the Test workflow, off the pull request
head, and has no part in the trust the step rests on. The corpus that step runs comes from
the base either way, so a pull request that rewrites this file still faces the step.
"""
import os
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
WORKFLOW = os.path.join(REPO, ".github", "workflows", "register.yml")
STEP_NAME = "The base corpus against this pull request's checker"
CHECKER = open(os.path.join(HERE, "register-lint.py"), encoding="utf-8").read()
CORPUS = os.path.join(HERE, "register-lint-selftest.py")


def step_script():
    """The `run:` block of the cross-run step, as the runner would execute it."""
    lines = open(WORKFLOW, encoding="utf-8").read().splitlines()
    try:
        at = next(i for i, l in enumerate(lines) if l.strip() == f"- name: {STEP_NAME}")
        start = next(i for i in range(at + 1, len(lines)) if lines[i].strip() == "run: |")
    except StopIteration:
        raise SystemExit(f"FAIL | no step named {STEP_NAME!r} with a literal run block in "
                         f"{WORKFLOW}; this corpus cannot speak for a step it cannot find")
    indent = len(lines[start]) - len(lines[start].lstrip()) + 2
    body = []
    for line in lines[start + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line[indent:] if line.strip() else "")
    if not body:
        raise SystemExit("FAIL | the cross-run step has an empty run block")
    return "\n".join(body)


SCRIPT = step_script()


def build(root, edit=None, delete=False, corpus_symlink=None, checker_symlink=None,
          scripts_symlink=None):
    """A workspace shaped like the runner's: the base checkout, with head/ beside it."""
    base = os.path.join(root, "base", ".github", "scripts")
    os.makedirs(base)
    shutil.copy(CORPUS, base)
    # The base carries the trusted checker too, as the real base checkout does.
    with open(os.path.join(base, "register-lint.py"), "w", encoding="utf-8") as fh:
        fh.write(CHECKER)
    head = os.path.join(root, "base", "head", ".github", "scripts")
    if scripts_symlink:
        os.makedirs(os.path.dirname(head))
        os.symlink(scripts_symlink, head)
        return os.path.join(root, "base"), _runner_temp(root)
    os.makedirs(head)
    if checker_symlink:
        os.symlink(checker_symlink, os.path.join(head, "register-lint.py"))
    elif not delete:
        with open(os.path.join(head, "register-lint.py"), "w", encoding="utf-8") as fh:
            fh.write(edit(CHECKER) if edit else CHECKER)
    if corpus_symlink:
        os.symlink(corpus_symlink, os.path.join(head, "register-lint-selftest.py"))
    return os.path.join(root, "base"), _runner_temp(root)


def _runner_temp(root):
    d = os.path.join(root, "runner-temp")
    os.makedirs(d)
    return d


def run(cwd, runner_temp):
    env = dict(os.environ, RUNNER_TEMP=runner_temp)
    r = subprocess.run(["bash", "-e", "-c", SCRIPT], cwd=cwd, env=env,
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def sub(old, new):
    def edit(text):
        out = text.replace(old, new, 1)
        if out == text:
            raise AssertionError(f"this corpus edits {old!r}, which the checker no longer has")
        return out
    return edit


def drop(needle):
    return sub(needle, "")


CASES = [
    # (name, build kwargs, the step must refuse, a string its output must contain)
    ("the head checker is unchanged", {}, False, "fixtures behave"),
    ("the head drops the co-author pattern",
     {"edit": drop('    r"co-authored-by",\n')}, True, "a co-author trailer"),
    ("the head drops a vendor name, which no fixture pinned before this change",
     {"edit": drop('r"\\bclaude\\b", ')}, True, "a vendor name, claude"),
    ("the head weakens main() and leaves lint() intact",
     {"edit": sub("    if findings:\n", "    if False:\n")}, True, "main() returned 0"),
    ("the head checker exits at import",
     {"edit": lambda t: "import sys\nsys.exit(0)\n" + t}, True, "does not import"),
    ("the head checker is emptied", {"edit": lambda t: ""}, True, "no callable"),
    ("the head deletes the checker", {"delete": True}, True, "removes or renames"),
    ("the head turns the checker off for pull request events and leaves review events alone",
     {"edit": sub('    name = os.environ.get("GITHUB_EVENT_NAME", "")\n',
                  '    name = os.environ.get("GITHUB_EVENT_NAME", "")\n'
                  '    if name == "pull_request":\n        return 0\n')},
     True, "main() returned 0"),
    ("the head stops reading the pull request body",
     {"edit": drop('        texts.append(("the pull request body", pr.get("body") or ""))\n')},
     True, "a pull request body with a finding"),
    ("the head neutralises its own exit so the corpus reports and passes",
     {"edit": lambda t: "import sys\nsys.exit = lambda *a, **k: None\n"
                        + t.replace('    r"co-authored-by",\n', "", 1)},
     True, "fixtures behave"),
    ("the head turns the checker off for comments posted outside a review",
     {"edit": sub('    name = os.environ.get("GITHUB_EVENT_NAME", "")\n',
                  '    name = os.environ.get("GITHUB_EVENT_NAME", "")\n'
                  '    if name == "issue_comment":\n        return 0\n')},
     True, "on issue_comment"),
    # `test -f` and `cp` both follow links, so a checker that resolves to the base's own copy
    # would have the run judge a file this pull request does not ship.
    ("the head's checker is a link to the base's trusted copy",
     {"checker_symlink": "../../../.github/scripts/register-lint.py"},
     True, "a link rather than a file"),
    ("the head's script directory is a link to the base's",
     {"scripts_symlink": "../../.github/scripts"},
     True, "outside the pull request's own tree"),
    # The step never touches the head's corpus path, so this is a guard against that changing
    # rather than evidence the step handled a write.
    ("a corpus path planted in the head is not the one that runs",
     {"edit": drop('    r"co-authored-by",\n'), "corpus_symlink": "/dev/null"},
     True, "a co-author trailer"),
]


def main():
    bad = 0
    for name, kwargs, want_refuse, needle in CASES:
        root = tempfile.mkdtemp(prefix="register-crossrun-")
        try:
            try:
                cwd, runner_temp = build(root, **kwargs)
            except AssertionError as exc:
                print("FAIL |", name, "| the case could not be built |", exc)
                bad += 1
                continue
            rc, out = run(cwd, runner_temp)
            refused = rc != 0
            ok = refused == want_refuse and needle in out
            bad += 0 if ok else 1
            why = ""
            if not ok:
                why = (f"| exit {rc}, expected {'nonzero' if want_refuse else 'zero'}"
                       + ("" if needle in out else f"; output lacks {needle!r}"))
            print(("PASS" if ok else "FAIL"), "|", name, "|",
                  "refused" if refused else "accepted", why)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    print(f"\n{len(CASES) - bad}/{len(CASES)} cases behave")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
