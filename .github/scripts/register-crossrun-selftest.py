#!/usr/bin/env python3
"""Fixture corpus for the two workflow steps of the Register check.

The required step lives in .github/workflows/register.yml and runs the default branch's
checker over a pull request's text. The cross-run step lives in
.github/workflows/register-crossrun.yml and runs the checker a pull request ships against the
default branch's corpus. Each set of cases below builds the workspace the runner would build,
runs the step out of the workflow file, and requires the right verdict for the right reason.

The step under test is read out of the workflow and executed, rather than restated here. Each
step's body has to live in its workflow: both jobs check out a trusted ref, and the trusted
ref of the change that would add a script beside the step does not carry that script, so the
step would fail on its own run. Reading the block back is what keeps these cases honest about
the thing that actually runs.

The required cases drive the step with a comment event, which is the branch of the checker
that reads only the event payload, so nothing here reaches the network. It runs in the Test
workflow, off the pull request head, and has no part in the trust either step rests on: the
corpus and the checker those steps run come from the trusted ref either way, so a pull request
that rewrites this file still faces both steps.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
WORKFLOWS = os.path.join(REPO, ".github", "workflows")
CROSSRUN_STEP = "The base corpus against this pull request's checker"
REQUIRED_STEP = "Lint the text of this pull request"
with open(os.path.join(HERE, "register-lint.py"), encoding="utf-8") as _fh:
    CHECKER = _fh.read()
CORPUS = os.path.join(HERE, "register-lint-selftest.py")


def step_script(workflow, step_name):
    """The `run:` block of one step, as the runner would execute it."""
    path = os.path.join(WORKFLOWS, workflow)
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    try:
        at = next(i for i, l in enumerate(lines) if l.strip() == f"- name: {step_name}")
        start = next(i for i in range(at + 1, len(lines)) if lines[i].strip() == "run: |")
    except StopIteration:
        raise SystemExit(f"FAIL | no step named {step_name!r} with a literal run block in "
                         f"{path}; this corpus cannot speak for a step it cannot find")
    indent = len(lines[start]) - len(lines[start].lstrip()) + 2
    body = []
    for line in lines[start + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line[indent:] if line.strip() else "")
    if not body:
        raise SystemExit(f"FAIL | the step named {step_name!r} has an empty run block")
    return "\n".join(body)


SCRIPT = step_script("register-crossrun.yml", CROSSRUN_STEP)
REQUIRED = step_script("register.yml", REQUIRED_STEP)


def build(root, edit=None, delete=False, corpus_symlink=None, checker_symlink=None,
          scripts_symlink=None, trusted_checker=True, head_tree=True):
    """A workspace shaped like the runner's: the trusted checkout, with head/ beside it."""
    base = os.path.join(root, "base", ".github", "scripts")
    os.makedirs(base)
    shutil.copy(CORPUS, base)
    # The trusted checkout carries the checker too, as the real one does.
    if trusted_checker:
        with open(os.path.join(base, "register-lint.py"), "w", encoding="utf-8") as fh:
            fh.write(CHECKER)
    if not head_tree:
        # The required job checks out one ref and never creates head/.
        return os.path.join(root, "base"), _runner_temp(root)
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


def run(cwd, runner_temp, step_env=None):
    env = dict(os.environ, RUNNER_TEMP=runner_temp)
    # A token in the environment is a case rather than an accident: drop whatever the shell
    # running this corpus happens to carry, so each case decides what the step is handed.
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN",
                 "ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
        env.pop(name, None)
    env.update(step_env or {})
    r = subprocess.run(["bash", "-e", "-c", SCRIPT], cwd=cwd, env=env,
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def run_required(cwd, event_name, payload):
    """The required step, driven by an event payload the way the runner drives it."""
    path = os.path.join(cwd, "event.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    env = dict(os.environ, GITHUB_EVENT_PATH=path, GITHUB_EVENT_NAME=event_name,
               GITHUB_REPOSITORY="owner/repo", GITHUB_TOKEN="fixture")
    r = subprocess.run(["bash", "-e", "-c", REQUIRED], cwd=cwd, env=env,
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


def comment(body):
    return {"comment": {"body": body, "user": {"login": "someone", "type": "User"}}}


DIRTY = "x\n\nCo-Authored-By: a <a@b.c>"
CLEAN = "withdraw: one intent builds one transaction"

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
    ("the head turns the checker off for the event the required job fires on",
     {"edit": sub('    name = os.environ.get("GITHUB_EVENT_NAME", "")\n',
                  '    name = os.environ.get("GITHUB_EVENT_NAME", "")\n'
                  '    if name == "pull_request_target":\n        return 0\n')},
     True, "on pull_request_target"),
    ("the head stops reading the pull request body",
     {"edit": drop('        texts.append(("the pull request body", pr.get("body") or ""))\n')},
     True, "a pull request body with a finding"),
    ("the head reads only the first page of the commits it is given",
     {"edit": sub("        items += page\n        url = next_page(link)\n",
                  "        items += page\n        url = None\n")},
     True, "both pages of a list endpoint are read"),
    ("the head neutralises its own exit so the corpus reports and passes",
     {"edit": lambda t: "import sys\nsys.exit = lambda *a, **k: None\n"
                        + t.replace('    r"co-authored-by",\n', "", 1)},
     True, "fixtures behave"),
    ("the head turns the checker off for comments posted outside a review",
     {"edit": sub('    name = os.environ.get("GITHUB_EVENT_NAME", "")\n',
                  '    name = os.environ.get("GITHUB_EVENT_NAME", "")\n'
                  '    if name == "issue_comment":\n        return 0\n')},
     True, "on issue_comment"),
    # `test -f` and `cp` both follow links, so a checker that resolves to the trusted copy
    # would have the run judge a file this pull request does not ship.
    ("the head's checker is a link to the trusted copy",
     {"checker_symlink": "../../../.github/scripts/register-lint.py"},
     True, "a link rather than a file"),
    ("the head's script directory is a link to the trusted one",
     {"scripts_symlink": "../../.github/scripts"},
     True, "outside the pull request's own tree"),
    # The step never touches the head's corpus path, so this is a guard against that changing
    # rather than evidence the step handled a write.
    ("a corpus path planted in the head is not the one that runs",
     {"edit": drop('    r"co-authored-by",\n'), "corpus_symlink": "/dev/null"},
     True, "a co-author trailer"),
    # The install of the checker is the one change whose trusted ref carries no corpus, and
    # this step says so rather than failing as a missing file.
    ("the trusted ref carries no corpus",
     {"trusted_checker": False, "corpus_absent": True}, True, "carries no register corpus"),
    # This step runs code the pull request ships. A run step is handed no repository token
    # unless the workflow puts one in its environment, and this one does not; these two hold
    # that property rather than stating it, one for a later edit that adds a token and one for
    # the runner's own service token, which every step does carry.
    ("a token in the step's environment stops it before any head code runs",
     {"step_env": {"GITHUB_TOKEN": "fixture"}}, True, "token in its environment"),
    ("the checker the pull request ships sees no token of the runner's",
     {"step_env": {"ACTIONS_RUNTIME_TOKEN": "fixture-value"},
      "edit": lambda t: "import os as _os\n"
                        'print("runtime-token=" + _os.environ.get("ACTIONS_RUNTIME_TOKEN",'
                        ' "absent"))\n' + t},
     False, "runtime-token=absent"),
]

# The required step runs the trusted checker over the pull request's own text. Its cases are
# about what a pull request cannot do to it: the head's copy of the checker is present in the
# workspace for most of them and has no bearing on the verdict.
REQUIRED_CASES = [
    # (name, build kwargs, event name, payload, must refuse, a string in the output)
    ("a comment of ours carrying a trailer is refused",
     {}, "issue_comment", comment(DIRTY), True, "attribution"),
    ("a comment of ours in register passes",
     {}, "issue_comment", comment(CLEAN), False, "no findings"),
    ("a head that drops the co-author pattern does not change the verdict",
     {"edit": drop('    r"co-authored-by",\n')}, "issue_comment", comment(DIRTY),
     True, "attribution"),
    ("a head that empties the checker does not change the verdict",
     {"edit": lambda t: ""}, "issue_comment", comment(DIRTY), True, "attribution"),
    ("the step reads nothing from a head tree, which its job never checks out",
     {"head_tree": False}, "issue_comment", comment(DIRTY), True, "attribution"),
    ("a trusted ref with no checker fails closed",
     {"trusted_checker": False}, "issue_comment", comment(CLEAN),
     True, "carries no register checker"),
]


def report(name, refused, want_refuse, needle, out, rc):
    ok = refused == want_refuse and needle in out
    why = ""
    if not ok:
        why = (f"| exit {rc}, expected {'nonzero' if want_refuse else 'zero'}"
               + ("" if needle in out else f"; output lacks {needle!r}"))
    print(("PASS" if ok else "FAIL"), "|", name, "|",
          "refused" if refused else "accepted", why)
    return 0 if ok else 1


def main():
    bad = 0
    for name, kwargs, want_refuse, needle in CASES:
        root = tempfile.mkdtemp(prefix="register-crossrun-")
        try:
            kwargs = dict(kwargs)
            corpus_absent = kwargs.pop("corpus_absent", False)
            step_env = kwargs.pop("step_env", None)
            try:
                cwd, runner_temp = build(root, **kwargs)
            except AssertionError as exc:
                print("FAIL |", name, "| the case could not be built |", exc)
                bad += 1
                continue
            if corpus_absent:
                os.remove(os.path.join(cwd, ".github", "scripts",
                                       "register-lint-selftest.py"))
            rc, out = run(cwd, runner_temp, step_env)
            bad += report(name, rc != 0, want_refuse, needle, out, rc)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    for name, kwargs, event_name, payload, want_refuse, needle in REQUIRED_CASES:
        root = tempfile.mkdtemp(prefix="register-required-")
        try:
            try:
                cwd, _ = build(root, **kwargs)
            except AssertionError as exc:
                print("FAIL |", name, "| the case could not be built |", exc)
                bad += 1
                continue
            rc, out = run_required(cwd, event_name, payload)
            bad += report(name, rc != 0, want_refuse, needle, out, rc)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    total = len(CASES) + len(REQUIRED_CASES)
    print(f"\n{total - bad}/{total} cases behave")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
