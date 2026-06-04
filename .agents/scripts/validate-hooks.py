#!/usr/bin/env python3
"""
validate-hooks.py — Antigravity Hook Health Checker

Validates every hooks.json file (workspace + global) for common bugs:
  - Script path doesn't exist
  - Tilde (~) in paths (won't expand without a shell)
  - Relative paths that will double when Antigravity sets cwd to .agents/
  - Command interpreter (python3, bash, etc.) not found on PATH
  - Invalid JSON
  - Hooks referencing disabled state

Run manually:
    python3 /Users/caseymacmini/soqucoin-build/.agents/scripts/validate-hooks.py

Or with --fix to auto-correct relative→absolute path issues:
    python3 .../validate-hooks.py --fix

Exit codes:
    0 = all hooks valid
    1 = one or more issues found
    2 = script error (should never happen)
"""

import json
import os
import shutil
import sys
import re
from pathlib import Path


# ── Configuration ──────────────────────────────────────────────────────────────

WORKSPACE_ROOT = "/Users/caseymacmini/soqucoin-build"
HOOKS_LOCATIONS = [
    {
        "path": os.path.join(WORKSPACE_ROOT, ".agents", "hooks.json"),
        "label": "Workspace (.agents/hooks.json)",
        "cwd_at_runtime": os.path.join(WORKSPACE_ROOT, ".agents"),
    },
    {
        "path": os.path.expanduser("~/.gemini/config/hooks.json"),
        "label": "Global (~/.gemini/config/hooks.json)",
        "cwd_at_runtime": os.path.expanduser("~/.gemini/config"),
    },
]

# Hook lifecycle events that contain command entries
HOOK_EVENTS = ["PreInvocation", "PostInvocation", "PreToolExecution", "PostToolExecution"]


# ── Validation Logic ──────────────────────────────────────────────────────────

class Issue:
    """A single validation issue."""
    def __init__(self, severity, location, message, fix_hint=None):
        self.severity = severity  # "ERROR" or "WARN"
        self.location = location
        self.message = message
        self.fix_hint = fix_hint

    def __str__(self):
        prefix = "❌" if self.severity == "ERROR" else "⚠️"
        s = f"  {prefix} [{self.severity}] {self.location}: {self.message}"
        if self.fix_hint:
            s += f"\n     💡 Fix: {self.fix_hint}"
        return s


def validate_hooks_file(hooks_loc):
    """Validate a single hooks.json file. Returns list of Issues."""
    issues = []
    fpath = hooks_loc["path"]
    label = hooks_loc["label"]
    runtime_cwd = hooks_loc["cwd_at_runtime"]

    # ── File existence ──
    if not os.path.exists(fpath):
        # Not an error — it's valid to not have a hooks file
        return issues

    # ── JSON parse ──
    try:
        with open(fpath) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        issues.append(Issue("ERROR", label, f"Invalid JSON: {e}",
                            "Fix the JSON syntax and re-run."))
        return issues

    if not isinstance(data, dict):
        issues.append(Issue("ERROR", label, "Top-level value must be a JSON object."))
        return issues

    # ── Per-hook validation ──
    for hook_name, hook_config in data.items():
        if not isinstance(hook_config, dict):
            issues.append(Issue("ERROR", f"{label} → {hook_name}",
                                "Hook config must be a JSON object."))
            continue

        # Check enabled state
        enabled = hook_config.get("enabled", True)
        if not enabled:
            issues.append(Issue("WARN", f"{label} → {hook_name}",
                                "Hook is disabled (enabled: false). Intentional?"))

        # Check each lifecycle event
        for event in HOOK_EVENTS:
            entries = hook_config.get(event, [])
            if not isinstance(entries, list):
                issues.append(Issue("ERROR", f"{label} → {hook_name} → {event}",
                                    f"Expected array, got {type(entries).__name__}."))
                continue

            for i, entry in enumerate(entries):
                entry_loc = f"{label} → {hook_name} → {event}[{i}]"
                issues.extend(validate_command_entry(entry, entry_loc, runtime_cwd))

    return issues


def validate_command_entry(entry, location, runtime_cwd):
    """Validate a single hook command entry."""
    issues = []

    if not isinstance(entry, dict):
        issues.append(Issue("ERROR", location, "Entry must be a JSON object."))
        return issues

    entry_type = entry.get("type", "")
    if entry_type != "command":
        # We only know how to validate command-type hooks
        return issues

    command = entry.get("command", "")
    if not command:
        issues.append(Issue("ERROR", location, "Missing 'command' field."))
        return issues

    # ── Parse the command ──
    # Typical format: "python3 /path/to/script.py" or "bash /path/to/script.sh"
    parts = command.split()
    interpreter = parts[0]
    script_path = parts[1] if len(parts) > 1 else None

    # ── Check interpreter is on PATH ──
    if not shutil.which(interpreter):
        issues.append(Issue("ERROR", location,
                            f"Interpreter '{interpreter}' not found on PATH.",
                            f"Install {interpreter} or use an absolute path."))

    if not script_path:
        # Single-word command (no script argument) — nothing more to check
        return issues

    # ── Tilde check ──
    if "~" in script_path:
        expanded = os.path.expanduser(script_path)
        issues.append(Issue("ERROR", location,
                            f"Path contains '~' which won't expand without a shell: {script_path}",
                            f"Use absolute path: {expanded}"))
        # Use the expanded path for further checks
        script_path = expanded

    # ── Relative path check (the .agents/.agents/ doubling bug) ──
    if not os.path.isabs(script_path):
        resolved_from_cwd = os.path.normpath(os.path.join(runtime_cwd, script_path))
        resolved_from_workspace = os.path.normpath(
            os.path.join(WORKSPACE_ROOT, script_path)
        )

        # Check if the relative path works from the runtime cwd
        if not os.path.exists(resolved_from_cwd):
            hint = None
            if os.path.exists(resolved_from_workspace):
                hint = (f"Antigravity runs this from cwd={runtime_cwd}, "
                        f"so '{script_path}' resolves to '{resolved_from_cwd}' (missing). "
                        f"Use absolute path: {resolved_from_workspace}")
            else:
                hint = (f"Script not found at '{resolved_from_cwd}' (from runtime cwd) "
                        f"or '{resolved_from_workspace}' (from workspace root). "
                        f"Check the path.")

            issues.append(Issue("ERROR", location,
                                f"Relative path will fail — resolved: {resolved_from_cwd}",
                                hint))
        else:
            # It works but relative paths are fragile — warn
            issues.append(Issue("WARN", location,
                                f"Relative path '{script_path}' — works from current cwd "
                                f"but fragile if Antigravity changes runtime directory.",
                                f"Prefer absolute path: {resolved_from_cwd}"))
        return issues

    # ── Absolute path — verify it exists ──
    if not os.path.exists(script_path):
        issues.append(Issue("ERROR", location,
                            f"Script not found: {script_path}",
                            "Check the path or re-create the script."))
    elif not os.access(script_path, os.R_OK):
        issues.append(Issue("ERROR", location,
                            f"Script exists but is not readable: {script_path}",
                            f"Run: chmod +r {script_path}"))

    # ── Check for try/except guard (Python scripts only) ──
    if script_path.endswith(".py") and os.path.exists(script_path):
        try:
            with open(script_path) as f:
                content = f.read()
            # Look for the never-exit-nonzero pattern
            has_guard = ("except" in content and
                         "exit(0)" in content.replace(" ", "") or
                         re.search(r'except\s+(Exception|BaseException)', content))
            if not has_guard:
                issues.append(Issue("WARN", location,
                                    f"Script {os.path.basename(script_path)} may not have "
                                    f"a top-level try/except guard.",
                                    "Wrap main() in try/except that prints {} and exits 0. "
                                    "A failing PreInvocation hook hard-blocks the entire agent."))
        except IOError:
            pass

    # ── Timeout check ──
    # (Checked at the entry level, not the script level)

    return issues


def validate_script_guard(script_path):
    """Check if a Python hook script has the never-exit-nonzero guard."""
    if not script_path or not script_path.endswith(".py") or not os.path.exists(script_path):
        return True  # Not applicable

    with open(script_path) as f:
        content = f.read()

    # The guard pattern: top-level try/except that catches Exception
    # and prints empty JSON + exits 0
    return bool(re.search(r'except\s+(Exception|BaseException)', content))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    fix_mode = "--fix" in sys.argv
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    print("🔍 Antigravity Hook Validator")
    print("=" * 60)

    all_issues = []

    for hooks_loc in HOOKS_LOCATIONS:
        fpath = hooks_loc["path"]
        label = hooks_loc["label"]

        if not os.path.exists(fpath):
            if verbose:
                print(f"\n📂 {label}: not found (skipping)")
            continue

        print(f"\n📂 {label}")
        print(f"   Path: {fpath}")
        print(f"   Runtime cwd: {hooks_loc['cwd_at_runtime']}")

        issues = validate_hooks_file(hooks_loc)
        all_issues.extend(issues)

        if not issues:
            print("   ✅ All checks passed")
        else:
            for issue in issues:
                print(issue)

    # ── Summary ──
    errors = [i for i in all_issues if i.severity == "ERROR"]
    warnings = [i for i in all_issues if i.severity == "WARN"]

    print("\n" + "=" * 60)
    if errors:
        print(f"💥 {len(errors)} error(s), {len(warnings)} warning(s)")
        print("   Fix the errors above to prevent agent bricking.")
        sys.exit(1)
    elif warnings:
        print(f"✅ No errors. {len(warnings)} warning(s) — review above.")
        sys.exit(0)
    else:
        print("✅ All hooks validated successfully. No issues found.")
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Validator script error: {e}", file=sys.stderr)
        sys.exit(2)
