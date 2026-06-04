# Antigravity Hook Authoring Guide

> **For Soqucoin Labs agents and contributors.** This documents the hard-won rules
> for writing Antigravity hooks that don't brick the agent.

---

## The Cardinal Rule

> **A failing PreInvocation hook hard-blocks the entire agent execution loop.**
> Every prompt dies with "Agent terminated due to error." There is no fallback,
> no retry, no graceful degradation. If your hook exits non-zero, the agent is dead.

This is not a bug — it's by design. Antigravity treats PreInvocation hooks as
mandatory pre-flight checks. A non-zero exit is treated as "unsafe to proceed."

---

## Required: The Never-Exit-Nonzero Guard

Every Python hook script **MUST** use this pattern:

```python
#!/usr/bin/env python3
import json
import sys

def main():
    input_data = json.loads(sys.stdin.read())
    # ... your hook logic ...
    print(json.dumps(response))

if __name__ == "__main__":
    # ⚠️  MANDATORY GUARD — a failing hook bricks the entire agent.
    # On ANY error, emit empty JSON (a no-op) and exit 0.
    try:
        main()
    except Exception:
        print(json.dumps({}))
```

For bash hooks:

```bash
#!/usr/bin/env bash
set +e  # Do NOT use set -e in hooks

main() {
    # ... your hook logic ...
    echo '{}'
}

# Mandatory guard
main "$@" 2>/dev/null || echo '{}'
```

---

## Path Rules

### ❌ Never use relative paths

Antigravity runs hook commands with the **customization directory** as the working
directory (e.g., `.agents/` for workspace hooks, `~/.gemini/config/` for global hooks).

A command like `python3 .agents/scripts/myhook.py` resolves to
`.agents/.agents/scripts/myhook.py` — a path that doesn't exist.

### ❌ Never use tilde (`~`)

The `~` character is only expanded by a shell. Antigravity `exec()`s commands
directly, so `~/path` is treated as a literal directory named `~`.

### ✅ Always use absolute paths

```json
{
  "command": "python3 /Users/caseymacmini/soqucoin-build/.agents/scripts/myhook.py"
}
```

### Validating your paths

Run the validator before deploying any hook change:

```bash
python3 /Users/caseymacmini/soqucoin-build/.agents/scripts/validate-hooks.py
```

---

## hooks.json Structure

```json
{
  "hook-name": {
    "enabled": true,
    "PreInvocation": [
      {
        "type": "command",
        "command": "python3 /absolute/path/to/script.py",
        "timeout": 5
      }
    ]
  }
}
```

**Lifecycle events**: `PreInvocation`, `PostInvocation`, `PreToolExecution`, `PostToolExecution`

**Fields per entry**:
- `type`: Always `"command"` for script hooks
- `command`: The full command string (absolute paths only)
- `timeout`: Seconds before the hook is killed (keep ≤ 5 for PreInvocation)

**Hook locations**:
| Scope | File | Runtime cwd |
|-------|------|-------------|
| Workspace | `.agents/hooks.json` | `.agents/` |
| Global | `~/.gemini/config/hooks.json` | `~/.gemini/config/` |

Workspace hooks fire only in their project. Global hooks fire in **every** project —
be careful not to reference project-specific tools from global hooks.

---

## Input/Output Protocol

Hooks receive JSON on **stdin** and must emit JSON on **stdout**.

### Input (from Antigravity)

```json
{
  "invocationNum": 0,
  "conversationId": "abc-123",
  "transcriptPath": "/path/to/transcript.jsonl"
}
```

### Output (to Antigravity)

**No-op** (do nothing):
```json
{}
```

**Inject an ephemeral message** (agent sees it as a system message):
```json
{
  "injectSteps": [
    {"ephemeralMessage": "Your message here"}
  ]
}
```

---

## Checklist Before Deploying a Hook

- [ ] Script uses absolute path in `hooks.json`
- [ ] Script has the never-exit-nonzero guard (`try/except` → `print({})`)
- [ ] Script reads stdin and writes valid JSON to stdout
- [ ] Timeout is ≤ 5 seconds for PreInvocation hooks
- [ ] Tested from the correct runtime cwd: `cd .agents && python3 /abs/path/script.py < test_input.json`
- [ ] Ran `validate-hooks.py` with no errors
- [ ] If global hook: verified it doesn't reference project-specific tools

---

## Incident Reference: June 3, 2026

**Bug**: Workspace hook used `python3 .agents/scripts/checkpoint-recovery-hook.py`
(relative path). Antigravity ran it from `.agents/` as cwd, resolving to
`.agents/.agents/scripts/...` → file not found → exit 2 → every prompt died.

**Root cause**: Relative path + unexpected runtime cwd.

**Fix**: Absolute path + try/except guard.

**Lesson**: Always validate paths from the perspective of Antigravity's executor,
not your shell.
