# Brain Architecture & Checkpoint Recovery

> How Antigravity's persistent memory works for Soqucoin, and what happens
> when a context window gets truncated.

---

## How the Brain Works

Antigravity maintains a per-conversation **brain directory** at:

```
~/.gemini/antigravity-ide/brain/<conversation-id>/
```

Each brain directory contains:

| File/Dir | Purpose |
|----------|---------|
| `implementation_plan.md` | Current approved plan |
| `task.md` | Active task checklist |
| `walkthrough.md` | Summary of completed work |
| `scratch/` | Temporary scripts and data files |
| `.system_generated/logs/transcript.jsonl` | Full conversation transcript |

This state **persists across checkpoints**. When the context window fills up,
Antigravity truncates older turns but keeps the brain directory intact on disk.

---

## What Is a Checkpoint?

When a conversation gets long, Antigravity performs a **checkpoint**: it
summarizes and discards older context to free up the context window. After a
checkpoint:

- The agent **loses** direct memory of earlier turns
- The agent **keeps** access to the brain directory on disk
- The `transcript.jsonl` file contains the full history

The problem: the agent doesn't *know* what it's forgotten. It may continue
working but make decisions that conflict with earlier context (wrong paths,
repeated work, missed constraints).

---

## The Recovery System

### Components

1. **PreInvocation Hook** ([checkpoint-recovery-hook.py](file:///Users/caseymacmini/soqucoin-build/.agents/scripts/checkpoint-recovery-hook.py))
   - Fires before every model invocation
   - On the first invocation of a conversation (invocationNum=0), injects an
     ephemeral message telling the agent to run recovery
   - Also detects checkpoint markers in the transcript and injects the message
     post-truncation
   - Uses a state file (`~/.gemini/antigravity/hook-state/<conv-id>.json`) to
     avoid repeating the injection

2. **buddy-recover** (CLI tool)
   - Queries procedural memory (`cm`) and session history (`cass`)
   - Reads `CURRENT_SPRINT.md` for active priorities
   - Outputs context the agent can use to re-orient after truncation

3. **br** (Beads CLI)
   - Lists active work units in `.beads/`
   - `br list --status open` shows what's in progress

### Recovery Flow

```
┌──────────────────┐
│  Antigravity      │
│  starts/resumes   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌─────────────────────────┐
│  PreInvocation    │────▶│  checkpoint-recovery-    │
│  hook fires       │     │  hook.py                 │
└────────┬─────────┘     └────────┬────────────────┘
         │                        │
         │              ┌─────────▼─────────┐
         │              │ First invocation   │
         │              │ OR checkpoint      │──── No ──▶ emit {}
         │              │ detected?          │
         │              └─────────┬─────────┘
         │                   Yes  │
         │              ┌─────────▼─────────┐
         │              │ Inject ephemeral   │
         │              │ message: "Run      │
         │              │ buddy-recover"     │
         │              └─────────┬─────────┘
         │                        │
         ▼                        ▼
┌──────────────────┐     ┌─────────────────────────┐
│  Agent sees       │     │  State file written:     │
│  recovery msg     │     │  {injected: true}        │
│  in context       │     └─────────────────────────┘
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Agent runs:      │
│  buddy-recover    │
│  br list          │
│  reads SPRINT.md  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Agent has full   │
│  context, resumes │
│  work             │
└──────────────────┘
```

---

## What to Do When Recovery Fires

If you see the checkpoint recovery message, the agent should:

1. **Run `buddy-recover "<current task>"`** — gets procedural memory + session context
2. **Run `br list --status open`** — shows active beads (work units)
3. **Read `.gemini/CURRENT_SPRINT.md`** — gets sprint priorities and infrastructure state
4. **Check the brain directory** — read `task.md` and `walkthrough.md` for recent progress

Only then should it proceed with work.

---

## State File Location

```
~/.gemini/antigravity/hook-state/
├── <conversation-id-1>.json   ← {injected: true, injection_time: ...}
├── <conversation-id-2>.json
└── ...
```

These accumulate over time. They're tiny (~100 bytes each) and keyed by
conversation ID, so old ones are harmless. You can periodically clean them:

```bash
# Remove state files older than 7 days
find ~/.gemini/antigravity/hook-state/ -name "*.json" -mtime +7 -delete
```

---

## Failure Modes & Mitigations

| Failure | Impact | Mitigation |
|---------|--------|------------|
| Hook script not found | Agent bricked (exit 2 → hard block) | Absolute paths + validate-hooks.py |
| Hook exits non-zero | Agent bricked | try/except guard (never exit non-zero) |
| Hook times out | Agent continues (timeout = 5s) | Keep hooks fast; no network calls |
| State dir not writable | Recovery msg repeats every invocation | Minor — functional, just noisy |
| buddy-recover not on PATH | Agent sees msg but can't recover | Export PATH in the recovery command |
| Transcript too large to parse | detect_checkpoint returns False | Only reads last 50KB; graceful fallback |

---

## Debugging

### Test the hook manually (simulating Antigravity's exact behavior):

```bash
# Simulate from the runtime cwd that Antigravity uses:
cd /Users/caseymacmini/soqucoin-build/.agents
echo '{"invocationNum": 0, "conversationId": "test-debug", "transcriptPath": ""}' | \
  python3 /Users/caseymacmini/soqucoin-build/.agents/scripts/checkpoint-recovery-hook.py
```

### Validate all hooks:

```bash
python3 /Users/caseymacmini/soqucoin-build/.agents/scripts/validate-hooks.py
```

### Check Antigravity logs for hook errors:

```bash
# Find the most recent session log
ls -lt ~/Library/Application\ Support/Antigravity\ IDE/logs/ | head -5

# Search for hook failures
grep -r "hook.*failed\|hook.*error\|exit status" \
  ~/Library/Application\ Support/Antigravity\ IDE/logs/<session>/*.log
```

---

## Incident Log

### June 3, 2026 — Hook Path Doubling

**Symptoms**: Every prompt returned "Agent terminated due to error" after a reboot.

**Root cause**: Workspace hook used relative path `python3 .agents/scripts/...`.
Antigravity runs hooks from `.agents/` as cwd, so the path resolved to
`.agents/.agents/scripts/...` (doubled). File not found → exit 2 → PreInvocation
hard-block → agent dead.

**Contributing factor**: Global hook at `~/.gemini/config/hooks.json` used tilde
(`~/...`) which doesn't expand without a shell.

**Fix**:
1. Switched to absolute paths in both hooks.json files
2. Added try/except guard so hook can never exit non-zero
3. Disabled global hook (it referenced project-specific tools)
4. Created `validate-hooks.py` to catch this class of bug proactively

**Fixed by**: Cursor (the irony is noted 😅)
