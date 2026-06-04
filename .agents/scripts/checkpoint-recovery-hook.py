#!/usr/bin/env python3
"""
PreInvocation hook: Detects post-checkpoint state and injects recovery context.

How it works:
1. Fires before EVERY model call
2. On first invocation (num=0), checks if this is a post-checkpoint session
3. If so, injects an ephemeralMessage forcing the agent to run recovery
4. Uses a state file to avoid repeating after the first injection per session

This is the "forcing function" — the agent has NO CHOICE but to see this message.
"""

import json
import sys
import os
from datetime import datetime, timezone

def detect_checkpoint(transcript_path):
    """Check if the transcript indicates a recent checkpoint/truncation."""
    if not transcript_path or not os.path.exists(transcript_path):
        return False
    
    try:
        with open(transcript_path, 'rb') as f:
            f.seek(0, 2)
            file_size = f.tell()
            read_size = min(file_size, 50000)
            f.seek(max(0, file_size - read_size))
            tail = f.read().decode('utf-8', errors='replace')
        
        # Look for checkpoint markers in recent entries
        for line in reversed(tail.strip().split('\n')[-30:]):
            try:
                entry = json.loads(line)
                content = str(entry.get("content", ""))
                if "CHECKPOINT" in content and "truncated" in content.lower():
                    return True
            except (json.JSONDecodeError, KeyError):
                continue
    except (IOError, OSError):
        pass
    
    return False


def main():
    input_data = json.loads(sys.stdin.read())
    
    invocation_num = input_data.get("invocationNum", 0)
    transcript_path = input_data.get("transcriptPath", "")
    conversation_id = input_data.get("conversationId", "")
    
    # Only check on first few invocations of a session to minimize overhead
    if invocation_num > 3:
        print(json.dumps({}))
        return
    
    # State file to track if we've already injected for this conversation
    state_dir = os.path.expanduser("~/.gemini/antigravity/hook-state")
    os.makedirs(state_dir, exist_ok=True)
    state_file = os.path.join(state_dir, f"{conversation_id}.json")
    
    # Load state
    state = {}
    if os.path.exists(state_file):
        try:
            with open(state_file) as f:
                state = json.load(f)
        except (json.JSONDecodeError, IOError):
            state = {}
    
    already_injected = state.get("injected", False)
    
    if already_injected:
        print(json.dumps({}))
        return
    
    # Detect if this is a post-checkpoint context
    is_checkpoint = detect_checkpoint(transcript_path)
    
    # On invocation 0, always inject a lightweight reminder (fresh session)
    should_inject = is_checkpoint or invocation_num == 0
    
    if should_inject:
        recovery_msg = (
            "⚠️ CHECKPOINT RECOVERY REQUIRED ⚠️\n\n"
            "Your context was just truncated. Before doing ANY work:\n\n"
            "1. Run: `export PATH=\"$HOME/.local/bin:$HOME/.cargo/bin:$PATH\" "
            "&& buddy-recover \"<describe your current task>\"`\n"
            "2. Run: `br list --status open` to see active beads\n"
            "3. Read `.gemini/CURRENT_SPRINT.md` for sprint priorities\n\n"
            "DO NOT skip this. Last time recovery was skipped, "
            "monitoring was down for 6+ hours undetected."
        )
        
        response = {
            "injectSteps": [
                {"ephemeralMessage": recovery_msg}
            ]
        }
        
        # Mark as injected so we don't repeat
        state["injected"] = True
        state["injection_time"] = datetime.now(timezone.utc).isoformat()
        state["invocation_num"] = invocation_num
        
        try:
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except IOError:
            pass
        
        print(json.dumps(response))
    else:
        print(json.dumps({}))


if __name__ == "__main__":
    # A failing PreInvocation hook hard-blocks the entire agent execution loop,
    # so this must NEVER exit non-zero. On any error, emit an empty JSON object
    # (a no-op) and exit 0.
    try:
        main()
    except Exception:
        print(json.dumps({}))
