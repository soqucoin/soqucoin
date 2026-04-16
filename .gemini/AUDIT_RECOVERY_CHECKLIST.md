# Audit Recovery Checklist — READ FIRST AFTER TRUNCATION

> **What this is:** If the conversation was truncated/checkpointed, Buddy MUST read this file BEFORE doing ANY audit work. This prevents the process amnesia that has happened TWICE.

## Step 1: Read GEMINI.md Section "Halborn SSC Remediation Process"

Location: `/Users/caseymacmini/soqucoin-build/GEMINI.md`

The process is:
1. Implement → compile → test
2. **STOP. Present SSC report to Casey for review.** DO NOT COMMIT.
3. Wait for Casey's explicit "commit" / "go ahead" approval
4. THEN commit + update registry
5. Pause — Casey manually updates Halborn SSC portal

## Step 2: Check Which Findings Are Still Open

Read: `/Users/caseymacmini/soqucoin-ops/security/SECURITY_ISSUE_REGISTRY.md`

Look at the `Status` column. Only work on `Open` findings. The commit plan is in the table at the bottom of the `> [!IMPORTANT]` block.

## Step 3: Read the Design Log for Next Commit

Read: `/Users/caseymacmini/soqucoin-ops/security/assessments/halborn-mainnet/DL-WALLET-FIND007-019-REMEDIATION.md`

Find the next commit (2d, 2e, 2f, 2g, 2h) and read its section for the fix plan.

## Step 4: Check the Correct SSC Report Format

Read ONE approved report to refresh the format:
- `/Users/caseymacmini/.gemini/antigravity/brain/3f473a4f-901a-4852-9ff5-6d6d1c5fcfc6/FIND008_remediation_report.md`

Key format rules:
- Title: `# SSC-FINDXXX-REMEDIATION`
- Submitter: `CW — Casey Wilson`
- Numbered list for "Aspect — Before → After"
- Numbered list for "Files" with function names and line numbers
- **Test Results section at bottom** — PAT regression count, compilation status, and description of any dedicated tests or explanation if none

## Step 5: Resume Work

Now you can implement the next Open finding. Follow the process from Step 1.

---

*Created: Mar 18, 2026 — after Buddy skipped the review step on Commit 2c (FIND-014/015)*
