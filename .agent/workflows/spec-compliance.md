---
description: Specification-to-code compliance checker for blockchain audits with evidence-based alignment analysis
---

# Spec-to-Code Compliance

Verifies that code implements exactly what documentation specifies. Finds gaps between intended behavior and actual implementation. Adapted from Trail of Bits methodology.

## When to Invoke

Use `/spec-compliance` when:
- Verifying code implements exactly what documentation specifies
- Finding gaps between intended behavior and actual implementation
- Auditing implementations against whitepapers or design documents
- Identifying undocumented code behavior or unimplemented spec claims

## Core Principle

**Zero speculation.** Every claim must be backed by:
- Exact quotes from documentation (section/title)
- Specific code references (file + line numbers)
- Confidence scores (0-1) for all mappings

## Phases

### Phase 1: Documentation Discovery
Identify all specification sources:
- Whitepapers
- README files
- Design documents
- Code comments (especially protocol specs)
- BIPs/SIPs referenced in code
- Architecture diagrams

### Phase 2: Spec Intent Extraction
For each spec document, extract:
```
SPEC-001: [Requirement title]
Source: [Document name, section]
Quote: "[Exact text from spec]"
Intent: [What behavior is required]
Priority: MUST / SHOULD / MAY
```

### Phase 3: Code Behavior Analysis
For each spec item:
```
CODE-001: [Implementation title]
Files: [file1.cpp:L100-150, file2.h:L50-60]
Behavior: [What the code actually does]
Evidence: [Code snippets proving behavior]
```

### Phase 4: Alignment Comparison
Map each spec item to code with match types:

| Match Type | Description |
|------------|-------------|
| `full_match` | Code exactly implements spec |
| `partial_match` | Incomplete implementation |
| `mismatch` | Spec says X, code does Y |
| `missing_in_code` | Spec claim not implemented |
| `code_stronger_than_spec` | Code adds behavior beyond spec |
| `code_weaker_than_spec` | Code misses spec requirements |
| `undocumented` | Code behavior not mentioned in spec |

### Phase 5: Divergence Classification

For each divergence:
```
## Divergence: [Title]
**Type:** mismatch | missing_in_code | code_weaker | undocumented
**Severity:** Critical / High / Medium / Low
**Confidence:** 0.0 - 1.0

### Specification Says
Document: [name]
Section: [section]
Quote: "[exact text]"

### Code Does
File: [path:lines]
Behavior: [description]
Evidence:
```cpp
[relevant code snippet]
```

### Impact
[Security/correctness implications]

### Resolution
- [ ] Update code to match spec
- [ ] Update spec to match code (if code is correct)
- [ ] Document intentional deviation
```

## Anti-Hallucination Rules

- If spec is silent on behavior: classify as **UNDOCUMENTED**
- If code adds behavior beyond spec: classify as **UNDOCUMENTED CODE PATH**
- If unclear: classify as **AMBIGUOUS** and flag for human review
- Every claim must quote original text or provide line numbers
- Never assume intent - only report what is explicitly stated

## Soqucoin Specification Sources

### Primary Specs
1. **Whitepaper** - Core protocol claims
2. **README.md** - Feature descriptions
3. **design-log/*.md** - Design decisions
4. **SECURITY.md** - Security guarantees
5. **ARCHITECTURE.md** - System design

### Protocol Specs (in code/docs)
- Dilithium signature verification rules
- AuxPoW consensus requirements
- Block validation criteria
- Transaction format specifications
- P2P message protocol
- RPC API contracts

### BIPs/Standards Referenced
- BIP-32 (HD wallets) - key derivation
- BIP-39 (Mnemonic) - seed phrases
- BIP-141 (SegWit) - witness data
- ML-DSA-44 (FIPS 204) - Dilithium parameters
- Bulletproofs++ range proofs

## Output Format

Generate a compliance report:

```markdown
# Spec-to-Code Compliance Report
**Date:** YYYY-MM-DD
**Codebase:** soqucoin-build @ [commit hash]
**Specifications Analyzed:** [count]
**Spec Items Extracted:** [count]

## Summary
| Status | Count |
|--------|-------|
| ✅ Full Match | X |
| ⚠️ Partial Match | X |
| ❌ Mismatch | X |
| 🚫 Missing in Code | X |
| 📝 Undocumented Code | X |

## Critical Divergences
[List of severity=Critical findings]

## High Priority Divergences
[List of severity=High findings]

## Full Analysis
[Detailed findings for each spec item]
```
