---
description: Build deep architectural context through ultra-granular code analysis before vulnerability hunting
---

# Audit Context Building

Build deep comprehension of a codebase before security auditing. Uses bottom-up analysis to reduce hallucinations and context loss during complex security review. Adapted from Trail of Bits methodology.

## When to Invoke

Use `/audit-context` when:
- Starting a new security audit engagement
- Developing deep comprehension of unfamiliar code
- Building bottom-up understanding (not high-level guessing)
- Reducing hallucinations during complex analysis
- Preparing for threat modeling or architecture review

## Core Principle

This is a **pure context building** skill. It does NOT:
- ❌ Identify vulnerabilities
- ❌ Propose fixes
- ❌ Generate proofs-of-concept
- ❌ Assign severity or impact

It exists solely to build deep understanding BEFORE the vulnerability-hunting phase.

## Phases

### Phase 1: Initial Orientation

Map the macro structure:

```markdown
## Module Map
| Module | Purpose | Entry Points | Key Dependencies |
|--------|---------|--------------|------------------|
| [name] | [what it does] | [public APIs] | [what it calls] |

## Actors
| Actor | Trust Level | Capabilities |
|-------|-------------|--------------|
| [who] | [high/medium/low/untrusted] | [what they can do] |

## Storage
| Store | Type | Sensitive? | Access Control |
|-------|------|------------|----------------|
| [name] | [DB/file/memory] | [yes/no] | [who can access] |

## Trust Boundaries
[Diagram or description of trust boundaries]
```

### Phase 2: Ultra-Granular Function Analysis

For each critical function, perform line-by-line analysis:

```markdown
## Function: `namespace::function_name`
**Location:** file:line
**Purpose:** [What it does]
**Caller Context:** [Who calls this and why]

### Line-by-Line Analysis
| Line | Code | Semantic Meaning | Assumptions | Questions |
|------|------|------------------|-------------|-----------|
| L100 | `if (x > 0)` | Guard: ensures positive | x is int | What if x is MAX_INT? |
| L101 | `  result = x * 2` | Double the value | No overflow? | Check caller bounds |

### Data Flow
input_param -> local_var -> [transformation] -> output/side_effect

### Invariants
- [What must always be true for this to work correctly]

### Cross-Function Calls
| Call | Purpose | Trust Level | Context Propagated |
|------|---------|-------------|-------------------|
| `other_func(x)` | [why called] | [trusted/untrusted] | [what flows in/out] |
```

### Phase 3: Global System Understanding

Synthesize understanding:

```markdown
## State Machine
[Mermaid diagram of system states and transitions]

## Invariants
| Invariant | Where Established | Where Checked | Could Break? |
|-----------|-------------------|---------------|--------------|

## Trust Boundaries
[Diagram showing data flow across trust levels]

## Workflows
| Workflow | Steps | Actors | Critical Points |
|----------|-------|--------|-----------------|
| [name] | [ordered steps] | [who participates] | [where things could go wrong] |
```

## Analytical Techniques

### First Principles
For each code block, ask:
1. What is the fundamental purpose?
2. What assumptions does it make?
3. What could invalidate those assumptions?

### 5 Whys
Trace causation backwards:
- Why does this function exist?
  - Why is that behavior needed?
    - Why was it implemented this way?
      - Why not a simpler approach?
        - Why are alternatives insufficient?

### 5 Hows
Trace implementation forward:
- How does input become output?
  - How are side effects managed?
    - How are errors handled?
      - How are edge cases addressed?
        - How could this fail safely/unsafely?

## Anti-Hallucination Rules

1. **Never reshape evidence** to fit earlier assumptions
2. **Update model explicitly** when contradicted by code
3. **Avoid vague guesses** - use "Unclear; need to inspect X"
4. **Cross-reference constantly** to maintain global coherence
5. **Quote code** when making claims about behavior
6. **Track uncertainty** explicitly with confidence levels

## Soqucoin Focus Areas

### Critical Modules to Map
1. **Consensus** - `src/consensus/`, `src/pow/`, `src/auxpow/`
2. **Cryptography** - `src/crypto/dilithium/`, `src/crypto/bulletproofs/`
3. **Validation** - `src/validation.cpp`, `src/script/`
4. **Network** - `src/net.cpp`, `src/net_processing.cpp`
5. **Wallet** - `src/wallet/`
6. **RPC** - `src/rpc/`

### Key Trust Boundaries
- Network peer ↔ Local node
- RPC client ↔ Node
- Wallet ↔ Consensus layer
- User input ↔ Script execution

## Output Format

```markdown
# Audit Context: [Component Name]
**Analyzed:** YYYY-MM-DD
**Commit:** [hash]
**Confidence:** High/Medium/Low

## Module Overview
[Summary of what was analyzed]

## Entry Points
[Public APIs and attack surface]

## Data Flows
[How data moves through the component]

## Trust Model
[Who trusts whom, what is validated]

## Invariants Identified
[Critical assumptions that must hold]

## Areas of Concern
[Not vulnerabilities, just "look closer here"]

## Cross-References
[Other components this interacts with]

## Questions for Follow-Up
[Things that need clarification]
```
