# ConfigGuard v1.2 — Field-Ready Validation Stack

**Status**: Production-Ready
**Version**: v1.2
**Date**: 2026-05-30
**Purpose**: Executable validation system for real user sessions — no theory knowledge required

---

## 0. What This Is vs v1.1

| v1.1 | v1.2 |
|------|------|
| Layered theory system | Compressed execution pipeline |
| 4-layer architecture | 3-step runtime path |
| DRIFT as meta-layer | DRIFT as validator (post-classification sanity check) |
| No decision contract | **Decision Contract as core** |
| Good for research | Good for field execution |

**v1.2 goal:** Interviewer can run 60-min session and produce a GO/NO-GO recommendation without understanding underlying theory.

---

## 1. Runtime Pipeline (3 Steps)

```
INPUT: User in 60-min session
    ↓
STEP 1: OBSERVE (v1.1 metrics, no interpretation)
    ↓
STEP 2: CLASSIFY (F1–F7 + DRIFT validator)
    ↓
STEP 3: DECIDE (Decision Contract)
    ↓
OUTPUT: GO / NO-GO / CONDITIONAL GO + reasoning
```

### Step 1: Observe (8 minutes)

**What to capture:** Raw data only. No interpretation.

```
[Complete standard v1.1 session tracker]
- H1/H2/H3/H4 scores
- TCT override behavior
- verbatim capture
- adoption signals
- warning signals
```

**Interviewer mindset:** "I'm recording what they say, not what it means."

---

### Step 2: Classify (5 minutes after session)

**Process:**

```
Step 2a: Assign primary F-type (F1–F7)
Step 2b: Run DRIFT validator
Step 2c: Compute taxonomy_trust_level
```

#### Step 2a: Primary F-Type Assignment

Look at session data, find best match:

```
F1: "We already use [X tool]" + zero integration questions
F2: "I'd use it but our process..." + process mentioned
F3: Zero signals, zero verbatim, no complaints
F4: 3+ skeptic questions (methodology)
F5: Auditor user type + needs control mapping
F6: Interested in one feature only
F7: "Need to check with manager" + has incumbent
```

**If multiple F-types apply → Primary = highest confidence match**

#### Step 2b: DRIFT Validator (Post-Classification Sanity Check)

**Run AFTER F-type assigned:**

```
IF behavior doesn't fit F1–F7 cleanly → D0 (log verbatim, don't force)
IF multiple F's apply → D1 (note all, primary = highest confidence)
IF user mentions time condition → D2 (flag for follow-up)
IF behavior contradicts F-type → D4 or D5 suspected
```

**Rule:** DRIFT is a warning signal, not a re-classification.

#### Step 2c: Taxonomy Trust Level

```
HIGH: Behavior fits F cleanly, no DRIFT detected
MEDIUM: D1/D2/D3 detected OR confidence 0.5–0.7
LOW: D0 detected OR confidence < 0.5 OR multiple DRIFT types
```

---

### Step 3: Decide (Decision Contract)

**This is the core of v1.2.**

**Decision is deterministic based on:**
1. H1 pass rate
2. Primary F-type
3. DRIFT rate
4. Taxonomy trust level

**No interpretation needed — just follow the contract.**

---

## 2. Decision Contract

### Decision Matrix

```
                    H1 Pass ≥80%?
                    ├─ NO → NO-GO
                    └─ YES → Continue
                          ↓
                    Primary F-type:
                    ├─ F5 (Compliance Mismatch) → Check if B-auditor material resolves
                    │   └─ Resolved → Continue
                    │   └─ Not resolved → CONDITIONAL GO
                    ├─ F4 (Methodology Doubt) → Check if 6-month evidence possible
                    │   └─ User willing to wait → CONDITIONAL GO
                    │   └─ User not willing → NO-GO
                    └─ F1/F2/F7 (Ecosystem/Org) → Continue to DRIFT check
                          ↓
                    DRIFT Rate (this session):
                    ├─ < 20% → Continue
                    ├─ 20–40% → CONDITIONAL GO
                    └─ > 40% → NO-GO (taxonomy insufficient)
                          ↓
                    Taxonomy Trust Level:
                    ├─ HIGH → GO
                    ├─ MEDIUM → CONDITIONAL GO
                    └─ LOW → NO-GO (classification unreliable)
```

### Simplified Decision Rules

```
GO IF:
  ✓ H1 ≥ 80%
  ✓ Primary F ≠ F4 (unresolved) or F5 (unresolved)
  ✓ DRIFT rate < 20%
  ✓ Taxonomy trust = HIGH

CONDITIONAL GO IF:
  ✓ H1 ≥ 80%
  ✓ Primary F = F4 or F5 but resolvable
  OR
  ✓ Primary F = F1/F2/F7 (ecosystem)
  ✓ DRIFT rate 20–40%
  OR
  ✓ Taxonomy trust = MEDIUM

NO-GO IF:
  ✗ H1 < 80%
  OR
  ✗ Primary F = F4/F5 with fundamental doubt (not resolvable)
  OR
  ✗ DRIFT rate > 40%
  OR
  ✗ Taxonomy trust = LOW
```

---

## 3. Decision Output Template

### Per-Session Output

```markdown
## Session [ID] — Decision Output

### Raw Scores
- H1: X/4
- H2: X/4
- H3: X/4
- H4: X/2
- TCT: [FOLLOW/OVERRIDE/ESCALATE/DEFER]

### Classification
- Primary F-type: F[X]
- F-type confidence: [HIGH/MEDIUM/LOW]
- Alternative F-types considered: [list if D1]

### DRIFT Check
- DRIFT detected: [YES/NO]
- DRIFT type: [D0/D1/D2/D3/D4/D5/D6 or None]
- Taxonomy trust level: [HIGH/MEDIUM/LOW]

### Decision
- Verdict: [GO / CONDITIONAL GO / NO-GO]
- Primary reason: [one sentence]
- Conditions for upgrade: [if CONDITIONAL]
- Notes for follow-up: [if D2/D3/D4/D5]
```

### Batch Output (After 6-10 Sessions)

```markdown
## Batch Analysis — Decision Output

### Summary Stats
- Sessions: N
- H1 pass rate: X%
- GO: N | CONDITIONAL: N | NO-GO: N

### F-Type Distribution
- F1: X | F2: X | F3: X | F4: X | F5: X | F6: X | F7: X
- Most common: F[X]
- Most blocking: F[X]

### DRIFT Summary
- Sessions with DRIFT: X/N
- DRIFT rate: X%
- Dominant DRIFT type: D[X]

### Final Verdict
- Overall: [GO / CONDITIONAL GO / NO-GO]
- Conditions: [list]
- Recommended next steps: [list]
```

---

## 4. Session Runbook (60 Minutes)

### Before Session (5 min prep)

```
□ Open session tracker spreadsheet (v1.1 fields)
□ Prepare Material A (diff output)
□ Prepare Material B (match user type: standard/auditor/operator)
□ Prepare Material C (CI/CD integration example)
□ Have DRIFT checklist visible but NOT active
□ Set timer for 60 minutes
```

### During Session (50 min)

```
[0-2 min]  Context setting
[2-5 min]  H1: Output Understandability + H1x
[5-8 min]  H2: Actionability (with appropriate Material B)
[8-11 min] H3: Integration
[11-14 min] H4: Differentiation
[14-18 min] TCT-1: Trust Calibration + dependency reason
[18-22 min] TCT-2: Override Test (4 states)
[22-26 min] TCT-3: Fix Execution
[26-30 min] Open feedback + verbatim capture
[30-50 min] Additional observation (if user continues discussing)
```

**Critical timing:**
- TCT-2: Ask personal rating BEFORE showing ConfigGuard rating
- H1x question: Ask AFTER standard H1 questions

### After Session (10 min)

```
[5 min] Complete session tracker (all v1.1 fields)
[3 min] Assign primary F-type (use F1–F7 quick reference)
[2 min] Run DRIFT validator (checklist, not deep analysis)
[1 min] Fill decision output template
[0 min] Move to next session (don't over-analyze)
```

### DRIFT Validator Checklist (Post-Session, 2 min)

```
□ Does behavior fit F cleanly?
  → Yes: Proceed
  → No: Log verbatim, mark D0

□ Multiple F-types apply?
  → No: Proceed
  → Yes: Note all, mark D1

□ User mention time condition?
  → No: Proceed
  → Yes: Mark D2

□ Behavior contradicts F-type?
  → No: Proceed
  → Yes: Mark D4 or D5

□ DRIFT detected? [YES/NO]
□ If yes, type: [D0/D1/D2/D4/D5]
□ Taxonomy trust: [HIGH/MEDIUM/LOW]
```

---

## 5. F1–F7 Quick Reference Card

**Print this. Keep visible during session.**

```
F1 — ECOSYSTEM TRAP
Signal: "We already use [X]"
Behavior: Treats as extra tool
Action: Don't block GO, note as constraint

F2 — WORKFLOW INERTIA
Signal: "I'd use but process..."
Behavior: Individual wants, org blocks
Action: CONDITIONAL, org change needed

F3 — SILENT ADOPTER / REJECTION
Signal: Zero signals, zero verbatim
Behavior: Unknown — need follow-up
Action: Don't count toward or against

F4 — METHODOLOGY DOUBT
Signal: 3+ "how was this calculated?"
Behavior: Skeptic, won't trust without proof
Action: CONDITIONAL if willing to wait

F5 — COMPLIANCE MISMATCH
Signal: Auditor + "need control mapping"
Behavior: Can't use without control ID
Action: Test B-auditor material first

F6 — FEATURE EXTRACTION
Signal: One feature interest only
Behavior: May extract and leave
Action: Note, bundle features later

F7 — POLITICAL BUY-IN
Signal: "Need manager approval"
Behavior: Individual wants, veto exists
Action: CONDITIONAL, target power user
```

---

## 6. Decision Contract Quick Reference

**Print this. Use after every session.**

```
┌─────────────────────────────────────────────────────────────┐
│                    DECISION CONTRACT                        │
├─────────────────────────────────────────────────────────────┤
│  GO if:                                                     │
│    ✓ H1 ≥ 80%                                              │
│    ✓ Primary F ≠ F4 (unresolved)                          │
│    ✓ Primary F ≠ F5 (unresolved)                          │
│    ✓ DRIFT < 20%                                           │
│    ✓ Taxonomy trust = HIGH                                  │
├─────────────────────────────────────────────────────────────┤
│  CONDITIONAL GO if:                                        │
│    ✓ H1 ≥ 80%                                              │
│    ○ F4/F5 present but resolvable                           │
│    OR                                                       │
│    ○ F1/F2/F7 present                                      │
│    ○ DRIFT 20–40%                                          │
│    OR                                                       │
│    ○ Taxonomy trust = MEDIUM                               │
├─────────────────────────────────────────────────────────────┤
│  NO-GO if:                                                  │
│    ✗ H1 < 80%                                              │
│    OR                                                       │
│    ✗ F4/F5 with fundamental doubt                          │
│    OR                                                       │
│    ✗ DRIFT > 40%                                           │
│    OR                                                       │
│    ✗ Taxonomy trust = LOW                                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. v1.1 Metrics (Frozen — Unchanged)

For detailed metrics definitions, see:
```
docs/superpowers/specs/validation/v1.1-validation-metrics-system.md
```

**v1.2 does NOT change v1.1 metrics. It only adds decision compression.**

### Key Metrics (v1.2 Reference)

| Metric | Definition | Decision Weight |
|--------|------------|----------------|
| H1 score | /4 | GO gate |
| H2 score | /4 | Informational |
| H3 score | /4 | CI/CD fit |
| H4 score | /2 | Preference |
| TCT override | 4 states | Trust signal |
| DRIFT rate | % sessions with DRIFT | Taxonomy validity |
| Taxonomy trust | HIGH/MEDIUM/LOW | Decision confidence |

---

## 8. File Structure

```
docs/superpowers/specs/validation/
├── v1.1-user-testing-protocol.md           (frozen)
├── v1.1-validation-metrics-system.md       (frozen)
├── v1.2-field-stack/
│   ├── session-runbook.md                  (THIS FILE)
│   ├── F1-F7-quick-reference.md            (printable card)
│   ├── decision-contract.md                (decision matrix)
│   └── protocol/
│       └── session-runbook.md              (executable steps)
├── interpretation/
│   └── adoption-failure-taxonomy.md         (flexible)
└── drift/
    └── real-user-drift-schema.md           (validator)
```

---

## 9. Version Summary

| Version | Purpose | Status |
|---------|---------|--------|
| v1.0 | Initial design | Obsolete |
| v1.1 | Measurement calibration (SAUS v2) | Frozen |
| v1.2 | Decision compression + field execution | **Current** |

### What Changed v1.1 → v1.2

1. **Decision Contract added** — GO/NO-GO/CONDITIONAL now deterministic
2. **DRIFT demoted** — From meta-layer to post-classification validator
3. **Session runbook** — 60-min executable protocol
4. **Quick reference cards** — No theory knowledge required
5. **Decision output template** — Standardized per-session and batch

---

## 10. Anti-Over-Engineering Reminder

**v1.2 is intentionally constrained:**

```
WHAT v1.2 DOES:
- Compress 4 layers into 3 steps
- Make decision deterministic
- Make session executable in 60 min
- Produce GO/NO-GO without ambiguity

WHAT v1.2 DOES NOT DO:
- Add new metrics
- Add new F-types
- Add new DRIFT types
- Expand taxonomy coverage
- Improve theoretical correctness
```

**If you find yourself wanting to add something to v1.2:**
- Ask: "Does this help an interviewer make a decision in 60 minutes?"
- If no → Don't add it
- If yes → Consider if v1.2 is the right layer or v1.1 is