# ConfigGuard — Adoption Failure Taxonomy v1.0

**Status**: Independent Interpretation Layer
**Version**: v1.0
**Date**: 2026-05-30
**Purpose**: Interpretive lens for classifying real-world adoption failures

**IMPORTANT**: This is NOT part of the measurement system (v1.1). It is a separate interpretive layer. Do not merge into scoring system.

---

## 0. Design Principles

### Layer Separation

```
Layer 1: Measurement (v1.1 frozen)
  H1 / H2 / H3 / H4 / TCT / state machine
  → answers: "What happened?"

Layer 2: Behavioral Signals (metrics system)
  adoption_signals / warning_signals / verbatim
  → answers: "What did the user do?"

Layer 3: Interpretation (this taxonomy)
  F1–F7 failure modes
  → answers: "Why no adoption?"
```

### Lock-in Warning

**Do NOT:**
- Embed F1–F7 into scoring system
- Use failure classification in GO/NO-GO decision
- Lock definition of F1–F7 before real data

**Do:**
- Use as interpretive lens after sessions
- Let real users break / expand F categories
- Track classification confidence per session

### Confidence Meta-Layer

F1–F7 are post-hoc interpretations, not directly observable truth.

Add per-session field:
```
failure_classification_confidence: 0.0–1.0
```

| Case | Confidence |
|------|-----------|
| F4 Skeptic (verbatim methodology questions > 2) | 0.9 |
| F5 Compliance (Auditor + SOLVABLE_PRODUCT_GAP) | 0.85 |
| F7 Political (has incumbent + needs team) | 0.7 |
| F6 Feature extraction (adopts one feature) | 0.6 |
| F2 vs F1 ambiguity | 0.4 |
| F3 Silent adopter (zero signals) | 0.2 |

**Low confidence means:** Classification may change with more data. Do not over-index.

---

## 1. The 7 Failure Modes

### F1: Ecosystem Trap

**Definition:** User has existing tool (Prisma/Wiz/Skybox/Ansible) → ConfigGuard treated as extra signal, not replacement

**Classic Signals:**
- "We already use [X]"
- High H1/H2 scores
- Zero workflow pull questions
- "Nice tool" but no integration question

**Behavior:** Will evaluate, not adopt. Ecosystem is sticky.

**Distinguishing from F2:**
- F1: "Nice extra" — no urgency to switch
- F2: "Want to use but blocked" — internal desire exists

### F2: Workflow Inertia

**Definition:** Individual wants ConfigGuard but organizational structure blocks adoption

**Classic Signals:**
- "I'd use it but our process is..."
- "We do manual approval + change window"
- Needs team buy-in
- Specific defer conditions around process

**Behavior:** Wants adoption, blocked by org structure. Product is not the problem.

**Distinguishing from F7:**
- F2: Individual wants it, process blocks
- F7: Organization/politics blocks (manager veto)

### F3: Silent Adopter / Silent Rejection

**Definition:** No feedback, no questions, no adoption signals — but behavior unknown

**Classic Signals:**
- Zero adoption_signals
- Zero verbatim comments
- Session completed, no complaints
- H1 ≥ 3/4

**Behavior:** Interpretation impossible without follow-up

**Why Most Dangerous:**
- F4 (Skeptic) = loud, know where you stand
- F3 = invisible, can't fix what you can't see

**Post-Session Check (Critical):**
```
1 week after session, send:
"Curious — did you end up trying ConfigGuard on a real config?"

Response:
- Used it → F3 = SILENT_ADOPTER (best possible outcome)
- Didn't use → F3 = SILENT_REJECTION (problem)
- No response → UNKNOWN (can't classify)
```

### F4: Methodology Doubt

**Definition:** Skeptic pattern — questions underlying methodology, won't trust without proof

**Classic Signals:**
- verbatim_skeptic_questions > 2
- "How was this calculated?"
- "What data trained this model?"
- "Can I see the evidence chain?"
- TCT override behavior: OVERRIDE
- tct_dependency_reason: FUNDAMENTAL_DOUBT

**Behavior:** Understands output but doesn't trust correctness. Will verify independently.

**Resolution Path:**
- Methodology documentation
- 6-month track record with zero false positives
- Evidence chain transparency

### F5: Compliance Mismatch

**Definition:** Auditor type — output doesn't map to control framework they use daily

**Classic Signals:**
- User type: Security Auditor
- H1 < 3 with standard Material B
- tct_dependency_reason: SOLVABLE_PRODUCT_GAP
- "Does this map to CIS-2.4?"
- "I need control ID for my report"

**Behavior:** Would adopt if control mapping provided (B-auditor material addresses this)

**Resolution Path:**
- B-auditor Material B (already in v1.1)
- CIS/NIST control mapping per finding
- Audit trail: config → finding → control → compliance gap

### F6: Feature Extraction

**Definition:** User adopts one specific feature, ignores rest → extracted and leaves

**Classic Signals:**
- adoption_2_explain_used = true
- adoption_4_cicd_strong = false
- Single feature interest (usually "explain" command)
- No questions about other features

**Behavior:** Likes one command, will use only that, ignore pipeline integration

**Why Problematic:**
- Single-feature adoption is fragile
- May not drive full workflow adoption
- Hard to expand to other features later

**Resolution Path:**
- Bundle features, don't fragment
- Show feature dependencies early
- Identify if single-feature user will expand or stay narrow

### F7: Political Buy-In

**Definition:** Individual wants ConfigGuard but manager/policy blocks

**Classic Signals:**
- warning_3_needs_team = true
- warning_2_has_incumbent = true
- "I'd need to check with my manager"
- "Our security policy requires..."
- Manager not in session

**Behavior:** Individual champion exists, organizational barrier blocks

**Distinguishing from F2:**
- F2: Individual blocked by their own process habits
- F7: Individual blocked by someone else's veto power

**Resolution Path:**
- Target power users (manager-level) not just individual contributors
- Build internal champion case
- Identify who has veto power and address directly

---

## 2. Taxonomy Decision Matrix

```
                    User says "yes I would use"
                           ↓
                   ┌───────┴───────┐
                   ↓               ↓
            F4/F5/F6          F1/F2/F7
            (Product Gap)     (Ecosystem/
                             Org Barrier)
                   ↓               ↓
              v1.1 roadmap    Not product failure
              + wait for      Don't block GO
              evidence        but adoption
                              probability lower
```

### GO/NO-GO Override by Failure Type

| Failure Type | Effect on GO/NO-GO | Action |
|--------------|-------------------|--------|
| F4 Methodology | Retryable with evidence | Don't block GO |
| F5 Compliance | Solvable (B-auditor) | Don't block GO |
| F6 Feature | Product bundling issue | Address in roadmap |
| F1 Ecosystem | External constraint | CONDITIONAL GO |
| F2 Inertia | Org change needed | CONDITIONAL GO |
| F7 Political | External veto | CONDITIONAL GO |
| F3 Silent | Time维度 — follow-up required | Wait before classifying |

**Key principle:** F4/F5/F6 = product issues (fixable). F1/F2/F7 = ecosystem issues (not ConfigGuard failure).

---

## 3. F3 (Silent) Time-Dimension Problem

### The Core Issue

F3 is not a static classification — it's a **temporal state**:

```
SILENT_ADOPTER (best)
  ↓ (over time)
Active user OR
  ↓
Silent dropout

SILENT_REJECTION (worst)
  ↓ (over time)
Never used OR
  ↓
Abandoned after trial
```

### Classification Timeline

```
Session time (t=0):
  F3_SILENT_UNKNOWN — Cannot classify yet

t+1 week follow-up:
  If used → F3_SILENT_ADOPTER
  If not → F3_SILENT_REJECTION
  If no response → UNKNOWN (need more time)

t+1 month:
  Check if silent adopter became active
  Check if silent rejection gave feedback
```

### Important: F3 is the Only Time-Dependent Failure Mode

F1–F2, F4–F7 are **structural** (relatively stable over time).
F3 is **behavioral** (changes over observation window).

---

## 4. Real-World Drift Watchlist

### What Breaks the Taxonomy

**These behaviors will emerge that don't fit F1–F7 cleanly:**

1. **Hybrid behaviors** — User shows F4 + F5 simultaneously
2. **Transition during session** — Starts F2, becomes F4
3. **Multiple F-types** — Matches F1 on CI/CD, F5 on compliance
4. **Time-variant** — F3 at session, F6 at 1-week follow-up

### How to Handle Classification Edge Cases

```
If ambiguous F1 vs F2:
  → Use confidence 0.4, note both possibilities
  → Don't force binary classification

If F4 + F5 simultaneously:
  → Classify as F4 (methodology doubt is more fundamental)
  → Address F5 with B-auditor after F4 resolves

If transition during session:
  → Record which F-type at which timestamp
  → This IS the signal — behavior change matters

If multi-F matches:
  → Primary = most prominent (highest confidence)
  → Secondary = note but don't weight equally
```

---

## 5. Post-Session Classification Template

```python
@dataclass
class SessionInterpretation:
    """Interpretation layer for a session (NOT measurement)."""

    session_id: str

    # Primary failure classification
    failure_type: str           # F1–F7 or POTENTIAL_ADOPTER
    failure_classification_confidence: float  # 0.0–1.0

    # If ambiguous
    alternative_classification: str | None  # If confidence < 0.5
    alternative_confidence: float | None

    # Temporal check (for F3)
    f3_followup_sent: bool
    f3_followup_response: str | None  # "used" / "not_used" / None

    # Verbatim justification
    classification_rationale: str   # Why this classification

    # Behavioral notes
    behavior_transitions: list[str]  # If behavior changed during session
    hybrid_matches: list[str]        # F-types that co-occur

    # Meta
    interpreter_notes: str            # Additional context
```

---

## 6. Confidence Scoring Guide

### High Confidence (≥0.7)

```
F4 Methodology Doubt:
  - verbatim_skeptic_questions >= 3
  - tct_override_behavior = OVERRIDE
  - tct_dependency_reason = FUNDAMENTAL_DOUBT

F5 Compliance Mismatch:
  - user_type = Security Auditor
  - tct_dependency_reason = SOLVABLE_PRODUCT_GAP
  - Missing control mapping (identified from verbatim)

F7 Political Buy-In:
  - warning_3_needs_team = true
  - warning_2_has_incumbent = true
  - verbatim includes "manager" or "policy"
```

### Medium Confidence (0.4–0.7)

```
F1 vs F2 ambiguous:
  - Has incumbent ("Skybox")
  - But mentions process constraints
  - Cannot determine if "nice extra" or "blocked by process"

F6 Feature Extraction:
  - adoption_2_explain_used = true
  - But adoption_4_cicd_weak = true (mixed signals)
  - May be expanding or narrowing

F2 Workflow Inertia:
  - "I'd use but process"
  - But no verbatim about team buy-in needed
  - Individual desire clear but org blockers unclear
```

### Low Confidence (≤0.3)

```
F3 Silent (any session with zero signals):
  - Cannot classify without follow-up
  - Session behavior may not predict real adoption
  - Time-dependent, not static

Any ambiguous multi-F match:
  - Hybrid behaviors = lower confidence per F-type
  - Don't force single classification
```

---

## 7. Summary

### The 7 Failure Modes

| ID | Name | Core Question | Confidence Typical |
|----|------|---------------|-------------------|
| F1 | Ecosystem Trap | "Nice but extra" vs replacement | 0.6 |
| F2 | Workflow Inertia | "Want but blocked by process" | 0.5 |
| F3 | Silent | "Used? Rejected? Unknown?" | 0.2 (needs follow-up) |
| F4 | Methodology Doubt | "Can I trust the model?" | 0.9 |
| F5 | Compliance Mismatch | "Does it map to my controls?" | 0.85 |
| F6 | Feature Extraction | "One piece, not whole" | 0.6 |
| F7 | Political Buy-In | "Blocked by manager/policy" | 0.7 |

### Key Principles

1. **F1–F2–F7**: Ecosystem/org barriers — not ConfigGuard failures
2. **F4–F5**: Product gaps — fixable via roadmap
3. **F6**: Fragmentation risk — bundling issue
4. **F3**: Most dangerous — time-dependent, needs follow-up

### Critical Reminder

**This taxonomy is an interpretive lens, not a scoring system.**

- Do not use F1–F7 in GO/NO-GO decision
- Do not lock definitions before real data
- Let real users break and expand these categories
- Track confidence per classification
- F3 is the only time-dependent failure mode

---

## 8. Open Questions for Real-User Phase

1. **Will F3 (Silent) resolve cleanly with 1-week follow-up?**
   - If response rate low → F3 stays unknown
   - If response rate high → F3 classification reliable

2. **Do hybrid F-types cluster in specific user types?**
   - If yes → User type determines primary F
   - If no → Hybrid is universal, can't simplify

3. **Does F1 (Ecosystem) show up differently by incumbent type?**
   - "We use Skybox" vs "We use Excel" vs "We use nothing"
   - May need sub-classification of F1

4. **Will F6 (Feature Extraction) predict full vs narrow adoption?**
   - Single feature interest → eventual full adoption?
   - Or single feature = max adoption ever?

5. **Does F4 (Methodology Doubt) resolve with documentation?**
   - If yes → Build methodology docs as adoption driver
   - If no → F4 users are unconvertable in v1.0