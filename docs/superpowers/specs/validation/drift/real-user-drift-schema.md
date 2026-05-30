# ConfigGuard — Real User Drift Schema v1.0

**Status**: Independent Drift Detection Layer
**Version**: v1.0
**Date**: 2026-05-30
**Purpose**: Capture where F1–F7 taxonomy fails to explain real user behavior

**IMPORTANT**: This is NOT part of the measurement system. It is a meta-layer that detects taxonomy failure, not a new classification system. Do not merge into F1–F7.

---

## 0. Design Philosophy

### Why This Layer Exists

**Problem:** F1–F7 can become a cognitive filter — once you have categories, you tend to force-fit everything into them.

**What DRIFT detects:**
- When real behavior doesn't fit F1–F7
- When multiple F-types co-occur and single-label fails
- When behavior changes over time (not captured statically)
- When observed signals contradict actual adoption

**Core principle:**
```
F1–F7 = "user failed adoption because..."
DRIFT = "our taxonomy failed to explain what happened"
```

### Layer Architecture

```
Layer 1: Measurement (v1.1 frozen)
  H1 / H2 / H3 / H4 / TCT / state machine
  → "What happened in the session?"

Layer 2: Behavioral Signals (metrics system)
  adoption_signals / warning_signals / verbatim
  → "What did the user do?"

Layer 3: Interpretation (adoption-failure-taxonomy.md)
  F1–F7 failure modes
  → "Why didn't adoption happen?"

Layer 4: Drift Detection (this document)
  D0–D6 failure modes
  → "When did our interpretation framework fail?"
```

### When to Use DRIFT

**Primary use:** After every 2-3 sessions, check if taxonomy is explaining behavior or forcing it.

**Trigger conditions (any of these):**
- Session behavior doesn't match any F1–F7 description
- User matches multiple F-types simultaneously
- User says something that contradicts their F classification
- User behavior changes between session and follow-up
- Taxonomy classification confidence < 0.4

---

## 1. The 7 Drift Modes

### D0: OUT_OF_SCHEMA (Most Critical)

**Definition:** User behavior cannot be classified into any F1–F7. Taxonomy design space is insufficient.

**Classic Signals:**
- "This tool is nice but we're already automated further downstream"
- "We use this to generate reports that feed into our AI pipeline"
- Complete workflow mismatch (e.g., SecOps → LLM integration)
- User references completely unexpected use case

**Example verbatim:**
```
"We don't use tools to make security decisions — we use them
to generate evidence for our AI system that does the analysis."
```

**Why Critical:**
- This is NOT a user failure
- This is a taxonomy design gap
- May indicate ConfigGuard is serving a different product category than designed

**Classification confidence:** N/A — out of schema means taxonomy doesn't apply

**Action:**
- Log verbatim verbatim
- Do NOT force into any F-type
- Flag as D0 for post-batch analysis
- Consider: Is this a v2 product direction signal?

### D1: HYBRID_FAILURE

**Definition:** Single user simultaneously triggers multiple F-types, but single-label classification fails.

**Classic Signals:**
- "We use Skybox" (F1) + "But need control mapping" (F5) + "Manager approval needed" (F7)
- User matches F4 on some dimensions, F5 on others, F6 on others
- Single-label classification leaves out significant behavior

**Example:**
```
User has:
- incumbent tool (F1)
- compliance requirement (F5)
- team buy-in needed (F7)
- methodology skepticism (F4)

Single F classification misses 3 of 4 failure dimensions.
```

**Why Critical:**
- Real world is multi-dimensional, not single-label
- F1–F7 assumes discrete failure types
- Reality is superposition of failure modes

**Classification confidence:** 0.3–0.5 (lower than single-F matches)

**Action:**
- Record all matching F-types with confidence per F
- Primary F = highest confidence
- Secondary F's = note but don't weight equally
- Flag as D1 for post-batch clustering analysis

### D2: TEMPORAL_SHIFT

**Definition:** User's F-type is time-dependent, not a static property. Behavior today ≠ behavior tomorrow.

**Classic Signals:**
- "I don't trust it now — but in 6 months with track record, maybe"
- "We can't integrate now — Q3 we have capacity"
- User's timeline for adoption is conditional on future state

**Example verbatim:**
```
"Trust is time-dependent for us. We've been burned by similar
tools. 6 months of zero false positives and we'd consider switching."
```

**Why Critical:**
- F4 (Methodology Doubt) at t=0 may resolve at t=6months
- F2 (Workflow Inertia) at t=0 may resolve at t=Q3
- Static classification misses adoption trajectory

**Classification confidence:** Time-dependent (need follow-up to re-classify)

**Action:**
- At session: Classify as Fx with "TEMPORAL_SHIFT" flag
- At follow-up: Re-assess F-type
- Track temporal patterns: Does F4 → F1 (trust → adoption) or F4 → REJECTION?

### D3: CONTEXT_DEPENDENT_SWITCH

**Definition:** Same user shows different F-type in different contexts/modes.

**Classic Signals:**
- Audit mode: F5 (compliance mismatch)
- Incident response: F4 (methodology doubt)
- CI/CD mode: F1 (ecosystem trap)
- Same user, different F-type depending on which hat they're wearing

**Example:**
```
User in session: Network Security Analyst
- As auditor → F5 (needs control mapping)
- As incident responder → F4 (questions methodology)
- As pipeline owner → F1 (has Skybox)

Which is their "real" F-type? All are real.
```

**Why Critical:**
- F-type may not be a property of the user, but of the context
- Single session captures one context
- Adoption may depend on which context drives the decision

**Classification confidence:** 0.4–0.6 (depends on session context coverage)

**Action:**
- Note context when F-type is assigned
- If multi-context observed in single session → D3
- Post-batch: Cluster by context, not just user type

### D4: FALSE_NEGATIVE_ADOPTION

**Definition:** User appears to fail (H1 low, TCT negative, F4 skeptic) but will actually adopt.

**Classic Signals:**
- Skeptic (F4) verbal: "I don't trust this"
- Skeptic behavior: Integrates into pipeline anyway
- "This is like X but..." — comparative statement is actually interest
- Questions methodology — but asks detailed integration questions

**Example verbatim:**
```
"I don't trust automated security tools. But this could work
for our CI pipeline because it's CLI-based and we can test it."
```

**Why Critical:**
- Trust ≠ Usage
- Methodology skeptic may integrate for workflow reasons
- Negative verbal ≠ negative behavior

**Classification confidence:** 0.5–0.7 (need follow-up to confirm adoption)

**Action:**
- If skeptic verbal + CI/CD question → Possible D4, set confidence 0.5
- At follow-up: Check if pipeline integration happened
- If adopted despite skepticism → Confirm D4

### D5: FALSE_POSITIVE_ADOPTION

**Definition:** User says they will adopt (verbal yes) but behavior shows they won't.

**Classic Signals:**
- "Yeah we'd use this" — but no integration questions
- H4 preference = "ConfigGuard" — but no CI/CD signals
- No follow-up behavior despite stated interest
- Enthusiasm without behavioral evidence

**Example verbatim:**
```
"Yeah this is really cool, we could definitely use this."
[No questions about CI/CD integration]
[No follow-up after session]
[No team discussion]
```

**Why Critical:**
- verbal adoption ≠ real adoption
- Social desirability bias in sessions
- Gift card incentive may inflate adoption signals

**Classification confidence:** 0.6–0.8 (can often detect from session alone)

**Action:**
- Flag when: High verbal adoption + zero workflow signals
- Follow-up at 1 week: Did they try it?
- If no follow-up despite stated interest → D5 confirmed

### D6: WORKFLOW_ABSTRACTION_GAP

**Definition:** User understands output but abstraction level doesn't match their mental model.

**Classic Signals:**
- Auditor: Wants "control mapping" (compliance abstraction)
- ConfigGuard: Provides "risk scoring" (security abstraction)
- Neither wrong — but different representation layers
- "This tells me what to fix, not what to document"

**Example verbatim:**
```
"Your risk score is useful, but what I need for audit is
control ID → evidence → finding → remediation text.
Risk score is internal, control mapping is external."
```

**Why Critical:**
- Not a feature gap (all features work correctly)
- Not a UX gap (output is clear)
- It's a representation mismatch — different abstraction levels for different use cases

**Classification confidence:** 0.7–0.9 (often detectable from explicit abstraction statements)

**Action:**
- Identify the abstraction gap: Risk score vs Control mapping vs Evidence chain
- This is input for v1.1 roadmap: Which abstraction layers to support?
- Not a taxonomy failure — indicates product direction signal

---

## 2. DRIFT Detection Checklist

### Per-Session DRIFT Check

After each session, before finalizing F-type classification:

```
[ ] Does behavior match any F1–F7 cleanly?
    → Yes: Proceed to F-type classification
    → No: Flag D0, log verbatim

[ ] Do multiple F-types apply simultaneously?
    → No: Proceed
    → Yes: Flag D1, record all F-types with confidence

[ ] Does user reference time ("6 months", "next quarter", "when we have capacity")?
    → No: Proceed
    → Yes: Flag D2, log temporal condition

[ ] Did user switch contexts during session?
    → No: Proceed
    → Yes: Flag D3, note context transitions

[ ] Is skeptic verbal + pipeline interest?
    → No: Proceed
    → Yes: Flag D4 (possible), confidence 0.5

[ ] Is verbal adoption high + workflow signals zero?
    → No: Proceed
    → Yes: Flag D5 (possible), confidence 0.6

[ ] Did user explicitly mention abstraction mismatch?
    → No: Proceed
    → Yes: Flag D6, note which abstraction layers
```

### Post-Session Template Update

```python
@dataclass
class SessionWithDrift:
    """Standard session fields (v1.1)"""
    session_id: str
    h1_score: int
    tct_override_behavior: str
    # ... all v1.1 fields

    """DRIFT detection layer"""
    drift_detected: bool
    drift_type: str | None  # D0–D6 or None

    # If multiple F-types match (D1)
    hybrid_f_types: list[tuple[str, float]]  # [(F1, 0.6), (F5, 0.5)]

    # If temporal shift observed (D2)
    temporal_condition: str | None  # "6_months", "Q3_capacity"

    # If context switch observed (D3)
    context_transitions: list[str]  # ["auditor→operator"]

    # Confidence that F-type is correct
    taxonomy_trust_level: str  # "high" / "medium" / "low"
    taxonomy_trust_confidence: float  # 0.0–1.0

    # Override recommendation
    interpretation_override: str | None  # If DRIFT suggests F-type wrong
    interpretation_override_reason: str | None
```

---

## 3. DRIFT → Action Mapping

| Drift Type | Effect | Action |
|------------|--------|--------|
| D0: OUT_OF_SCHEMA | Taxonomy design gap | Log verbatim, consider product direction change |
| D1: HYBRID_FAILURE | Multi-dimensional reality | Don't force single F, report all with confidence |
| D2: TEMPORAL_SHIFT | Time-dependent adoption | Re-assess at follow-up, track trajectory |
| D3: CONTEXT_SWITCH | Context-dependent F | Cluster by context, not user type |
| D4: FALSE_NEGATIVE | Trust ≠ Usage | Follow-up at 1 week, confirm pipeline use |
| D5: FALSE_POSITIVE | Verbal ≠ Real | Follow-up at 1 week, confirm trial |
| D6: ABSTRACTION_GAP | Representation mismatch | Product direction input |

---

## 4. DRIFT Rate Monitoring

### Per-Batch Analysis

After each batch of 3-6 sessions:

```python
def compute_drift_rate(sessions: list[SessionWithDrift]) -> dict:
    """
    Track how often taxonomy fails to explain behavior.
    """
    total = len(sessions)
    drift_detected = sum(1 for s in sessions if s.drift_detected)

    drift_by_type = {
        "D0": sum(1 for s in sessions if s.drift_type == "D0"),
        "D1": sum(1 for s in sessions if s.drift_type == "D1"),
        "D2": sum(1 for s in sessions if s.drift_type == "D2"),
        "D3": sum(1 for s in sessions if s.drift_type == "D3"),
        "D4": sum(1 for s in sessions if s.drift_type == "D4"),
        "D5": sum(1 for s in sessions if s.drift_type == "D5"),
        "D6": sum(1 for s in sessions if s.drift_type == "D6"),
    }

    avg_taxonomy_trust = sum(
        s.taxonomy_trust_confidence for s in sessions
    ) / total

    return {
        "drift_rate": drift_detected / total,
        "drift_by_type": drift_by_type,
        "avg_taxonomy_trust": avg_taxonomy_trust,
        "low_trust_sessions": [
            s.session_id for s in sessions
            if s.taxonomy_trust_level == "low"
        ],
    }
```

### DRIFT Rate Thresholds

```
drift_rate < 20%:
  → Taxonomy is robust, F1–F7 covers most cases
  → GO decision safe to rely on F-type classification

drift_rate 20–40%:
  → Taxonomy has gaps, D0/D1/D2 are common
  → Use F-type as hint, not verdict
  → Consider adding new F-type based on D0 patterns

drift_rate > 40%:
  → Taxonomy structure insufficient
  → STOP using F-type for GO/NO-GO
  → Return to taxonomy redesign before decision
```

---

## 5. Meta-Principle: Taxonomy Humility

### The Core Risk

```
"The more categories you have, the more you try to fit everything into them."
```

This is the inverse of Goodhart's Law for classification systems:
- When classification is the tool, everything looks like a classification problem.

### DRIFT Schema Purpose

**NOT to add more categories.** DRIFT is a constraint on F1–F7:

```
Every time you assign an F-type, ask:
  "Is this classification or forcing?"
  "Does the behavior actually fit, or am I making it fit?"
  "What would count as evidence that this F-type is wrong?"
```

### DRIFT Confidence Score

For each session, rate how much you trust the F-type classification:

```python
def compute_taxonomy_trust(
    drift_detected: bool,
    drift_type: str | None,
    hybrid_f_types: list,
    verbatim_clarity: str,
) -> tuple[str, float]:
    """
    Returns: (trust_level, confidence)
    """
    if drift_detected and drift_type in ["D0", "D1"]:
        return ("low", 0.3)

    if len(hybrid_f_types) >= 3:
        return ("low", 0.4)

    if verbatim_clarity == "clear":
        if not drift_detected:
            return ("high", 0.85)
        elif drift_type in ["D4", "D5"]:
            return ("medium", 0.6)

    return ("medium", 0.5)
```

### Anti-Over-Classification Rules

```
1. If confidence < 0.5, don't assign F-type as primary
2. If D0 detected, log verbatim and move on
3. If D1 detected, report all F-types, don't pick one
4. If D2/D3 detected, this is data, not classification failure
5. If D4/D5 suspected, set confidence 0.5 and schedule follow-up
```

---

## 6. Summary

### The 7 Drift Modes

| DRIFT | Definition | Key Question | Trust Impact |
|-------|------------|---------------|--------------|
| D0 | OUT_OF_SCHEMA | "Does any F apply?" | Taxonomy doesn't cover this |
| D1 | HYBRID_FAILURE | "Do multiple F's apply?" | Can't single-label |
| D2 | TEMPORAL_SHIFT | "Is F stable over time?" | Time-dependent |
| D3 | CONTEXT_SWITCH | "Does F change with context?" | Context-dependent |
| D4 | FALSE_NEGATIVE | "Will they adopt despite skepticism?" | Trust ≠ Usage |
| D5 | FALSE_POSITIVE | "Will verbal adoption be real?" | Verbal ≠ Real |
| D6 | ABSTRACTION_GAP | "Is abstraction level wrong?" | Representation mismatch |

### DRIFT vs F-Type

```
F1–F7 = Why adoption failed (attribution)
DRIFT = When attribution fails (failure of attribution)
```

### Critical Reminder

**DRIFT is not a new classification system.**

Its only purpose is to detect when F1–F7 should NOT be applied.

If DRIFT rate exceeds 40%:
- Stop using F-type for decisions
- Taxonomy redesign needed before GO/NO-GO

---

## 7. Open Questions for Real-User Phase

1. **How often does D0 (OUT_OF_SCHEMA) occur?**
   - If frequent → F1–F7 covers narrow use case
   - If rare → Taxonomy is robust

2. **Does D1 (HYBRID_FAILURE) cluster by user type?**
   - If yes → User type determines which F is primary
   - If no → Hybrid is universal

3. **Does D2 (TEMPORAL_SHIFT) resolve cleanly with 1-week follow-up?**
   - If F4 → F1 trajectory observed → Temporal trust model exists
   - If no pattern → Time doesn't predict adoption

4. **Does D6 (ABSTRACTION_GAP) indicate product direction or taxonomy gap?**
   - If abstractable → New output format for v1.1
   - If fundamental → Different product category

5. **Is D4 (FALSE_NEGATIVE) more common than D5 (FALSE_POSITIVE)?**
   - If D4 > D5 → Users under-report adoption (good)
   - If D5 > D4 → Users over-report adoption (dangerous)