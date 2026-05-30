# ConfigGuard SAUS v3 — Adversarial Decision Stress Test

**Status**: Production-Ready
**Version**: v3.0
**Date**: 2026-05-30
**Purpose**: Stress-test the v1.2 decision contract against adversarial reality

---

## 0. What SAUS v3 Is vs Previous Versions

| Version | Question | Nature |
|---------|----------|--------|
| SAUS v1 | Does taxonomy classify correctly? | Classification test |
| SAUS v2 | Does protocol eliminate bias? | Bias elimination test |
| **SAUS v3** | **Does decision contract survive adversarial ambiguity?** | **Decision stress test** |

**SAUS v3 does NOT test:**
- User understanding (H1)
- Trust calibration (TCT)
- Taxonomy accuracy (F1–F7)

**SAUS v3 ONLY tests:**
- Decision stability under contradictory signals
- Decision robustness under adversarial injections
- Decision non-collapsibility under noise

---

## 1. Core Concepts

### Decision Stability Index (DSI)

```python
@dataclass
class DecisionStabilityIndex:
    """Measures decision contract consistency under stress."""

    consistent_decisions: float  # % of sessions with stable decision
    flipped_due_to_user_type: float  # % that flipped based on user type
    flipped_due_to_drifts: float  # % that flipped due to DRIFT detection
    false_negative_go: float  # % sessions that should GO but NO-GO
    false_positive_go: float  # % sessions that should NO-GO but GO

    @property
    def dsi_score(self) -> float:
        """
        DSI = 1.0 - (false_negative + false_positive)
        1.0 = perfect decision stability
        0.5 = 50% error rate
        """
        return 1.0 - (self.false_negative_go + self.false_positive_go)
```

**DSI Thresholds:**

```
DSI ≥ 0.9: DECISION STABLE — decision contract is robust
DSI 0.7–0.9: MARGINAL — review borderline cases
DSI < 0.7: DECISION UNSTABLE — contract needs redesign
```

### Failure Mode Collapse Map

```python
@dataclass
class FailureModeCollapse:
    """Maps which F-types cause decision collapse."""

    f1_collapse_risk: str  # "HIGH" / "MEDIUM" / "LOW" / "N/A"
    f2_collapse_risk: str
    f3_collapse_risk: str
    f4_collapse_risk: str
    f5_collapse_risk: str
    f6_collapse_risk: str
    f7_collapse_risk: str

    dominant_collapse_mode: str  # Which F causes most instability
    critical_drifts: list[str]  # Which DRIFT types cause collapse
```

### Contract Robustness Score (CRS)

```python
@dataclass
class ContractRobustnessScore:
    """Overall decision contract stability."""

    stable_under_adversary: bool
    weakest_contract_point: str  # DRIFT / F3 / F5 / F4 / F7
    stability_confidence: float  # 0.0–1.0
    recommended_action: str  # "PROCEED" / "REVIEW" / "REDESIGN"
```

---

## 2. Adversarial Injections

### Injection Design Principle

Each injection introduces **contradictory authority** or **suppressed information** that challenges the decision contract.

**NOT tested:** Can user understand output? (SAUS v1/v2 handled this)
**TESTED:** Does decision remain stable when reality contradicts assumptions?

---

### Injection A: Contradictory Authority (F4 + F7 conflict)

**Setup:** Skeptic user mentions internal policy against automated SNMP detection

**Verbatim script:**
```
User: "This looks fine for telnet, but our internal policy says
       we NEVER trust automated SNMP detection tools.
       Any automated tool that flags SNMP gets escalated to our
       security team regardless of the score."
```

**What this tests:**
- F4 (Methodology Doubt) + F7 (Political Buy-In) simultaneously
- Decision contract may see F4 → NO-GO or F7 → CONDITIONAL
- But policy override makes both irrelevant
- **Collapse risk:** Decision flips when authority is invoked

**Expected decision under contract:** CONDITIONAL (F4 + F7 hybrid)
**Actual decision:** Should be CONDITIONAL but may collapse to NO-GO (policy is absolute block)

---

### Injection B: Latent Integration Dependency (F1 + F7 hybrid)

**Setup:** Pragmatist has Skybox but only evaluates tools that integrate with ServiceNow

**Verbatim script:**
```
User: "We already use Skybox for most of this. But honestly,
       if ConfigGuard doesn't integrate with ServiceNow CMDB,
       it won't matter how good the analysis is.
       We only manage what we track in CMDB."
```

**What this tests:**
- F1 (Ecosystem) + F7 (Political) + Integration dependency
- Decision contract sees F1 → CONDITIONAL
- But integration requirement is binary (not in contract)
- **Collapse risk:** Contract says GO but real adoption blocked by missing integration

**Expected decision under contract:** CONDITIONAL (F1 dominant)
**Actual decision:** Should be NO-GO until ServiceNow integration confirmed

---

### Injection C: Silent Acceptance Trap (F3 false positive)

**Setup:** User says nothing bad, nothing good — just "looks fine"

**Verbatim script:**
```
Interviewer: "What do you think?"
User: "Looks fine."
[Long pause]
Interviewer: "Any questions?"
User: "Nope."
[Session ends]
```

**What this tests:**
- F3 (Silent) with zero signals
- H1 = 3/4 (passes comprehension)
- TCT = ESCALATE (not clearly positive or negative)
- No F-type fits cleanly
- **Collapse risk:** Contract may assign F3 → DON'T COUNT but silent = potentially best adopter

**Expected decision under contract:** CONDITIONAL or INCONCLUSIVE
**Actual decision:** Should flag as F3_UNRESOLVED requiring follow-up

---

### Injection D: Control Mapping Dependency Flip (F5 decision flip)

**Setup:** User sees standard Material B first, then B-auditor variant

**Verbatim script:**
```
Interviewer: [Shows Material B-standard]
User: "I don't see how this maps to our CIS controls.
       We need control ID and evidence for audit."

[Interviewer switches to Material B-auditor]

User: "Oh, this is what we need. We'd use this immediately."
```

**What this tests:**
- F5 (Compliance Mismatch) decision flip when B-auditor shown
- Contract says F5 → CONDITIONAL with standard material
- But B-auditor resolves F5 immediately
- **Collapse risk:** Decision depends entirely on which material shown first

**Expected decision under contract:** CONDITIONAL (F5 present)
**Actual decision:** GO if B-auditor material used in real session

---

## 3. SAUS v3 Session Structure

### Phase 1: Normal Run (v1.2 pipeline)

```
[0-2 min]   Context setting
[2-5 min]   H1 + H1x (no change from v1.1)
[5-8 min]   H2 (with appropriate Material B)
[8-11 min]  H3
[11-14 min] H4
[14-18 min] TCT-1 + TCT-2
[18-22 min] TCT-3
[22-26 min] F-type assignment + verbatim
[26-30 min] DRIFT validator (2 min)
[30-35 min] Decision contract application
```

**Output:** Standard decision output (GO/NO-GO/CONDITIONAL)

### Phase 2: Adversarial Injection (15 min)

```
[35-40 min]  Select injection based on F-type
[40-45 min]  Introduce injection without prompting
[45-48 min]  Observe decision reaction
[48-50 min]  Re-apply decision contract with new data
```

**Output:** Does decision flip? Why? What failed in contract?

---

## 4. Per-Injection Analysis Template

### For Each Injection, Answer:

```markdown
## Injection [A/B/C/D] Analysis

### Session Baseline
- F-type (before injection): F[X]
- Decision (before injection): [GO/NO-GO/CONDITIONAL]
- DRIFT status: [D0/D1/D2/etc or None]

### Injection Introduced
- Type: [A/B/C/D]
- Trigger verbatim: [user quote]

### Decision Under Stress
- Decision (after injection): [GO/NO-GO/CONDITIONAL]
- Did decision flip?: [YES/NO]
- If yes, from what to what: [GO → CONDITIONAL]

### Collapse Analysis
- What caused the flip?: [specific contract rule]
- Is this contract failure or correct adaptation?: [FAILURE/CORRECT]
- If contract failure, which rule?: [rule description]

### DSI Impact
- false_negative_affected?: [YES/NO]
- false_positive_affected?: [YES/NO]
- DSI delta: [+/- X%]
```

---

## 5. SAUS v3 Pass Criteria

### DSI Thresholds

```
SAUS v3 PASSES if:
  DSI ≥ 0.85
  AND no single injection causes >30% DSI drop
  AND decision contract stability confirmed under:
    - F4 + F7 hybrid
    - F1 + F7 hybrid
    - F3 unknown state
    - F5 decision flip (B-auditor material)
```

### Failure Mode Collapse Criteria

```
SAUS v3 PASSES if:
  critical_collapse_modes: ≤ 2
  AND no F-type causes complete decision inversion
  AND DRIFT > 40% does NOT trigger GO (conservative)
```

### Contract Robustness Criteria

```
SAUS v3 PASSES if:
  weakest_point identified and documented
  AND no "hidden collapse" (decision looks stable but isn't)
  AND F3 handling requires explicit follow-up protocol
```

---

## 6. Failure Mode Collapse Map Template

```markdown
## Failure Mode Collapse Map

### F1 (Ecosystem Trap)
- Collapse risk: [HIGH/MEDIUM/LOW]
- Triggers: [what causes decision collapse]
- Under stress: [how F1 decision behaves]

### F2 (Workflow Inertia)
- Collapse risk: [HIGH/MEDIUM/LOW]
- Triggers: [what causes decision collapse]
- Under stress: [how F2 decision behaves]

### F3 (Silent)
- Collapse risk: [HIGH — undetectable in session]
- Triggers: [what causes decision collapse]
- Under stress: [F3 is invisible in session, only visible at follow-up]

### F4 (Methodology Doubt)
- Collapse risk: [HIGH — policy override collapses F4]
- Triggers: [what causes decision collapse]
- Under stress: [authority overrides F4]

### F5 (Compliance Mismatch)
- Collapse risk: [MEDIUM — B-auditor material resolves immediately]
- Triggers: [what causes decision collapse]
- Under stress: [decision flip with B-auditor material]

### F6 (Feature Extraction)
- Collapse risk: [LOW — single feature adoption is honest signal]
- Triggers: [what causes decision collapse]
- Under stress: [stable if correctly classified]

### F7 (Political Buy-In)
- Collapse risk: [HIGH — manager veto is absolute]
- Triggers: [what causes decision collapse]
- Under stress: [veto power collapses decision regardless of signals]

### Dominant Collapse Mode: [F#]
### Critical DRIFT Types: [D#]
```

---

## 7. SAUS v3 Output Format

### Per-Session Output

```markdown
## SAUS v3 Session [ID]

### Phase 1: Normal Decision
- F-type: F[X]
- Decision: [GO/NO-GO/CONDITIONAL]
- DRIFT: [D0/D1/etc or None]
- Taxonomy trust: [HIGH/MEDIUM/LOW]

### Phase 2: Adversarial Injection
- Injection applied: [A/B/C/D]
- Decision post-injection: [GO/NO-GO/CONDITIONAL]
- Decision flipped?: [YES/NO]

### DSI Contribution
- This session DSI: [1.0 / 0.8 / etc]
- Cumulative DSI: [after this session]

### Contract Robustness
- Stable under adversary?: [YES/NO/PARTIAL]
- Weakest point exposed?: [F#/DRIFT]
```

### Aggregate SAUS v3 Output

```markdown
## SAUS v3 Aggregate Results

### Decision Stability Index
- DSI Score: [X] (≥0.85 = PASS)
- Consistent decisions: [X%]
- Flipped due to user type: [X%]
- Flipped due to DRIFT: [X%]

### Failure Mode Collapse Map
- F1: [risk] | F2: [risk] | F3: [risk]
- F4: [risk] | F5: [risk] | F6: [risk] | F7: [risk]
- Dominant collapse mode: [F#]
- Critical DRIFT types: [D#]

### Contract Robustness Score
- Overall: [STABLE/MARGINAL/UNSTABLE]
- Weakest point: [F#/DRIFT]
- Recommended action: [PROCEED/REVIEW/REDESIGN]

### SAUS v3 Verdict
- [PASS / MARGINAL / FAIL]
- If MARGINAL: Specific rules to review
- If FAIL: Redesign decision contract before real users
```

---

## 8. SAUS v3 Execution Plan

### Sessions Required: 4 (minimum)

```
S-A: The Skeptic with Authority Override (Injection A)
S-B: The Pragmatist with Integration Dependency (Injection B)
S-C: The Silent with Zero Signals (Injection C)
S-D: The Auditor with Control Mapping Flip (Injection D)
```

### Quick Reference: Which Injection Per User Type

| User Type | Primary F | Use Injection |
|-----------|-----------|---------------|
| Network Security Analyst | F4 (Skeptic) | A (Authority Override) |
| Platform Lead | F2/F1 (Pragmatist) | B (Integration Dependency) |
| Any (low signal) | F3 (Silent) | C (Silent Trap) |
| Security Auditor | F5 (Compliance) | D (Control Mapping Flip) |

---

## 9. Key Insight

**SAUS v3 is not a validation test. It is a stress test.**

```
SAUS v1/v2: "Is our measurement correct?"
SAUS v3: "Does our decision survive reality being worse than our model?"
```

**The question SAUS v3 answers:**

> "Given that reality is messier than our model, will our decision contract still make defensible choices?"

**If DSI < 0.85:**
- Don't proceed to real users
- Redesign decision contract
- SAUS v4 with new contract

**If DSI ≥ 0.85 but marginal on specific F-types:**
- Document as known weak points
- Add explicit handling to session runbook
- Proceed to real users with caveats

---

## 10. Open Questions for SAUS v3

1. **Will F7 (Political) cause complete decision inversion?**
   - If policy override collapses any F → F7 is critical weakness
   - May need "veto override" flag in decision contract

2. **Will F3 (Silent) create false positive GO?**
   - Zero signals + GO decision = dangerous
   - Need protocol: F3 → automatic CONDITIONAL + follow-up required

3. **Will B-auditor material cause F5 decision flip?**
   - If yes: This means F5 decision is material-dependent
   - Need protocol: Auditor user → always use B-auditor first

4. **Is DRIFT too slow to prevent bad decisions?**
   - DRIFT is post-classification
   - May need "DRIFT warning" to block decision until resolved

5. **Does DSI stabilize after 4 sessions?**
   - If yes: SAUS v3 is sufficient
   - If no: Need more synthetic users or larger batch