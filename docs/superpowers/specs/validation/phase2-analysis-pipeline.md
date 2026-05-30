# ConfigGuard Phase 2 Analysis Pipeline

**Status**: Ready
**Date**: 2026-05-30
**Purpose**: Process raw replies + screener responses into F-type posterior + DRIFT detection

---

## 0. Input Data (What to Collect)

### From Outreach Phase 1

```
raw_replies/
├── version_a_replies.txt     # Full email threads, 3 users
├── version_b_replies.txt    # Full email threads, 3 users
├── no_reply_count.txt       # A: X, B: X
└── response_timestamps.txt   # For latency analysis
```

### From Screener Calls

```
screener_responses/
├── U001/
│   ├── q1_primary_workflow: "A"  # or B/C/D/E
│   ├── q2_where_caught: "a"      # or b/c/d/e
│   ├── q3_system_of_record: "1"  # or 2/3/4/5
│   ├── q4_tooling: ["II", "III"] # multiple selection
│   ├── q5_adoption_latency: "beta"
│   └── f_type_prior_computed: {F1: 0.2, F2: 0.4, ...}
├── U002/
│   └── ...
```

---

## 1. A/B Language Clustering

### Step 1: Extract Reply Language

For each reply, extract:

```
reply_id, version, first_response_language, self_descriptor, interest_level
```

**Interest Level Coding:**
```
HIGH: "yes I'm available tomorrow" / "definitely interested"
MEDIUM: "maybe next week" / "sounds interesting, can you send more info"
LOW: "not now but keep me posted" / "not my area"
NO_REPLY: (no response within 48h)
```

### Step 2: Compute A/B Separation Score

```python
def compute_ab_separation(replies_a: list, replies_b: list) -> dict:
    """
    Measures how well A vs B language clusters apart.
    """

    # Language features
    audit_keywords = ["compliance", "CIS", "NIST", "audit", "control mapping"]
    devops_keywords = ["CI/CD", "pipeline", "GitHub", "deployment", "automation"]

    # Count keyword presence per reply
    def count_keywords(text, keywords):
        return sum(1 for k in keywords if k.lower() in text.lower())

    # Score each reply
    audit_score_a = [count_keywords(r, audit_keywords) for r in replies_a]
    devops_score_a = [count_keywords(r, devops_keywords) for r in replies_a]
    audit_score_b = [count_keywords(r, audit_keywords) for r in replies_b]
    devops_score_b = [count_keywords(r, devops_keywords) for r in replies_b]

    # Separation strength
    # If A has high audit, low devops and B is opposite → strong separation
    # If both have similar mix → weak separation

    separation_strength = {
        "audit_in_A": sum(audit_score_a) / len(audit_score_a) if audit_score_a else 0,
        "audit_in_B": sum(audit_score_b) / len(audit_score_b) if audit_score_b else 0,
        "devops_in_A": sum(devops_score_a) / len(devops_score_a) if devops_score_a else 0,
        "devops_in_B": sum(devops_score_b) / len(devops_score_b) if devops_score_b else 0,
    }

    # Separation validity
    # A should have audit > devops, B should have devops > audit
    a_valid = separation_strength["audit_in_A"] > separation_strength["devops_in_A"]
    b_valid = separation_strength["devops_in_B"] > separation_strength["audit_in_B"]

    return {
        "separation_strength": separation_strength,
        "ab_separation_valid": a_valid and b_valid,
        "overlap_detected": abs(
            separation_strength["audit_in_A"] - separation_strength["audit_in_B"]
        ) < threshold,
    }
```

### Step 3: Output

```markdown
## A/B Language Clustering Results

### Response Rate
- Version A (compliance-first): X/3 responses
- Version B (devops-first): X/3 responses

### Language Separation
- audit keywords in A: X.X avg
- audit keywords in B: X.X avg
- devops keywords in A: X.X avg
- devops keywords in B: X.X avg

### Separation Valid? [YES/NO]
- If YES: A/B framing successfully segments audience
- If NO: A/B overlap significant, may cause F-type misclassification

### Overlap Detected? [YES/NO]
- If YES: Role ambiguity present, hard to separate F1 vs F5
```

---

## 2. Posterior F-Type Inference (Probabilistic)

### Why Probabilistic, Not Hard Classification

**Problem:** Early batch (n=6) is too small for hard classification.

**Solution:** Compute likelihood distribution, not point estimates.

```python
def compute_posterior_f_type(screener_responses: list) -> dict:
    """
    Compute probabilistic F-type distribution from screener Q1-Q5.
    Returns likelihood, not hard classification.
    """

    # Start with prior from screener (compute_f_type_prior from v1.3-screener-protocol.md)
    priors = [compute_f_type_prior(
        q1=r["q1_primary_workflow"],
        q2=r["q2_where_caught"],
        q3=r["q3_system_of_record"],
        q4=r["q4_tooling"],
        q5=r["q5_adoption_latency"],
    ) for r in screener_responses]

    # Aggregate across batch
    aggregated = {
        "F1": [], "F2": [], "F3": [], "F4": [],
        "F5": [], "F6": [], "F7": []
    }

    for p in priors:
        aggregated["F1"].append(p.f1_probability)
        aggregated["F2"].append(p.f2_probability)
        aggregated["F3"].append(p.f3_probability)
        aggregated["F4"].append(p.f4_probability)
        aggregated["F5"].append(p.f5_probability)
        aggregated["F6"].append(p.f6_probability)
        aggregated["F7"].append(p.f7_probability)

    # Compute mean and std per F-type
    posterior = {}
    for f, values in aggregated.items():
        posterior[f] = {
            "mean": statistics.mean(values),
            "std": statistics.stdev(values) if len(values) > 1 else 0,
        }

    return posterior
```

### Output

```markdown
## Posterior F-Type Distribution (n=X)

### F-Type Likelihood (mean ± std)
- F1 (Ecosystem): X.X ± X.X
- F2 (Workflow): X.X ± X.X
- F3 (Silent): X.X ± X.X
- F4 (Methodology): X.X ± X.X
- F5 (Compliance): X.X ± X.X
- F6 (Feature): X.X ± X.X
- F7 (Political): X.X ± X.X

### Dominant F-Type(s)
- Primary: F[X] (mean: X.X)
- Secondary: F[Y] (mean: X.X)

### Confidence Assessment
- [HIGH] if any F-type mean > 0.5
- [MEDIUM] if any F-type mean 0.3-0.5
- [LOW] if all F-type means < 0.3

### Hybrid Risk Flag
- [YES] if 2+ F-types have mean > 0.3
- [NO] if one F-type dominates
```

---

## 3. DRIFT v1 Detection

### Check for These Signals

```python
@dataclass
class DriftSignal:
    """DRIFT signals in early batch."""

    # D0: Out of schema
    out_of_schema_count: int  # Language doesn't fit F1-F7 at all
    out_of_schema_examples: list[str]

    # D3: Context switch (role ambiguity)
    context_switch_count: int  # User fits multiple F-types equally
    context_switch_users: list[str]

    # D5: False positive adoption risk
    false_positive_risk: list[str]  # High interest but no workflow signals
    false_negative_risk: list[str]  # Low interest but might adopt silently
```

### Detection Rules

```python
def detect_drift_v1(replies: list, screener: list) -> DriftSignal:
    """
    Detect DRIFT in early batch.
    """

    drift = DriftSignal(
        out_of_schema_count=0,
        out_of_schema_examples=[],
        context_switch_count=0,
        context_switch_users=[],
        false_positive_risk=[],
        false_negative_risk=[],
    )

    # Rule 1: Language doesn't fit F1-F7
    # If reply language is generic ("interesting tool") without specific workflow reference
    generic_patterns = ["interesting", "cool tool", "nice idea", "keep me posted"]
    for reply in replies:
        if any(p in reply.lower() for p in generic_patterns):
            if not any(k in reply.lower() for k in ["audit", "CI/CD", "compliance", "pipeline"]):
                drift.out_of_schema_count += 1
                drift.out_of_schema_examples.append(reply[:100])

    # Rule 2: Context switch (screener Q1 ambiguous)
    for s in screener:
        if s["q1_primary_workflow"] in ["C", "D"]:  # Ambiguous options
            # Check if other Q's also ambiguous
            if s["q2_where_caught"] in ["d", "e"] and s["q3_system_of_record"] == "5":
                drift.context_switch_count += 1
                drift.context_switch_users.append(s["user_id"])

    # Rule 3: False positive (high interest but no workflow signals)
    # Reply says "yes" but screener shows F3 or workflow gap
    for reply, screen in zip(replies, screener):
        if "yes" in reply.lower() and screen["f_type_prior"].f3_probability > 0.4:
            drift.false_positive_risk.append(screen["user_id"])

    return drift
```

### Output

```markdown
## DRIFT v1 Detection (Early Batch)

### D0: Out of Schema
- Count: X
- Examples: [verbatim if available]

### D3: Context Switch
- Count: X
- Users: [list]

### D5: False Positive Risk
- Users: [list]
- Interpretation: High verbal interest but weak workflow alignment

### DRIFT Rate
- X / total batch
- If > 40%: Taxonomy needs redesign before proceeding
- If < 20%: Taxonomy stable, proceed
```

---

## 4. False Taxonomy Signal Check

### The Critical Question

> Is your system actually measuring adoption failure, or just language segmentation of early adopters?

### Detection Method

```python
def false_taxonomy_signal_check(
    posterior: dict,
    ab_separation: dict,
    drift: DriftSignal,
) -> dict:
    """
    Detect where F1-F7 model may be overfitting to early adopter language
    rather than capturing real adoption failure.
    """

    findings = []

    # Check 1: Is F5 over-indexed?
    if posterior["F5"]["mean"] > 0.5:
        # Was this driven by A/B framing (language) or real compliance workflow?
        if ab_separation["ab_separation_valid"]:
            findings.append({
                "risk": "F5_OVER_INDEX",
                "cause": "A/B framing attracted auditor-dominant sample",
                "action": "Cannot conclude F5 is dominant in population",
            })

    # Check 2: Is F1 actually F2 in disguise?
    # (User says "CI/CD" but their actual problem is workflow inertia, not ecosystem)
    if posterior["F1"]["mean"] > 0.3 and posterior["F2"]["mean"] > 0.2:
        findings.append({
            "risk": "F1_F2_AMBIGUITY",
            "cause": "DevOps language may conflate ecosystem (F1) with workflow (F2)",
            "action": "Separate in session with Q2/Q3 deep-dive",
        })

    # Check 3: Is F3 truly silent or just early adopters with low engagement?
    if drift.out_of_schema_count > 0:
        findings.append({
            "risk": "F3_INVISIBILITY",
            "cause": "No-reply may be low engagement, not latent adoption",
            "action": "Distinguish 'no reply from interest' vs 'no reply from rejection'",
        })

    # Check 4: Is A/B separation creating artificial F1/F5 split?
    if ab_separation["overlap_detected"]:
        findings.append({
            "risk": "A/B_SPLIT_INVALID",
            "cause": "A/B messages segment language but not adoption behavior",
            "action": "Need real behavior data, not just message response",
        })

    return {
        "findings": findings,
        "false_taxonomy_risk": len(findings) > 0,
        "can_make_strong_inference": len(findings) == 0 and drift.drift_rate < 0.2,
    }
```

### Output

```markdown
## False Taxonomy Signal Check

### Risks Detected
[Each finding with cause + recommended action]

### Overall Assessment
- [HIGH RISK] Model may be overfitting to early adopter language
- [MEDIUM RISK] Some ambiguity in F1/F2/F5 separation
- [LOW RISK] Signals look like real behavior, not just language clustering

### Key Question Answer
"Is system measuring adoption failure, or just language segmentation?"
→ [ANSWER based on findings]
```

---

## 5. Phase 2 Summary

### Decision Gate

```markdown
## Phase 2 Verdict

### Can we proceed to full calibration batch?
[YES] if:
  - A/B separation valid
  - DRIFT rate < 40%
  - No false taxonomy signals (or low confidence only)
  - At least 4 qualified responses

[CONDITIONAL] if:
  - Separation valid but weak
  - Some DRIFT detected but manageable

[STOP] if:
  - A/B overlap significant
  - DRIFT rate > 40%
  - High false taxonomy risk
```

### Next Action

```
If YES: Expand to full 15-20 outreach
If CONDITIONAL: Recruit 2-3 more in dominant F-type, re-assess
If STOP: Redesign A/B messages before continuing
```

---

## 6. Raw Data Collection Template

```markdown
## Raw Data to Collect (for analysis)

### From 48h Waiting Period

1. Reply count by version
   - A replied: X/3
   - B replied: X/3
   - Total reply rate: X%

2. Reply verbatim (as-is, no editing)
   - Copy full email/LinkedIn message text
   - Include timestamps

3. Interest level (simple coding)
   - HIGH / MEDIUM / LOW / NO_REPLY

4. Self-descriptor in reply
   - What does user say they do?
   - What keywords do they use?

### From Screener Calls (for each qualified respondent)

Q1 answer: [letter]
Q2 answer: [letter]
Q3 answer: [number]
Q4 answer: [letters]
Q5 answer: [greek letter]

F-type prior computed: [dict]
```

---

## 7. Phase 2 Executable Questions

When raw data arrives, I'll answer these 5 questions:

```
1. A/B separation: Is compliance-first vs devops-first actually segmenting the population?
   → YES/NO + separation strength score

2. Response asymmetry: Which version got more replies? Is the difference significant?
   → Reply rate + statistical significance

3. F-type distribution: What is the actual F-type posterior from this batch?
   → Mean + std per F-type

4. DRIFT detected: What taxonomy failure modes appeared in early data?
   → D0/D3/D5 counts + verbatim examples

5. False taxonomy signal: Is the F-type signal real or just A/B language clustering?
   → Risk assessment per finding + overall confidence
```