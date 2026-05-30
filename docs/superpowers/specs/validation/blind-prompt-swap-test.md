# ConfigGuard — Blind Prompt Swap Test v1.0

**Status**: Causal Invariance Test Design
**Version**: v1.0
**Date**: 2026-05-30
**Purpose**: Test whether F1–F7 is intrinsic latent structure or prompt-induced artifact

---

## 0. Why This Test Exists

### The Core Problem

Current system assumes:

```
User latent workflow (U) → Language (L) → Observed F-type (F)
```

But experiments混入了:

```
Prompt framing (P) → Language (L)
```

Real model is:

```
U ─┐
   ├──→ L → F
P ─┘
```

**We cannot distinguish which dominates.**

### What This Test Answers

> Does F1–F7 capture intrinsic user workflow structure, or is it a semantic projection induced by prompt framing?

If prompt dominates:
- F1–F7 = "narrative structure", not real structure
- Taxonomy is a self-fulfilling prophecy

If user dominates:
- F1–F7 = intrinsic latent structure ✅
- Taxonomy has causal validity

---

## 1. Causal Model

### Structural Equations

```
L = αU*U + βP*P + ε
F = f(L)
```

Where:
- U = user latent workflow type (fixed per user)
- P = prompt framing type (compliance A vs devops B)
- L = observed language output
- F = F-type classification
- α = user effect size (what we want to measure)
- β = prompt effect size (what we want to be small)
- ε = noise

### Testable Hypotheses

```
H1 (intrinsic structure): α >> β (user dominates)
H2 (prompt artifact): β >> α (prompt dominates)
H3 (hybrid): α ≈ β (both contribute)
```

---

## 2. Experimental Design

### Minimal Design (N=4)

| Group | User Type | Prompt Version | Expected if H1 | Expected if H2 |
|-------|-----------|----------------|----------------|----------------|
| G1 | DevOps | Compliance A | CI/CD language | Audit language |
| G2 | DevOps | DevOps B | CI/CD language | CI/CD language |
| G3 | Auditor | DevOps B | Audit language | CI/CD language |
| G4 | Auditor | Compliance A | Audit language | Audit language |

### Key Principle

**User-type fixed, prompt swapped.** This is within-subject comparison at population level.

### What to Measure (Frozen Variables)

**Primary signals (only these):**
1. Keyword domain:
   - audit/compliance terms: "CIS", "NIST", "control mapping", "evidence", "audit"
   - CI/CD terms: "pipeline", "GitHub Actions", "Jenkins", "deploy", "block"
   - generic infrastructure: "config", "server", "network"
2. Workflow anchoring:
   - CIS/NIST reference (yes/no)
   - CI/CD tool named (yes/no)
   - CMDB/ServiceNow mention (yes/no)

**Secondary signals:**
3. Initiation source:
   - USER-initiated: user volunteers concept without prompt trigger
   - PROMPT-induced: user echoes prompt vocabulary directly

**What NOT to measure:**
- F-type classification (until after analysis)
- Confidence scores
- DRIFT assignment (until after analysis)

---

## 3. Decision Rules

### Case A: Intrinsic Structure (H1 supported)

**Pattern:**
- Auditor (G3) given DevOps prompt → still produces audit language
- DevOps (G1) given Compliance prompt → still produces CI/CD language

**Evidence:**
```
P(user_type|audit_language) >> P(prompt_type|audit_language)
```

**Conclusion:**
> F1–F7 captures intrinsic latent structure. User workflow dominates language output.

---

### Case B: Prompt Artifact (H2) ⚠️ DANGER

**Pattern:**
- G3 → CI/CD language (auditor switched to DevOps vocabulary)
- G1 → audit language (DevOps switched to compliance vocabulary)

**Evidence:**
```
P(prompt_type|language) >> P(user_type|language)
```

**Conclusion:**
> F1–F7 is prompt-induced labeling artifact. Taxonomy collapses without prompt framing.

---

### Case C: Hybrid (Most Likely)

**Pattern:**
- User dominates within domain boundaries
- Prompt shifts vocabulary only, not underlying structure

**Evidence:**
- G3: audit language present but CI/CD vocabulary mixed in
- G1: CI/CD language present but compliance framing acknowledged

**Conclusion:**
> F1–F7 partially real. Structure exists but vocabulary is prompt-sensitive.

---

## 4. New DRIFT Type: D6

### D6: Prompt Invariance Drift

**Definition:** Cluster assignment changes when only prompt framing changes.

**Detection:**
```python
def detect_D6(g1_result, g2_result, g3_result, g4_result):
    """
    If user type same but language flips with prompt:
    → D6 = True
    """

    # G1 (DevOps, A) vs G2 (DevOps, B)
    g1_vs_g2_language_same = g1_result.cluster == g2_result.cluster

    # G3 (Auditor, B) vs G4 (Auditor, A)
    g3_vs_g4_language_same = g3_result.cluster == g4_result.cluster

    if not g1_vs_g2_language_same or not g3_vs_g4_language_same:
        return {
            "D6": True,
            "flip_type": "prompt_dominates",
            "affected_groups": [...]
        }

    return {"D6": False}
```

**D6 Rate:**
```
D6 rate = groups_with_prompt_flip / total_groups
```

---

## 5. Analysis Pipeline

### Step 1: Language Clustering (No F-type)

```python
def cluster_language(responses):
    """
    Cluster by keyword domain only.
    Do NOT use F-type labels yet.
    """

    audit_score = count_keywords(response, audit_terms)
    devops_score = count_keywords(response, devops_terms)

    if audit_score > 0 and devops_score == 0:
        return "AUDIT_CLUSTER"
    elif devops_score > 0 and audit_score == 0:
        return "DEVOPS_CLUSTER"
    elif audit_score > 0 and devops_score > 0:
        return "HYBRID_CLUSTER"
    else:
        return "GENERIC_CLUSTER"
```

### Step 2: Attribution Analysis

```python
def attribution_analysis(results):
    """
    Compute variance decomposition.

    user_effect = P(cluster|user_type) - P(cluster|random)
    prompt_effect = P(cluster|prompt_type) - P(cluster|random)

    If user_effect > 0.7 and prompt_effect < 0.3:
        → H1 supported
    If prompt_effect > 0.5:
        → H2 supported (DANGER)
    If both moderate:
        → H3 (hybrid)
    """
```

### Step 3: D6 Detection

```python
def full_analysis(g1, g2, g3, g4):
    results = {
        "G1": cluster_language(g1),
        "G2": cluster_language(g2),
        "G3": cluster_language(g3),
        "G4": cluster_language(g4),
    }

    user_dominance = compute_user_dominance(results)
    prompt_dominance = compute_prompt_dominance(results)

    d6 = detect_D6(results["G1"], results["G2"], results["G3"], results["G4"])

    return {
        "user_effect_size": user_dominance,
        "prompt_effect_size": prompt_dominance,
        "D6_detected": d6,
        "verdict": classify_case(user_dominance, prompt_dominance, d6),
    }
```

---

## 6. Success Criteria

### PASS (H1 supported)

```
user_type explains ≥ 70% variance
prompt explains ≤ 30% variance
D6 rate < 20%
```

**Interpretation:** F1–F7 is intrinsic latent structure. Proceed to full validation.

### MARGINAL (H3)

```
user_type explains 50-70% variance
prompt explains 30-50% variance
D6 rate 20-40%
```

**Interpretation:** F1–F7 partially real. Requires taxonomy refinement before expansion.

### FAIL (H2)

```
prompt explains ≥ 50% variance
user effect weak
D6 rate ≥ 40%
```

**Interpretation:** F1–F7 is prompt artifact. STOP current taxonomy. Need invariant extraction protocol.

---

## 7. Failure Mode: Taxonomy Illusion

**If H2 supported:**

```
The experiment found:
- User language follows prompt, not workflow
- F1–F7 clusters = prompt vocabulary, not user structure

This means:
- F1–F7 system is a "semantic projection"
- Not a "latent structure detector"
- Current taxonomy would self-fulfill in any prompt-framed experiment
```

**Required action:**
> Do NOT expand to full batch. Return to taxonomy design.
> Implement Invariant Extraction Protocol v1.0 (extract structure from language, not impose structure on language)

---

## 8. Minimal Execution Protocol

### Before Experiment

```
□ Recruit 4 users (2 DevOps, 2 Auditor)
□ Blind assignment: G1-G4 as defined
□ Do NOT tell users about the swap (single-blind preferred)
□ Prepare both message versions
□ Set timer for 30 min per session
```

### During Session

```
[0-2 min]  Context only (no hint at experiment structure)
[2-15 min] Natural conversation about their workflow
[15-20 min] Share the assigned message
[20-30 min] Observe language response to assigned message
           — Record keywords, workflow anchoring, initiation source
           — Do NOT classify F-type during session
```

### After Session

```
□ Run cluster_language() on each response
□ Compute attribution analysis
□ Detect D6
□ Generate verdict
```

---

## 9. Why This Design Is Rigorous

### Eliminates Common Biases

| Bias | How This Design Avoids It |
|-------|---------------------------|
| Confirmation bias | F-type not used in measurement |
| Prompt framing bias | Explicitly tests prompt vs user effect |
| Small n bias | N=4 is sufficient for causal test (not statistical inference) |
| Post-hoc rationalization | Clustering precedes F-type assignment |

### Causal Validity

```
This is a true causal experiment:
- Manipulation: prompt framing (P)
- Outcome: language output (L)
- Control: user type (U) held constant

Not a survey — a controlled perturbation.
```

---

## 10. Relationship to Full System

```
PHASE 2 (current): Does language cluster exist?
   ↓
BLIND SWAP (this test): Do clusters follow user or prompt?
   ↓
IF H1 supported: F1–F7 is valid → proceed to full validation
IF H2 supported: F1–F7 is artifact → Invariant Extraction Protocol
IF H3: F1–F7 partially real → refine before expansion
```

---

## 11. Open Questions

1. **Can single-blind be maintained?** (Users may figure out the swap)
2. **Is N=4 sufficient for decision?** (Yes for causal, no for statistical inference)
3. **Should we use within-subject replication?** (Would strengthen H1/H2 evidence)

---

## 12. Key Reminder

**This test temporarily removes F1–F7 from measurement layer.**

F1–F7 only re-enters as interpretation layer AFTER cluster analysis is complete.

If F1–F7 is used in measurement, it contaminates the causal test — same problem as Goodhart's Law in measurement systems.