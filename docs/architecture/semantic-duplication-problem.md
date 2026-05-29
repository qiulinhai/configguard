# ConfigGuard v0.2: Semantic Duplication Problem

> **Status:** Architecture Discovery
> **Date:** 2026-05-29
> **Version:** 0.2.0

---

## Executive Summary

v0.2 introduced Signal Layer to normalize configuration observations into canonical signals. However, testing revealed that signal extraction alone does NOT eliminate duplication — it exposes two fundamental types of semantic duplication that require different solutions.

**Key Finding:** Signal extraction is necessary but insufficient for semantic security reasoning.

---

## Duplication Taxonomy

### Type A: Cross-Rule Duplication

**Example:**
```
CISCO-MGMT-003: Secure VTY Configuration
CISCO-MGMT-001: Disable Telnet

Both triggered by: "transport input telnet"
```

**Nature:** Multiple atomic rules describe the same security risk from different angles.

**Solution:** Composite rules or finding-level grouping.

---

### Type B: Same-Rule Multi-Instance Duplication

**Example:**
```
CISCO-SNMP-001: Disable SNMP v2c

Triggered twice:
  - Evidence: snmp-server community public
  - Evidence: snmp-server community private
```

**Nature:** Same semantic issue (insecure SNMP) triggered by multiple distinct signal values.

**Solution:** Context Builder (semantic aggregation layer).

---

## Why Signal Layer Alone Is Insufficient

### Current v0.2 Architecture

```
Config → Parser → ConfigIR → SignalExtractor → Signals
                                                  ↓
                                         Legacy Rules (per-signal)
                                                  ↓
                                             Findings
```

### The Problem

SignalExtractor normalizes config into signals:
```
signals: [
  {type: snmp_community, value: "public"},
  {type: snmp_community, value: "private"}
]
```

But legacy rules evaluate EACH signal independently → duplicate findings.

### Root Cause

**Deduplication happens at the WRONG layer:**

| Layer | Current Behavior |
|-------|-----------------|
| Signal Extraction | Deduplicates by (type, context, value) ✓ |
| Rule Evaluation | Evaluates per-signal, not per-context ✗ |
| Finding Output | Multiple findings for semantically same issue ✗ |

---

## Architecture Gap

```
Current State:
Signal Extraction ✅ → Rule Evaluation (syntactic) ❌ → Findings (duplicates)

Target State:
Signal Extraction ✅ → Context Aggregation (semantic) ✅ → Rule Evaluation (per-context) ✅ → Findings (deduplicated)
```

---

## Required Components

### 1. Context Builder (Immediate Need)

Groups signals by semantic dimensions before rule evaluation:
```
signals: [public, private, v2c]
          ↓
context: {
  key: "snmp_security",
  evidence: ["public", "private", "v2c"]
}
          ↓
Rule evaluates ONCE against context
          ↓
Finding: 1 (aggregated evidence)
```

### 2. Composite Rules (Future)

Multiple atomic rules combined:
```
CISCO-MGMT-COMPOSITE-001:
  depends_on:
    - CISCO-MGMT-001 (telnet)
    - CISCO-MGMT-002 (ssh-only)
  condition: telnet present = FAIL
```

### 3. Finding Grouping (Alternative to Composite Rules)

Post-processing deduplication at finding level:
```
findings: [FAIL telnet, FAIL telnet]
          ↓
grouped: [FAIL {telnet: multiple contexts}]
```

---

## Strategic Implications

### Current Position

ConfigGuard has evolved from:
- ❌ `regex engine` (v0.1)
- → ✅ `semantic pre-processing engine` (v0.2)
- → ❌ NOT YET `semantic reasoning engine`

### Two Future Routes

**Route 1: Tool**
```
signal-aware rule engine
- more rules
- more vendors
- web UI
```

**Route 2: Platform** (recommended)
```
semantic context reasoning
- Context Builder
- Composite rules
- Risk abstraction
- Optional AI explanation
```

### Why Route 2 Has Real Value

Enterprise willingness to pay:

| Approach | Value |
|----------|-------|
| `config → LLM → findings` | Low (nondeterministic, hallucination, unverifiable) |
| `config → semantic IR → normalized signals → reasoning → findings` | High (deterministic, verifiable, certifiable) |

---

## Next Steps

### v0.2.x: Context Builder Implementation

1. **Document:** SignalContext data structure
2. **Implement:** ContextBuilder._cluster_signals()
3. **Integrate:** Rule engine evaluates against contexts (not signals)
4. **Test:** SNMP case produces single finding with aggregated evidence

### v0.3: Composite Rules

1. Define composite rule schema
2. Implement dependency resolution
3. Add topological sort for evaluation order

### v0.4: Optional AI Layer

1. Add LLM explanation capability (explain finding given context)
2. Not replacing reasoning — augmenting explainability

---

## Appendix: Test Evidence

```
$ configguard audit /tmp/test.cfg

[FAIL] CISCO-MGMT-003 Secure VTY Configuration
       Evidence: transport input telnet
[FAIL] CISCO-MGMT-001 Disable Telnet
       Evidence: transport input telnet
[FAIL] CISCO-SNMP-001 Disable SNMP v2c
       Evidence: snmp-server community public
[FAIL] CISCO-SNMP-001 Disable SNMP v2c
       Evidence: snmp-server community private
```

**Analysis:**
- MGMT-003 + MGMT-001: Type A duplication (cross-rule)
- SNMP-001 appears twice: Type B duplication (same-rule multi-instance)

---

## Appendix: Key Design Decisions

1. **Deduplication MUST happen before reasoning, not after.** Post-processing loses semantic context.

2. **Context key must be rule-relevant dimensions, not arbitrary grouping.** SNMP all clusters together, VTY separates by line instance.

3. **Evidence aggregation preserves audit completeness.** "public, private" not "multiple communities".