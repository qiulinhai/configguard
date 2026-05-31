# ConfigGuard v0.2 Context Builder Design Specification

> **Status:** Ready for Implementation
> **Date:** 2026-05-29
> **Type:** Architecture Addition (Signal Aggregation Layer)

---

## 1. Problem Statement

v0.2 Signal Layer introduced signal extraction from config, but **rule evaluation remains per-signal** rather than per-context.

**Current (Broken) Behavior:**
```
signals: [snmp_community=public, snmp_community=private]
↓
rule: SNMP v2c check
↓
findings: [FAIL for public, FAIL for private]  ← DUPLICATE findings
```

**Expected Behavior:**
```
signals: [snmp_community=public, snmp_community=private]
↓
context builder: groups by rule-relevant dimensions
↓
rule: SNMP v2c check (evaluated ONCE)
↓
findings: [FAIL with evidence: public, private]  ← SINGLE finding
```

---

## 2. Architecture

### 2.1 Current v0.2 Architecture

```
Config → Parser → ConfigIR → SignalExtractor → Signals
                                                    ↓
                                           RuleEngine (per-signal)
                                                    ↓
                                               Findings
```

### 2.2 Fixed Architecture (with Context Builder)

```
Config → Parser → ConfigIR → SignalExtractor → Signals
                                                    ↓
                                              ContextBuilder  ← NEW
                                                    ↓
                                              SignalContexts
                                                    ↓
                                           RuleEngine (per-context)
                                                    ↓
                                               Findings
```

### 2.3 Context Builder Role

| Layer | Responsibility |
|-------|---------------|
| Signal Extractor | Raw signal extraction from config |
| **Context Builder** | **Group signals by rule-relevant semantic dimensions** |
| Rule Engine | Evaluate rules against contexts |

---

## 3. Context Definition

### 3.1 What is a Context?

A **Context** is a semantic grouping of signals relevant to a single rule evaluation.

```python
@dataclass
class SignalContext:
    rule_id: str                    # Which rule this context is for
    context_key: str                 # e.g., "snmp_security", "vty_mgmt"
    signals: list[Signal]           # All signals in this context
    aggregated_evidence: list[str]  # All evidence values
    metadata: dict                  # Additional context info
```

### 3.2 Context Key Strategy

Context keys are defined by **rule grouping semantics**:

| Rule Category | Context Key | Rationale |
|--------------|-------------|-----------|
| SNMP security | `snmp_security` | All SNMP configs are related |
| VTY management | `vty_{line_name}` | Per-VTY-instance security |
| Interface | `interface_{name}` | Per-interface security |
| Global auth | `global_auth` | AAA is global |
| Global services | `global_services` | HTTP, telnet are global |

### 3.3 Signal Clustering Rules

```python
# Group signals into contexts based on rule relevance

SIGNAL_CONTEXT_CLUSTERS = {
    # SNMP: all SNMP signals cluster by security context
    "snmp_version": "snmp_security",
    "snmp_community": "snmp_security",

    # VTY: per-VTY instance
    "transport_input": "vty_{context}",  # e.g., vty_0_4
    "auth_method": "vty_{context}",

    # Interface: per-interface
    "interface_state": "interface_{context}",
    "interface_description": "interface_{context}",

    # Global: single context
    "aaa_enabled": "global_auth",
    "http_server": "global_services",
    "syslog_host": "global_logging",
    "ntp_server": "global_time",
}
```

---

## 4. Context Builder Design

### 4.1 ContextBuilder Interface

```python
class ContextBuilder:
    def build_contexts(self, signals: list[Signal], rules: list[Rule]) -> list[SignalContext]:
        """
        Group signals into contexts for rule evaluation.

        Each context is scoped to a specific rule_id and contains
        all signals relevant to that rule's evaluation.
        """
        ...

    def _cluster_signals(self, signals: list[Signal]) -> dict[str, list[Signal]]:
        """Cluster signals by context key."""
        ...

    def _build_context(self, rule_id: str, cluster_key: str, signals: list[Signal]) -> SignalContext:
        """Build a single context from clustered signals."""
        ...
```

### 4.2 Context Building Flow

```
Input: signals = [s1, s2, s3, ...], rules = [r1, r2, ...]

Step 1: Cluster signals by context key
  For each signal:
    Determine cluster_key based on signal.type and signal.context
    Add to cluster[cluster_key]

Step 2: Build contexts for each rule
  For each rule:
    Determine relevant cluster_key(s)
    Gather signals for that rule's evaluation
    Create SignalContext with aggregated evidence

Output: list[SignalContext]
```

### 4.3 Example: SNMP Context

```python
# Input signals
signals = [
    Signal(type="snmp_community", value="public", context="global", ...),
    Signal(type="snmp_community", value="private", context="global", ...),
    Signal(type="snmp_version", value="v2c", context="global", ...),
]

# After clustering
clusters = {
    "snmp_security": [
        Signal(type="snmp_community", value="public", ...),
        Signal(type="snmp_community", value="private", ...),
        Signal(type="snmp_version", value="v2c", ...),
    ]
}

# Context for SNMP rule
context = SignalContext(
    rule_id="CISCO-SNMP-001",
    context_key="snmp_security",
    signals=[...],
    aggregated_evidence=["public", "private", "v2c"],
    metadata={"community_count": 2, "version": "v2c"}
)

# Rule evaluates ONCE against this context
# Produces ONE finding with all evidence
```

---

## 5. Rule Engine Changes

### 5.1 New Evaluation Interface

```python
class RuleEngine:
    def evaluate_with_contexts(
        self,
        ir: ConfigIR,
        contexts: list[SignalContext]
    ) -> list[Finding]:
        """Evaluate rules using signal contexts."""
        ...

    def _evaluate_context(self, rule: Rule, context: SignalContext) -> Finding | None:
        """Evaluate a single rule against a single context."""
        ...
```

### 5.2 Finding Generation from Context

```python
def _evaluate_context(self, rule: Rule, context: SignalContext) -> Finding | None:
    # Rule evaluates context as a whole, not per-signal
    evidence_values = context.aggregated_evidence

    # Check if rule condition is met
    if self._condition_met(rule, context):
        return Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            evidence=", ".join(evidence_values),  # Aggregated
            ...
        )
    return None
```

---

## 6. Example: SNMP Rule Evaluation

### 6.1 Before (per-signal, broken)

```
Input: signals = [public, private]
Rule: CISCO-SNMP-001 (v2c community = FAIL)

Evaluation:
  - public → FAIL
  - private → FAIL

Output: 2 findings (WRONG)
```

### 6.2 After (per-context, correct)

```
Input: signals = [public, private]

Context Builder:
  → cluster_key = "snmp_security"
  → aggregated_evidence = ["public", "private"]

Context for rule:
  → signals: [public, private]
  → aggregated_evidence: "public, private"

Rule Evaluation:
  → CISCO-SNMP-001 evaluated ONCE against context
  → Condition: "snmp_version == v2c AND snmp_community present"
  → Result: FAIL

Output: 1 finding with evidence "public, private" (CORRECT)
```

---

## 7. Signal Types and Context Keys

### 7.1 Complete Mapping

| Signal Type | Context Key | Context Scope |
|------------|------------|--------------|
| `transport_input` | `vty_{context}` | Per VTY line |
| `auth_method` | `vty_{context}` | Per VTY line |
| `aaa_enabled` | `global_auth` | Global |
| `http_server` | `global_services` | Global |
| `snmp_version` | `snmp_security` | Global |
| `snmp_community` | `snmp_security` | Global |
| `syslog_host` | `global_logging` | Global |
| `ntp_server` | `global_time` | Global |
| `interface_state` | `interface_{context}` | Per interface |
| `interface_description` | `interface_{context}` | Per interface |

### 7.2 Context Key Template Expansion

```python
def expand_context_key(template: str, signal: Signal) -> str:
    """Expand context key template with signal context."""
    if "{context}" in template:
        # Normalize context for use in key (replace spaces, special chars)
        normalized = signal.context.replace(" ", "_").replace("/", "_")
        return template.format(context=normalized)
    return template

# Examples:
# template="vty_{context}", signal.context="vty 0 4" → "vty_0_4"
# template="interface_{context}", signal.context="GigabitEthernet0/0" → "interface_GigabitEthernet0_0"
```

---

## 8. Backward Compatibility

### 8.1 v0.1 Rules Remain Unchanged

v0.1 legacy rules continue to work with the existing per-signal evaluation.

### 8.2 Signal-Based Rules Use Context Builder

v0.2 signal-based rules evaluate against contexts.

### 8.3 Finding Schema Unchanged

Findings still have same schema - only the evaluation path changes internally.

---

## 9. Testing Strategy

### 9.1 Context Building Tests

- Test signal clustering for each signal type
- Test context key expansion
- Test aggregated evidence collection

### 9.2 Integration Tests

- Test SNMP: public + private → single finding
- Test VTY: multiple transport types → single finding
- Test interface: multiple issues → single finding

### 9.3 Regression Tests

- All v0.1 ground truth cases pass
- All v0.2 signal extraction tests pass

---

## 10. Scope

### 10.1 In Scope

- ContextBuilder class
- Signal clustering logic
- Context-key expansion
- Rule engine update for context evaluation
- SNMP deduplication fix
- VTY deduplication fix

### 10.2 Out of Scope

- Composite rules (v0.3)
- Multi-signal reasoning beyond aggregation
- Hierarchical taxonomy

---

## 11. Rejected Alternatives

| Approach | Why Rejected |
|----------|--------------|
| Post-processing dedup (Option A) | Loses evidence completeness, violates source-of-truth principle |
| Per-signal rule evaluation | Doesn't fix underlying semantic issue |
| Global signal aggregation | Too coarse, loses per-interface/per-VTY granularity |

---

## 12. Summary

**Context Builder** adds semantic grouping to the signal layer:

```
Signals → Context Builder → SignalContexts → RuleEngine → Findings
                    ↑
            Semantic grouping by rule-relevant dimensions
```

**Key benefits:**
- Single finding per rule evaluation (not per signal)
- Aggregated evidence preserves completeness
- Per-context granularity preserved (interface vs VTY vs global)
- Backward compatible with v0.1 rules