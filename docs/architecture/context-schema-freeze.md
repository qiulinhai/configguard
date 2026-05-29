# Context Schema Freeze (v0.2.x)

> **Status:** Draft for Review
> **Date:** 2026-05-30
> **Version:** 0.2.1

---

## Overview

SignalContext is the core ABI (Application Binary Interface) of ConfigGuard's semantic layer. All future features depend on its stability.

**This document freezes the Context schema and defines stabilization requirements.**

---

## SignalContext Schema (Final)

```python
@dataclass
class SignalContext:
    """A semantic grouping of signals relevant to a rule evaluation.

    This is the core semantic unit of ConfigGuard's reasoning layer.
    All rule evaluations operate on contexts, not individual signals.
    """

    # Core identity
    id: str                              # Unique: f"{context_key}_{rule_id}"
    context_key: str                      # Semantic type: "snmp_security", "vty_0_4"

    # Signal data
    signals: list[Signal]               # Original signals (preserves audit trail)
    aggregated_evidence: list[str]        # Evidence values for pattern matching

    # Metadata
    metadata: dict = field(default_factory=dict)

    # Derived (computed at evaluation time, not stored)
    # - severity: from rule evaluation
    # - finding_status: from rule evaluation
```

### Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | str | Yes | Unique identifier. Format: `{context_key}_{rule_id}` |
| `context_key` | str | Yes | Semantic grouping key. Examples: `snmp_security`, `vty_0_4`, `interface_GigabitEthernet0_0` |
| `signals` | list[Signal] | Yes | Original signals. Preserves raw text for pattern matching |
| `aggregated_evidence` | list[str] | Yes | Evidence values. Used for regex pattern matching in rules |
| `metadata` | dict | No | Extensible metadata. Examples: `community_count`, `transport`, `version` |

### SignalContext Usage Patterns

```python
# Building a context
signals = [Signal(...), Signal(...)]
context = SignalContext(
    id="snmp_security_CISCO-SNMP-001",
    context_key="snmp_security",
    signals=signals,
    aggregated_evidence=[s.raw for s in signals],  # Raw text for pattern matching
    metadata={"community_count": 2, "version": "v2c"}
)

# Evaluating a context
findings = rule.evaluate_with_context(context)
```

---

## SignalContext Lifecycle

```
1. Signal Extraction
   config → ConfigIR → SignalExtractor → signals

2. Context Building
   signals → ContextBuilder._cluster_signals() → clusters
         → ContextBuilder._build_context() → contexts

3. Context Evaluation
   contexts → RuleEngine.evaluate_with_contexts() → findings

4. Finding Output
   findings → JSON/MD renderer → report
```

---

## Context Key Reference

| Context Key | Signal Types | Scope | Example |
|------------|-------------|-------|---------|
| `snmp_security` | snmp_version, snmp_community | Global | All SNMP configs |
| `vty_{name}` | transport_input, auth_method | Per VTY | `vty_0_4`, `vty_5_9` |
| `interface_{name}` | interface_state, interface_description | Per interface | `interface_GigabitEthernet0_0` |
| `global_auth` | aaa_enabled | Global | AAA configuration |
| `global_services` | http_server | Global | HTTP server |
| `global_logging` | syslog_host | Global | Syslog configuration |
| `global_time` | ntp_server | Global | NTP configuration |

---

## Stabilization Checklist

### Schema Stability ✅
- [x] SignalContext dataclass defined
- [x] All fields have clear types
- [x] metadata is extensible dict

### API Stability ✅
- [x] ContextBuilder.build_contexts() signature stable
- [x] Rule.evaluate_with_context() signature stable
- [x] RuleEngine.evaluate_with_contexts() signature stable

### Test Coverage
- [x] Unit tests for context building
- [x] Unit tests for context evaluation
- [x] Integration test for SNMP single finding
- [ ] Test for VTY multi-line separation
- [ ] Test for evidence aggregation formatting

### Documentation
- [x] ADR-005 (Context Schema Design)
- [x] This document (Context Schema Freeze)
- [ ] Context debug output tooling
- [ ] Evidence formatter layer

---

## Breaking Change Policy

**Before v1.0, any change to SignalContext schema requires:**
1. Deprecation warning period
2. Migration guide
3. Test coverage for affected paths
4. ADR documenting the change reason

**Fields that CAN be added without breaking:**
- New metadata keys (dict is extensible)
- Computed properties (derived, not stored)

**Fields that CANNOT be changed without major version:**
- Field names
- Field types
- Semantic meaning of context_key values
- aggregated_evidence generation logic

---

## Future Extensions (Post-v0.3)

### CompositeContext (v0.3)
```python
@dataclass
class CompositeContext:
    """Multiple SignalContexts combined for composite rule evaluation."""
    contexts: list[SignalContext]
    relationship: str  # e.g., "AND", "OR"
    metadata: dict
```

### Context History
```python
@dataclass
class ContextWithHistory:
    """Context with change tracking for audit trail."""
    context: SignalContext
    config_snapshot: str
    timestamp: datetime
```

---

## Open Questions

1. **Context versioning:** Should contexts carry a schema version for forward compatibility?
2. **Context serialization:** JSON schema for API/Web UI consumption?
3. **Context registry:** Should we maintain a registry of known context keys?