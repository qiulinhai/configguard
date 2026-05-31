# ConfigGuard Semantic Architecture v1

> **Status:** Architecture Defined
> **Date:** 2026-05-31
> **Type:** Semantic Architecture Specification
> **Version:** 1.0

---

## 1. Core Objective

ConfigGuard's goal is not to store configurations, but to:

> **Transform network/security signals into a composable, reason-able semantic graph.**

This is the fundamental architectural shift from v0 (configuration scanner) to v1 (semantic rule engine).

---

## 2. Three-Layer IR Model

The system is structured as a three-layer Intermediate Representation (IR):

```
Signal
   ↓
Binding Layer
   ↓
Aggregation Layer
   ↓
Reasoning Layer
   ↓
Context
   ↓
Rule
   ↓
Finding
```

### Layer 1 — Binding Layer (Data Binding)

**Responsibility:** Define how a signal extracts data from a context.

**Core Field:**
```python
context_template: str | None
```

**Examples:**
| Template | Meaning |
|----------|---------|
| `"snmp_security"` | Bind to singleton context named "snmp_security" |
| `"{context}"` | Bind to context using signal's own context value |
| `"{interface}.{vrf}"` | Bind by interface and VRF |

**Characteristics:**
- No semantic judgment
- No aggregation information
- Pure mapping DSL

### Layer 2 — Aggregation Layer (Structural Organization)

**Responsibility:** Define how signals aggregate and instantiate in the system.

**Core Field:**
```python
aggregation_strategy: str
```

**Standard Values:**
| Strategy | Meaning |
|----------|---------|
| `singleton` | Global unique, one instance |
| `per_instance` | One per context instance |
| `per_scope` | Per scope (device, VRF, site) |
| `composite` | Multiple signals combined |

**Examples:**
| Strategy | Signal Type |
|----------|-------------|
| `singleton` | `http_server` (global HTTP config) |
| `per_instance` | `interface_state` (one per interface) |
| `composite` | `routing_health` (BGP + OSPF + VRF) |

### Layer 3 — Reasoning Layer (Semantic Reasoning)

**Responsibility:** Define the security/compliance/observability meaning of a signal.

**Core Field:**
```python
security_domain: str
```

**Standard Values:**
| Domain | Meaning |
|--------|---------|
| `management_plane` | Management and control plane |
| `data_plane` | Data forwarding plane |
| `observability` | Logging, monitoring, NTP |
| `compliance` | Security compliance |
| `access_control` | Authentication and authorization |

---

## 3. Execution Dimension vs Reasoning Dimension

A critical distinction:

| Dimension | Field | Role |
|-----------|-------|------|
| **Execution** | `category` | How signals cluster, match, and aggregate |
| **Reasoning** | `security_domain` | How signals relate across categories for composite analysis |

**Example:**
```python
SignalDefinition(
    signal_type="snmp_version",
    category="snmp",                    # Execution dimension
    security_domain="management_plane"  # Reasoning dimension
)
```

**Rule Matching** uses `category`: `applies_to: category: snmp`
**Composite Rules** use `security_domain`: `domain: management_plane`

---

## 4. SignalDefinition v1 (Final Form)

```python
@dataclass
class SignalDefinition:
    # Identity
    signal_type: str

    # Layer 1 — Binding
    context_template: str | None

    # Layer 2 — Aggregation
    aggregation_strategy: str

    # Layer 3 — Reasoning
    security_domain: str

    # Optional metadata
    scope: str | None = None
```

### Example: SNMP Signal

```python
SignalDefinition(
    signal_type="snmp_version",
    context_template="snmp_security",      # Layer 1
    aggregation_strategy="singleton",     # Layer 2
    security_domain="management_plane",   # Layer 3
    scope="global"
)
```

### Example: VTY Signal

```python
SignalDefinition(
    signal_type="transport_input",
    context_template="{context}",         # Layer 1: per instance
    aggregation_strategy="per_instance", # Layer 2
    security_domain="management_plane",  # Layer 3
    scope="line"
)
```

---

## 5. Context Model (Type + Instance Separation)

### 5.1 Current Problem

`context_key` currently conflates three responsibilities:

| Responsibility | Example | Problem |
|----------------|---------|---------|
| Aggregation | `"snmp_security"` | Groups signals |
| Type | `"snmp"` | Identifies category |
| Instance | `"vty_0_4"` | Identifies specific instance |

This violates Single Responsibility Principle.

### 5.2 Proposed Model

```python
@dataclass
class SignalContext:
    context_type: str          # "snmp", "vty", "interface"
    instance_id: str | None    # None for singleton, "0_4" for vty
    category: str             # Same as context_type for now
    signals: list[Signal]
```

**Example: Singleton Context**
```python
SignalContext(
    context_type="snmp",
    instance_id=None,          # Singleton has no instance
    category="snmp",
    signals=[snmp_version, snmp_community]
)
```

**Example: Instance Context**
```python
SignalContext(
    context_type="vty",
    instance_id="0_4",        # Specific instance
    category="vty",
    signals=[transport_input]
)
```

### 5.3 Category vs context_type

**Current Finding:** 100% of existing signal types have `family == context_type`.

**Decision:** Merge `family` and `context_type` into single `category` field.

---

## 6. Rule Contract (applies_to Schema)

### 6.1 Two-Stage Matching

Rules use two-stage selector matching:

```yaml
applies_to:
  category:           # Execution dimension
    - snmp
    - vty
  security_domain:    # Reasoning dimension (future)
    - management_plane
```

### 6.2 Matching Logic

```python
def matches_context(rule, context):
    # Stage 1: Category matching (required, v0.2+)
    if context.category not in rule.applies_to.category:
        return False

    # Stage 2: Domain matching (optional, v0.3+)
    if rule.applies_to.security_domain:
        if context.security_domain not in rule.applies_to.security_domain:
            return False

    return True
```

### 6.3 Future Extension

```yaml
applies_to:
  category:
    - snmp
  context_type:       # Future: match by type only (not instance)
    - vty
```

---

## 7. Key Design Principles

### Principle 1: Unidirectional Dependency

```
Binding → Aggregation → Reasoning
```

Cannot derive backward. Higher layers do not control lower layers.

### Principle 2: No String Semantic Inference

**Wrong:**
```python
context_template = "{context}"  # Implies per_instance
```

**Correct:**
```python
context_template = "{context}"
aggregation_strategy = "per_instance"
```

### Principle 3: Reasoning Does Not Affect Execution

`security_domain`:
- Does NOT affect data structure
- Does NOT affect runtime execution
- Only affects policy/rule grouping

### Principle 4: Composite is First-Class

`aggregation_strategy = "composite"` is not a hack. It's a first-class aggregation type that enables multi-signal reasoning.

---

## 8. Evolution Roadmap

```
v0.2.1: Semantic Stabilization
├── SignalDefinition Registry
├── Context Type/Instance Separation
├── Rule applies_to Contract
└── Coverage Matrix

v0.3: Composite Rules
├── Context + Context → Risk Finding
├── security_domain Matching
└── Cross-category Reasoning

v0.4: Resource Layer
├── CanonicalResource Introduction
├── security_domain as Resource Label
└── Resource Graph Building

v1.0: Graph Layer
├── Resource Relationships
├── Attack Path Detection
└── Knowledge Graph Completion
```

---

## 9. From v0 to v1: Architectural Transition

| Aspect | v0 (Configuration Scanner) | v1 (Semantic Rule Engine) |
|--------|---------------------------|---------------------------|
| Core Model | Config → Rule → Finding | Signal → IR → Context → Rule → Finding |
| Signal Role | Raw data | Semantic observations |
| Context Role | Implicit grouping | Explicit Type + Instance model |
| Rule Matching | String regex | Category-based matching |
| Aggregation | None | Singleton / per_instance / composite |
| Reasoning | None | security_domain layers |
| Architecture | String + Convention | Typed Semantic IR |

---

## 10. Rejected Alternatives

| Approach | Why Rejected |
|----------|--------------|
| `context_template` as aggregation strategy | Conflates binding with aggregation semantics |
| `family` + `context_type` as separate fields | 100% correlation, unnecessary complexity |
| `resource_type` in applies_to (v0.2) | Premature coupling to Resource layer |
| Direct Graph construction (v0.2) | Resource boundaries undefined, premature abstraction |

---

## 11. Open Questions (Deferred)

| Question | Decision Point | Target Version |
|----------|---------------|----------------|
| Scope field usage | How does `scope` interact with aggregation? | v0.2.1 |
| Composite signal definition | How to express composite signal composition? | v0.3 |
| Graph relationship types | What are valid resource relationships? | v1.0 |

---

## 12. Summary

**ConfigGuard Semantic Roadmap:**

```
Signal
   ↓
Context (Type + Instance)
   ↓
Canonical Resource
   ↓
Security Knowledge Graph
```

**v0.2.1 Focus:**
- Signal → Context stabilization
- Separation of Binding / Aggregation / Reasoning
- Category as execution dimension
- security_domain as future reasoning dimension