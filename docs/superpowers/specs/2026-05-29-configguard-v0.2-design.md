# ConfigGuard v0.2 Design Specification

> **Status:** Ready for Implementation
> **Version:** 0.2-draft → 0.2-final
> **Date:** 2026-05-29

---

## 1. Overview

**v0.2 Type:** Architecture Transition Release

v0.2 introduces a **Signal Layer** — a semantic abstraction layer between configuration parsing and rule evaluation. This is not a feature release; it is an architecture insertion that enables future reasoning capabilities.

**Design Principle:** Additive architecture, not replacement architecture. v0.1 rules remain fully functional.

---

## 2. Architecture

### 2.1 v0.1 Architecture (Reference)

```
Config → Parser → Raw Config IR → Rule Engine (v0.1) → Findings
```

Problem: Multiple atomic rules independently match the same config observation.

### 2.2 v0.2 Architecture (Dual-Path)

```
Config → Parser → Raw Config IR
                      ↓
             Signal Extractor (NEW)
                      ↓
             Fine-grained Signals
                      ↓
        ┌─────────────┴─────────────┐
        ↓                           ↓
 v0.1 Legacy Rules           v0.2 Signal Rules
        ↓                           ↓
        └─────────────┬─────────────┘
                      ↓
              Findings (Unified)
```

### 2.3 Key Properties

| Property | Description |
|----------|-------------|
| Backward compatible | v0.1 rules work unchanged |
| Zero disruption | Existing CI/tests unaffected |
| Deduplication | Same signal → single finding |
| Extensible | New parsers only add signal types |

---

## 3. Signal Layer

### 3.1 Signal Definition

A **Signal** is a canonical security-relevant observation derived from configuration.

```python
@dataclass
class Signal:
    type: str           # e.g., "transport_input"
    value: str          # e.g., "telnet"
    context: str        # e.g., "vty 0 4"
    block_type: str     # e.g., "line"
    raw: str            # original config line
    severity_hint: str | None = None  # optional: "high", "medium", "low"
```

### 3.2 Signal Extraction

```
Raw Config IR
    ↓
For each block in IR.blocks:
    For each command in block.commands:
        Extract signal(s) based on command content
    For each block header:
        Extract block-level signals
    ↓
Deduplicate signals by (type, context) key
    ↓
Signal Store
```

### 3.3 Deduplication Strategy

**Key:** `(signal.type, signal.context)`

Example:
- `transport_input + vty 0 4` → one signal
- `transport_input + vty 0 4` (duplicate) → skipped
- `auth_method + vty 0 4` → separate signal (different type)
- `transport_input + vty 0 4` (different context) → separate signal

### 3.4 Signal Types (v0.2 Flat Taxonomy)

| Signal Type | Value Examples | Context Examples |
|-------------|----------------|------------------|
| `transport_input` | `telnet`, `ssh`, `none` | `vty 0 4` |
| `auth_method` | `local`, `tacacs`, `none` | `vty 0 4` |
| `aaa_enabled` | `true`, `false` | `global` |
| `http_server` | `enabled`, `disabled` | `global` |
| `snmp_version` | `v1`, `v2c`, `v3`, `none` | `global` |
| `snmp_community` | `public`, `private`, `strong` | `global` |
| `syslog_host` | `configured`, `missing` | `global` |
| `ntp_server` | `configured`, `missing` | `global` |
| `interface_state` | `up`, `down`, `shutdown` | `GigabitEthernet0/0` |
| `interface_description` | `present`, `missing` | `interface_name` |

### 3.5 Signal Schema (Locked)

```python
{
    "type": str,           # required, non-empty
    "value": str,          # required, non-empty
    "context": str,        # required, identifies location
    "block_type": str,     # required: "interface", "line", "router", "global"
    "raw": str,            # required, original command
    "severity_hint": str | None  # optional, derived
}
```

---

## 4. Signal Extractor Design

### 4.1 Extractor Interface

**Contract:** `ConfigIR` schema is frozen at v0.1. Signal Extractor reads from stable IR, never modifies it.

```python
class SignalExtractor:
    def extract(self, config_ir: ConfigIR) -> list[Signal]:
        """Extract signals from parsed config IR."""
        ...

    def _extract_from_block(self, block: Block) -> list[Signal]:
        """Extract signals from a single block."""
        ...

    def _extract_block_level_signals(self, block: Block) -> list[Signal]:
        """Extract signals from block header itself."""
        ...
```

### 4.2 Extraction Rules

| Block Type | Commands Analyzed | Signals Extracted |
|------------|-------------------|-------------------|
| `line` (vty) | `transport input`, `login`, `access-class` | `transport_input`, `auth_method` |
| `line` (console) | `login`, `password` | `auth_method` |
| `interface` | all | `interface_state`, `interface_description` |
| `global` | `aaa new-model`, `ip http server`, `snmp-server` | `aaa_enabled`, `http_server`, `snmp_version` |
| `global` | `logging host`, `ntp server` | `syslog_host`, `ntp_server` |

### 4.3 Signal Registry

```python
SIGNAL_EXTRACTORS = {
    "transport_input": extract_transport_input,
    "auth_method": extract_auth_method,
    "aaa_enabled": extract_aaa_enabled,
    "http_server": extract_http_server,
    "snmp_version": extract_snmp_version,
    "snmp_community": extract_snmp_community,
    "syslog_host": extract_syslog_host,
    "ntp_server": extract_ntp_server,
    "interface_state": extract_interface_state,
}
```

---

## 5. Dual Rule Execution

### 5.1 Execution Flow

```
1. Parse config → ConfigIR
2. Extract signals → Signal Store
3. Run v0.1 legacy rules on ConfigIR → Findings_v1
4. Run v0.2 signal rules on Signal Store → Findings_v2
5. Merge Findings (v1 + v2), deduplicate by (rule_id, evidence)
6. Return unified findings
```

### 5.2 Deduplication in Findings

**Key:** `(f.rule_id, f.block_name, f.evidence)` — uses block_name for stable context, not evidence alone.

Evidence is not a stable dedup key because variations like `transport input telnet` and `transport input telnet ssh` are semantically the same issue but produce different evidence strings.

```python
def merge_findings(v1_findings: list[Finding], v2_findings: list[Finding]) -> list[Finding]:
    seen = set()
    merged = []

    for findings in [v1_findings, v2_findings]:
        for f in findings:
            key = (f.rule_id, f.block_name, f.evidence)
            if key not in seen:
                seen.add(key)
                merged.append(f)

    return merged
```

### 5.3 v0.1 Backward Compatibility

v0.1 rules continue to work unchanged:
- They match against `ConfigIR.raw_lines` and `ConfigIR.blocks`
- No signal dependency
- Behavior identical to v0.1

### 5.4 v0.2 Signal Rules

v0.2 signal rules are an **alternative execution path**:
- They match against signals, not raw config
- More expressive, deduplication-aware
- New rule format (optional for v0.2)

---

## 6. Rule Migration Path

### 6.1 Migration Stages

| Stage | v0.1 Rules | v0.2 Signal Rules | Notes |
|-------|-----------|-------------------|-------|
| v0.2 init | 100% | 0% | Legacy only, signal layer added |
| v0.2 mid | 80% | 20% | Critical rules migrated first |
| v0.3 | 30% | 70% | Majority signal-based |
| v1.0 | 0% | 100% | Legacy removed |

### 6.2 Migration Criteria

A rule should migrate to signal-based when:
1. It detects a signal that is commonly duplicated
2. It benefits from semantic context
3. It is part of composite rule composition

---

## 7. Signal Taxonomy (Post-v1.0)

v0.2 uses flat signals. Hierarchical taxonomy planned for v1.0:

```
mgmt_plane.transport_input  →  v0.2: transport_input
mgmt_plane.auth_method    →  v0.2: auth_method
snmp.security.version     →  v0.2: snmp_version
logging.syslog.config     →  v0.2: syslog_host
```

**Note:** This mapping is informational only. v0.2 does not implement hierarchical taxonomy — it is documented here to clarify the evolution path.

---

## 8. Testing Strategy

### 8.1 Signal Extraction Tests

- Unit tests for each signal extractor
- Deduplication verified
- Edge cases: empty blocks, malformed config

### 8.2 Dual Execution Tests

- Run same config through v0.1 and v0.2
- Verify findings are equivalent (or v0.2 is superset)
- Deduplication verified in merged output

### 8.3 Regression Tests

- All v0.1 ground truth cases pass
- New signal-based tests added
- CI maintains 100% pass rate

---

## 9. Scope Boundaries

### 9.1 v0.2 In Scope

- Signal layer architecture
- Fine-grained signal extraction
- Signal deduplication
- Dual rule execution
- v0.1 backward compatibility
- Ground truth tests for signal extraction

### 9.2 v0.2 Out of Scope

- NX-OS parser
- Juniper support
- Batch scanning
- Composite rules
- Hierarchical signal taxonomy
- LLM-based signal generation

---

## 10. Architecture Summary

**v0.2 = Hybrid deterministic + semantic security reasoning system**

| Layer | v0.1 | v0.2 |
|-------|------|------|
| Input | config | config |
| Parser | block-aware | block-aware |
| IR | ConfigIR | ConfigIR + Signals |
| Rules | atomic only | atomic + signal |
| Execution | single-path | dual-path |
| Deduplication | n/a | via signal |
| Extensibility | medium | high |

**v0.2 Core Principle:** Atomic for reasoning, aggregated for presentation.

---

## 11. Rejected Designs

| Approach | Why Rejected |
|----------|--------------|
| Replace v0.1 with signal-based rules | Destroys working system, no validation data |
| Hierarchical signal taxonomy in v0.2 | Premature ontology design, blocks signal validation |
| Composite rules in v0.2 | Separate feature, not architecture |
| Batch scanning in v0.2 | Adds concurrency complexity, distracts from signal validation |
| Multi-vendor in v0.2 | Vendor abstraction requires validated signal layer first |