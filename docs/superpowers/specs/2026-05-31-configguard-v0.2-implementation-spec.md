# ConfigGuard v0.2 Context Builder - Implementation Specification

> **Status:** Implemented
> **Date:** 2026-05-29 (original) / 2026-05-31 (updated)
> **Type:** Architecture Addition (Signal Aggregation Layer)

---

## 1. Problem Statement

v0.2 Signal Layer introduced signal extraction from config, but **rule evaluation was per-signal** rather than per-context.

**Before:**
```
signals: [snmp_community=public, snmp_community=private]
↓
rule: SNMP v2c check
↓
findings: [FAIL for public, FAIL for private]  ← DUPLICATE findings
```

**After:**
```
signals: [snmp_community=public, snmp_community=private]
↓
context builder: groups by semantic dimensions
↓
rule: SNMP v2c check (evaluated ONCE)
↓
findings: [FAIL with evidence: public, private]  ← SINGLE finding
```

---

## 2. Architecture

### 2.1 Final Architecture

```
Config → Parser → ConfigIR → SignalExtractor → Signals
                                                    ↓
                                              ContextBuilder
                                                    ↓
                                              SignalContexts
                                                    ↓
                                         RuleEngine (per-context)
                                                    ↓
                                               Findings
                                                    ↓
                                           EvidenceBuilder  ← NEW (v0.2)
                                                    ↓
                                               Findings (with evidence_summary)
                                                    ↓
                                            RiskEngine  ← NEW (v0.3)
                                                    ↓
                                               Risk Score
```

### 2.2 Key Design Decisions

1. **Pure Semantic Contexts**: `ContextBuilder.build_contexts(signals)` takes NO `rules` parameter. Contexts are pure semantic groupings, independent of rule knowledge.

2. **Automatic Rule Matching**: `RuleEngine._find_rules_for_context()` matches rules to contexts based on `context_key` patterns, not during context building.

3. **Context/Rule Separation**: Contexts are observations (WHAT), rules are policy (SHOULD). Separating them enables reuse.

---

## 3. Implemented Components

### 3.1 SignalContext (context.py)

```python
@dataclass
class SignalContext:
    id: str                    # Deterministic SHA256 hash
    context_key: str           # e.g., "snmp_security", "vty_0_4"
    signals: list[Signal]      # Original signals (preserves audit trail)
    aggregated_evidence: list[str]  # Raw command text for pattern matching
    metadata: dict             # Extensible metadata (signal_count, types, etc.)
```

### 3.2 ContextBuilder (context.py)

```python
class ContextBuilder:
    def build_contexts(self, signals: list[Signal]) -> list[SignalContext]:
        """Group signals into semantic contexts. No rule knowledge."""
        ...

    def _cluster_signals(self, signals: list[Signal]) -> dict[str, list[Signal]]:
        """Cluster signals by context key."""

    def _build_context(self, cluster_key: str, signals: list[Signal]) -> SignalContext:
        """Build a single context from clustered signals."""
```

### 3.3 Signal Clustering Rules

```python
SIGNAL_CONTEXT_CLUSTERS = {
    # SNMP: all SNMP signals cluster by security context
    "snmp_version": "snmp_security",
    "snmp_community": "snmp_security",

    # VTY: per-VTY instance
    "transport_input": "{context}",     # → vty_0_4
    "auth_method": "{context}",

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

### 3.4 RuleEngine._find_rules_for_context()

```python
def _find_rules_for_context(self, context_key: str, rules: list) -> list:
    """Find rules relevant for a context based on context_key patterns."""
    if context_key == "snmp_security" and "snmp" in rule_id_lower:
        relevant.append(rule)
    elif context_key.startswith("vty_") and ("vty" in rule_id_lower or "mgmt" in rule_id_lower):
        relevant.append(rule)
    elif context_key.startswith("interface_") and ("interface" in rule_id_lower ...):
        relevant.append(rule)
    elif context_key == "global_auth" and ("auth" in rule_id_lower or "aaa" in rule_id_lower):
        relevant.append(rule)
    elif context_key == "global_services" and ("http" in rule_id_lower ...):
        relevant.append(rule)
    elif context_key == "global_logging" and ("syslog" in rule_id_lower ...):
        relevant.append(rule)
    elif context_key == "global_time" and ("ntp" in rule_id_lower ...):
        relevant.append(rule)
    return relevant
```

### 3.5 EvidenceBuilder (evidence.py)

```python
class EvidenceBuilder:
    """PURE formatting layer - transforms SignalContext to human-readable evidence."""

    def build(self, context: SignalContext) -> dict:
        """Returns: {summary, details, raw_count}"""

    def attach_evidence_summary(self, finding: Finding, context: SignalContext) -> Finding:
        """Attaches evidence_summary to finding in-place."""
```

Evidence builders for each context type:
- `_build_snmp_evidence()` - "SNMP v2c enabled with 3 community strings: public, private, ..."
- `_build_vty_evidence()` - "VTY line (vty_0_4) with transports: telnet, ssh, auth: local"
- `_build_http_evidence()` - "HTTP server: enabled"
- `_build_aaa_evidence()` - "AAA: enabled"
- etc.

### 3.6 RiskEngine v0.3 (risk/engine.py)

```python
class RiskEngine:
    """Pure post-processing layer - computes risk score from findings."""

    def evaluate(self, findings: list[Finding]) -> RiskEngineResult:
        """Returns RiskEngineResult with risk_score and breakdowns."""
```

Risk scoring:
- Base score from severity weights
- Context multiplier for coverage
- Normalized to 0-100 with levels (LOW, MEDIUM, HIGH, CRITICAL)

---

## 4. Signal States

### 4.1 Three-State Signaling

All signals emit for ALL states (enabled, disabled, missing) to enable distinct rules:

| Signal Type | enabled | disabled | missing |
|------------|---------|----------|---------|
| `aaa_enabled` | `aaa new-model` | `no aaa new-model` | `AAA_MISSING` |
| `http_server` | `HTTP_ENABLED` | `no ip http server` | `HTTP_MISSING` |

### 4.2 AAA Rules (Implemented)

| Rule ID | Name | Pattern | Triggers When |
|--------|------|---------|--------------|
| `CISCO-AUTH-001` | AAA Required | `AAA_MISSING` | AAA completely absent |
| `CISCO-AUTH-001b` | AAA Disabled | `no aaa new-model` | AAA explicitly disabled |

---

## 5. Context Key Expansion

```python
def _expand_context_key(self, template: str, signal: Signal) -> str:
    """Expand context key template with signal context."""
    if "{context}" in template:
        normalized = signal.context.replace(" ", "_").replace("/", "_")
        return template.format(context=normalized)
    return template

# Examples:
# template="{context}", signal.context="vty 0 4" → "vty_0_4"
# template="interface_{context}", signal.context="GigabitEthernet0/0" → "interface_GigabitEthernet0_0"
```

---

## 6. Finding Schema

### 6.1 Base Fields (from models.py)

```python
class Finding(BaseModel):
    rule_id: str
    rule_name: str
    category: str
    severity: Severity
    status: FindingStatus
    evidence: str
    block_type: Optional[str]
    block_name: Optional[str]
    remediation: Optional[str]
```

### 6.2 Extended Fields

```python
class Finding(BaseModel):
    ...
    evidence_summary: Optional[dict]  # Human-readable from EvidenceBuilder
```

---

## 7. CLI Integration

### 7.1 Command Options

```python
@app.command()
def audit(
    ...
    use_context: bool = typer.Option(True, help="Use context-based evaluation"),
    debug_contexts: bool = typer.Option(False, help="Output SignalContext JSON for debugging"),
    risk_score: bool = typer.Option(False, help="Include risk score calculation (v0.3)"),
):
```

### 7.2 Output Flow

```
1. Parse config → ConfigIR
2. Extract signals
3. Build contexts
4. Evaluate with contexts → findings
5. Attach evidence summaries
6. (Optional) Compute risk score
7. Generate reports (JSON, Markdown)
8. Output STDOUT summary
```

---

## 8. Testing

### 8.1 Test Categories

| Category | Tests | Location |
|----------|-------|----------|
| Context building | Signal clustering, key expansion | `tests/test_context.py` |
| Engine evaluation | Context-aware evaluation | `tests/test_engine.py` |
| IR validation | Schema compliance, determinism | `tests/ir_validation/` |
| Rule coverage | All rules have valid resource types | `tests/ir_validation/test_rule_coverage_matrix.py` |
| Ontology | Knowledge graph, attack paths | `tests/ontology/`, `tests/rules/` |

### 8.2 Integration Tests

- `test_snmp_single_finding_with_all_communities` - SNMP aggregation
- `test_engine_evaluate_with_contexts` - Context evaluation flow
- `test_cli_dual_path_evaluation` - CLI context mode

---

## 9. Files Changed

### 9.1 Core Modules

| File | Changes |
|------|---------|
| `configguard/context.py` | Pure semantic contexts, deterministic ID |
| `configguard/engine.py` | `_find_rules_for_context()`, `evaluate_with_contexts()` |
| `configguard/signals.py` | Three-state signaling |
| `configguard/models.py` | `CanonicalResource` added |
| `configguard/evidence.py` | NEW - EvidenceBuilder |
| `configguard/risk/` | NEW - RiskEngine v0.3 |
| `configguard/cli.py` | `--risk-score`, evidence integration |

### 9.2 Rules

| File | Changes |
|------|---------|
| `rules/auth/aaa_required.yaml` | Pattern → `AAA_MISSING` |
| `rules/auth/aaa_missing.yaml` | Pattern → `no aaa new-model`, renamed to "AAA Disabled" |
| `rules/interface/unused_shutdown.yaml` | Pattern → `no shutdown` |
| `rules/management/disable_http.yaml` | Pattern → `HTTP_ENABLED` |

### 9.3 Tests

| File | Changes |
|------|---------|
| `tests/test_context.py` | Updated for pure semantic contexts |
| `tests/test_engine.py` | Updated for new rule IDs |
| `tests/cases/case_003_missing_aaa/expected.json` | Updated expected rule ID |

---

## 10. Commits

```
224c15f fix: clarify AAA rules - separate 'required' vs 'disabled' semantics
bee860d test: fix test_missing_aaa_case for new rule IDs
a518855 models: add CanonicalResource for vendor-neutral IR
e943571 signals: enhance extraction with missing-state signals
3a6859f context: refactor to pure semantic contexts
a056231 engine: add context-aware evaluation with automatic rule matching
c4392bd evidence: add EvidenceBuilder for human-readable evidence summaries
a24ce57 risk: add RiskEngine v0.3 for post-processing risk scoring
7f27c01 cli: integrate evidence summaries and risk scoring
441a6f1 rules: update patterns for context-aware evaluation
8f14261 tests: update for context-aware evaluation
```

---

## 11. Status

- [x] ContextBuilder - Pure semantic contexts
- [x] RuleEngine - Context-aware evaluation
- [x] EvidenceBuilder - Human-readable evidence
- [x] RiskEngine v0.3 - Post-processing risk scoring
- [x] AAA Rules - Separate "required" vs "disabled" semantics
- [x] All 190 tests passing