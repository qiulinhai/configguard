# ConfigGuard Architecture Decision Records

> **Status:** Active
> **Date:** 2026-05-30
> **Version:** 0.2.1

---

## ADR-001: Why Per-Context Execution

**Context:** v0.2.0 introduced signal extraction but rule evaluation remained per-signal, causing duplicate findings for semantically same issues.

**Decision:** Switch from `RuleEngine.evaluate(ir)` to `RuleEngine.evaluate_with_contexts(contexts)`.

**Rationale:**
- `public` + `private` SNMP communities are TWO signals but ONE semantic issue
- Per-signal evaluation produces `N findings` where `N = signal count`
- Per-context evaluation produces `1 finding` where `1 = semantic issue count`

**Consequences:**
- Context Builder becomes the semantic aggregation layer
- Rule evaluation changes from `(rule, ir)` to `(rule, context)`
- Evidence becomes aggregated command text instead of individual matches

**Trade-offs:**
- "+" More accurate security semantics
- "+" Fewer duplicate findings
- "-" Context Builder must be stable before rule authoring
- "-" Breaking change for existing rule contracts

**Related:** ADR-003, ADR-004

---

## ADR-002: Why Not LLM-First Architecture

**Context:** Many security startups build `config → LLM → findings`. This appears simpler but has fundamental problems.

**Decision:** Build deterministic semantic normalization layer BEFORE any AI integration.

**Rationale:**
| Approach | Deterministic | Auditable | Certifiable | Regression-safe |
|----------|--------------|-----------|-------------|----------------|
| LLM-only | ❌ | ❌ | ❌ | ❌ |
| **Our approach** | ✅ | ✅ | ✅ | ✅ |

**Why it matters for enterprise:**
- Compliance requires reproducible audit results
- Security findings must be explainable without AI
- Regression testing must catch rule changes

**Our architecture:**
```
config → semantic IR → signals → contexts → deterministic findings
                                                    ↓
                                           optional AI explanation
```

**Consequences:**
- "+" Deterministic core never depends on AI availability
- "+" Findings are reproducible and verifiable
- "+" Enables CI/CD regression testing
- "-" Initial development takes longer

---

## ADR-003: Why Signal ≠ Context

**Context:** v0.2 introduced signals as semantic atoms, but later discovered signals alone don't solve duplication.

**Decision:** Signals normalize config observations; Contexts group signals by rule-relevant semantics.

**Why signals alone were insufficient:**
```
signals: [public, private]
         ↓
per-signal evaluation: 2 findings ❌
```

```
signals: [public, private]
         ↓
ContextBuilder → context(snmp_security, evidence=[public, private])
         ↓
per-context evaluation: 1 finding ✅
```

**Signal role:**
- Normalize vendor-specific config syntax
- Extract atomic security observations
- Deduplicate identical observations

**Context role:**
- Group related signals by rule relevance
- Aggregate evidence for rule evaluation
- Preserve per-interface/per-VTY granularity

**Key insight:** Signal extraction happens once per config; context aggregation happens per rule. This separation allows rules to subscribe to relevant contexts without knowing signal-level details.

---

## ADR-004: Why Evidence Aggregation at Context Layer

**Context:** v0.2.0 produced `Evidence: public` and `Evidence: private` for SNMP. v0.2.1 produces `Evidence: snmp-server community, snmp-server community public, snmp-server community private`.

**Decision:** Aggregate evidence at context layer using raw signal text, not at output layer.

**Rationale:**
- Pattern matching in rules expects full command text (e.g., `snmp-server community.*public`)
- Aggregated evidence preserves pattern matchability
- Evidence aggregation is a semantic operation, not cosmetic

**Why NOT output-layer dedup:**
```
❌ findings = dedup(findings)  # Loses semantic context
✅ context = aggregate(signals); finding = evaluate(rule, context)  # Preserves semantics
```

**Evidence formatter (presentation layer) should be separate:**
```python
def format_evidence(context):
    """Clean presentation formatting, not semantic reasoning."""
    return f"Communities detected: {', '.join(context.evidence)}"
```

---

## ADR-005: Context Schema Design

**Context:** SignalContext will become the core ABI for all future features.

**Decision:**
```python
@dataclass
class SignalContext:
    id: str                              # Unique context identifier
    context_key: str                      # Semantic grouping key (e.g., "snmp_security")
    signals: list[Signal]                 # Original signals in this context
    aggregated_evidence: list[str]        # Evidence values for pattern matching
    metadata: dict                        # Context-specific metadata
```

**Field decisions:**

| Field | Purpose | Rationale |
|-------|---------|-----------|
| `id` | Unique identifier | For cross-referencing in composite rules |
| `context_key` | Semantic type | Groups contexts by security domain |
| `signals` | Original signals | Preserves audit trail and raw text |
| `aggregated_evidence` | Pattern matching target | Joined raw text for regex compatibility |
| `metadata` | Extensible | Future fields without breaking change |

**What's NOT included:**
- `severity`: Derived at rule evaluation time
- `rule_id`: Contexts are rule-agnostic; rule_id comes from relationship
- `block_name`: Replaced by `context_key` for semantic grouping

---

## ADR-006: Rule Migration Priority

**Context:** We have legacy rules (evaluate on ConfigIR) and signal rules (evaluate on contexts). Migration priority needed.

**Decision:** Migrate in order: SNMP → VTY → AAA → Logging/NTP → Interface.

**Priority rationale:**

| Domain | Priority | Reason |
|--------|----------|--------|
| SNMP | P0 | Most visible duplication (3 communities → 1 finding) |
| VTY | P0 | Clear per-line semantics, multiple rules overlap |
| AAA | P1 | Global scope, simple signals |
| Logging/NTP | P1 | Global scope, straightforward signals |
| Interface | P2 | More complex state, less overlap |

**Migration criteria:**
1. Rules that produce duplicate findings for semantically same issue
2. Rules with clear context boundaries (global vs per-interface)
3. Rules where evidence aggregation adds audit value

**What's NOT migrated yet:**
- Composite rules (v0.3)
- Absence detection rules (context evaluation assumes presence)
- Rules requiring multi-context reasoning

---

## Future ADRs (Planned)

| ADR | Status | Description |
|-----|--------|-------------|
| ADR-007 | Planned | Composite rule evaluation order |
| ADR-008 | Planned | Why not multi-vendor yet |
| ADR-009 | Planned | AI explanation layer separation |
| ADR-010 | Planned | Batch scan architecture |