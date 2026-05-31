# ConfigGuard v0.2.1 Semantic Stabilization - Implementation Plan

> **Status:** Ready for Implementation
> **Target Version:** v0.2.1
> **Type:** Implementation Plan
> **Date:** 2026-05-31

---

## Phase 0: Baseline & Scope Definition

### 0.1 Current State

- **190 tests passing** (baseline stability)
- **Architecture:** v0.2 Context Builder (partial semantic model)
- **Key Debt:** `context_key` conflates Type + Instance + Aggregation

### 0.2 v0.2.1 Goal

> **斩断配置扫描器的历史包袱，彻底确立 Signal → Context 的 typed IR 模型，并为专家规则提供端到端的静态校验。**

### 0.3 Scope

| In Scope | Out of Scope |
|----------|-------------|
| SignalDefinition Registry | Composite Rules (v0.3) |
| SignalContext Type/Instance Separation | Resource Layer (v0.4) |
| Dual-Axis Rule Index | Graph Layer (v1.0) |
| Rule Contract Static Validator | Attack Path Engine |
| Guard Rails & Circuit Breaker | LLM Integration |
| Coverage Matrix | |

---

## Phase 1: Data Model Refactoring (Week 1-2)

### Task 1.1: SignalDefinition Registry & Linter

**Deliverable:** `configguard/signal_registry.py`

**Implementation:**

```python
@dataclass
class SignalDefinition:
    signal_type: str
    category: str                    # Execution dimension
    security_domain: str            # Reasoning dimension
    context_template: str | None    # Binding layer
    aggregation_strategy: str       # singleton / per_instance / composite
    scope: str | None = None

class SignalRegistry:
    """Singleton registry for signal definitions."""

    _instance: 'SignalRegistry | None' = None

    def __init__(self):
        self._definitions: dict[str, SignalDefinition] = {}
        self._category_index: dict[str, list[str]] = {}  # category → [signal_types]
        self._template_var_allowlist = {"interface", "vrf", "context", "site"}

    def register(self, definition: SignalDefinition) -> None:
        """Register a signal definition with static validation."""
        self._validate_template(definition.context_template)
        self._definitions[definition.signal_type] = definition
        self._rebuild_index()

    def _validate_template(self, template: str | None) -> None:
        """Static validation of context_template placeholders."""
        if not template:
            return
        import re
        placeholders = re.findall(r'\{(\w+)\}', template)
        for var in placeholders:
            if var not in self._template_var_allowlist:
                raise SignalDefinitionError(
                    f"Illegal placeholder '{{{var}}}' in context_template. "
                    f"Allowed: {self._template_var_allowlist}"
                )

    def get(self, signal_type: str) -> SignalDefinition | None:
        return self._definitions.get(signal_type)

    def get_by_category(self, category: str) -> list[SignalDefinition]:
        return [
            self._definitions[st]
            for st in self._category_index.get(category, [])
        ]
```

**Acceptance Criteria:**
- [ ] `SignalRegistry` is a singleton accessible via `SignalRegistry.get_instance()`
- [ ] `context_template` with illegal placeholder (e.g., `{foo}`) raises `SignalDefinitionError` at registration
- [ ] `category_index` rebuilt on each registration
- [ ] `configguard lint --registry` command validates all registered definitions

---

### Task 1.2: SignalContext Type/Instance Separation

**Deliverable:** Refactored `configguard/context.py`

**Implementation:**

```python
@dataclass
class SignalContext:
    """Type + Instance separation (SRP fix for context_key)."""

    context_type: str              # "snmp", "vty", "interface"
    instance_id: str | None       # None for singleton, "0_4" for vty
    category: str                  # Mirrors context_type (for backward compat)
    signals: list[Signal] = field(default_factory=list)
    aggregated_evidence: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    id: str = field(default="")

    def __post_init__(self):
        # Enforce concept boundary: category and context_type
        # may have same value initially, but are distinct concepts
        self.category = self.context_type

    @staticmethod
    def _compute_context_id(context_type: str, instance_id: str | None, evidence: list[str]) -> str:
        """Stable deterministic ID."""
        key = f"{context_type}:{instance_id or 'singleton'}:{','.join(sorted(evidence))}"
        return hashlib.sha256(key.encode()).hexdigest()[:8]
```

**Guard Rail (Context Snowball Prevention):**

```python
class ContextBuilder:
    MAX_INSTANCES_PER_NODE = 1000  # Configurable via env

    def build_contexts(self, signals: list[Signal]) -> list[SignalContext]:
        clusters = self._cluster_signals(signals)

        # Guard rail: per_instance explosion prevention
        for cluster_key, cluster_signals in clusters.items():
            if len(cluster_signals) > ContextBuilder.MAX_INSTANCES_PER_NODE:
                raise ContextOverflowError(
                    f"Cluster '{cluster_key}' has {len(cluster_signals)} instances, "
                    f"exceeding limit of {ContextBuilder.MAX_INSTANCES_PER_NODE}. "
                    f"Possible configuration error or attack."
                )

        contexts = []
        for cluster_key, cluster_signals in clusters.items():
            context = self._build_context(cluster_key, cluster_signals)
            contexts.append(context)
        return contexts
```

**Acceptance Criteria:**
- [ ] `SignalContext.context_type` and `SignalContext.instance_id` are explicit fields
- [ ] Singleton contexts (snmp, aaa, http) have `instance_id = None`
- [ ] Instance contexts (vty, interface) have `instance_id` populated
- [ ] Injecting 10,000 fake interface configs triggers `ContextOverflowError`
- [ ] Memory growth under control during stress test

---

## Phase 2: Dual-Axis Rule Engine (Week 3-4)

### Task 2.1: Compile-Time Inverted Index

**Deliverable:** Refactored `configguard/engine.py`

**Implementation:**

```python
class Rule:
    def __init__(self, rule_data: dict):
        self.id = rule_data["id"]
        self.name = rule_data["name"]
        self.category = rule_data["category"]
        self.applies_to: dict = rule_data.get("applies_to", {})
        # ... existing fields ...

    def matches_category(self, category: str) -> bool:
        """Stage 1: O(1) category lookup."""
        return category in self.applies_to.get("category", [])

    def matches_domain(self, security_domain: str) -> bool:
        """Stage 2: Domain matching (future)."""
        return security_domain in self.applies_to.get("security_domain", [])

class RuleEngine:
    def __init__(self, rules_dir: str):
        self.rules: list[Rule] = []
        self.rules_dir = Path(rules_dir)
        # Stage 1 index: category → [rules]
        self._category_index: dict[str, list[Rule]] = {}
        self._load_rules()

    def _load_rules(self):
        """Build compile-time inverted index."""
        if not self.rules_dir.exists():
            return
        for yaml_file in self.rules_dir.rglob("*.yaml"):
            with open(yaml_file) as f:
                rule_data = yaml.safe_load(f)
                rule = Rule(rule_data)
                self.rules.append(rule)

        # Build Stage 1 index: O(1) hash lookup
        self._rebuild_index()

    def _rebuild_index(self):
        """Rebuild category → rules inverted index."""
        self._category_index.clear()
        for rule in self.rules:
            for category in rule.applies_to.get("category", []):
                if category not in self._category_index:
                    self._category_index[category] = []
                self._category_index[category].append(rule)

    def evaluate_with_contexts(self, contexts: list[SignalContext]) -> list[Finding]:
        """Two-stage matching with O(1) Stage 1."""
        all_findings = []
        seen_findings = set()

        for context in contexts:
            # Stage 1: O(1) hash lookup
            relevant_rules = self._category_index.get(context.context_type, [])

            for rule in relevant_rules:
                findings = rule.evaluate_with_context(context)
                for finding in findings:
                    dedup_key = (finding.rule_id, finding.block_name, finding.evidence)
                    if dedup_key not in seen_findings:
                        seen_findings.add(dedup_key)
                        all_findings.append(finding)

        return all_findings
```

**Acceptance Criteria:**
- [ ] No nested loops in `evaluate_with_contexts()`
- [ ] Stage 1 lookup is O(1) hash lookup (no list iteration)
- [ ] `_category_index` is built at initialization, not at runtime
- [ ] Perf test: 100 rules × 1000 contexts evaluates in < 10ms

---

### Task 2.2: Rule Contract Static Validator

**Deliverable:** `configguard lint` CLI command

**Implementation:**

```python
@app.command()
def lint(
    rules_dir: Path = typer.Option(Path("configguard/rules"), help="Rules directory"),
    registry: bool = typer.Option(False, help="Validate signal registry"),
):
    """Validate rule files and signal definitions."""
    registry_instance = SignalRegistry.get_instance()
    errors = []

    # Validate rule files
    for yaml_file in rules_dir.rglob("*.yaml"):
        rule_errors = validate_rule_file(yaml_file, registry_instance)
        errors.extend(rule_errors)

    if errors:
        for error in errors:
            typer.echo(f"ERROR: {error}", err=True)
        raise typer.Exit(1)
    else:
        typer.echo("All validations passed.")

def validate_rule_file(yaml_path: Path, registry: SignalRegistry) -> list[str]:
    """Validate a single rule file."""
    errors = []
    with open(yaml_path) as f:
        rule_data = yaml.safe_load(f)

    # Check applies_to categories exist in registry
    applies_to = rule_data.get("applies_to", {})
    for category in applies_to.get("category", []):
        # If we have registry entries, validate against them
        if registry._definitions:
            if not any(d.category == category for d in registry._definitions.values()):
                errors.append(
                    f"{yaml_path}: Unknown category '{category}' in applies_to. "
                    f"Did you mean 'snmp'?"
                )

    # Validate context_template placeholders
    # ... (similar to registry validation)

    return errors
```

**Acceptance Criteria:**
- [ ] `configguard lint rules/` detects `category: snmpp` (typo) and reports error
- [ ] `configguard lint rules/` detects illegal `context_template: {foo}` and reports error
- [ ] Lint runs in CI/CD pipeline and fails on validation errors
- [ ] Clear error messages with suggestions (e.g., "Did you mean...")

---

## Phase 3: Coverage Matrix (Week 5)

### Task 3.1: Auto-Generated Coverage Matrix

**Deliverable:** `configguard/coverage` CLI command

**Implementation:**

```python
@app.command()
def coverage(
    rules_dir: Path = typer.Option(Path("configguard/rules"), help="Rules directory"),
    output: Path = typer.Option(Path("coverage_matrix.md"), help="Output file"),
):
    """Generate coverage matrix showing category → rule coverage."""
    registry = SignalRegistry.get_instance()
    engine = RuleEngine(str(rules_dir))

    # Build matrix
    categories = set(d.category for d in registry._definitions.values())
    matrix = []

    for category in sorted(categories):
        rules = engine._category_index.get(category, [])
        coverage = "✓" if rules else "✗"
        rule_ids = ", ".join(r.id for r in rules) if rules else "(none)"

        matrix.append(f"| {category} | {coverage} | {rule_ids} |")

    header = "| Category | Covered | Rules |"
    separator = "|----------|---------|-------|"

    content = "\n".join([
        "# ConfigGuard Coverage Matrix",
        f"Generated: {datetime.now().isoformat()}",
        "",
        header,
        separator,
        *matrix,
    ])

    output.write_text(content)
    typer.echo(f"Coverage matrix written to {output}")
```

**Acceptance Criteria:**
- [ ] `configguard coverage` generates `coverage_matrix.md`
- [ ] Matrix shows all categories from registry
- [ ] Covered categories show rule IDs
- [ ] Uncovered categories flagged with "(none)"

---

## Milestones & Definition of Done

### Milestone 1: SignalDefinition Registry
- [ ] `SignalRegistry` singleton implemented
- [ ] Static validation of `context_template` placeholders
- [ ] Illegal placeholder raises error at registration time

### Milestone 2: SignalContext Separation
- [ ] `SignalContext` has explicit `context_type` and `instance_id`
- [ ] Singleton vs instance contexts distinguished
- [ ] Circuit breaker triggers at 1000+ instances per node

### Milestone 3: Dual-Axis Rule Engine
- [ ] `Rule.applies_to.category` is the primary matching dimension
- [ ] Stage 1 lookup is O(1) hash lookup
- [ ] No nested loops in `evaluate_with_contexts()`

### Milestone 4: Rule Contract Validator
- [ ] `configguard lint` command available
- [ ] Typos in `category` detected and reported
- [ ] Invalid `context_template` detected and reported

### Milestone 5: Coverage Matrix
- [ ] `configguard coverage` command available
- [ ] Matrix shows category → rule coverage
- [ ] Uncovered categories clearly flagged

---

## Engineering Criteria (Acceptance Standards)

Derived from architectural consensus:

| Criterion | Standard |
|-----------|----------|
| **O(1) Lookup** | Stage 1 matching must be hash lookup, no nested iteration |
| **Static Validation** | All `context_template` variables validated at registration |
| **Concept Boundary** | `category` and `context_type` are distinct fields, not interchangeable |
| **Guard Rail** | `MAX_INSTANCES_PER_NODE = 1000` enforced via circuit breaker |
| **Schema Lint** | `configguard lint` catches category typos before runtime |
| **Memory Safety** | Stress test with 10,000 fake configs triggers protection |

---

## Execution Options

| Option | Description |
|--------|-------------|
| **Subagent-Driven (Recommended)** | Dispatch subagent per task, review between phases |
| **Inline Execution** | Execute tasks sequentially in this session with checkpoints |
| **Hybrid** | Phase 1 as subagent, Phase 2-3 inline |

---

## Dependencies

- Task 2.1 depends on Task 1.1 (needs `SignalRegistry` for category index)
- Task 2.2 depends on Task 1.1 (needs validation logic)
- Task 3.1 depends on Task 2.1 (needs `RuleEngine` with index)

**Execution Order:** Task 1.1 → Task 1.2 → Task 2.1 → Task 2.2 → Task 3.1

---

## Summary

```
v0.2.1 Semantic Stabilization

Week 1-2: Data Model
├── SignalDefinition Registry
└── SignalContext Type/Instance Separation

Week 3-4: Rule Engine
├── Dual-Axis Inverted Index
└── Rule Contract Static Validator

Week 5: Coverage
└── Coverage Matrix Generation
```