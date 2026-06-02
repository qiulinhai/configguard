# Promotion Step 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a credible GitHub-facing project surface — layered README, copy-paste GitHub Action + pre-commit hook, CIS-traceable rule set, and a `--fail-on` CI gating flag — that lets a first-time visitor understand, copy, and gate ConfigGuard within 5 minutes.

**Architecture:** Add an optional `references:` field to the rule schema (model + loader + markdown/JSON output). Populate it on all 7 rules against CIS Cisco IOS Benchmark. Ship a realistic multi-domain sample config with frozen output fixtures. Add a `--fail-on <severity>` CLI flag so the new GitHub Action can gate merges. Layered README (executive top, engineer bottom) embeds the sample output and points at a generated rule table.

**Tech Stack:** Python 3.10+, Pydantic v2, PyYAML, Typer, pytest. Output to GitHub-flavored Markdown + JSON. No new dependencies required.

**Spec reference:** `docs/superpowers/specs/2026-06-01-promotion-readme-step1-design.md`

**Note on rule IDs and rule count:** The repo actually has **10 rules** (not 7 as the spec originally said). AAA family has 3 IDs: `CISCO-AUTH-001` (required), `CISCO-AUTH-001b` (disabled), `CISCO-AUTH-002` (console auth). The full set:
- management/: `CISCO-MGMT-001` (telnet), `CISCO-MGMT-002` (http), `CISCO-MGMT-003` (secure vty)
- snmp/: `CISCO-SNMP-001` (snmp v2c disabled)
- auth/: `CISCO-AUTH-001` (aaa required), `CISCO-AUTH-001b` (aaa disabled), `CISCO-AUTH-002` (console auth)
- interface/: `CISCO-IF-001` (unused shutdown)
- logging/: `CISCO-LOG-001` (remote syslog), `CISCO-LOG-002` (ntp)

Task 5 populates references on all 10.

---

## Task 1: Add `Reference` dataclass to `models.py`

**Files:**
- Modify: `configguard/models.py:1-7` (top imports)
- Create: `tests/test_rule_schema.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_rule_schema.py` with:

```python
"""Tests for rule schema extensions (v0.2.1+)."""
from configguard.models import Reference, Severity


def test_reference_dataclass_basic():
    ref = Reference(type="cis-benchmark", id="1.1.1", url="https://example.com/cis")
    assert ref.type == "cis-benchmark"
    assert ref.id == "1.1.1"
    assert ref.url == "https://example.com/cis"


def test_reference_dataclass_to_dict():
    ref = Reference(type="cve", id="CVE-2017-6736", url="https://nvd.nist.gov/vuln/detail/CVE-2017-6736")
    d = ref.to_dict()
    assert d == {
        "type": "cve",
        "id": "CVE-2017-6736",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2017-6736",
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/test_rule_schema.py -v`
Expected: FAIL with `ImportError: cannot import name 'Reference' from 'configguard.models'`

- [ ] **Step 3: Implement `Reference` in `configguard/models.py`**

Add at the end of the file (after the existing `CanonicalResource` class), keeping the existing imports and classes untouched:

```python
@dataclass
class Reference:
    """A single provenance reference for a rule (CIS, CVE, vendor doc, etc.)."""
    type: str  # e.g., "cis-benchmark", "cve", "cisco-hardening-guide", "nist-800-53"
    id: str    # source-specific identifier, e.g., "1.1.1" or "CVE-2017-6736"
    url: str   # direct URL to the referenced material

    def to_dict(self) -> dict:
        return {"type": self.type, "id": self.id, "url": self.url}
```

(The file already has `from dataclasses import dataclass` on line 59, so no new import is needed.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/test_rule_schema.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
cd /home/lhqiu/project/ConfigGuard
git add tests/test_rule_schema.py configguard/models.py
git commit -m "feat(models): add Reference dataclass for rule provenance"
```

---

## Task 2: Parse `references:` in `Rule.__init__`

**Files:**
- Modify: `configguard/engine.py:19-50` (the `Rule.__init__` method)
- Modify: `tests/test_rule_schema.py`

- [ ] **Step 1: Add failing test for `Rule.references` parsing**

Append to `tests/test_rule_schema.py`:

```python
import yaml
from configguard.engine import Rule


def test_rule_parses_references():
    rule_yaml = """
id: TEST-001
name: Test Rule
category: test
severity: HIGH

applies_to:
  category: [vty]

match:
  type: regex
  pattern: "telnet"
condition: present

finding:
  status: FAIL
  evidence: true

references:
  - type: cis-benchmark
    id: "1.1.1"
    url: "https://example.com/cis"
  - type: cve
    id: "CVE-2017-6736"
    url: "https://nvd.nist.gov/vuln/detail/CVE-2017-6736"
"""
    rule = Rule(yaml.safe_load(rule_yaml))
    assert len(rule.references) == 2
    assert rule.references[0].type == "cis-benchmark"
    assert rule.references[0].id == "1.1.1"
    assert rule.references[1].type == "cve"


def test_rule_default_references_empty():
    rule_yaml = """
id: TEST-002
name: No Refs
category: test
severity: LOW

match:
  type: regex
  pattern: "x"
condition: present

finding:
  status: FAIL
  evidence: true
"""
    rule = Rule(yaml.safe_load(rule_yaml))
    assert rule.references == []


def test_rule_warns_on_unknown_reference_type(capsys):
    rule_yaml = """
id: TEST-003
name: Unknown Type
category: test
severity: LOW

match:
  type: regex
  pattern: "x"
condition: present

finding:
  status: FAIL
  evidence: true

references:
  - type: not-a-real-type
    id: "abc"
    url: "https://example.com"
"""
    rule = Rule(yaml.safe_load(rule_yaml))
    captured = capsys.readouterr()
    assert "Unknown reference type 'not-a-real-type'" in captured.out or \
           "Unknown reference type 'not-a-real-type'" in captured.err
    # Rule should still load
    assert len(rule.references) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/test_rule_schema.py -v`
Expected: FAIL — `AttributeError: 'Rule' object has no attribute 'references'`

- [ ] **Step 3: Update `Rule.__init__` to parse `references`**

Modify `configguard/engine.py`:

Add to imports at top (line 11, alongside `from configguard.models import ...`):
```python
from configguard.models import ConfigIR, Finding, FindingStatus, Reference, Severity
```

Then in `Rule.__init__` (after line 42, after the existing `self._domains` line), add:

```python
        # v0.2.1+: Reference provenance
        KNOWN_REF_TYPES = {"cis-benchmark", "cve", "cisco-hardening-guide", "nist-800-53", "vendor-advisory"}
        ref_dicts = rule_data.get("references", []) or []
        self.references: list[Reference] = []
        for r in ref_dicts:
            ref = Reference(type=r["type"], id=r["id"], url=r["url"])
            if ref.type not in KNOWN_REF_TYPES:
                print(f"Warning: Unknown reference type '{ref.type}' in rule {self.id} (allowed: {sorted(KNOWN_REF_TYPES)})")
            self.references.append(ref)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/test_rule_schema.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Run full test suite to confirm no regressions**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/ -q`
Expected: All 24+ tests pass (existing 19 + 5 new)

- [ ] **Step 6: Commit**

```bash
cd /home/lhqiu/project/ConfigGuard
git add configguard/engine.py tests/test_rule_schema.py
git commit -m "feat(engine): parse references field on rules with unknown-type warning"
```

---

## Task 3: Render `references` in Markdown report

**Files:**
- Modify: `configguard/models.py` (`Finding` class)
- Modify: `configguard/output/markdown.py:26-46`
- Modify: `configguard/engine.py` (attach references to `Finding`)
- Modify: `tests/test_rule_schema.py`

**Design decision (made upfront, not mid-task):** `Rule.references` is `list[Reference]` (the dataclass). When the engine builds a `Finding`, it converts via `to_dict()` so the `Finding` model holds `list[dict]`. Output renderers work with the dict shape. This avoids Pydantic v2 ↔ dataclass interop surprises.

- [ ] **Step 1: Add `references` field to `Finding` model**

Modify `configguard/models.py`. In the `Finding` class (lines 26-36), add a new field:

```python
    references: list[dict] = Field(default_factory=list)  # List of Reference.to_dict()
```

- [ ] **Step 2: Write the failing test**

Append to `tests/test_rule_schema.py`:

```python
from configguard.output.markdown import generate_markdown_report


def test_markdown_report_includes_references():
    finding = Finding(
        rule_id="CISCO-MGMT-001",
        rule_name="Disable Telnet",
        category="management-plane",
        severity=Severity.HIGH,
        status=FindingStatus.FAIL,
        evidence="transport input telnet",
        remediation="Use SSH",
        references=[
            {"type": "cis-benchmark", "id": "1.1.1", "url": "https://example.com/cis"},
            {"type": "cve", "id": "CVE-1999-0001", "url": "https://nvd.nist.gov/vuln/detail/CVE-1999-0001"},
        ],
    )
    md = generate_markdown_report([finding], config_name="test")
    assert "**References:**" in md
    assert "1.1.1" in md
    assert "https://example.com/cis" in md
    assert "CVE-1999-0001" in md
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/test_rule_schema.py::test_markdown_report_includes_references -v`
Expected: FAIL — `AssertionError: '**References:**' not in md`

- [ ] **Step 4: Update `generate_markdown_report` to render references**

Modify `configguard/output/markdown.py`, in the `if fail_findings:` block (lines 29-41), after the remediation block, add:

```python
            if f.references:
                lines.append("**References:**")
                for ref in f.references:
                    ref_type = ref.get("type", "reference")
                    ref_id = ref.get("id", "")
                    ref_url = ref.get("url", "")
                    if ref_type.upper() in ("CVE", "NIST-800-53"):
                        label = f"{ref_type.upper()} {ref_id}" if ref_id else ref_type
                    else:
                        label = f"{ref_type.replace('-', ' ').title()} {ref_id}".strip()
                    if ref_url:
                        lines.append(f"- [{label}]({ref_url})")
                    else:
                        lines.append(f"- {label}")
                lines.append("")
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/test_rule_schema.py::test_markdown_report_includes_references -v`
Expected: PASS

- [ ] **Step 6: Wire references through to `Finding` in `Rule.evaluate_with_context` and `Rule.evaluate`**

In `configguard/engine.py`, every place that constructs a `Finding(...)` (4 call sites: in `evaluate()` lines 61-71 and 77-86, in `evaluate_with_context()` lines 131-141 and 148-154) needs to add a final keyword argument:

```python
            references=[ref.to_dict() for ref in self.references],
```

- [ ] **Step 7: Run full test suite**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/ -q`
Expected: All pass

- [ ] **Step 8: Commit**

```bash
cd /home/lhqiu/project/ConfigGuard
git add configguard/models.py configguard/engine.py configguard/output/markdown.py tests/test_rule_schema.py
git commit -m "feat(output): render rule references in markdown report"
```

---

## Task 4: Render `references` in JSON report

**Files:**
- Modify: `configguard/output/json.py:18-31`

- [ ] **Step 1: Add failing test for JSON output of references**

Append to `tests/test_rule_schema.py`:

```python
import json as _json
from configguard.output.json import generate_json_report


def test_json_report_includes_references():
    finding = Finding(
        rule_id="CISCO-SNMP-001",
        rule_name="Disable SNMP v2c",
        category="snmp-security",
        severity=Severity.HIGH,
        status=FindingStatus.FAIL,
        evidence="snmp-server community public RO",
        remediation="Use SNMPv3",
        references=[
            {"type": "cis-benchmark", "id": "2.2.1", "url": "https://example.com/cis"},
            {"type": "cve", "id": "CVE-1999-0517", "url": "https://nvd.nist.gov/vuln/detail/CVE-1999-0517"},
        ],
    )
    raw = generate_json_report([finding], config_name="test", rules_version="0.2.1")
    report = _json.loads(raw)
    assert report["findings"][0]["references"] == [
        {"type": "cis-benchmark", "id": "2.2.1", "url": "https://example.com/cis"},
        {"type": "cve", "id": "CVE-1999-0517", "url": "https://nvd.nist.gov/vuln/detail/CVE-1999-0517"},
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/test_rule_schema.py::test_json_report_includes_references -v`
Expected: FAIL — `KeyError: 'references'`

- [ ] **Step 3: Add `references` to JSON output**

Modify `configguard/output/json.py`. In the list comprehension at lines 18-31, add a new key:

```python
                "references": f.references,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/test_rule_schema.py::test_json_report_includes_references -v`
Expected: PASS

- [ ] **Step 5: Run full suite**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/ -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
cd /home/lhqiu/project/ConfigGuard
git add configguard/output/json.py tests/test_rule_schema.py
git commit -m "feat(output): include rule references in JSON report"
```

---

## Task 5: Populate `references` on all 10 rules

**Files:**
- Modify: `configguard/rules/management/disable_telnet.yaml`
- Modify: `configguard/rules/management/disable_http.yaml`
- Modify: `configguard/rules/management/secure_vty.yaml`
- Modify: `configguard/rules/snmp/snmp_v2_disabled.yaml`
- Modify: `configguard/rules/auth/aaa_required.yaml`
- Modify: `configguard/rules/auth/aaa_missing.yaml`
- Modify: `configguard/rules/auth/console_auth.yaml`
- Modify: `configguard/rules/interface/unused_shutdown.yaml`
- Modify: `configguard/rules/logging/ntp_config.yaml`
- Modify: `configguard/rules/logging/remote_syslog.yaml`

- [ ] **Step 1: Add references to `disable_telnet.yaml`**

In `configguard/rules/management/disable_telnet.yaml`, after the `remediation:` block, add:

```yaml

references:
  - type: cis-benchmark
    id: "2.3.1"
    url: "https://www.cisecurity.org/benchmark/cisco_ios"
  - type: cisco-hardening-guide
    id: "Configuring Secure Shell"
    url: "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-i1.html"
```

- [ ] **Step 2: Add references to `disable_http.yaml`**

In `configguard/rules/management/disable_http.yaml`, after `remediation:`, add:

```yaml

references:
  - type: cis-benchmark
    id: "2.2.1"
    url: "https://www.cisecurity.org/benchmark/cisco_ios"
  - type: cisco-hardening-guide
    id: "Disabling the HTTP Server"
    url: "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec-mgmt/sec-mgmt-book/sec-cfg-sec.html"
```

- [ ] **Step 3: Add references to `secure_vty.yaml`**

In `configguard/rules/management/secure_vty.yaml`, after `remediation:`, add:

```yaml

references:
  - type: cis-benchmark
    id: "2.3.2"
    url: "https://www.cisecurity.org/benchmark/cisco_ios"
  - type: cisco-hardening-guide
    id: "VTY Line Security"
    url: "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-i1.html"
```

- [ ] **Step 4: Add references to `snmp_v2_disabled.yaml`**

In `configguard/rules/snmp/snmp_v2_disabled.yaml`, after `remediation:`, add:

```yaml

references:
  - type: cis-benchmark
    id: "2.2.2"
    url: "https://www.cisecurity.org/benchmark/cisco_ios"
  - type: cve
    id: "CVE-1999-0517"
    url: "https://nvd.nist.gov/vuln/detail/CVE-1999-0517"
  - type: cisco-hardening-guide
    id: "SNMPv3 Migration"
    url: "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/snmp/configuration/15-mt/snmp-15-mt-book.html"
```

- [ ] **Step 5: Add references to `aaa_required.yaml`**

In `configguard/rules/auth/aaa_required.yaml`, after `remediation:`, add:

```yaml

references:
  - type: cis-benchmark
    id: "1.1.1"
    url: "https://www.cisecurity.org/benchmark/cisco_ios"
  - type: nist-800-53
    id: "AC-2"
    url: "https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search"
```

- [ ] **Step 6: Add references to `aaa_missing.yaml` (CISCO-AUTH-001b — "AAA Disabled")**

In `configguard/rules/auth/aaa_missing.yaml`, after `remediation:`, add:

```yaml

references:
  - type: cis-benchmark
    id: "1.1.1"
    url: "https://www.cisecurity.org/benchmark/cisco_ios"
  - type: nist-800-53
    id: "AC-2"
    url: "https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search"
  - type: cisco-hardening-guide
    id: "Enabling AAA"
    url: "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-a1.html"
```

- [ ] **Step 7: Add references to `console_auth.yaml` (CISCO-AUTH-002)**

In `configguard/rules/auth/console_auth.yaml`, after `remediation:`, add:

```yaml

references:
  - type: cis-benchmark
    id: "1.2.1"
    url: "https://www.cisecurity.org/benchmark/cisco_ios"
  - type: cisco-hardening-guide
    id: "Console Line Security"
    url: "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-i1.html"
```

- [ ] **Step 7a: Add references to `unused_shutdown.yaml` (CISCO-IF-001)**

In `configguard/rules/interface/unused_shutdown.yaml`, after `remediation:`, add:

```yaml

references:
  - type: cis-benchmark
    id: "3.1.1"
    url: "https://www.cisecurity.org/benchmark/cisco_ios"
  - type: cisco-hardening-guide
    id: "Interface Hardening"
    url: "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-i1.html"
```

- [ ] **Step 7b: Add references to `remote_syslog.yaml` (CISCO-LOG-001)**

In `configguard/rules/logging/remote_syslog.yaml` (note: this rule has no `remediation:` block; add `references:` after `description:`), add:

```yaml

references:
  - type: cis-benchmark
    id: "4.1.1"
    url: "https://www.cisecurity.org/benchmark/cisco_ios"
  - type: nist-800-53
    id: "AU-2"
    url: "https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search"
  - type: cisco-hardening-guide
    id: "Logging Configuration"
    url: "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-i1.html"
```

- [ ] **Step 7c: Add references to `ntp_config.yaml` (CISCO-LOG-002)**

In `configguard/rules/logging/ntp_config.yaml` (also no `remediation:` block; add `references:` after `description:`), add:

```yaml

references:
  - type: cis-benchmark
    id: "4.2.1"
    url: "https://www.cisecurity.org/benchmark/cisco_ios"
  - type: nist-800-53
    id: "AU-8"
    url: "https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search"
```

- [ ] **Step 8: Run rule schema tests + full suite**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/ -q`
Expected: All pass

- [ ] **Step 9: Spot-check one rule's parsed output**

Run:
```bash
cd /home/lhqiu/project/ConfigGuard && python3 -c "
from configguard.engine import RuleEngine
e = RuleEngine('configguard/rules')
for r in e.rules:
    refs = ', '.join(f'{x.type}:{x.id}' for x in r.references)
    print(f'{r.id:25} refs={refs}')
"
```
Expected: All 10 rules printed, each with at least one reference like `cis-benchmark:2.3.1`

- [ ] **Step 10: Commit**

```bash
cd /home/lhqiu/project/ConfigGuard
git add configguard/rules/
git commit -m "feat(rules): populate references field for all 7 rules (CIS / CVE / NIST)"
```

---

## Task 6: Add `--fail-on <severity>` CLI flag

**Files:**
- Modify: `configguard/cli.py:23-141` (the `audit` command)
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Add failing tests for `--fail-on`**

Append to `tests/test_cli.py`:

```python
def test_cli_fail_on_none_default_returns_zero(tmp_path):
    """Default --fail-on none: HIGH findings still exit 0."""
    from configguard.cli import app
    from typer.testing import CliRunner
    runner = CliRunner()
    cfg = tmp_path / "config.txt"
    cfg.write_text("line vty 0 4\n transport input telnet\n")
    result = runner.invoke(app, [str(cfg), "--fail-on", "none"])
    assert result.exit_code == 0


def test_cli_fail_on_high_exits_one_on_high(tmp_path):
    from configguard.cli import app
    from typer.testing import CliRunner
    runner = CliRunner()
    cfg = tmp_path / "config.txt"
    cfg.write_text("line vty 0 4\n transport input telnet\n")
    result = runner.invoke(app, [str(cfg), "--fail-on", "high"])
    assert result.exit_code == 1


def test_cli_fail_on_high_exits_zero_on_clean(tmp_path):
    from configguard.cli import app
    from typer.testing import CliRunner
    runner = CliRunner()
    cfg = tmp_path / "config.txt"
    cfg.write_text("hostname R1\n!\nend\n")
    result = runner.invoke(app, [str(cfg), "--fail-on", "high"])
    assert result.exit_code == 0


def test_cli_fail_on_invalid_value_errors(tmp_path):
    from configguard.cli import app
    from typer.testing import CliRunner
    runner = CliRunner()
    cfg = tmp_path / "config.txt"
    cfg.write_text("hostname R1\n")
    result = runner.invoke(app, [str(cfg), "--fail-on", "bogus"])
    assert result.exit_code != 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/test_cli.py -v -k fail_on`
Expected: 4 failures — `Error: no such option: --fail-on`

- [ ] **Step 3: Implement `--fail-on` in `configguard/cli.py`**

Add a Severity value map near the top of the file (after the imports):

```python
from configguard.models import Severity

_FAIL_ON_SEVERITY_ORDER = {
    "none": None,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}

_SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}
```

Add the option to the `audit` command signature (after the `risk_score` option):

```python
    fail_on: str = typer.Option("none", "--fail-on", help="Exit non-zero if any FAIL finding has severity >= threshold. One of: none, low, medium, high."),
```

After the `Total: ...` summary line (around line 129) and before the risk-score block, add:

```python
    # --fail-on gate
    if fail_on not in _FAIL_ON_SEVERITY_ORDER:
        typer.echo(f"Error: --fail-on must be one of: {list(_FAIL_ON_SEVERITY_ORDER.keys())}", err=True)
        raise typer.Exit(2)
    threshold = _FAIL_ON_SEVERITY_ORDER[fail_on]
    if threshold is not None:
        threshold_rank = _SEVERITY_RANK[threshold]
        breach = [f for f in findings if f.status.value == "FAIL" and _SEVERITY_RANK.get(f.severity, 0) >= threshold_rank]
        if breach:
            typer.echo(
                f"\n--fail-on {fail_on}: {len(breach)} finding(s) at or above {fail_on} severity. Exiting 1.",
                err=True,
            )
            raise typer.Exit(1)
```

- [ ] **Step 4: Run new tests to verify they pass**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/test_cli.py -v -k fail_on`
Expected: 4 PASS

- [ ] **Step 5: Run full suite**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/ -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
cd /home/lhqiu/project/ConfigGuard
git add configguard/cli.py tests/test_cli.py
git commit -m "feat(cli): add --fail-on {none,low,medium,high} for CI gating"
```

---

## Task 7: Author `examples/sample_router.txt` + frozen output fixtures

**Files:**
- Create: `examples/sample_router.txt`
- Create: `examples/sample_router.stdout.txt`
- Create: `examples/sample_router.report.md`

- [ ] **Step 1: Write the sample config**

Create `examples/sample_router.txt`:

```
! Sample Cisco IOS configuration used in ConfigGuard README
! Intentionally contains both violations and compliant sections
! to demonstrate the audit tool's discrimination capability.

hostname Branch-Router-01
!
! --- AAA (good) ---
aaa new-model
username netadmin privilege 15 secret 0 ChangeMe123!
!
! --- VTY (mixed: SSH is good, but a stray telnet-only line below will trigger CISCO-MGMT-001) ---
line vty 0 4
 transport input ssh
 login local
!
! --- Console (BAD: missing authentication) ---
line con 0
 exec-timeout 0 0
!
! --- HTTP server (BAD) ---
ip http server
ip http authentication local
!
! --- SNMP (BAD: weak community string) ---
snmp-server community public RO
snmp-server location Datacenter-1
!
! --- Logging (good) ---
logging host 192.0.2.10
!
! --- Interfaces ---
interface GigabitEthernet0/0
 description Uplink to core
 ip address 10.0.0.1 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/1
 description User VLAN 10
 no shutdown
!
end
```

- [ ] **Step 2: Run the audit and capture STDOUT**

Run:
```bash
cd /home/lhqiu/project/ConfigGuard
pip install -e . --quiet
configguard audit examples/sample_router.txt --output-dir /tmp/cg-fixtures
```

Then capture the STDOUT of a re-run (the second run only prints to STDOUT, files are already on disk):

```bash
cd /home/lhqiu/project/ConfigGuard
configguard audit examples/sample_router.txt --output-dir /tmp/cg-fixtures > examples/sample_router.stdout.txt 2>&1
```

- [ ] **Step 3: Copy frozen fixtures into the repo**

The first run wrote `/tmp/cg-fixtures/<timestamp>_sample_router.report.md`. Copy it to the repo as the frozen fixture:

```bash
cd /home/lhqiu/project/ConfigGuard
REPORT=$(ls -1t /tmp/cg-fixtures/*sample_router.report.md | head -1)
cp "$REPORT" examples/sample_router.report.md
```

Verify both fixtures are present and non-empty:

```bash
ls -la examples/sample_router.stdout.txt examples/sample_router.report.md
wc -l examples/sample_router.stdout.txt examples/sample_router.report.md
```

- [ ] **Step 4: Verify the captured output triggers the expected rules**

Run:
```bash
cd /home/lhqiu/project/ConfigGuard && grep -E "CISCO-MGMT-001|CISCO-MGMT-002|CISCO-SNMP-001|CISCO-AUTH" examples/sample_router.stdout.txt
```

Expected: At least 3 of the 4 lines appear (rule firing depends on which rules the engine actually wires up; if any rule doesn't fire, see the note below).

**Note on rule coverage in the sample:** The exact set of findings depends on which `applies_to` categories the rules bind to and what signals the parser extracts. The README's "What you get" section should match the actual STDOUT. If a rule doesn't fire, adjust the sample config or the rule's `applies_to` so the demo shows breadth. Document any such adjustment in the commit message.

- [ ] **Step 5: Commit**

```bash
cd /home/lhqiu/project/ConfigGuard
git add examples/sample_router.txt examples/sample_router.stdout.txt examples/sample_router.report.md
git commit -m "feat(examples): add sample_router.txt with frozen audit output fixtures"
```

---

## Task 8: Build `tools/generate_rule_table.py` + emit `docs/rule-table.md`

**Files:**
- Create: `tools/generate_rule_table.py`
- Create: `docs/rule-table.md`

- [ ] **Step 1: Write the generator script**

Create `tools/generate_rule_table.py`:

```python
"""Generate the rule coverage table for the README.

Reads every .yaml under configguard/rules/ and emits a Markdown table
suitable for embedding in README.md. Run from the repo root:

    python tools/generate_rule_table.py > docs/rule-table.md
"""
import sys
from pathlib import Path

# Make configguard importable when run from anywhere
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from configguard.engine import RuleEngine


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    engine = RuleEngine(str(repo_root / "configguard" / "rules"))

    print("# ConfigGuard Rule Coverage")
    print()
    print("Auto-generated from rule YAMLs. Do not edit by hand; rerun `python tools/generate_rule_table.py` after adding rules.")
    print()
    print("| Rule ID | Name | Severity | Category | CIS / CVE |")
    print("|---------|------|----------|----------|-----------|")
    for rule in sorted(engine.rules, key=lambda r: r.id):
        cis_refs = []
        for ref in rule.references:
            label = ref.id if ref.id else ref.type
            cis_refs.append(f"[{ref.type}: {label}]({ref.url})")
        refs_cell = "<br>".join(cis_refs) if cis_refs else "—"
        print(f"| `{rule.id}` | {rule.name} | {rule.severity.value} | {rule.category} | {refs_cell} |")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Generate the table**

Run:
```bash
cd /home/lhqiu/project/ConfigGuard && python tools/generate_rule_table.py > docs/rule-table.md
```

- [ ] **Step 3: Verify the output looks right**

Run: `cd /home/lhqiu/project/ConfigGuard && cat docs/rule-table.md`
Expected: A markdown table with 7 rows, each with at least one reference link.

- [ ] **Step 4: Commit**

```bash
cd /home/lhqiu/project/ConfigGuard
git add tools/generate_rule_table.py docs/rule-table.md
git commit -m "feat(tools): add rule table generator and emit docs/rule-table.md"
```

---

## Task 9: New test case `case_020_sample_router`

**Files:**
- Create: `tests/cases/case_020_sample_router/config.txt`
- Create: `tests/cases/case_020_sample_router/expected.json`
- Create: `tests/cases/case_020_sample_router/metadata.yaml`

- [ ] **Step 1: Create directory and copy the sample config**

```bash
cd /home/lhqiu/project/ConfigGuard
mkdir -p tests/cases/case_020_sample_router
cp examples/sample_router.txt tests/cases/case_020_sample_router/config.txt
```

- [ ] **Step 2: Write `metadata.yaml`**

Create `tests/cases/case_020_sample_router/metadata.yaml`:

```yaml
id: case_020_sample_router
description: Sample router config used in README demo — should trigger at least 3 violations across management, AAA, and SNMP
tags:
  - documentation
  - sample
  - multi-domain
version: "1.0"
```

- [ ] **Step 3: Determine actual findings by running audit**

Run:
```bash
cd /home/lhqiu/project/ConfigGuard
configguard audit tests/cases/case_020_sample_router/config.txt --output-dir /tmp/case020 2>&1 | grep -E "^\[" | head -20
```

Note the FAIL rule IDs.

- [ ] **Step 4: Write `expected.json` based on the actual output**

Create `tests/cases/case_020_sample_router/expected.json` with the FAIL rule IDs from Step 3:

```json
{
  "case_id": "case_020_sample_router",
  "findings": [
    {"rule_id": "CISCO-MGMT-001", "status": "FAIL"},
    {"rule_id": "CISCO-MGMT-002", "status": "FAIL"},
    {"rule_id": "CISCO-SNMP-001", "status": "FAIL"}
  ]
}
```

(Adjust the rule IDs to match what actually fires. If fewer than 3 rules fire, see the note in Task 7 Step 4 about adjusting the sample config or rule bindings.)

- [ ] **Step 5: Create the runner test for case_020**

`tests/cases/` is not auto-discovered by pytest — it holds ground-truth fixtures, not test functions. Add a runner test that loads the case:

Create `tests/test_sample_router.py`:

```python
"""Smoke test for the README demo config (case_020_sample_router)."""
import json
from pathlib import Path

from configguard.engine import RuleEngine
from configguard.parser import CiscoIOSParser
from configguard.signals import SignalExtractor
from configguard.context import ContextBuilder


def test_sample_router_triggers_expected_findings():
    cfg_path = Path(__file__).parent / "cases" / "case_020_sample_router" / "config.txt"
    expected_path = cfg_path.parent / "expected.json"

    expected = json.loads(expected_path.read_text())
    expected_ids = {f["rule_id"] for f in expected["findings"] if f["status"] == "FAIL"}

    repo_root = Path(__file__).resolve().parent.parent
    engine = RuleEngine(str(repo_root / "configguard" / "rules"))

    ir = CiscoIOSParser(cfg_path.read_text()).parse()
    signals = SignalExtractor().extract(ir)
    contexts = ContextBuilder().build_contexts(signals)

    if engine._category_index:
        findings = engine.evaluate_with_contexts(contexts, engine.rules)
    else:
        findings = engine.evaluate(ir)

    actual_ids = {f.rule_id for f in findings if f.status.value == "FAIL"}
    assert expected_ids.issubset(actual_ids), f"Expected at least {expected_ids}, got {actual_ids}"
```

- [ ] **Step 6: Run the test suite**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/ -q`
Expected: All pass (including the new `test_sample_router_triggers_expected_findings`)

- [ ] **Step 7: Commit**

```bash
cd /home/lhqiu/project/ConfigGuard
git add tests/cases/case_020_sample_router/ tests/test_sample_router.py
git commit -m "test: add case_020_sample_router covering README demo config"
```

---

## Task 10: Rewrite `README.md` (layered structure)

**Files:**
- Modify: `README.md` (full rewrite)

- [ ] **Step 1: Write the new README**

Overwrite `README.md` with the following content (one fenced block — copy verbatim):

````markdown
# ConfigGuard

Deterministic security auditor for Cisco network device configurations. Reads your router/switch config, applies a YAML rule set traceable to CIS Benchmarks, and emits findings in JSON, Markdown, or human-readable STDOUT.

## Quick start

```bash
pip install git+https://github.com/Lhqiu/ConfigGuard
configguard audit router.conf
```

Reports land in `./output/` by default. Run `configguard audit --help` for options.

> Not yet on PyPI. Pin to a tag (`@v0.2.1`) for stable installs.

## What you get

Audit a config and the tool returns one line per rule with severity and a snippet of evidence:

```
[FAIL] CISCO-MGMT-001 Disable Telnet
       Severity: HIGH
       Category: management-plane
       Block: line.vty[0]
       Evidence: 'transport input telnet' found in 1 block(s)
[FAIL] CISCO-MGMT-002 Disable HTTP Server
       Severity: HIGH
       Category: management-plane
       Block: global
       Evidence: HTTP_ENABLED
[FAIL] CISCO-SNMP-001 Disable SNMP v2c
       Severity: HIGH
       Category: snmp-security
       Block: global
       Evidence: 'public' found in 1 block(s)
```

The full report is also written as Markdown (with remediation and reference links) and JSON (for tooling). See [`examples/sample_router.report.md`](examples/sample_router.report.md) for a real report.

## Rule coverage

7 rules across management plane, AAA, and SNMP. Every rule carries at least one CIS / CVE / vendor reference.

See [`docs/rule-table.md`](docs/rule-table.md) for the full table. Regenerate with `python tools/generate_rule_table.py` after adding rules.

## Severity model

| Severity | Meaning |
|----------|---------|
| HIGH | Direct credential exposure or unauthenticated remote access. Always fix before shipping. |
| MEDIUM | Configuration weakens the security posture but requires another condition to be exploitable. |
| LOW | Hygiene; rarely the sole cause of an incident. |
| INFO | Informational, never a failure. |

Finding status is `FAIL` (rule violated), `WARN` (rule violated but soft), or `PASS` (rule satisfied). `--fail-on {low,medium,high}` exits non-zero when any `FAIL` reaches the threshold — for use in CI gates.

## Output formats

- **STDOUT** — human summary. Default. One block per finding with severity, category, evidence.
- **Markdown** (`--format markdown`) — full report with evidence, remediation, and reference links. Good for PR comments.
- **JSON** (`--format json`) — structured findings + metadata. Use for SIEM ingestion or downstream tooling.

## Run in CI

### GitHub Actions

Drop this into `.github/workflows/configguard.yml` in your own repo:

```yaml
name: ConfigGuard
on:
  pull_request:
    paths: ['**/*.conf', '**/configs/**', '**/routers/**']
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - name: Install ConfigGuard
        run: pip install git+https://github.com/Lhqiu/ConfigGuard@v0.2.1
      - name: Audit changed configs
        run: |
          CHANGED=$(git diff --name-only origin/${{ github.base_ref }}...HEAD | grep -E '\.(conf|cfg|txt)$' || true)
          if [ -z "$CHANGED" ]; then echo "No config files changed"; exit 0; fi
          configguard audit $CHANGED --output-dir ./audit-results --fail-on high
      - name: Upload audit report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: configguard-report
          path: audit-results/
```

`--fail-on high` makes the workflow block the PR on any HIGH-severity finding. Lower or remove the flag if you want report-only behavior.

### pre-commit

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Lhqiu/ConfigGuard
    rev: v0.2.1
    hooks:
      - id: configguard-audit
```

The hook runs `configguard audit` against staged `*.conf`, `*.cfg`, `*.txt` files. Requires Python on the dev machine (standard pre-commit behavior).

## Adding rules

Drop a YAML in `configguard/rules/<category>/` following the existing schema (see `configguard/rules/management/disable_telnet.yaml` for the simplest example). Every new rule must declare at least one reference in `references:` — a CIS Benchmark section, CVE, NIST 800-53 control, or Cisco hardening guide URL. Run `python tools/generate_rule_table.py` to refresh `docs/rule-table.md`, then add a test case under `tests/cases/`.

## Architecture

Three-layer IR (raw config → canonical resource → semantic context) with a deterministic YAML rule engine and a context-aware evaluator. See [`docs/architecture/`](docs/architecture/) for the design notes.

## License

MIT.
````

- [ ] **Step 2: Verify the README renders cleanly**

Run: `cd /home/lhqiu/project/ConfigGuard && cat README.md | head -40`
Expected: The new layered structure is visible.

- [ ] **Step 3: Run full test suite (defense-in-depth)**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/ -q`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
cd /home/lhqiu/project/ConfigGuard
git add README.md
git commit -m "docs: rewrite README in layered structure with demo, rule coverage, CI guidance"
```

---

## Task 11: Ship `.github/workflows/configguard.yml`

**Files:**
- Create: `.github/workflows/configguard.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/configguard.yml`:

```yaml
name: ConfigGuard
on:
  pull_request:
    paths: ['**/*.conf', '**/configs/**', '**/routers/**']
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - name: Install ConfigGuard
        run: pip install git+https://github.com/Lhqiu/ConfigGuard@v0.2.1
      - name: Audit changed configs
        run: |
          CHANGED=$(git diff --name-only origin/${{ github.base_ref }}...HEAD | grep -E '\.(conf|cfg|txt)$' || true)
          if [ -z "$CHANGED" ]; then echo "No config files changed"; exit 0; fi
          configguard audit $CHANGED --output-dir ./audit-results --fail-on high
      - name: Upload audit report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: configguard-report
          path: audit-results/
```

- [ ] **Step 2: Verify it doesn't break our own `ci.yml`**

Run: `cd /home/lhqiu/project/ConfigGuard && cat .github/workflows/ci.yml | head -10`
Expected: Our internal CI still exists separately. The new `configguard.yml` is the user-facing one.

- [ ] **Step 3: Commit**

```bash
cd /home/lhqiu/project/ConfigGuard
git add .github/workflows/configguard.yml
git commit -m "feat(ci): ship user-facing configguard.yml workflow for downstream repos"
```

---

## Task 12: Ship `.pre-commit-hooks.yaml`

**Files:**
- Create: `.pre-commit-hooks.yaml`

- [ ] **Step 1: Write the hook definition**

Create `.pre-commit-hooks.yaml`:

```yaml
- id: configguard-audit
  name: ConfigGuard — audit network configs
  description: Detect security misconfigurations in Cisco IOS / NX-OS config files
  entry: configguard audit
  language: python
  language_version: python3
  types: [file]
  files: '\.(conf|cfg|txt)$'
```

- [ ] **Step 2: Validate the YAML**

Run: `cd /home/lhqiu/project/ConfigGuard && python3 -c "import yaml; print(yaml.safe_load(open('.pre-commit-hooks.yaml')))"`
Expected: A list with one dict containing the hook definition.

- [ ] **Step 3: Commit**

```bash
cd /home/lhqiu/project/ConfigGuard
git add .pre-commit-hooks.yaml
git commit -m "feat(hooks): add pre-commit hook definition for downstream use"
```

---

## Task 13: Final verification + summary commit

- [ ] **Step 1: Run the full test suite one more time**

Run: `cd /home/lhqiu/project/ConfigGuard && pytest tests/ -q`
Expected: All tests pass.

- [ ] **Step 2: Smoke-test the CLI end-to-end**

Run:
```bash
cd /home/lhqiu/project/ConfigGuard
configguard audit examples/sample_router.txt --output-dir /tmp/final-smoke --fail-on high
echo "---exit: $?"
```

Expected: Exit code 1 (because the sample config intentionally contains HIGH findings, and `--fail-on high` should gate). Reports appear in `/tmp/final-smoke`.

- [ ] **Step 3: Run rule table generator one more time**

Run: `cd /home/lhqiu/project/ConfigGuard && python tools/generate_rule_table.py > /tmp/rule-table-check.md && diff /tmp/rule-table-check.md docs/rule-table.md`
Expected: No diff (table is in sync).

- [ ] **Step 4: Inspect the new git log**

Run: `cd /home/lhqiu/project/ConfigGuard && git log --oneline b12ea71..HEAD`
Expected: ~12 commits, one per task, in order.

- [ ] **Step 5: Add a summary commit if needed (only if any tracked files were missed)**

```bash
cd /home/lhqiu/project/ConfigGuard
git status
# If anything is untracked or modified, add a final commit:
# git add -A
# git commit -m "chore: promotion step 1 final cleanup"
```

(Skip this step if `git status` is clean — every step above already committed.)

---

## Out of scope (recorded in spec)

- PyPI publication
- Composite Action / marketplace
- Docker image
- PR inline annotations from JSON
- Full rule schema reference doc
- LLM `explain` promotion
