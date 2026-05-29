# ConfigGuard v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic security rule compiler CLI for Cisco IOS configurations, with block-aware parsing, YAML rule engine, JSON/Markdown/STDOUT output, and pytest-based ground truth testing.

**Architecture:** CLI → Block-aware Parser → Normalized IR → Rule Engine (YAML rules) → Findings JSON → LLM Explanation Layer (optional) → Output (JSON/Markdown/STDOUT)

**Tech Stack:** Python 3.10+, Typer (CLI), Pydantic (models), PyYAML (rule parsing), pytest (testing)

---

## File Structure

```
configguard/
  __init__.py              # Package init, version
  cli.py                   # Typer CLI entry point
  parser.py                # Block-aware parser → dual representation + IR
  engine.py                # Rule engine evaluator
  models.py                # Pydantic models (Finding, ConfigIR, etc.)
  output/
    __init__.py
    json.py                # JSON output generator
    markdown.py            # Markdown report generator
  rules/                   # YAML rule definitions
    management/
      disable_telnet.yaml
      disable_http.yaml
      secure_vty.yaml
    auth/
      aaa_required.yaml
      console_auth.yaml
    snmp/
      snmp_v2_disabled.yaml
    logging/
      remote_syslog.yaml
      ntp_config.yaml
    interface/
      unused_shutdown.yaml
tests/
  cases/
    case_001_telnet_enabled/
      config.txt
      expected.json
      metadata.yaml
    case_002_snmp_v2c/
      config.txt
      expected.json
      metadata.yaml
    case_003_missing_aaa/
      config.txt
      expected.json
      metadata.yaml
  test_engine.py           # Pytest test runner
  conftest.py             # Pytest fixtures
.github/
  workflows/
    ci.yml
pyproject.toml
README.md
```

---

## Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `configguard/__init__.py`
- Create: `configguard/output/__init__.py`
- Create: `README.md`

- [ ] **Step 1: Create pyproject.toml**

```toml
[project]
name = "configguard"
version = "0.1.0"
description = "Network device configuration security auditor (Cisco-first)"
requires-python = ">=3.10"
dependencies = [
    "typer>=0.12.0",
    "pydantic>=2.0.0",
    "pyyaml>=6.0",
    "pytest>=8.0.0",
    "pytest-xdist>=3.5.0",
]

[project.scripts]
configguard = "configguard.cli:main"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_functions = ["test_*"]
```

- [ ] **Step 2: Create configguard/__init__.py**

```python
"""ConfigGuard - Network Configuration Security Auditor."""

__version__ = "0.1.0"
```

- [ ] **Step 3: Create configguard/output/__init__.py**

```python
"""Output formatters for ConfigGuard."""
```

- [ ] **Step 4: Create README.md**

```markdown
# ConfigGuard

Network Device Configuration Security Auditor (Cisco-first).

## Quick Start

```bash
pip install -e .
configguard audit router_config.txt
```

## Features

- Deterministic rule engine (YAML rules)
- Block-aware Cisco IOS parser
- 5 security domains covered
- JSON, Markdown, STDOUT output
- Ground truth test suite
```

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml configguard/__init__.py configguard/output/__init__.py README.md
git commit -m "chore: project scaffolding"
```

---

## Task 2: Pydantic Models

**Files:**
- Create: `configguard/models.py`

- [ ] **Step 1: Write failing test for models**

```python
# tests/test_models.py
import pytest
from configguard.models import Finding, ConfigIR, RuleMatch, Severity

def test_finding_model():
    finding = Finding(
        rule_id="TEST-001",
        rule_name="Test Rule",
        category="test",
        severity=Severity.HIGH,
        status="FAIL",
        evidence="some config line",
    )
    assert finding.rule_id == "TEST-001"
    assert finding.severity == Severity.HIGH

def test_config_ir_structure():
    ir = ConfigIR(
        raw_lines=["line vty 0 4", " transport input telnet"],
        blocks=[],
        normalized={"services": {"telnet": {"status": "enabled"}}},
    )
    assert len(ir.raw_lines) == 2
    assert ir.normalized["services"]["telnet"]["status"] == "enabled"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal models implementation**

```python
"""Pydantic models for ConfigGuard."""
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


class RuleMatch(BaseModel):
    type: str = Field(description="match type: regex, exact, contains")
    pattern: str
    scope: Optional[str] = Field(default=None, description="block type scope")


class Finding(BaseModel):
    rule_id: str
    rule_name: str
    category: str
    severity: Severity
    status: FindingStatus
    evidence: str
    block_type: Optional[str] = None
    block_name: Optional[str] = None
    remediation: Optional[str] = None


class Block(BaseModel):
    type: str
    name: str
    commands: list[str] = Field(default_factory=list)


class ConfigIR(BaseModel):
    raw_lines: list[str] = Field(default_factory=list)
    blocks: list[Block] = Field(default_factory=list)
    normalized: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)


class AuditReport(BaseModel):
    version: str = "0.1.0"
    summary: dict
    findings: list[Finding]
    metadata: dict
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_models.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_models.py configguard/models.py
git commit -m "feat: add Pydantic models for findings, config IR, and rules"
```

---

## Task 3: Block-Aware Parser

**Files:**
- Create: `configguard/parser.py`
- Create: `tests/test_parser.py`

- [ ] **Step 1: Write failing test for parser**

```python
# tests/test_parser.py
import pytest
from configguard.parser import CiscoIOSParser

SAMPLE_CONFIG = """
hostname Router1
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
line vty 0 4
 transport input telnet ssh
 login local
!
end
"""

def test_parser_extracts_blocks():
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    result = parser.parse()
    assert len(result.blocks) == 2
    assert result.blocks[0].type == "interface"
    assert result.blocks[0].name == "GigabitEthernet0/0"
    assert result.blocks[1].type == "line"
    assert result.blocks[1].name == "vty 0 4"

def test_parser_raw_lines_preserved():
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    result = parser.parse()
    assert "hostname Router1" in result.raw_lines
    assert "transport input telnet ssh" in result.raw_lines

def test_parser_normalizes_services():
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    result = parser.parse()
    assert result.normalized["services"]["telnet"]["status"] == "enabled"
    assert result.normalized["services"]["ssh"]["status"] == "enabled"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_parser.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal parser implementation**

```python
"""Block-aware Cisco IOS parser producing dual representation + IR."""
import re
from configguard.models import ConfigIR, Block


class CiscoIOSParser:
    BLOCK_STARTERS = {
        "interface": "interface",
        "line": "line",
        "router": "router",
        "access-list": "access-list",
    }

    def __init__(self, config_text: str):
        self.config_text = config_text
        self.lines = config_text.strip().splitlines()
        self.current_block = None
        self.blocks = []
        self.raw_lines = []

    def parse(self) -> ConfigIR:
        for line in self.lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("!"):
                if self.current_block:
                    self._finalize_block()
                continue

            self.raw_lines.append(stripped)

            block_type = self._detect_block_start(stripped)
            if block_type:
                if self.current_block:
                    self._finalize_block()
                self.current_block = {
                    "type": block_type,
                    "name": stripped,
                    "commands": [],
                }
            elif self.current_block is not None:
                self.current_block["commands"].append(stripped)

        if self.current_block:
            self._finalize_block()

        normalized = self._build_normalized_ir()
        metadata = {
            "total_lines": len(self.raw_lines),
            "block_count": len(self.blocks),
        }

        return ConfigIR(
            raw_lines=self.raw_lines,
            blocks=self.blocks,
            normalized=normalized,
            metadata=metadata,
        )

    def _detect_block_start(self, line: str) -> str | None:
        for keyword, block_type in self.BLOCK_STARTERS.items():
            if line.startswith(keyword):
                return block_type
        return None

    def _finalize_block(self):
        if self.current_block:
            self.blocks.append(Block(**self.current_block))
            self.current_block = None

    def _build_normalized_ir(self) -> dict:
        ir = {
            "services": {},
            "management": {},
            "logging": {},
            "snmp": {},
            "interfaces": {},
        }

        # Extract telnet/ssh from VTY blocks
        for block in self.blocks:
            if block.type == "line" and "vty" in block.name.lower():
                for cmd in block.commands:
                    if "transport input" in cmd:
                        if "telnet" in cmd:
                            ir["services"]["telnet"] = {"status": "enabled", "scope": "vty"}
                        if "ssh" in cmd:
                            ir["services"]["ssh"] = {"status": "enabled", "scope": "vty"}

        # Extract management settings
        for block in self.blocks:
            if block.type == "global" or block.type == "line":
                for cmd in block.commands:
                    if cmd.startswith("logging"):
                        ir["logging"]["syslog"] = {"status": "configured"}

        return ir
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_parser.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_parser.py configguard/parser.py
git commit -m "feat: add block-aware Cisco IOS parser with dual representation"
```

---

## Task 4: Rule Engine Evaluator

**Files:**
- Create: `configguard/engine.py`
- Create: `tests/test_engine.py`
- Create: `configguard/rules/management/disable_telnet.yaml`

- [ ] **Step 1: Write failing test for rule engine**

```python
# tests/test_engine.py
import pytest
from configguard.engine import RuleEngine
from configguard.models import ConfigIR, Block

SAMPLE_IR = ConfigIR(
    raw_lines=["line vty 0 4", "transport input telnet ssh"],
    blocks=[
        Block(type="line", name="vty 0 4", commands=["transport input telnet ssh"])
    ],
    normalized={"services": {"telnet": {"status": "enabled"}}},
)

def test_rule_engine_loads_rules():
    engine = RuleEngine("configguard/rules")
    assert len(engine.rules) > 0

def test_rule_engine_detects_telnet():
    engine = RuleEngine("configguard/rules")
    findings = engine.evaluate(SAMPLE_IR)
    telnet_findings = [f for f in findings if "telnet" in f.rule_id.lower()]
    assert len(telnet_findings) == 1
    assert telnet_findings[0].status == "FAIL"

def test_rule_engine_passes_when_no_telnet():
    clean_ir = ConfigIR(
        raw_lines=["line vty 0 4", "transport input ssh"],
        blocks=[Block(type="line", name="vty 0 4", commands=["transport input ssh"])],
        normalized={"services": {"ssh": {"status": "enabled"}}},
    )
    engine = RuleEngine("configguard/rules")
    findings = engine.evaluate(clean_ir)
    telnet_findings = [f for f in findings if "telnet" in f.rule_id.lower()]
    assert len(telnet_findings) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_engine.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Create first rule YAML**

```yaml
# configguard/rules/management/disable_telnet.yaml
id: CISCO-MGMT-001
name: Disable Telnet
category: management-plane
severity: HIGH

match:
  type: regex
  pattern: "transport input .*telnet"
  scope: line.vty

condition: present

finding:
  status: FAIL
  evidence: true

description: >
  Telnet transmits credentials in plaintext.

remediation: >
  Use 'transport input ssh' instead.
```

- [ ] **Step 4: Write minimal engine implementation**

```python
"""Deterministic rule engine evaluator."""
import re
import yaml
from pathlib import Path
from typing import Iterator
from configguard.models import ConfigIR, Finding, FindingStatus, Severity


class Rule:
    def __init__(self, rule_data: dict):
        self.id = rule_data["id"]
        self.name = rule_data["name"]
        self.category = rule_data["category"]
        self.severity = Severity(rule_data["severity"])
        self.match_type = rule_data["match"]["type"]
        self.pattern = rule_data["match"]["pattern"]
        self.scope = rule_data["match"].get("scope")
        self.condition = rule_data["condition"]
        self.finding_status = FindingStatus(rule_data["finding"]["status"])
        self.description = rule_data.get("description", "")
        self.remediation = rule_data.get("remediation", "")

    def evaluate(self, ir: ConfigIR) -> list[Finding]:
        findings = []
        text_to_search = self._get_search_text(ir)

        if self.condition == "present":
            matches = list(re.finditer(self.pattern, text_to_search))
            if matches:
                for match in matches:
                    findings.append(Finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        status=self.finding_status,
                        evidence=match.group(),
                        block_type=self._get_block_type_for_match(match, ir),
                        block_name=self._get_block_name_for_match(match, ir),
                        remediation=self.remediation,
                    ))

        return findings

    def _get_search_text(self, ir: ConfigIR) -> str:
        if self.scope:
            scope_type = self.scope.split(".")[0]
            for block in ir.blocks:
                if block.type == scope_type:
                    return "\n".join(block.commands)
        return "\n".join(ir.raw_lines)

    def _get_block_type_for_match(self, match, ir: ConfigIR) -> str | None:
        if not self.scope:
            return None
        scope_type = self.scope.split(".")[0]
        for block in ir.blocks:
            if block.type == scope_type:
                block_text = "\n".join(block.commands)
                if match.group() in block_text:
                    return block.type
        return None

    def _get_block_name_for_match(self, match, ir: ConfigIR) -> str | None:
        if not self.scope:
            return None
        scope_type = self.scope.split(".")[0]
        for block in ir.blocks:
            if block.type == scope_type:
                block_text = "\n".join(block.commands)
                if match.group() in block_text:
                    return block.name
        return None


class RuleEngine:
    def __init__(self, rules_dir: str):
        self.rules = []
        self.rules_dir = Path(rules_dir)
        self._load_rules()

    def _load_rules(self):
        if not self.rules_dir.exists():
            return
        for yaml_file in self.rules_dir.rglob("*.yaml"):
            with open(yaml_file) as f:
                rule_data = yaml.safe_load(f)
                self.rules.append(Rule(rule_data))

    def evaluate(self, ir: ConfigIR) -> list[Finding]:
        all_findings = []
        for rule in self.rules:
            findings = rule.evaluate(ir)
            all_findings.extend(findings)
        return all_findings
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_engine.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add tests/test_engine.py configguard/engine.py configguard/rules/management/disable_telnet.yaml
git commit -m "feat: add rule engine with YAML loader and deterministic evaluator"
```

---

## Task 5: Output Layer

**Files:**
- Create: `configguard/output/json.py`
- Create: `configguard/output/markdown.py`
- Create: `tests/test_output.py`

- [ ] **Step 1: Write failing test for JSON output**

```python
# tests/test_output.py
import pytest
import json
from configguard.output.json import generate_json_report
from configguard.models import Finding, Severity, FindingStatus

FINDINGS = [
    Finding(
        rule_id="CISCO-MGMT-001",
        rule_name="Disable Telnet",
        category="management-plane",
        severity=Severity.HIGH,
        status=FindingStatus.FAIL,
        evidence="transport input telnet ssh",
    )
]

def test_json_report_structure():
    report = generate_json_report(
        findings=FINDINGS,
        config_name="test_config.txt",
        rules_version="0.1.0",
    )
    data = json.loads(report)

    assert data["version"] == "0.1.0"
    assert data["summary"]["total"] == 1
    assert data["summary"]["fail"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "CISCO-MGMT-001"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_output.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write JSON output generator**

```python
"""JSON output generator for ConfigGuard."""
import json
from datetime import datetime
from configguard.models import Finding


def generate_json_report(findings: list[Finding], config_name: str, rules_version: str) -> str:
    summary = {
        "total": len(findings),
        "pass": sum(1 for f in findings if f.status.value == "PASS"),
        "fail": sum(1 for f in findings if f.status.value == "FAIL"),
        "warnings": sum(1 for f in findings if f.status.value == "WARN"),
    }

    report = {
        "version": "0.1.0",
        "summary": summary,
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "category": f.category,
                "severity": f.severity.value,
                "status": f.status.value,
                "evidence": f.evidence,
                "block_type": f.block_type,
                "block_name": f.block_name,
                "remediation": f.remediation,
            }
            for f in findings
        ],
        "metadata": {
            "config_name": config_name,
            "device_type": "Cisco IOS",
            "parser_version": "0.1.0",
            "rules_version": rules_version,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        },
    }

    return json.dumps(report, indent=2)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_output.py -v`
Expected: PASS

- [ ] **Step 5: Write Markdown output generator**

```python
"""Markdown report generator for ConfigGuard."""
from configguard.models import Finding


def generate_markdown_report(findings: list[Finding], config_name: str) -> str:
    summary = {
        "total": len(findings),
        "pass": sum(1 for f in findings if f.status.value == "PASS"),
        "fail": sum(1 for f in findings if f.status.value == "FAIL"),
        "warnings": sum(1 for f in findings if f.status.value == "WARN"),
    }

    lines = [
        "# ConfigGuard Security Audit Report",
        "",
        "## Summary",
        f"- **Total Checks:** {summary['total']}",
        f"- **Passed:** {summary['pass']}",
        f"- **Failed:** {summary['fail']}",
        f"- **Warnings:** {summary['warnings']}",
        "",
        "---",
        "",
    ]

    fail_findings = [f for f in findings if f.status.value == "FAIL"]
    pass_findings = [f for f in findings if f.status.value == "PASS"]

    if fail_findings:
        lines.append("## Failed Findings\n")
        for f in fail_findings:
            lines.append(f"### [{f.severity.value}] {f.rule_name}")
            lines.append(f"**Rule ID:** {f.rule_id}")
            lines.append(f"**Category:** {f.category}")
            lines.append("")
            lines.append("**Evidence:**")
            lines.append(f"```\n{f.evidence}\n```")
            lines.append("")
            if f.remediation:
                lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")

    if pass_findings:
        lines.append("## Passed Findings\n")
        for f in pass_findings:
            lines.append(f"- [{f.severity.value}] {f.rule_name} ({f.rule_id})")

    return "\n".join(lines)
```

- [ ] **Step 6: Write test for Markdown output**

```python
# tests/test_output.py — add after existing tests
from configguard.output.markdown import generate_markdown_report

def test_markdown_report_structure():
    report = generate_markdown_report(FINDINGS, "test_config.txt")
    assert "# ConfigGuard Security Audit Report" in report
    assert "## Summary" in report
    assert "Disable Telnet" in report
    assert "[HIGH] Disable Telnet" in report
```

- [ ] **Step 7: Run all output tests**

Run: `pytest tests/test_output.py -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add tests/test_output.py configguard/output/json.py configguard/output/markdown.py
git commit -m "feat: add JSON and Markdown output generators"
```

---

## Task 6: CLI Entry Point

**Files:**
- Create: `configguard/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write failing test for CLI**

```python
# tests/test_cli.py
import pytest
from click.testing import CliRunner
from configguard.cli import audit

def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(audit, ["--help"])
    assert result.exit_code == 0
    assert "configguard audit" in result.output

def test_cli_basic_audit(tmp_path):
    runner = CliRunner()
    config_file = tmp_path / "config.txt"
    config_file.write_text("line vty 0 4\n transport input telnet ssh\n")

    result = runner.invoke(audit, [str(config_file)])
    assert result.exit_code == 0
    assert "FAIL" in result.output or "telnet" in result.output.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write CLI using Typer**

```python
"""ConfigGuard CLI entry point."""
import typer
from pathlib import Path
from configguard.parser import CiscoIOSParser
from configguard.engine import RuleEngine
from configguard.output.json import generate_json_report
from configguard.output.markdown import generate_markdown_report

app = typer.Typer()


@app.command()
def audit(
    config_file: Path,
    output_dir: Path = typer.Option(Path("./output"), help="Output directory"),
    format: str = typer.Option("all", help="Output format: json, markdown, all"),
    rules_dir: Path = typer.Option(Path("configguard/rules"), help="Rules directory"),
    explain: bool = typer.Option(False, help="Enable LLM explanations"),
    verbose: bool = typer.Option(False, help="Verbose output"),
):
    """Audit a network device configuration file."""
    if not config_file.exists():
        typer.echo(f"Error: File not found: {config_file}", err=True)
        raise typer.Exit(1)

    config_text = config_file.read_text()
    parser = CiscoIOSParser(config_text)
    ir = parser.parse()

    engine = RuleEngine(str(rules_dir))
    findings = engine.evaluate(ir)

    output_dir.mkdir(parents=True, exist_ok=True)
    config_name = config_file.name

    if format in ("json", "all"):
        json_report = generate_json_report(
            findings=findings,
            config_name=config_name,
            rules_version="0.1.0",
        )
        json_path = output_dir / f"{config_name}.report.json"
        json_path.write_text(json_report)
        typer.echo(f"JSON report: {json_path}")

    if format in ("markdown", "all"):
        md_report = generate_markdown_report(findings=findings, config_name=config_name)
        md_path = output_dir / f"{config_name}.report.md"
        md_path.write_text(md_report)
        typer.echo(f"Markdown report: {md_path}")

    # STDOUT summary
    typer.echo("\n--- Audit Summary ---")
    for f in findings:
        status_icon = "FAIL" if f.status.value == "FAIL" else "PASS"
        typer.echo(f"[{status_icon}] {f.rule_name}")

    typer.echo(f"\nTotal: {len(findings)} findings")


def main():
    app()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_cli.py configguard/cli.py
git commit -m "feat: add Typer CLI entry point with audit command"
```

---

## Task 7: Remaining Rules

**Files:**
- Create: `configguard/rules/management/disable_http.yaml`
- Create: `configguard/rules/management/secure_vty.yaml`
- Create: `configguard/rules/auth/aaa_required.yaml`
- Create: `configguard/rules/auth/console_auth.yaml`
- Create: `configguard/rules/snmp/snmp_v2_disabled.yaml`
- Create: `configguard/rules/logging/remote_syslog.yaml`
- Create: `configguard/rules/logging/ntp_config.yaml`
- Create: `configguard/rules/interface/unused_shutdown.yaml`

- [ ] **Step 1: Create disable_http.yaml**

```yaml
id: CISCO-MGMT-002
name: Disable HTTP Server
category: management-plane
severity: HIGH

match:
  type: regex
  pattern: "ip http server"

condition: present

finding:
  status: FAIL
  evidence: true

description: >
  HTTP server exposes management interface to network attacks.

remediation: >
  Use 'no ip http server' to disable and use SSH for management.
```

- [ ] **Step 2: Create secure_vty.yaml**

```yaml
id: CISCO-MGMT-003
name: Secure VTY Configuration
category: management-plane
severity: HIGH

match:
  type: regex
  pattern: "transport input telnet"

condition: absent

finding:
  status: FAIL
  evidence: true

description: >
  VTY lines must not allow telnet access.

remediation: >
  Configure 'transport input ssh' on all VTY lines.
```

- [ ] **Step 3: Create aaa_required.yaml**

```yaml
id: CISCO-AUTH-001
name: AAA Required
category: authentication
severity: HIGH

match:
  type: regex
  pattern: "aaa new-model"

condition: present

finding:
  status: PASS
  evidence: true

description: >
  AAA (Authentication, Authorization, Accounting) must be enabled.
```

- [ ] **Step 4: Create console_auth.yaml**

```yaml
id: CISCO-AUTH-002
name: Console Authentication Required
category: authentication
severity: HIGH

match:
  type: regex
  pattern: "line con 0"

condition: present

finding:
  status: FAIL
  evidence: true

description: >
  Console line must have authentication configured.

remediation: >
  Configure 'login authentication' under line con 0.
```

- [ ] **Step 5: Create snmp_v2_disabled.yaml**

```yaml
id: CISCO-SNMP-001
name: Disable SNMP v2c
category: snmp-security
severity: HIGH

match:
  type: regex
  pattern: "snmp-server community.*(public|private)"

condition: present

finding:
  status: FAIL
  evidence: true

description: >
  SNMP v2c with public/private community strings exposes device to read/write attacks.

remediation: >
  Use SNMPv3 with authpriv. If SNMP v2c required, use strong community strings.
```

- [ ] **Step 6: Create remote_syslog.yaml**

```yaml
id: CISCO-LOG-001
name: Remote Syslog Required
category: logging
severity: MEDIUM

match:
  type: regex
  pattern: "logging host"

condition: present

finding:
  status: PASS
  evidence: true

description: >
  Remote syslog must be configured for audit trail.
```

- [ ] **Step 7: Create ntp_config.yaml**

```yaml
id: CISCO-LOG-002
name: NTP Configuration Required
category: logging
severity: MEDIUM

match:
  type: regex
  pattern: "ntp server"

condition: present

finding:
  status: PASS
  evidence: true

description: >
  NTP must be configured for time synchronization.
```

- [ ] **Step 8: Create unused_shutdown.yaml**

```yaml
id: CISCO-IF-001
name: Unused Interfaces Must Be Shutdown
category: interface-hygiene
severity: MEDIUM

match:
  type: regex
  pattern: "interface.*GigabitEthernet"

condition: present

finding:
  status: WARN
  evidence: true

description: >
  Unused interfaces should be shutdown to reduce attack surface.

remediation: >
  Configure 'shutdown' on unused interfaces.
```

- [ ] **Step 9: Commit**

```bash
git add configguard/rules/management/disable_http.yaml \
  configguard/rules/management/secure_vty.yaml \
  configguard/rules/auth/aaa_required.yaml \
  configguard/rules/auth/console_auth.yaml \
  configguard/rules/snmp/snmp_v2_disabled.yaml \
  configguard/rules/logging/remote_syslog.yaml \
  configguard/rules/logging/ntp_config.yaml \
  configguard/rules/interface/unused_shutdown.yaml
git commit -m "feat: add rules for all 5 security domains"
```

---

## Task 8: Ground Truth Test Cases

**Files:**
- Create: `tests/cases/case_001_telnet_enabled/config.txt`
- Create: `tests/cases/case_001_telnet_enabled/expected.json`
- Create: `tests/cases/case_001_telnet_enabled/metadata.yaml`
- Create: `tests/cases/case_002_snmp_v2c/config.txt`
- Create: `tests/cases/case_002_snmp_v2c/expected.json`
- Create: `tests/cases/case_002_snmp_v2c/metadata.yaml`
- Create: `tests/cases/case_003_missing_aaa/config.txt`
- Create: `tests/cases/case_003_missing_aaa/expected.json`
- Create: `tests/cases/case_003_missing_aaa/metadata.yaml`
- Create: `tests/conftest.py`
- Create: `tests/test_engine.py` (update with test case runner)

- [ ] **Step 1: Create case_001_telnet_enabled artifacts**

```text
# tests/cases/case_001_telnet_enabled/config.txt
hostname Router1
!
line vty 0 4
 transport input telnet ssh
 login local
!
end
```

```json
// tests/cases/case_001_telnet_enabled/expected.json
{
  "case_id": "case_001_telnet_enabled",
  "findings": [
    {
      "rule_id": "CISCO-MGMT-001",
      "status": "FAIL"
    }
  ]
}
```

```yaml
# tests/cases/case_001_telnet_enabled/metadata.yaml
id: case_001_telnet_enabled
description: Telnet enabled on VTY lines should trigger FAIL
tags:
  - management-plane
  - cisco-ios
  - high-risk
version: "1.0"
```

- [ ] **Step 2: Create case_002_snmp_v2c artifacts**

```text
# tests/cases/case_002_snmp_v2c/config.txt
hostname Router1
!
snmp-server community public RO
snmp-server community private RW
!
end
```

```json
// tests/cases/case_002_snmp_v2c/expected.json
{
  "case_id": "case_002_snmp_v2c",
  "findings": [
    {
      "rule_id": "CISCO-SNMP-001",
      "status": "FAIL"
    }
  ]
}
```

```yaml
# tests/cases/case_002_snmp_v2c/metadata.yaml
id: case_002_snmp_v2c
description: SNMP v2c with public community string should trigger FAIL
tags:
  - snmp-security
  - cisco-ios
  - high-risk
version: "1.0"
```

- [ ] **Step 3: Create case_003_missing_aaa artifacts**

```text
# tests/cases/case_003_missing_aaa/config.txt
hostname Router1
!
no aaa new-model
!
end
```

```json
// tests/cases/case_003_missing_aaa/expected.json
{
  "case_id": "case_003_missing_aaa",
  "findings": [
    {
      "rule_id": "CISCO-AUTH-001",
      "status": "FAIL"
    }
  ]
}
```

```yaml
# tests/cases/case_003_missing_aaa/metadata.yaml
id: case_003_missing_aaa
description: Missing AAA model should trigger FAIL
tags:
  - authentication
  - cisco-ios
  - high-risk
version: "1.0"
```

- [ ] **Step 4: Create conftest.py with test case fixtures**

```python
"""Pytest fixtures for ConfigGuard tests."""
import pytest
from pathlib import Path
import json
import yaml


@pytest.fixture
def test_cases_dir():
    return Path(__file__).parent / "cases"


@pytest.fixture
def load_test_case(test_cases_dir):
    def _load(case_name: str):
        case_dir = test_cases_dir / case_name
        config_file = case_dir / "config.txt"
        expected_file = case_dir / "expected.json"
        metadata_file = case_dir / "metadata.yaml"

        config_text = config_file.read_text()
        expected = json.loads(expected_file.read_text())
        metadata = yaml.safe_load(metadata_file.read_text())

        return {
            "config": config_text,
            "expected": expected,
            "metadata": metadata,
        }
    return _load
```

- [ ] **Step 5: Update test_engine.py with test case runner**

```python
# tests/test_engine.py — add test case runner tests
import pytest
from configguard.parser import CiscoIOSParser
from configguard.engine import RuleEngine


def test_telnet_case(load_test_case):
    case = load_test_case("case_001_telnet_enabled")
    parser = CiscoIOSParser(case["config"])
    ir = parser.parse()
    engine = RuleEngine("configguard/rules")
    findings = engine.evaluate(ir)

    expected_rule_ids = [f["rule_id"] for f in case["expected"]["findings"]]
    actual_rule_ids = [f.rule_id for f in findings]

    for rule_id in expected_rule_ids:
        matching = [f for f in findings if f.rule_id == rule_id]
        assert len(matching) == 1
        assert matching[0].status.value == "FAIL"


def test_snmp_v2c_case(load_test_case):
    case = load_test_case("case_002_snmp_v2c")
    parser = CiscoIOSParser(case["config"])
    ir = parser.parse()
    engine = RuleEngine("configguard/rules")
    findings = engine.evaluate(ir)

    snmp_findings = [f for f in findings if f.rule_id == "CISCO-SNMP-001"]
    assert len(snmp_findings) == 1
    assert snmp_findings[0].status.value == "FAIL"


def test_missing_aaa_case(load_test_case):
    case = load_test_case("case_003_missing_aaa")
    parser = CiscoIOSParser(case["config"])
    ir = parser.parse()
    engine = RuleEngine("configguard/rules")
    findings = engine.evaluate(ir)

    aaa_findings = [f for f in findings if f.rule_id == "CISCO-AUTH-001"]
    assert len(aaa_findings) == 1
    assert aaa_findings[0].status.value == "FAIL"
```

- [ ] **Step 6: Run all ground truth tests**

Run: `pytest tests/test_engine.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add tests/cases/
git commit -m "feat: add ground truth test cases with config/expected/metadata"
```

---

## Task 9: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create CI workflow**

```yaml
name: ConfigGuard CI

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.10"

      - name: Install dependencies
        run: |
          pip install -e .

      - name: Run tests
        run: pytest tests/ -v

      - name: Upload test report
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: test-report
          path: test-report.txt
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions workflow for pytest"
```

---

## Self-Review Checklist

1. **Spec coverage:** All spec sections implemented:
   - Architecture: Task 3 (Parser) + Task 4 (Engine) + Task 5 (Output)
   - 5 Security Domains: Task 7 (8 rules covering all domains)
   - Block-aware parser: Task 3
   - YAML rules: Task 4
   - JSON/Markdown/STDOUT output: Task 5
   - Ground truth system: Task 8
   - CLI: Task 6
   - CI: Task 9

2. **Placeholder scan:** No TBD/TODO found. All steps have concrete code.

3. **Type consistency:** All method signatures use consistent types (ConfigIR, Finding, FindingStatus, Severity).

4. **File paths:** All files use correct paths under `configguard/` and `tests/`.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-05-29-configguard-v0.1-implementation.md`.**

Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**